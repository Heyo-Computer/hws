//! Retained-artifact rollout protocol for app-lb static sites.
//!
//! The app-lb job ledger is the effect receipt. CI always looks up the exact
//! operation before POSTing, and never treats acceptance as deployment success.
use crate::{bus::JobMessage, dispatch::Dispatcher, secrets::Masker};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub url: String,
    pub deployment: String,
    pub namespace: String,
    pub config_sha256: String,
}

#[derive(Debug, Serialize)]
struct Intent<'a> {
    target: &'a Target,
    operation_id: &'a str,
    artifact_sha256: &'a str,
    source_revision: &'a str,
    workflow: &'a str,
    artifact: &'a str,
}

fn sha(value: &Value) -> String {
    let mut value = value.clone();
    value.sort_all_objects();
    hex::encode(Sha256::digest(
        serde_json::to_vec(&value).expect("JSON serializes"),
    ))
}

/// Must match app-lb's rollout fingerprint: the requested digest replaces the
/// artifact ref, so that mutable selector is not configuration identity.
fn config_fingerprint(mut spec: Value) -> String {
    if let Some(vm) = spec.get_mut("vm").and_then(Value::as_object_mut) {
        // Option::None is omitted by app-lb's serializer, rather than emitted
        // as JSON null.
        vm.remove("image");
    }
    if let Some(artifact) = spec.get_mut("artifact").and_then(Value::as_object_mut) {
        artifact.insert("ref".into(), json!(""));
    }
    sha(&spec)
}

fn exact_job<'a>(jobs: &'a Value, operation: &str) -> Result<Option<&'a Value>> {
    let jobs = jobs
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid app-lb job list"))?;
    let found: Vec<_> = jobs
        .iter()
        .filter(|job| job["operation_id"] == operation)
        .collect();
    ensure!(
        found.len() <= 1,
        "app-lb returned duplicate operation receipts"
    );
    Ok(found.first().copied())
}

fn receipt(
    job: &Value,
    operation: &str,
    target: &Target,
    digest: &str,
    root: &str,
) -> Result<Option<bool>> {
    ensure!(
        job["operation_id"] == operation
            && job["deployment"] == target.deployment
            && job["target_namespace"] == target.namespace
            && job["config_fingerprint"] == target.config_sha256,
        "site rollout receipt identity or configuration differs"
    );
    ensure!(
        job["artifact"] == digest,
        "site rollout requested a different digest"
    );
    match job["status"].as_str() {
        Some("running") => Ok(None),
        Some("failed") => Ok(Some(false)),
        Some("succeeded") => {
            ensure!(
                job["digest"] == digest && job["site_root"] == root && job["verified"] == true,
                "site rollout lacks exact digest, root, or verified-index receipt"
            );
            ensure!(
                job.get("readiness_verified").is_none() || job["readiness_verified"].is_null(),
                "static-site receipt must not claim VM readiness"
            );
            ensure!(
                job["reconciliation_required"] != true,
                "site rollout requires reconciliation"
            );
            Ok(Some(true))
        }
        _ => anyhow::bail!("unknown site rollout receipt status"),
    }
}

pub fn validate_target(target: &Target) -> Result<()> {
    crate::cd::app_lb_endpoint(&target.url).map_err(anyhow::Error::msg)?;
    ensure!(
        !target.namespace.is_empty()
            && !target.deployment.is_empty()
            && target
                .deployment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid site target identity"
    );
    ensure!(
        target.config_sha256.len() == 64
            && target
                .config_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "site target requires a lowercase SHA-256 configuration fingerprint"
    );
    Ok(())
}

/// Deploy one retained release component using frozen operator configuration.
pub async fn deploy(
    d: &Dispatcher,
    msg: &JobMessage,
    step: &str,
    target: Target,
    token: &str,
    workflow: &str,
    artifact_name: &str,
    timeout: Duration,
    _masker: &Masker,
) -> Result<String> {
    validate_target(&target)?;
    ensure!(
        !token.trim().is_empty(),
        "site rollout requires a secret credential"
    );
    let bundle = crate::release_environment::bundle_for_run(&d.store, &msg.run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("site rollout requires an admitted retained release"))?;
    let stored =
        crate::release_environment::artifact(&bundle["manifest"], workflow, artifact_name, None)?;
    let digest = stored
        .digest
        .ok_or_else(|| anyhow::anyhow!("retained site artifact has no digest"))?;
    let source_revision = bundle["manifest"]["revision"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("retained release has no source revision"))?;
    let operation = format!("ci-site-{}", hex::encode(Sha256::digest(step.as_bytes())));
    let intent = serde_json::to_value(Intent {
        target: &target,
        operation_id: &operation,
        artifact_sha256: &digest,
        source_revision,
        workflow,
        artifact: artifact_name,
    })?;
    let inserted = d
        .store
        .begin_service_deployment(&operation, step, &target.deployment, &sha(&intent))
        .await?;
    let ledger = sqlx::query("SELECT status,created_at FROM ci_service_deployment WHERE id=$1")
        .bind(&operation)
        .fetch_one(d.store.pool())
        .await?;
    let ledger_status: String = ledger.get("status");
    if !inserted {
        if ledger_status == "passed" {
            return Ok(format!(
                "[ci] {} site already verified at {}\n",
                target.deployment, source_revision
            ));
        }
        if ledger_status == "failed" {
            anyhow::bail!("site rollout failed; operation {operation} previously settled failed");
        }
    }
    let created_at: chrono::DateTime<chrono::Utc> = ledger.get("created_at");
    let base = crate::cd::app_lb_endpoint(&target.url).map_err(anyhow::Error::msg)?;
    let endpoint = format!("{base}/deployments/{}", target.deployment);
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let allowance = timeout.min(d.config.max_job_duration);
    let elapsed = (chrono::Utc::now() - created_at)
        .to_std()
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + allowance.saturating_sub(elapsed);
    let mut may_post = inserted;
    loop {
        if tokio::time::Instant::now() >= deadline || d.store.is_job_cancelled(&msg.job_id).await? {
            anyhow::bail!("site rollout outcome unresolved; reconcile operation {operation}");
        }
        let snapshot: Value = http
            .get(&endpoint)
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            snapshot["spec"]["namespace"].as_str().unwrap_or("default") == target.namespace
                && snapshot["kind"].as_str() == Some("site")
                && snapshot["spec"]["site"].is_object()
                && config_fingerprint(snapshot["spec"].clone()) == target.config_sha256,
            "site source configuration changed before publication"
        );
        let root = snapshot["spec"]["site"]["root"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("site target has no root"))?;
        let jobs: Value = http
            .get(format!("{endpoint}/jobs"))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(job) = exact_job(&jobs, &operation)? {
            may_post = false;
            match receipt(job, &operation, &target, &digest, root)? {
                Some(true) => {
                    d.store
                        .update_service_deployment(
                            &operation,
                            "passed",
                            Some("complete"),
                            Some("Exact retained site digest and index verified."),
                            None,
                        )
                        .await?;
                    return Ok(format!(
                        "[ci] {} site verified at {}\n",
                        target.deployment, source_revision
                    ));
                }
                Some(false) => {
                    d.store
                        .update_service_deployment(
                            &operation,
                            "failed",
                            Some("settled_failure"),
                            Some("app-lb site pull failed."),
                            None,
                        )
                        .await?;
                    anyhow::bail!("site rollout failed; operation {operation} settled failed");
                }
                None => {}
            }
        } else if may_post {
            let response = http
                .post(format!("{endpoint}/pull"))
                .bearer_auth(token)
                .json(&json!({"operation_id":operation,"ref":digest,"force":true}))
                .send()
                .await;
            may_post = false; // an uncertain POST is reconciled, never blindly repeated
            if let Ok(response) = response {
                ensure!(
                    !response.status().is_client_error() && !response.status().is_redirection(),
                    "app-lb refused site pull"
                );
            }
        } else {
            d.store
                .update_service_deployment(
                    &operation,
                    "submission_unknown",
                    Some("reconciliation"),
                    None,
                    Some("exact app-lb operation receipt is absent"),
                )
                .await?;
            anyhow::bail!("site rollout effect unknown; operation {operation} remains unresolved");
        }
        d.store
            .update_service_deployment(
                &operation,
                "running",
                Some("site_pull"),
                Some("Waiting for exact static-site receipt."),
                None,
            )
            .await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            url: "https://admin.test".into(),
            deployment: "retail".into(),
            namespace: "public".into(),
            config_sha256: "c".repeat(64),
        }
    }
    fn succeeded() -> Value {
        json!({"operation_id":"op","deployment":"retail","kind":"artifact-pull",
        "status":"succeeded","target_namespace":"public","config_fingerprint":"c".repeat(64),
        "artifact":"a".repeat(64),"digest":"a".repeat(64),"site_root":"/srv/retail","verified":true})
    }

    #[test]
    fn receipt_rejects_wrong_digest_config_and_vm_readiness() {
        let good = succeeded();
        assert_eq!(
            receipt(&good, "op", &target(), &"a".repeat(64), "/srv/retail").unwrap(),
            Some(true)
        );
        for (key, value) in [
            ("digest", json!("b".repeat(64))),
            ("config_fingerprint", json!("d".repeat(64))),
            ("operation_id", json!("other")),
            ("readiness_verified", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                receipt(&bad, "op", &target(), &"a".repeat(64), "/srv/retail").is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn operation_replay_is_exact_and_source_file_changes_change_fingerprint() {
        let jobs = json!([succeeded()]);
        assert!(exact_job(&jobs, "op").unwrap().is_some());
        assert!(exact_job(&jobs, "other").unwrap().is_none());
        let mut duplicate = jobs.clone();
        duplicate.as_array_mut().unwrap().push(succeeded());
        assert!(exact_job(&duplicate, "op").is_err());
        let spec = json!({"id":"retail","namespace":"public","site":{"root":"/srv/retail","index":"index.html"},
            "artifact":{"store":"https://art.test","ref":"old"}});
        let first = config_fingerprint(spec.clone());
        let mut ref_only = spec.clone();
        ref_only["artifact"]["ref"] = json!("new");
        assert_eq!(first, config_fingerprint(ref_only));
        let mut changed = spec;
        changed["site"]["index"] = json!("home.html");
        assert_ne!(first, config_fingerprint(changed));
    }

    #[test]
    fn fingerprint_uses_app_lb_option_omission_semantics() {
        let omitted = json!({"id":"app","vm":{"driver":"firecracker","port":8080},
            "artifact":{"store":"https://art.test","ref":"old"}});
        let explicit_null = json!({"id":"app","vm":{"driver":"firecracker","port":8080,"image":null},
            "artifact":{"store":"https://art.test","ref":"old"}});
        assert_eq!(
            config_fingerprint(omitted),
            config_fingerprint(explicit_null)
        );
    }
}
