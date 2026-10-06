//! CAS replacement of a singleton Firecracker service while retaining its
//! persistent workspace. Unlike `service_rollout`, this is deliberately not a
//! candidate-first rollout: app-lb replaces the only VM and keeps its workspace.
use crate::{bus::JobMessage, dispatch::Dispatcher, secrets::Masker, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Target {
    pub url: String,
    pub deployment: String,
    pub namespace: String,
    pub mount_path: String,
    pub revision_env: String,
    pub start_command: String,
    pub working_directory: String,
    pub health_url: String,
}

/// Deliberately excludes the deployment spec, environment, routes, workspace
/// configuration, credentials and response bodies.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Intent {
    target: Target,
    store: String,
    artifact: String,
    sha: String,
    previous_artifact: String,
    previous_revision: String,
    source_sandbox_id: String,
    original_spec_sha256: String,
    desired_spec_sha256: String,
}

#[derive(Debug, PartialEq)]
enum Decision {
    VerifyNoop,
    SettleOriginal,
    PutDesired,
    WaitReplacement,
    VerifyReplacement,
    PutRollback,
    WaitRollback,
    VerifyRollback,
    WaitRollbackCapture,
    ConcurrentEdit,
}

fn digest(value: &Value) -> String {
    let mut value = value.clone();
    value.sort_all_objects();
    hex::encode(Sha256::digest(
        serde_json::to_vec(&value).expect("JSON serializes"),
    ))
}

fn etag(value: &Value) -> String {
    format!("\"{}\"", digest(value))
}

pub fn validate_target(target: &Target) -> Result<()> {
    use std::path::{Component, Path};
    ensure!(
        !target.deployment.is_empty()
            && target
                .deployment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid deployment identifier"
    );
    ensure!(
        target.mount_path.starts_with("/opt/")
            && Path::new(&target.mount_path)
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "invalid release mount path"
    );
    ensure!(
        target.working_directory == target.mount_path
            && target.start_command == format!("{}/start.sh", target.mount_path),
        "service must use the existing release mount start.sh"
    );
    ensure!(
        !target.revision_env.is_empty()
            && target
                .revision_env
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit())),
        "invalid revision environment name"
    );
    crate::cd::app_lb_endpoint(&target.url).map_err(anyhow::Error::msg)?;
    crate::cd::app_lb_endpoint(&target.health_url).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Only the existing release mount and revision marker change. In particular,
/// workspace, env/env_from, secrets, routes, health and all unrelated mounts
/// are inherited byte-for-byte from the observed spec.
fn desired_spec(
    mut spec: Value,
    target: &Target,
    store: &str,
    artifact: &str,
    revision: &str,
) -> Result<Value> {
    validate_target(target)?;
    ensure!(
        spec["id"] == target.deployment
            && spec["namespace"].as_str().unwrap_or("default") == target.namespace,
        "deployment identity differs from frozen target"
    );
    ensure!(
        spec["vm"]["driver"] == "firecracker"
            && spec["vm"]["workspace"].is_object()
            && spec["scaling"]["min_replicas"] == 1
            && spec["scaling"]["max_replicas"] == 1
            && spec["scaling"]["warm_pool"].as_u64().unwrap_or(0) == 0,
        "stateful replacement requires one Firecracker VM with a persistent workspace"
    );
    ensure!(
        spec["vm"]["start_command"] == target.start_command
            && spec["vm"]["working_directory"] == target.working_directory,
        "live service no longer uses the frozen start.sh location"
    );
    let mounts = spec["vm"]["mounts"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("missing release mounts"))?;
    let selected: Vec<_> = mounts
        .iter()
        .enumerate()
        .filter(|(_, m)| m["path"] == target.mount_path)
        .map(|(i, _)| i)
        .collect();
    ensure!(
        selected.len() == 1,
        "service must already have exactly one release mount"
    );
    let mount = &mut mounts[selected[0]];
    ensure!(
        mount["read_only"] == true
            && mount["strip_components"] == 1
            && mount["store"].as_str().map(|s| s.trim_end_matches('/'))
                == Some(store.trim_end_matches('/')),
        "existing release mount is not the exact read-only artifact mount"
    );
    mount["ref"] = json!(artifact);
    mount["digest"] = json!(artifact);
    ensure!(
        !spec["vm"]["env_from"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|r| r["as"] == target.revision_env)),
        "secret reference overrides revision marker"
    );
    let env = spec["vm"]["env_vars"]
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("missing service environment"))?;
    ensure!(
        env.contains_key(&target.revision_env),
        "revision marker must already exist"
    );
    env.insert(target.revision_env.clone(), json!(revision));
    Ok(spec)
}

fn release_identity(spec: &Value, target: &Target) -> Result<(String, String)> {
    let mounts = spec["vm"]["mounts"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing release mounts"))?;
    let mounts: Vec<_> = mounts
        .iter()
        .filter(|m| m["path"] == target.mount_path)
        .collect();
    ensure!(
        mounts.len() == 1,
        "service must have exactly one release mount"
    );
    let artifact = mounts[0]["digest"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("release mount has no immutable digest"))?;
    ensure!(
        mounts[0]["ref"] == artifact,
        "release mount ref is not its immutable digest"
    );
    let revision = spec["vm"]["env_vars"][&target.revision_env]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing previous release revision"))?;
    Ok((artifact.into(), revision.into()))
}

fn singleton(snapshot: &Value) -> Option<(&str, bool)> {
    let vms = snapshot["vms"].as_array()?;
    if vms.len() != 1 {
        return None;
    }
    Some((
        vms[0]["sandbox_id"].as_str()?,
        vms[0]["healthy"] == true && vms[0]["draining"] == false,
    ))
}

fn workspace_ready(snapshot: &Value) -> bool {
    snapshot["workspace"]["phase"] == "idle" && snapshot["workspace"]["push_pending"] == false
}

fn decide(
    snapshot: &Value,
    intent: &Intent,
    phase: &str,
    expired: bool,
    abandoned: bool,
) -> Decision {
    let hash = digest(&snapshot["spec"]);
    if hash == intent.original_spec_sha256 {
        return if intent.original_spec_sha256 == intent.desired_spec_sha256 {
            Decision::VerifyNoop
        } else if phase == "verifying_rollback" {
            Decision::VerifyRollback
        } else if phase == "rolling_back" {
            Decision::WaitRollback
        } else if expired || abandoned {
            Decision::SettleOriginal
        } else {
            Decision::PutDesired
        };
    }
    if hash != intent.desired_spec_sha256 {
        return Decision::ConcurrentEdit;
    }
    if matches!(phase, "rolling_back" | "verifying_rollback") || expired {
        return if workspace_ready(snapshot) {
            Decision::PutRollback
        } else {
            Decision::WaitRollbackCapture
        };
    }
    match singleton(snapshot) {
        Some((id, true)) if id != intent.source_sandbox_id && workspace_ready(snapshot) => {
            Decision::VerifyReplacement
        }
        _ => Decision::WaitReplacement,
    }
}

async fn snapshot(http: &reqwest::Client, endpoint: &str, token: &str) -> Result<Value> {
    let response = http
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    let header = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("app-lb omitted deployment ETag"))?
        .to_owned();
    let body: Value = response.json().await?;
    ensure!(
        header == etag(&body["spec"]),
        "app-lb ETag differs from deployment spec"
    );
    Ok(body)
}

async fn cas_put(
    http: &reqwest::Client,
    endpoint: &str,
    token: &str,
    expected: &Value,
    wanted: &Value,
) -> Result<()> {
    let response = http
        .put(endpoint)
        .bearer_auth(token)
        .header(reqwest::header::IF_MATCH, etag(expected))
        .json(wanted)
        .send()
        .await;
    if let Ok(response) = response {
        ensure!(
            response.status() != reqwest::StatusCode::PRECONDITION_FAILED,
            "deployment changed concurrently"
        );
        ensure!(
            response.status() == reqwest::StatusCode::CONFLICT
                || (!response.status().is_client_error() && !response.status().is_redirection()),
            "app-lb refused replacement"
        );
    }
    // Transport/server outcomes are deliberately unknown. GET reconciliation,
    // never this response, determines whether the CAS took effect.
    Ok(())
}

async fn exact_health(
    http: &reqwest::Client,
    target: &Target,
    token: &str,
    revision: &str,
) -> Result<bool> {
    let health = reqwest::Url::parse(&target.health_url)?;
    let admin = reqwest::Url::parse(&target.url)?;
    let authenticated = health.scheme() == admin.scheme()
        && health.host_str() == admin.host_str()
        && health.port_or_known_default() == admin.port_or_known_default();
    // Same-origin administrative health retains app-lb authentication; public
    // service health retains its existing unauthenticated contract.
    let request = http.get(health);
    let request = if authenticated {
        request.bearer_auth(token)
    } else {
        request
    };
    let response = match request.send().await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    Ok(response.status().is_success()
        && response.headers().get_all("x-heyo-revision").iter().count() == 1
        && response
            .headers()
            .get("x-heyo-revision")
            .and_then(|h| h.to_str().ok())
            == Some(revision))
}

async fn set_phase(
    store: &Store,
    id: &str,
    phase: &str,
    status: &str,
    message: &str,
) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    let changed = sqlx::query("UPDATE ci_stateful_release_rollout SET phase=$2,updated_at=now() WHERE id=$1 AND phase NOT IN ('complete','settled_failure') AND phase IS DISTINCT FROM $2")
        .bind(id)
        .bind(phase)
        .execute(&mut *tx)
        .await?.rows_affected();
    if changed == 1 {
        sqlx::query("UPDATE ci_service_deployment SET status=$2,phase=$3,message=$4,error=NULL,updated_at=now() WHERE id=$1 AND status<>'passed' AND phase IS DISTINCT FROM 'settled_failure'")
            .bind(id).bind(status).bind(phase).bind(message).execute(&mut *tx).await?;
        Store::add_service_deployment_event(&mut tx, id).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Deploy to a parent-resolved and frozen target. The parent integrates policy
/// and dispatch; [`spawn`] provides durable recovery after restart.
pub async fn deploy(
    d: &Dispatcher,
    msg: &JobMessage,
    step: &str,
    target: Target,
    token: &str,
    workflow: &str,
    artifact: &str,
    timeout: Duration,
    masker: &Masker,
) -> Result<String> {
    crate::submission::authorize_publication(&d.store, &msg.run_id)
        .await
        .map_err(anyhow::Error::msg)?;
    validate_target(&target)?;
    ensure!(!token.trim().is_empty(), "app-lb credential is required");
    let (revision, git_ref) = crate::release::deployment_source(&d.store, &msg.run_id)
        .await
        .map_err(anyhow::Error::msg)?;
    let stored = crate::submission::artifact(&d.store, &msg.run_id, workflow, artifact, None)
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        stored.sink == "artifacts" && stored.size_bytes <= 512 * 1024 * 1024,
        "invalid stateful release artifact"
    );
    let artifact_digest = stored
        .digest
        .clone()
        .ok_or_else(|| anyhow::anyhow!("artifact omitted immutable digest"))?;
    let bytes = d.artifacts.get(&stored).await?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == artifact_digest,
        "artifact digest mismatch"
    );
    let start = crate::service_archive::validated_archive(&bytes, "dist/start.sh")
        .map_err(anyhow::Error::msg)?;
    ensure!(
        start.starts_with(b"#!"),
        "release lacks executable dist/start.sh"
    );
    let store_url = d
        .config
        .artifacts
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing artifact store"))?
        .url
        .trim_end_matches('/')
        .to_string();
    let id = format!(
        "ci-stateful-{}",
        hex::encode(Sha256::digest(step.as_bytes()))
    );
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let endpoint = format!(
        "{}/deployments/{}",
        target.url.trim_end_matches('/'),
        target.deployment
    );
    let saved: Option<Value> =
        sqlx::query_scalar("SELECT intent FROM ci_stateful_release_rollout WHERE id=$1")
            .bind(&id)
            .fetch_optional(d.store.pool())
            .await?;
    let intent = if let Some(saved) = saved {
        let intent: Intent = serde_json::from_value(saved)?;
        ensure!(
            intent.target == target && intent.artifact == artifact_digest && intent.sha == revision,
            "stateful rollout inputs changed on replay"
        );
        intent
    } else {
        let current = snapshot(&http, &endpoint, token).await?;
        ensure!(workspace_ready(&current), "workspace capture is not idle");
        let (source_sandbox_id, healthy) =
            singleton(&current).ok_or_else(|| anyhow::anyhow!("deployment is not a singleton"))?;
        ensure!(healthy, "source sandbox is not healthy");
        let (previous_artifact, previous_revision) = release_identity(&current["spec"], &target)?;
        let wanted = desired_spec(
            current["spec"].clone(),
            &target,
            &store_url,
            &artifact_digest,
            &revision,
        )?;
        let intent = Intent {
            target,
            store: store_url,
            artifact: artifact_digest,
            sha: revision.clone(),
            previous_artifact,
            previous_revision,
            source_sandbox_id: source_sandbox_id.into(),
            original_spec_sha256: digest(&current["spec"]),
            desired_spec_sha256: digest(&wanted),
        };
        let value = serde_json::to_value(&intent)?;
        let mut tx = d.store.pool().begin().await?;
        let run_status: String =
            sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
                .bind(&msg.run_id)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            !matches!(run_status.as_str(), "cancelled" | "failure"),
            "run stopped before stateful replacement"
        );
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) SELECT $1,$2,$3,$4,$5,$6,'submitting','prepared',$7,$8 WHERE EXISTS(SELECT 1 FROM ci_job WHERE id=$4 AND status='running') ON CONFLICT(step_id) DO NOTHING")
            .bind(&id).bind(step).bind(&msg.run_id).bind(&msg.job_id).bind(&intent.target.deployment).bind(digest(&value)).bind(&revision).bind(&git_ref).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO ci_stateful_release_rollout(id,intent,phase,deadline) VALUES($1,$2,'prepared',now()+make_interval(secs=>$3)) ON CONFLICT(id) DO NOTHING")
            .bind(&id).bind(&value).bind(timeout.min(d.config.max_job_duration).as_secs() as f64).execute(&mut *tx).await?;
        let actual: Value =
            sqlx::query_scalar("SELECT intent FROM ci_stateful_release_rollout WHERE id=$1")
                .bind(&id)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(
            actual == value,
            "concurrent stateful rollout intent differs"
        );
        Store::add_service_deployment_event(&mut tx, &id).await?;
        tx.commit().await?;
        intent
    };

    reconcile(
        d,
        &http,
        &endpoint,
        &id,
        &intent,
        token,
        masker,
        &msg.job_id,
        true,
    )
    .await
}

async fn reconcile(
    d: &Dispatcher,
    http: &reqwest::Client,
    endpoint: &str,
    id: &str,
    intent: &Intent,
    token: &str,
    masker: &Masker,
    job_id: &str,
    may_submit_desired: bool,
) -> Result<String> {
    loop {
        let mut operation = d.store.pool().begin().await?;
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,734))")
                .bind(id)
                .fetch_one(&mut *operation)
                .await?;
        if !locked {
            operation.rollback().await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        let row = sqlx::query("SELECT r.phase,r.deadline,d.status FROM ci_stateful_release_rollout r JOIN ci_service_deployment d ON d.id=r.id WHERE r.id=$1")
            .bind(&id).fetch_one(d.store.pool()).await?;
        let phase: String = row.get("phase");
        if phase == "complete" {
            return Ok(format!(
                "[ci] {} stateful replacement verified at {}\n",
                intent.target.deployment, intent.sha
            ));
        }
        if phase == "settled_failure" {
            anyhow::bail!("replacement was unhealthy; previous release restored and verified");
        }
        // Recovery may finish an observed replacement or rollback, but an
        // abandoned job is never authority to initiate its first mutation.
        let cancelled = !may_submit_desired || d.store.is_job_cancelled(job_id).await?;
        let expired = row.get::<chrono::DateTime<chrono::Utc>, _>("deadline") <= chrono::Utc::now();
        let current = match snapshot(&http, &endpoint, token).await {
            Ok(v) => v,
            Err(_) => {
                operation.rollback().await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        match decide(&current, &intent, &phase, expired, cancelled) {
            Decision::VerifyNoop => {
                let ready = singleton(&current).is_some_and(|(_, healthy)| healthy)
                    && workspace_ready(&current);
                if ready && exact_health(&http, &intent.target, token, &intent.sha).await? {
                    set_phase(
                        &d.store,
                        &id,
                        "complete",
                        "passed",
                        "Exact requested release already healthy; no replacement needed.",
                    )
                    .await?;
                }
            }
            Decision::SettleOriginal => {
                let unchanged = singleton(&current).is_some_and(|(sandbox, healthy)| {
                    sandbox == intent.source_sandbox_id && healthy
                }) && workspace_ready(&current);
                if unchanged {
                    set_phase(
                        &d.store,
                        &id,
                        "settled_failure",
                        "failed",
                        "Release stopped before mutation; original service remains healthy.",
                    )
                    .await?;
                }
            }
            Decision::PutDesired => {
                let Some((sandbox, healthy)) = singleton(&current) else {
                    anyhow::bail!("source VM changed before replacement")
                };
                ensure!(
                    sandbox == intent.source_sandbox_id && healthy && workspace_ready(&current),
                    "source VM or workspace changed before replacement"
                );
                let wanted = desired_spec(
                    current["spec"].clone(),
                    &intent.target,
                    &intent.store,
                    &intent.artifact,
                    &intent.sha,
                )?;
                ensure!(
                    digest(&wanted) == intent.desired_spec_sha256,
                    "desired spec differs from persisted intent"
                );
                set_phase(
                    &d.store,
                    &id,
                    "submitting",
                    "submitting",
                    "Submitting conditional stateful replacement.",
                )
                .await?;
                cas_put(&http, &endpoint, token, &current["spec"], &wanted).await?;
            }
            Decision::WaitReplacement => {
                set_phase(
                    &d.store,
                    &id,
                    "verifying",
                    "running",
                    "Waiting for replacement and workspace capture.",
                )
                .await?
            }
            Decision::VerifyReplacement => {
                if exact_health(&http, &intent.target, token, &intent.sha).await? {
                    set_phase(
                        &d.store,
                        &id,
                        "complete",
                        "passed",
                        "Exact replacement revision healthy; workspace retained.",
                    )
                    .await?;
                } else if expired {
                    set_phase(
                        &d.store,
                        &id,
                        "rolling_back",
                        "running",
                        "Replacement unhealthy; restoring previous release.",
                    )
                    .await?;
                }
            }
            Decision::PutRollback => {
                // Rollback recovery remains permitted after cancellation: it is
                // completion of the already-submitted safety obligation.
                let wanted = desired_spec(
                    current["spec"].clone(),
                    &intent.target,
                    &intent.store,
                    &intent.previous_artifact,
                    &intent.previous_revision,
                )?;
                ensure!(
                    digest(&wanted) == intent.original_spec_sha256,
                    "rollback no longer equals original spec"
                );
                set_phase(
                    &d.store,
                    &id,
                    "rolling_back",
                    "running",
                    "Restoring previous release with retained workspace.",
                )
                .await?;
                cas_put(&http, &endpoint, token, &current["spec"], &wanted).await?;
            }
            Decision::WaitRollback => {
                set_phase(
                    &d.store,
                    &id,
                    "verifying_rollback",
                    "running",
                    "Waiting for restored release readiness.",
                )
                .await?
            }
            Decision::WaitRollbackCapture => {
                set_phase(
                    &d.store,
                    &id,
                    "rolling_back",
                    "running",
                    "Waiting for workspace capture before conditional rollback.",
                )
                .await?
            }
            Decision::VerifyRollback => {
                let ready = singleton(&current)
                    .is_some_and(|(id, healthy)| id != intent.source_sandbox_id && healthy)
                    && workspace_ready(&current);
                if ready
                    && exact_health(&http, &intent.target, token, &intent.previous_revision).await?
                {
                    set_phase(&d.store, &id, "settled_failure", "failed", "Replacement unhealthy; previous release restored and verified with latest workspace.").await?;
                }
            }
            Decision::ConcurrentEdit => {
                let note = masker.mask("deployment spec changed concurrently; stateful rollout outcome remains unresolved");
                d.store
                    .update_service_deployment(
                        &id,
                        "submission_unknown",
                        Some("reconciliation"),
                        None,
                        Some(&note),
                    )
                    .await?;
                anyhow::bail!("{note}; reconcile operation {id}");
            }
        }
        operation.rollback().await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Recover using only the persisted bounded intent and the credential
/// expression in the immutable job plan. No specification or credential is
/// copied into the rollout ledger.
pub async fn recover(d: &Dispatcher, run_id: &str, id: &str) -> Result<()> {
    crate::submission::authorize_publication(&d.store, run_id)
        .await
        .map_err(anyhow::Error::msg)?;
    let row = sqlx::query("SELECT r.intent,d.job_id,d.step_id,d.status,d.phase FROM ci_stateful_release_rollout r JOIN ci_service_deployment d ON d.id=r.id WHERE r.id=$1 AND d.run_id=$2")
        .bind(id).bind(run_id).fetch_one(d.store.pool()).await?;
    if row.get::<String, _>("status") == "passed"
        || row.get::<Option<String>, _>("phase").as_deref() == Some("settled_failure")
    {
        return Ok(());
    }
    let intent: Intent = serde_json::from_value(row.get("intent"))?;
    let job_id: String = row.get("job_id");
    let step_id: String = row.get("step_id");
    let job = d
        .store
        .get_job(&job_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing rollout job"))?;
    let plan: crate::plan::JobPlan = serde_json::from_value(job.plan)?;
    let (_, step) = plan
        .steps
        .iter()
        .enumerate()
        .find(|(index, _)| crate::store::step_id(&job_id, *index) == step_id)
        .ok_or_else(|| anyhow::anyhow!("missing rollout step"))?;
    ensure!(
        step.uses.as_deref() == Some("ci/rollout-stateful-service"),
        "rollout action differs"
    );
    let secret = crate::host_maintenance::token_secret(
        step.with
            .get("token")
            .ok_or_else(|| anyhow::anyhow!("missing rollout credential reference"))?,
    )?;
    let run = d
        .store
        .get_run(run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing rollout run"))?;
    let prefix = crate::secrets::Secrets::prefix(
        &run.workflow_id,
        plan.env
            .get("CI_ENVIRONMENT")
            .map(String::as_str)
            .unwrap_or("default"),
    );
    let resolved = d.secrets.resolve(&prefix).await?;
    let token = resolved
        .secrets
        .get(&secret)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("rollout credential unavailable"))?;
    let masker = resolved.masker();
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let endpoint = format!(
        "{}/deployments/{}",
        intent.target.url.trim_end_matches('/'),
        intent.target.deployment
    );
    reconcile(
        d, &http, &endpoint, id, &intent, token, &masker, &job_id, false,
    )
    .await
    .map(|_| ())
}

pub fn spawn(d: std::sync::Arc<Dispatcher>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut recovering =
            std::collections::HashMap::<String, tokio::task::JoinHandle<()>>::new();
        loop {
            tick.tick().await;
            recovering.retain(|_, task| !task.is_finished());
            let rows = sqlx::query("SELECT d.id,d.run_id FROM ci_stateful_release_rollout r JOIN ci_service_deployment d ON d.id=r.id JOIN ci_job j ON j.id=d.job_id WHERE r.phase NOT IN ('complete','settled_failure') AND (r.deadline<=now() OR j.status IN ('success','failure','cancelled','skipped')) ORDER BY r.updated_at")
                .fetch_all(d.store.pool()).await;
            match rows {
                Ok(rows) => {
                    for row in rows {
                        let child = d.clone();
                        let id: String = row.get("id");
                        if recovering.contains_key(&id) {
                            continue;
                        }
                        let run_id: String = row.get("run_id");
                        let task_id = id.clone();
                        let task = tokio::spawn(async move {
                            if recover(&child, &run_id, &id).await.is_err() {
                                tracing::warn!(operation=%id, "stateful rollout recovery remains unresolved");
                            }
                        });
                        recovering.insert(task_id, task);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "could not select abandoned stateful rollouts")
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> Target {
        Target {
            url: "https://admin.test".into(),
            deployment: "artifacts".into(),
            namespace: "default".into(),
            mount_path: "/opt/artifacts-release".into(),
            revision_env: "HEYO_REVISION".into(),
            start_command: "/opt/artifacts-release/start.sh".into(),
            working_directory: "/opt/artifacts-release".into(),
            health_url: "https://artifacts.test/healthz".into(),
        }
    }
    fn spec() -> Value {
        json!({"id":"artifacts","namespace":"default","routes":[{"host":"artifacts.test"}],
        "health":{"path":"/healthz"},"scaling":{"min_replicas":1,"max_replicas":1,"warm_pool":0},"vm":{"driver":"firecracker",
        "workspace":{"ref":"data","secret":"keep"},"working_directory":"/opt/artifacts-release","start_command":"/opt/artifacts-release/start.sh",
        "env_vars":{"HEYO_REVISION":"old","SECRET":"keep"},"mounts":[{"path":"/opt/artifacts-release","store":"https://store.test",
        "ref":"old-artifact","digest":"old-artifact","read_only":true,"strip_components":1}]}})
    }
    fn intent() -> Intent {
        let t = target();
        let old = spec();
        let new = desired_spec(
            old.clone(),
            &t,
            "https://store.test",
            "new-artifact",
            "same-revision",
        )
        .unwrap();
        Intent {
            target: t,
            store: "https://store.test".into(),
            artifact: "new-artifact".into(),
            sha: "same-revision".into(),
            previous_artifact: "old-artifact".into(),
            previous_revision: "old".into(),
            source_sandbox_id: "old-vm".into(),
            original_spec_sha256: digest(&old),
            desired_spec_sha256: digest(&new),
        }
    }
    #[test]
    fn desired_preserves_workspace_routes_and_secrets() {
        let before = spec();
        let after = desired_spec(
            before.clone(),
            &target(),
            "https://store.test",
            "new",
            "rev",
        )
        .unwrap();
        assert_eq!(after["vm"]["workspace"], before["vm"]["workspace"]);
        assert_eq!(after["routes"], before["routes"]);
        assert_eq!(after["vm"]["env_vars"]["SECRET"], "keep");
    }
    #[test]
    fn changed_artifact_at_same_revision_still_requires_new_boot() {
        let i = intent();
        let s = json!({"spec":desired_spec(spec(),&target(),"https://store.test","new-artifact","same-revision").unwrap(),
        "vms":[{"sandbox_id":"old-vm","healthy":true,"draining":false}],"workspace":{"phase":"idle","push_pending":false}});
        assert_eq!(
            decide(&s, &i, "verifying", false, false),
            Decision::WaitReplacement
        );
    }
    #[test]
    fn identical_fingerprint_is_verified_without_put() {
        let mut i = intent();
        i.desired_spec_sha256 = i.original_spec_sha256.clone();
        i.artifact = i.previous_artifact.clone();
        i.sha = i.previous_revision.clone();
        let s = json!({"spec":spec(),"vms":[{"sandbox_id":"old-vm","healthy":true,"draining":false}],"workspace":{"phase":"idle","push_pending":false}});
        assert_eq!(
            decide(&s, &i, "prepared", false, false),
            Decision::VerifyNoop
        );
    }
    #[test]
    fn expired_or_abandoned_original_settles_without_mutation() {
        let i = intent();
        let s = json!({"spec":spec(),"vms":[{"sandbox_id":"old-vm","healthy":true,"draining":false}],"workspace":{"phase":"idle","push_pending":false}});
        assert_eq!(
            decide(&s, &i, "prepared", true, false),
            Decision::SettleOriginal
        );
        assert_eq!(
            decide(&s, &i, "prepared", false, true),
            Decision::SettleOriginal
        );
        assert_eq!(
            decide(&s, &i, "prepared", false, false),
            Decision::PutDesired
        );
    }
    #[test]
    fn concurrent_edit_is_never_overwritten() {
        let i = intent();
        let mut changed = spec();
        changed["routes"][0]["host"] = json!("edited.test");
        let s = json!({"spec":changed,"vms":[],"workspace":{}});
        assert_eq!(
            decide(&s, &i, "submitting", false, false),
            Decision::ConcurrentEdit
        );
    }
}
