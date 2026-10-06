//! Pooler replacement through app-lb's managed maintenance launcher.
//! The host protocol is the existing, embedded `replace_pooler.py`; CI only
//! supplies immutable artifact identity and runtime secret references.
use crate::{bus::JobMessage, dispatch::Dispatcher, secrets::Masker, store::Store};
use anyhow::{Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::BTreeMap, io::Read, path::Component, time::Duration};

pub const ACTION: &str = "ci/rollout-pooler";
const LIMIT: usize = 256 * 1024 * 1024;
const RECIPE: &str = include_str!("../../pg-fc/deploy/replace_pooler.py");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub url: String,
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub env_from: Vec<SecretEnv>,
    pub pooler: Pooler,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecretEnv {
    pub secret: String,
    #[serde(default = "default_secret_key")]
    pub key: String,
    #[serde(default, rename = "as", skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}
fn default_secret_key() -> String {
    "token".into()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Pooler {
    pub executable: String,
    pub manager: String,
    pub service: String,
    pub config_files: Vec<String>,
    pub sql_url_envs: Vec<String>,
    pub port: u16,
    pub registry: String,
    pub update_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Intent {
    target: Target,
    operation: String,
    revision: String,
    artifact_sha256: String,
    binary_sha256: String,
    artifact_url: String,
    launcher: String,
    launcher_spec: Value,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
}
fn absolute(s: &str) -> bool {
    let p = std::path::Path::new(s);
    p.is_absolute()
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

pub fn validate_target(t: &Target) -> Result<()> {
    crate::cd::app_lb_endpoint(&t.url).map_err(anyhow::Error::msg)?;
    ensure!(
        t.url.starts_with("https://") || cfg!(test) && t.url.starts_with("http://127.0.0.1:"),
        "pooler operator requires HTTPS"
    );
    ensure!(
        ident(&t.name) && ident(&t.namespace) && ident(&t.pooler.service),
        "invalid pooler target identity"
    );
    ensure!(
        matches!(t.pooler.manager.as_str(), "systemd" | "supervisor"),
        "invalid pooler process manager"
    );
    ensure!(
        absolute(&t.pooler.executable)
            && std::path::Path::new(&t.pooler.executable)
                .file_name()
                .is_some_and(|n| n == "pg-vm-pool"),
        "invalid pooler executable"
    );
    ensure!(
        absolute(&t.pooler.registry)
            && absolute(&t.pooler.update_state)
            && !t.pooler.config_files.is_empty()
            && t.pooler.config_files.iter().all(|p| absolute(p)),
        "pooler state paths must be absolute and normalized"
    );
    ensure!(
        !t.pooler.sql_url_envs.is_empty()
            && t.pooler.sql_url_envs.len() <= 16
            && t.pooler.sql_url_envs.iter().all(|n| !n.is_empty()
                && n.len() <= 128
                && n.bytes().enumerate().all(|(i, b)| b == b'_'
                    || b.is_ascii_uppercase()
                    || i > 0 && b.is_ascii_digit())),
        "invalid SQL credential environment reference"
    );
    ensure!(
        t.env_from.len() <= 32
            && t.env_from.iter().all(|v| {
                ident(&v.secret)
                    && ident(&v.key)
                    && v.namespace.as_ref().is_none_or(|n| ident(n))
                    && v.env.as_ref().is_none_or(|n| {
                        !n.is_empty()
                            && n.len() <= 128
                            && n.bytes().enumerate().all(|(i, b)| {
                                b == b'_' || b.is_ascii_uppercase() || i > 0 && b.is_ascii_digit()
                            })
                    })
            }),
        "invalid launcher secret reference"
    );
    ensure!(
        t.pooler
            .tls_server_name
            .as_ref()
            .is_none_or(|n| !n.is_empty()
                && n.len() <= 253
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))),
        "invalid pooler TLS server name"
    );
    Ok(())
}

fn executable(bytes: &[u8], revision: &str) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= LIMIT, "pooler artifact exceeds bound");
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let wanted = ["dist/pg-vm-pool", "dist/BUILD-INFO", "dist/SHA256SUMS"];
    let mut found = BTreeMap::new();
    let mut total = 0usize;
    for item in archive.entries()? {
        let item = item?;
        let path = item.path()?.into_owned();
        ensure!(
            path.components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "unsafe pooler artifact path"
        );
        total = total
            .checked_add(item.size() as usize)
            .ok_or_else(|| anyhow::anyhow!("artifact size overflow"))?;
        ensure!(
            total <= LIMIT
                && (item.header().entry_type().is_file() || item.header().entry_type().is_dir()),
            "expanded pooler artifact exceeds bound or contains links"
        );
        let name = path.to_string_lossy();
        if wanted.contains(&name.as_ref()) {
            ensure!(
                item.header().entry_type().is_file() && !found.contains_key(name.as_ref()),
                "ambiguous pooler artifact"
            );
            let mut data = Vec::new();
            item.take((LIMIT + 1) as u64).read_to_end(&mut data)?;
            ensure!(
                data.len() <= LIMIT && (name == "dist/pg-vm-pool" || data.len() <= 65536),
                "oversized pooler metadata"
            );
            found.insert(name.into_owned(), data);
        }
    }
    ensure!(
        found.len() == wanted.len(),
        "missing pooler artifact identity"
    );
    let info = std::str::from_utf8(&found["dist/BUILD-INFO"])?;
    ensure!(
        info.lines()
            .filter(|l| l.starts_with("commit "))
            .eq([format!("commit {revision}").as_str()]),
        "pooler artifact revision differs"
    );
    let binary = &found["dist/pg-vm-pool"];
    ensure!(
        binary.starts_with(b"\x7fELF"),
        "pooler artifact is not a Linux ELF"
    );
    let sums = std::str::from_utf8(&found["dist/SHA256SUMS"])?;
    for name in ["pg-vm-pool", "BUILD-INFO"] {
        let expected = format!("{}  {name}", sha(&found[&format!("dist/{name}")]));
        ensure!(
            sums.lines()
                .filter(|l| l.split_whitespace().nth(1) == Some(name))
                .eq([expected.as_str()]),
            "pooler artifact checksum differs"
        );
    }
    Ok(binary.clone())
}

fn command(intent: &Intent) -> Result<String> {
    let envelope = json!({"target":intent.target.pooler,"request":{"operation":intent.operation,"revision":intent.revision,
        "artifact_sha256":intent.artifact_sha256,"binary_sha256":intent.binary_sha256,"artifact_url":intent.artifact_url},"preflight":false});
    let encoded = STANDARD.encode(serde_json::to_vec(&envelope)?);
    Ok(format!(
        "python3 -c \"import base64;exec(base64.b64decode('{}'))\" '{}'",
        STANDARD.encode(RECIPE),
        encoded
    ))
}

fn launcher_spec(intent: &Intent, command: String) -> Value {
    // app-lb stamps omitted secret namespaces on admission. Build the same
    // normalized spec so the subsequent exact comparison accepts that result.
    let mut env_from = intent.target.env_from.clone();
    for reference in &mut env_from {
        reference
            .namespace
            .get_or_insert_with(|| intent.target.namespace.clone());
    }
    let mut spec = json!({"id":intent.launcher,"namespace":intent.target.namespace,"maintenance":true,
        "routes":[{"host":format!("{}.invalid",intent.launcher)}],"upstreams":["127.0.0.1:1"],
        "health":{"path":null,"timeout_secs":2},"update":{"working_dir":"/","commands":[command],
        "timeout_secs":900,"verify_timeout_secs":0,"env_from":env_from}});
    if intent.target.env_from.is_empty() {
        spec["update"].as_object_mut().unwrap().remove("env_from");
    }
    spec
}

fn same_spec(actual: &Value, wanted: &Value) -> bool {
    let actual = actual.get("spec").unwrap_or(actual);
    wanted.as_object().is_some_and(|w| {
        w.iter().all(|(k, v)| {
            actual.get(k) == Some(v)
                || k == "namespace" && v == "default" && actual.get(k).is_none()
        })
    })
}

fn receipt(job: &Value, intent: &Intent) -> Result<bool> {
    ensure!(
        job["deployment"] == intent.launcher
            && matches!(job["kind"].as_str(), Some("update" | "host-update")),
        "launcher job identity differs"
    );
    match job["status"].as_str() {
        Some("queued" | "pending" | "running") => Ok(false),
        Some("failed") => bail!("managed pooler replacement failed"),
        Some("succeeded") => {
            let lines: Vec<_> = job["log"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .flat_map(str::lines)
                .filter_map(|l| l.strip_prefix("POOLER_REPLACEMENT="))
                .collect();
            ensure!(
                lines.len() == 1,
                "exactly one pooler replacement receipt is required"
            );
            let r: Value = serde_json::from_str(lines[0])?;
            ensure!(
                r == json!({"status":"succeeded","binary_sha256":intent.binary_sha256,"operation":intent.operation}),
                "pooler replacement receipt differs"
            );
            Ok(true)
        }
        _ => bail!("unknown launcher mutation outcome"),
    }
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?)
}
async fn body(mut response: reqwest::Response) -> Result<Value> {
    ensure!(
        response.status().is_success(),
        "operator returned {}",
        response.status()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 8 * 1024 * 1024,
            "operator response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Promote the retained `pg-fc` bundle to one frozen operator target.
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
    ensure!(
        !token.trim().is_empty(),
        "pooler rollout requires a runtime credential"
    );
    validate_target(&target)?;
    let run = d
        .store
        .get_run(&msg.run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing run"))?;
    let (revision, git_ref) = crate::release::deployment_source(&d.store, &msg.run_id)
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        revision == run.sha,
        "pooler bundle must match exact retained release revision"
    );
    let stored = crate::submission::artifact(&d.store, &msg.run_id, workflow, artifact, None)
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        stored.sink == "artifacts" && stored.size_bytes as usize <= LIMIT,
        "pooler rollout requires a bounded retained HTTP artifact"
    );
    let digest = stored
        .digest
        .clone()
        .ok_or_else(|| anyhow::anyhow!("pooler artifact digest missing"))?;
    let bytes = d.artifacts.get(&stored).await?;
    ensure!(sha(&bytes) == digest, "pooler artifact digest differs");
    let binary_sha256 = sha(&executable(&bytes, &revision)?);
    let store = d
        .config
        .artifacts
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("artifact HTTP store is not configured"))?
        .url
        .trim_end_matches('/');
    let id = format!("ci-pooler-{}", sha(step.as_bytes()));
    let operation = format!("pooler-{}", sha(step.as_bytes()));
    let launcher = format!(
        "pooler-update-{}",
        &sha(format!("{id}:{}", target.name).as_bytes())[..32]
    );
    let mut intent = Intent {
        target,
        operation,
        revision,
        artifact_sha256: digest,
        binary_sha256,
        artifact_url: format!("{store}/blobs/{}", stored.digest.as_ref().unwrap()),
        launcher,
        launcher_spec: Value::Null,
    };
    intent.launcher_spec = launcher_spec(&intent, command(&intent)?);
    let value = serde_json::to_value(&intent)?;
    let hash = sha(&serde_json::to_vec(&value)?);
    let mut tx = d.store.pool().begin().await?;
    let existing=sqlx::query("SELECT request_hash,sha,status,message FROM ci_service_deployment WHERE step_id=$1 FOR UPDATE").bind(step).fetch_optional(&mut *tx).await?;
    if let Some(row) = existing {
        ensure!(
            row.get::<String, _>("request_hash") == hash && row.get::<String, _>("sha") == run.sha,
            "pooler rollout inputs changed on replay"
        );
        match row.get::<String, _>("status").as_str() {
            "passed" => return Ok(format!("[ci] pooler {id} already verified\n")),
            "failed" => bail!("pooler rollout previously failed"),
            _ => {}
        }
    } else {
        let status: String = sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1 FOR UPDATE")
            .bind(&msg.job_id)
            .fetch_one(&mut *tx)
            .await?;
        ensure!(status == "running", "pooler rollout job is not running");
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,message,sha,git_ref) VALUES($1,$2,$3,$4,$5,$6,'submitting','registering',$7,$8,$9)")
            .bind(&id).bind(step).bind(&msg.run_id).bind(&msg.job_id).bind(&intent.target.name).bind(&hash).bind(serde_json::to_string(&intent)?).bind(&run.sha).bind(git_ref).execute(&mut *tx).await?;
        Store::add_service_deployment_event(&mut tx, &id).await?;
    }
    tx.commit().await?;
    reconcile(
        &d.store,
        msg,
        &id,
        &intent,
        token,
        timeout.min(d.config.max_job_duration),
        masker,
    )
    .await
}

async fn reconcile(
    store: &Store,
    msg: &JobMessage,
    id: &str,
    intent: &Intent,
    token: &str,
    timeout: Duration,
    masker: &Masker,
) -> Result<String> {
    let http = client()?;
    let base = intent.target.url.trim_end_matches('/');
    let endpoint = format!("{base}/deployments/{}", intent.launcher);
    let started: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT created_at FROM ci_service_deployment WHERE id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
    let deadline = started + chrono::Duration::from_std(timeout)?;
    loop {
        let row = sqlx::query("SELECT status,phase FROM ci_service_deployment WHERE id=$1")
            .bind(id)
            .fetch_one(store.pool())
            .await?;
        match row.get::<String, _>("status").as_str() {
            "passed" => {
                return Ok(format!(
                    "[ci] pooler {} verified at {}\n",
                    intent.target.name, intent.revision
                ));
            }
            "failed" => bail!("pooler rollout failed"),
            _ => {}
        }
        ensure!(
            chrono::Utc::now() < deadline && !store.is_job_cancelled(&msg.job_id).await?,
            "pooler mutation unresolved; reconcile {id}"
        );
        let phase: String = row.get("phase");
        let result:Result<Option<bool>>=async{
            let registered=http.get(&endpoint).bearer_auth(token).send().await?;
            if matches!(registered.status(),reqwest::StatusCode::NOT_FOUND|reqwest::StatusCode::FORBIDDEN) {
                ensure!(phase=="registering","managed launcher disappeared after mutation; stop and reconcile");
                body(http.post(format!("{base}/deployments")).bearer_auth(token).json(&intent.launcher_spec).send().await?).await?;
            } else { ensure!(same_spec(&body(registered).await?,&intent.launcher_spec),"managed launcher configuration differs"); }
            let exact=body(http.get(&endpoint).bearer_auth(token).send().await?).await?;
            ensure!(same_spec(&exact,&intent.launcher_spec),"managed launcher configuration differs");
            let jobs=body(http.get(format!("{endpoint}/jobs")).bearer_auth(token).send().await?).await?;
            let jobs=jobs.as_array().ok_or_else(||anyhow::anyhow!("invalid launcher history"))?;
            ensure!(jobs.len()<=1,"ambiguous launcher history; stop and reconcile");
            if let Some(job)=jobs.first(){return Ok(Some(receipt(job,intent)?));}
            ensure!(phase=="registering","missing launcher job after submission; mutation outcome unknown");
            let changed = sqlx::query("UPDATE ci_service_deployment SET status='running',phase='submitting',updated_at=now() WHERE id=$1 AND phase='registering'").bind(id).execute(store.pool()).await?.rows_affected();
            if changed == 0 { return Ok(None); }
            let response=http.post(format!("{endpoint}/update")).bearer_auth(token).json(&json!({})).send().await?;
            ensure!(response.status().is_success(),"launcher update submission outcome is unknown");
            Ok(Some(false))
        }.await;
        match result {
            Ok(Some(true)) => {
                let mut tx = store.pool().begin().await?;
                let changed=sqlx::query("UPDATE ci_service_deployment SET status='passed',phase='complete',message='Exact pooler replacement receipt verified.',error=NULL,updated_at=now() WHERE id=$1 AND status NOT IN ('passed','failed')").bind(id).execute(&mut *tx).await?.rows_affected();
                if changed == 1 {
                    Store::add_service_deployment_event(&mut tx, id).await?;
                }
                tx.commit().await?;
            }
            Ok(Some(false)) => {
                sqlx::query("UPDATE ci_service_deployment SET status='running',phase='polling',updated_at=now() WHERE id=$1 AND status NOT IN ('passed','failed')").bind(id).execute(store.pool()).await?;
            }
            Ok(None) => {}
            Err(error) => {
                let note = masker.mask(&error.to_string()).replace(token, "***");
                let terminal = !error.is::<reqwest::Error>()
                    && (note.contains("replacement failed") || note.contains("receipt differs"));
                store
                    .update_service_deployment(
                        id,
                        if terminal {
                            "failed"
                        } else {
                            "submission_unknown"
                        },
                        Some("reconciliation"),
                        None,
                        Some(&note),
                    )
                    .await?;
                bail!("{note}; reconcile operation {id}");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target() -> Target {
        Target {
            url: "https://admin.test".into(),
            name: "pooler-us3".into(),
            namespace: "default".into(),
            env_from: vec![SecretEnv {
                secret: "pooler-runtime".into(),
                key: "token".into(),
                env: None,
                namespace: None,
            }],
            pooler: Pooler {
                executable: "/usr/local/bin/pg-vm-pool".into(),
                manager: "systemd".into(),
                service: "pg-vm-pool".into(),
                config_files: vec!["/etc/pg-vm-pool.json".into()],
                sql_url_envs: vec!["DATABASE_URL".into()],
                port: 6432,
                registry: "/var/lib/pg-vm-pool/registry.tsv".into(),
                update_state: "/var/lib/pg-vm-pool/updates".into(),
                tls_server_name: None,
            },
        }
    }
    fn intent() -> Intent {
        let mut i = Intent {
            target: target(),
            operation: "pooler-operation".into(),
            revision: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            binary_sha256: "c".repeat(64),
            artifact_url: "https://art.test/blobs/x".into(),
            launcher: "pooler-update-test".into(),
            launcher_spec: Value::Null,
        };
        i.launcher_spec = launcher_spec(&i, command(&i).unwrap());
        i
    }
    #[test]
    fn validates_typed_target_and_embeds_fixed_recipe() {
        let i = intent();
        validate_target(&i.target).unwrap();
        let c = command(&i).unwrap();
        assert!(c.contains(&STANDARD.encode(RECIPE)));
        assert_eq!(
            i.launcher_spec["update"]["env_from"][0]["namespace"],
            "default"
        );
        let mut explicit = i.clone();
        explicit.target.env_from[0].namespace = Some("credentials".into());
        assert_eq!(
            launcher_spec(&explicit, c)["update"]["env_from"][0]["namespace"],
            "credentials"
        );
        let mut bad = i.target;
        bad.pooler.sql_url_envs = vec!["password".into()];
        assert!(validate_target(&bad).is_err());
    }
    #[test]
    fn wrong_revision_and_receipt_are_rejected() {
        let i = intent();
        let good = json!({"deployment":i.launcher,"kind":"host-update","status":"succeeded","log":[format!("POOLER_REPLACEMENT={}",json!({"status":"succeeded","binary_sha256":i.binary_sha256,"operation":i.operation}))]});
        assert!(receipt(&good, &i).unwrap());
        let mut wrong = good.clone();
        wrong["log"][0] = json!(
            "POOLER_REPLACEMENT={\"status\":\"succeeded\",\"binary_sha256\":\"wrong\",\"operation\":\"pooler-operation\"}"
        );
        assert!(receipt(&wrong, &i).is_err());
        let binary = b"\x7fELFpooler";
        let info = format!("commit {}\n", i.revision);
        let sums = format!(
            "{}  pg-vm-pool\n{}  BUILD-INFO\n",
            sha(binary),
            sha(info.as_bytes())
        );
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, bytes) in [
            ("dist/pg-vm-pool", binary.as_slice()),
            ("dist/BUILD-INFO", info.as_bytes()),
            ("dist/SHA256SUMS", sums.as_bytes()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, bytes).unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        assert_eq!(executable(&bytes, &i.revision).unwrap(), binary);
        assert!(
            executable(&bytes, &"d".repeat(40))
                .unwrap_err()
                .to_string()
                .contains("revision differs")
        );
    }
    #[test]
    fn replay_identity_changes_are_detectable() {
        let a = serde_json::to_vec(&intent()).unwrap();
        let mut b = intent();
        b.revision = "d".repeat(40);
        assert_ne!(sha(&a), sha(&serde_json::to_vec(&b).unwrap()));
        let mut b = intent();
        b.target.pooler.port = 6433;
        assert_ne!(sha(&a), sha(&serde_json::to_vec(&b).unwrap()));
    }
}
