//! Deferred self-deployment. The requesting job finishes before replacement;
//! the replacement controller reconciles the same durable operation at startup.
use crate::{artifacts::{ArtifactSink, StoredArtifact}, bus::JobMessage, dispatch::Dispatcher, store::Store};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{io::Read, sync::{Arc, LazyLock}, time::Duration};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Request {
    deployment: String,
    base_url: String,
    public_url: String,
    artifact: String,
    sha: String,
    binary_sha256: String,
    previous_vm: String,
    previous_etag: String,
    desired_etag: String,
    #[serde(default)]
    source_boot: Option<uuid::Uuid>,
}

/// Durable identities needed to validate and record a controller replacement.
/// The artifact digest and release revision are deliberately not inputs: they
/// are derived again from the run, published release, artifact row and bytes.
pub struct PreparationInputs<'a> {
    pub store: &'a Store,
    pub artifacts: &'a dyn ArtifactSink,
    pub run_id: &'a str,
    pub step_id: &'a str,
    pub artifact_name: &'a str,
    pub workflow: Option<&'a str>,
    pub controller_repository: Option<&'a str>,
    pub artifact_store_url: Option<&'a str>,
    pub target: PreparationTarget<'a>,
    pub application_id: Option<&'a str>,
    pub parent_operation_id: Option<&'a str>,
}

/// A caller-attested target boot and the deployment authority used to verify
/// it. `prepare` still reads the authority's live snapshot and pins its ETags
/// and VM identity; attestation cannot substitute caller-provided digests.
pub struct PreparationTarget<'a> {
    pub deployment: &'a str,
    pub base_url: &'a str,
    pub token: &'a str,
    pub public_url: &'a str,
    pub source_boot: uuid::Uuid,
}

pub struct PreparedRollout {
    pub id: String,
    pub already_recorded: bool,
}

pub fn binary_sha256() -> Option<&'static str> {
    static HASH: LazyLock<Option<String>> = LazyLock::new(|| {
        let mut file = std::fs::File::open(std::env::current_exe().ok()?).ok()?;
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash).ok()?;
        Some(hex::encode(hash.finalize()))
    });
    HASH.as_deref()
}

fn etag(spec: &Value) -> String {
    let mut spec = spec.clone();
    // Match app-lb independently of serde_json's transitive preserve_order feature.
    spec.sort_all_objects();
    format!("\"{}\"", hex::encode(Sha256::digest(serde_json::to_vec(&spec).expect("JSON serializes"))))
}

pub(crate) fn artifact_identity(bytes: &[u8], sha: &str) -> Result<String, String> {
    let mut revision = None;
    let mut binary = None;
    let mut checksums = None;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let name = path.to_str().ok_or("non-UTF8 artifact path")?;
        if !matches!(name, "dist/REVISION" | "dist/ci" | "dist/SHA256SUMS") { continue; }
        if !entry.header().entry_type().is_file() || entry.size() > 256 * 1024 * 1024 {
            return Err("invalid controller artifact entry".into());
        }
        if name == "dist/ci" {
            if binary.is_some() { return Err("duplicate ci executable".into()); }
            let mut hash = Sha256::new();
            std::io::copy(&mut entry, &mut hash).map_err(|e| e.to_string())?;
            binary = Some(hex::encode(hash.finalize()));
        } else {
            if entry.size() > 1024 * 1024 { return Err("oversized artifact metadata".into()); }
            let mut text = String::new();
            entry.read_to_string(&mut text).map_err(|e| e.to_string())?;
            let slot = if name == "dist/REVISION" { &mut revision } else { &mut checksums };
            if slot.replace(text).is_some() { return Err("duplicate artifact metadata".into()); }
        }
    }
    if revision.as_deref().map(str::trim) != Some(sha) { return Err("artifact REVISION differs from confirmed release".into()); }
    let binary = binary.ok_or("artifact has no ci executable")?;
    let expected = format!("{binary}  ci");
    if !checksums.ok_or("artifact has no SHA256SUMS")?.lines().any(|line| line == expected) {
        return Err("artifact executable checksum mismatch".into());
    }
    Ok(binary)
}

fn desired_spec(mut spec: Value, digest: &str, sha: &str) -> Result<Value, String> {
    let broker = spec["vm"]["env_vars"]["CI_NATS_URL"].as_str()
        .ok_or("controller requires an explicit external CI_NATS_URL before self-deployment")?;
    let url = reqwest::Url::parse(broker).map_err(|_| "invalid controller CI_NATS_URL")?;
    let host = url.host_str().ok_or("CI_NATS_URL has no host")?;
    let local = host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost")
        || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
    if !matches!(url.scheme(), "nats" | "tls" | "ws" | "wss") || local {
        return Err("controller self-deployment requires an independently managed NATS service, not a loopback broker".into());
    }
    if spec["vm"]["driver"] != "firecracker" || !spec["vm"]["workspace"].is_object()
        || spec["scaling"]["max_replicas"] != 1 || spec["scaling"]["min_replicas"] != 1
        || spec["scaling"]["warm_pool"].as_u64().unwrap_or(0) != 0 {
        return Err("self-deployment requires one Firecracker controller with persistent workspace".into());
    }
    let mounts = spec["vm"]["mounts"].as_array_mut().ok_or("controller has no artifact mounts")?;
    let matching: Vec<_> = mounts.iter_mut().filter(|m| m["path"] == "/opt/ci-release").collect();
    if matching.len() != 1 { return Err("controller must have exactly one /opt/ci-release mount".into()); }
    let mount = matching.into_iter().next().unwrap();
    if mount["read_only"] != true || mount["strip_components"] != 1 {
        return Err("controller release mount must be read-only with strip_components=1".into());
    }
    mount["ref"] = json!(digest);
    mount["digest"] = json!(digest);
    spec["vm"]["env_vars"]["CI_EXPECTED_SHA"] = json!(sha);
    let boot = base64::engine::general_purpose::STANDARD.encode(include_str!("../deploy/start-artifact.sh"));
    spec["vm"]["start_command"] = json!(format!("echo {boot} | base64 -d > /tmp/ci-start-artifact.sh; setsid nohup bash /tmp/ci-start-artifact.sh /opt/ci-release /opt/ci /workspace/ci-state </dev/null >/workspace/ci-state.log 2>&1 &"));
    Ok(spec)
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder().timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())
}

fn success_message(request: &Request) -> String {
    format!(
        "Deployed CI controller `{}` at {} from revision {}; verified the exact executable through {}/healthz; submissions reopened.",
        request.deployment,
        request.public_url.trim_end_matches('/'),
        request.sha,
        request.public_url.trim_end_matches('/'),
    )
}

pub(crate) fn target(d: &Dispatcher) -> Result<(&str, &str, &str), String> {
    let id = d.config.controller_deployment.as_deref().ok_or("CI_CONTROLLER_DEPLOYMENT is not configured")?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("invalid CI_CONTROLLER_DEPLOYMENT".into());
    }
    let base = d.config.controller_app_lb_url.as_deref().ok_or("CI_CONTROLLER_APP_LB_URL is not configured")?;
    crate::cd::app_lb_endpoint(base)?;
    crate::cd::app_lb_endpoint(&d.config.public_url)?;
    let token = d.config.controller_app_lb_token.as_deref().filter(|s| !s.is_empty()).ok_or("CI_CONTROLLER_APP_LB_TOKEN is not configured")?;
    Ok((id, base.trim_end_matches('/'), token))
}

async fn snapshot_at(base: &str, id: &str, token: &str) -> Result<Value, String> {
    let response = client()?.get(format!("{base}/deployments/{id}")).bearer_auth(token).send().await
        .map_err(|_| "could not read controller deployment")?.error_for_status().map_err(|_| "controller deployment read refused")?;
    let tag = response.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok())
        .ok_or("app-lb must support conditional deployment updates before enabling self-deployment")?.to_owned();
    let body: Value = response.json().await.map_err(|_| "invalid deployment response")?;
    if tag != etag(&body["spec"]) { return Err("app-lb deployment ETag does not match its spec".into()); }
    Ok(body)
}

/// Persist intent, not credentials or a running deploy job. Publication and
/// merge must already have succeeded; the run remains running after this job.
pub async fn request(d: &Dispatcher, msg: &JobMessage, step: &str, artifact: &str, workflow: Option<&str>) -> Result<String, String> {
    if d.config.managed_deployment.is_some() {
        return Err("managed CI requires a regional platform update; direct app-lb self-replacement is forbidden".into());
    }
    let (deployment, base, token) = target(d)?;
    let application = update_application(d)?;
    if application.is_some() {
        return crate::regional_update::request(d, msg, step, artifact, workflow).await;
    }
    let prepared = prepare(PreparationInputs {
        store: &d.store, artifacts: d.artifacts.as_ref(), run_id: &msg.run_id, step_id: step,
        artifact_name: artifact, workflow, controller_repository: d.config.controller_repository.as_deref(),
        artifact_store_url: d.config.artifacts.as_ref().map(|a| a.url.as_str()), application_id: application,
        parent_operation_id: None,
        target: PreparationTarget { deployment, base_url: base, token,
            public_url: &d.config.public_url, source_boot: d.executor.boot_id() },
    }).await?;
    if prepared.already_recorded {
        Ok(format!("[ci] controller deployment {} is durably recorded\n", prepared.id))
    } else {
        Ok(format!("[ci] controller deployment {} recorded; run waits for drain, replacement, and public revision verification\n", prepared.id))
    }
}

/// Validate the published release and artifact against durable CI state, pin
/// a live target snapshot, and atomically record the legacy rollout rows.
/// This is independent of `Dispatcher` so compatibility entry points can use
/// the exact same authorization and persistence path.
pub async fn prepare(input: PreparationInputs<'_>) -> Result<PreparedRollout, String> {
    let target = &input.target;
    if target.deployment.is_empty() || !target.deployment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("invalid CI_CONTROLLER_DEPLOYMENT".into());
    }
    crate::cd::app_lb_endpoint(target.base_url)?;
    crate::cd::app_lb_endpoint(target.public_url)?;
    if target.token.is_empty() { return Err("CI_CONTROLLER_APP_LB_TOKEN is not configured".into()); }
    let base = target.base_url.trim_end_matches('/');
    if input.application_id.is_none() {
        let adopted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_controller_rollout WHERE application_id IS NOT NULL AND request->>'deployment'=$1 AND request->>'base_url'=$2)")
            .bind(target.deployment).bind(base).fetch_one(input.store.pool()).await.map_err(|e| e.to_string())?;
        if adopted { return Err("previously adopted CI deployment requires its application lifecycle configuration".into()); }
    }
    let (sha, stored) = published_artifact(input.store, input.run_id, input.controller_repository,
        input.artifact_name, input.workflow).await?;
    let (_, git_ref) = crate::release::deployment_source(input.store, input.run_id).await?;
    let digest = stored.digest.clone().ok_or("artifact omitted digest")?;
    let id = match input.parent_operation_id {
        Some(parent) => crate::regional_update::child_id(parent, base, target.deployment),
        None => format!("ci-controller-{}", hex::encode(Sha256::digest(input.step_id.as_bytes()))),
    };
    if let Some(existing) = sqlx::query("SELECT c.request,c.application_id,c.phase,s.run_id FROM ci_controller_rollout c JOIN ci_service_deployment s ON s.id=COALESCE(c.deployment_record_id,c.id) WHERE c.id=$1")
        .bind(&id).fetch_optional(input.store.pool()).await.map_err(|e| e.to_string())? {
        let saved_application: Option<String> = existing.get("application_id");
        if existing.get::<String,_>("run_id") != input.run_id || saved_application.as_deref() != input.application_id
            || (input.application_id.is_none() && existing.get::<String,_>("phase") == "prepared") {
            return Err("controller rollout approval contract changed on replay".into());
        }
        let existing: Request = serde_json::from_value(existing.get("request")).map_err(|e| e.to_string())?;
        if existing.sha != sha || existing.artifact != digest || existing.deployment != target.deployment || existing.base_url != base
            || existing.public_url.trim_end_matches('/') != target.public_url.trim_end_matches('/') {
            return Err("controller rollout request changed on replay".into());
        }
        return Ok(PreparedRollout { id, already_recorded: true });
    }
    if !(1..=256 * 1024 * 1024).contains(&stored.size_bytes) { return Err("controller artifact exceeds verification budget".into()); }
    let bytes = input.artifacts.get(&stored).await.map_err(|e| e.to_string())?;
    if hex::encode(Sha256::digest(&bytes)) != digest { return Err("controller artifact digest mismatch".into()); }
    let binary_sha256 = artifact_identity(&bytes, &sha)?;
    let current = snapshot_at(base, target.deployment, target.token).await?;
    let spec = &current["spec"];
    if spec["vm"]["env_vars"]["CI_PUBLIC_URL"].as_str().map(|s| s.trim_end_matches('/')) != Some(target.public_url.trim_end_matches('/'))
        || spec["vm"]["env_vars"]["CI_CONTROLLER_DEPLOYMENT"] != target.deployment {
        return Err("registered deployment is not this controller".into());
    }
    let artifact_store_url = input.artifact_store_url.ok_or("controller update requires the HTTP artifact sink")?;
    let mount = spec["vm"]["mounts"].as_array().and_then(|m| m.iter().find(|m| m["path"] == "/opt/ci-release"))
        .ok_or("missing controller release mount")?;
    if mount["store"].as_str().map(|s| s.trim_end_matches('/')) != Some(artifact_store_url.trim_end_matches('/')) {
        return Err("controller mount uses a different artifact store".into());
    }
    let vms = current["vms"].as_array().ok_or("missing controller VM inventory")?;
    if vms.len() != 1 || vms[0]["healthy"] != true || vms[0]["draining"] != false { return Err("controller must have exactly one healthy, non-draining VM".into()); }
    let wanted = desired_spec(spec.clone(), &digest, &sha)?;
    let request = Request { deployment: target.deployment.into(), base_url: base.into(), public_url: target.public_url.into(),
        artifact: digest, sha: sha.clone(), binary_sha256, previous_vm: vms[0]["sandbox_id"].as_str().ok_or("missing VM identity")?.into(),
        previous_etag: etag(spec), desired_etag: etag(&wanted), source_boot: Some(target.source_boot) };
    let value = serde_json::to_value(&request).map_err(|e| e.to_string())?;
    let hash = etag(&value);
    let mut tx = input.store.pool().begin().await.map_err(|e| e.to_string())?;
    if let Some(parent) = input.parent_operation_id {
        let row = sqlx::query("SELECT u.request,u.application_id,u.result,s.run_id,s.step_id,j.status AS job_status,r.status AS run_status FROM ci_regional_update u JOIN ci_service_deployment s ON s.id=u.id JOIN ci_job j ON j.id=s.job_id JOIN ci_run r ON r.id=s.run_id WHERE u.id=$1 AND u.attempted FOR UPDATE OF u")
            .bind(parent).fetch_optional(&mut *tx).await.map_err(|e| e.to_string())?.ok_or("regional parent is not submitted")?;
        let command: Value = row.get("request");
        let cancelled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_regional_cancelled_child WHERE id=$1)")
            .bind(&id).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
        if cancelled || row.get::<Option<String>,_>("result").is_some() || row.get::<String,_>("run_id") != input.run_id
            || row.get::<String,_>("step_id") != input.step_id || row.get::<String,_>("job_status") != "success"
            || matches!(row.get::<String,_>("run_status").as_str(), "failure" | "cancelled")
            || Some(row.get::<String,_>("application_id").as_str()) != input.application_id
            || command["release"]["targetRevision"] != request.sha
            || command["release"]["artifactDigest"] != request.artifact
            || command["release"]["binarySha256"] != request.binary_sha256 {
            return Err("regional preparation does not match its eligible parent".into());
        }
        sqlx::query("INSERT INTO ci_controller_rollout(id,deployment_record_id,request,phase,application_id) VALUES($1,$2,$3,'prepared',$4) ON CONFLICT(id) DO NOTHING")
            .bind(&id).bind(parent).bind(&value).bind(input.application_id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        let saved: Value = sqlx::query_scalar("SELECT request FROM ci_controller_rollout WHERE id=$1")
            .bind(&id).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
        if saved != value { return Err("regional preparation changed on replay".into()); }
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(PreparedRollout { id, already_recorded: false });
    }
    let inserted = sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) SELECT $1,s.id,r.id,j.id,$3,$4,'running','pending',$5,$7 FROM ci_step s JOIN ci_job j ON j.id=s.job_id JOIN ci_run r ON r.id=j.run_id WHERE s.id=$2 AND r.id=$6 AND j.status='running' AND r.status NOT IN ('cancelled','failure')")
        .bind(&id).bind(input.step_id).bind(target.deployment).bind(hash).bind(&sha).bind(input.run_id).bind(&git_ref)
        .execute(&mut *tx).await.map_err(|e| e.to_string())?.rows_affected();
    if inserted != 1 { return Err("requesting job is no longer running".into()); }
    sqlx::query("INSERT INTO ci_controller_rollout(id,request,phase,application_id) VALUES($1,$2,$3,$4)")
        .bind(&id).bind(value).bind(if input.application_id.is_some() { "prepared" } else { "pending" }).bind(input.application_id)
        .execute(&mut *tx).await.map_err(|e| format!("another controller rollout is active, or intent could not be recorded: {e}"))?;
    Store::add_service_deployment_event(&mut tx, &id).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(PreparedRollout { id, already_recorded: false })
}

/// A never-adopted app-lb deployment already authorizes its release through
/// repository, merged revision, artifact and deployment-scoped credentials.
/// Partial lifecycle configuration is an error, never a fallback to that mode.
fn update_application(d: &Dispatcher) -> Result<Option<&str>, String> {
    if d.config.application_id.is_none() && d.config.application_orchestrator_url.is_none()
        && d.config.application_lifecycle_token.is_none() {
        return Ok(None);
    }
    application_target(d).map(|(application, _, _)| Some(application))
}

pub(crate) fn application_target(d: &Dispatcher) -> Result<(&str, &str, &str), String> {
    let application = d.config.application_id.as_deref().filter(|id| !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
        .ok_or("CI_APPLICATION_ID must be configured")?;
    let base = d.config.application_orchestrator_url.as_deref().ok_or("CI_APPLICATION_ORCHESTRATOR_URL must be configured")?;
    crate::cd::app_lb_endpoint(base)?;
    let token = d.config.application_lifecycle_token.as_deref().filter(|t| !t.is_empty())
        .ok_or("CI_APPLICATION_LIFECYCLE_TOKEN must be configured through HeyoSecret")?;
    Ok((application, base, token))
}

pub(crate) async fn published_artifact(store: &Store, run_id: &str, repository: Option<&str>,
    artifact: &str, workflow: Option<&str>) -> Result<(String, StoredArtifact), String> {
    let run = store.get_run(run_id).await.map_err(|e| e.to_string())?.ok_or("missing run")?;
    let repository = repository.ok_or("CI_CONTROLLER_REPOSITORY is not configured")?;
    if !crate::repos::same_repo(repository, &run.repo_url) { return Err("this repository may not replace the CI app".into()); }
    let (sha, _) = crate::release::deployment_source(store, run_id).await?;
    if sha != run.sha { return Err("build must match the exact merged revision; version-bump releases must rebuild first".into()); }
    let stored = if let Some(workflow) = workflow {
        crate::submission::artifact(store, run_id, workflow, artifact, None).await?
    } else {
        let row = sqlx::query("SELECT a.* FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id WHERE a.run_id=$1 AND a.name=$2 AND a.sink='artifacts' AND j.status='success' ORDER BY a.created_at DESC LIMIT 1")
            .bind(run_id).bind(artifact).fetch_optional(store.pool()).await.map_err(|e| e.to_string())?.ok_or("no successfully built CI artifact")?;
        StoredArtifact { sink: "artifacts", digest: row.get("digest"),
            size_bytes: row.get::<i64,_>("size_bytes").try_into().map_err(|_| "invalid artifact size")?,
            uri: row.get("uri"), public_url: None }
    };
    if stored.sink != "artifacts" { return Err("CI update requires the HTTP artifact sink".into()); }
    Ok((sha, stored))
}

pub async fn application_status(d: &Dispatcher, id: &str) -> Result<Value, String> {
    let row = sqlx::query("SELECT c.request,c.application_id,c.phase,s.run_id,CASE WHEN c.deployment_record_id IS NULL THEN s.status ELSE COALESCE(c.result,'running') END AS status,COALESCE(c.message,s.message) AS message FROM ci_controller_rollout c JOIN ci_service_deployment s ON s.id=COALESCE(c.deployment_record_id,c.id) WHERE c.id=$1")
        .bind(id).fetch_optional(d.store.pool()).await.map_err(|e| e.to_string())?.ok_or("unknown controller update")?;
    let request: Value = row.get("request");
    let status: String = row.get("status");
    let phase: String = row.get("phase");
    let mut result = Value::Null;
    if status == "passed" && phase == "complete" {
        let (deployment, base, token) = target(d)?;
        if request["deployment"] != deployment || request["base_url"] != base {
            return Err("completed update must be observed through its target instance".into());
        }
        let current = snapshot_at(base, deployment, token).await?;
        let vms = current["vms"].as_array().ok_or("missing replacement VM inventory")?;
        if vms.len() != 1 || vms[0]["healthy"] != true || vms[0]["draining"] != false
            || current["workspace"]["phase"] != "idle" || current["workspace"]["push_pending"] != false {
            return Err("replacement workspace is not ready".into());
        }
        let runtime = vms[0]["sandbox_id"].as_str().ok_or("missing replacement VM identity")?;
        let admission = d.executor.status().await?;
        result = json!({"applicationRevision":d.config.expected_sha,"binarySha256":binary_sha256(),
            "runtimeSandboxId":runtime,"admissionsOpen":admission["admissionClosed"] == false});
        if result["applicationRevision"] != request["sha"] || result["binarySha256"] != request["binary_sha256"] {
            return Err("serving executable differs from the completed update".into());
        }
    }
    Ok(json!({"operationId":id,"applicationId":row.get::<Option<String>,_>("application_id"),
        "intentHash":etag(&request),"deploymentId":request["deployment"],"authority":request["base_url"],
        "targetRevision":request["sha"],"artifactDigest":request["artifact"],"binarySha256":request["binary_sha256"],
        "runId":row.get::<String,_>("run_id"),"status":status,
        "phase":phase,"message":row.get::<Option<String>,_>("message"),"result":result}))
}

pub async fn activate_application_update(d: &Dispatcher, id: &str, hash: &str) -> Result<(), String> {
    let (application, _, _) = application_target(d)?;
    let _permit = d.executor.effect_permit_for(Some(id)).await?;
    let mut tx = d.store.pool().begin().await.map_err(|e| e.to_string())?;
    // Use the same run-before-operation lock order as cancellation/submission.
    let run: String = sqlx::query_scalar("SELECT s.run_id FROM ci_service_deployment s JOIN ci_controller_rollout c ON s.id=COALESCE(c.deployment_record_id,c.id) WHERE c.id=$1")
        .bind(id).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    let run_status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
        .bind(run).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    let row = sqlx::query("SELECT request,application_id,phase,activation_hash FROM ci_controller_rollout WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    if row.get::<Option<String>,_>("application_id").as_deref() != Some(application)
        || etag(&row.get::<Value,_>("request")) != hash { return Err("application intent identity mismatch".into()); }
    if let Some(previous) = row.get::<Option<String>,_>("activation_hash") {
        if previous != hash { return Err("application activation changed on replay".into()); }
        return Ok(());
    }
    if row.get::<String,_>("phase") != "prepared" || matches!(run_status.as_str(), "cancelled" | "failure") {
        return Err("application update is no longer eligible for activation".into());
    }
    sqlx::query("UPDATE ci_controller_rollout SET phase='pending',activation_hash=$2,activated_at=now(),updated_at=now() WHERE id=$1")
        .bind(id).bind(hash).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}

async fn finish(d: &Dispatcher, id: &str, run: &str, passed: bool, message: &str) -> Result<(), String> {
    let mut tx = d.store.pool().begin().await.map_err(|e| e.to_string())?;
    sqlx::query("SELECT id FROM ci_run WHERE id=$1 FOR UPDATE")
        .bind(run).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    sqlx::query("UPDATE ci_service_deployment SET status=$2,phase='complete',message=$3,updated_at=now() WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM ci_regional_update WHERE id=$1)")
        .bind(id).bind(if passed { "passed" } else { "failed" }).bind(message).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    let parent: Option<String> = sqlx::query_scalar("UPDATE ci_controller_rollout SET phase='complete',result=$2,message=$3,updated_at=now() WHERE id=$1 RETURNING deployment_record_id")
        .bind(id).bind(if passed { "passed" } else { "failed" }).bind(message).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    if parent.is_none() { Store::add_service_deployment_event(&mut tx, id).await.map_err(|e| e.to_string())?; }
    Store::roll_up_run_in(&mut tx, run).await.map_err(|e| e.to_string())?;
    // Reopen only boots paused by this exact rollout. A retired predecessor
    // stays retired; neither another region nor operator maintenance is changed.
    sqlx::query("UPDATE ci_executor_boot b SET draining=FALSE,maintenance_operation=NULL FROM ci_controller_rollout c WHERE c.id=$1 AND b.maintenance_operation=(c.request->>'source_boot')::uuid AND b.deployment_id=(c.request->>'base_url')||'/deployments/'||(c.request->>'deployment') AND NOT b.retired")
        .bind(id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn mark_submitting(store: &Store, id: &str, run: &str) -> Result<bool, String> {
    let mut tx = store.pool().begin().await.map_err(|e| e.to_string())?;
    // Serialize the first externally visible attempt against cancellation.
    // Cancellation after this commit cannot retract a remote PUT.
    let status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
        .bind(run).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    let phase: String = sqlx::query_scalar("SELECT phase FROM ci_controller_rollout WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
    if phase == "quiesced" && matches!(status.as_str(), "cancelled" | "failure") { return Ok(false); }
    if !matches!(phase.as_str(), "quiesced" | "submitting") { return Err("rollout attempt is not quiesced".into()); }
    sqlx::query("UPDATE ci_controller_rollout SET phase='submitting',updated_at=now() WHERE id=$1")
        .bind(id).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(true)
}

async fn reconcile(d: &Dispatcher) -> Result<(), String> {
    if d.config.managed_deployment.is_some() || d.config.controller_deployment.is_none() { return Ok(()); }
    let (local_deployment, local_base, token) = target(d)?;
    let id: Option<String> = sqlx::query_scalar("SELECT id FROM ci_controller_rollout WHERE phase<>'complete' AND request->>'deployment'=$1 AND request->>'base_url'=$2")
        .bind(local_deployment).bind(local_base).fetch_optional(d.store.pool()).await.map_err(|e| e.to_string())?;
    let Some(id) = id else { return Ok(()); };
    // This exact operation can outlive the old process. It must not require
    // its retired boot's work permit or acquire any global execution authority.
    let mut operation = d.store.pool().begin().await.map_err(|e| e.to_string())?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,734))")
        .bind(&id).fetch_one(&mut *operation).await.map_err(|e| e.to_string())?;
    if !locked { return Ok(()); }
    let result = reconcile_operation(d, &id, token).await;
    // Await release on success and error; do not leave the next reconciliation
    // racing an asynchronously dropped transaction's rollback.
    operation.rollback().await.map_err(|e| e.to_string())?;
    result
}

async fn reconcile_operation(d: &Dispatcher, id: &str, token: &str) -> Result<(), String> {
    let row = sqlx::query("SELECT c.*,s.run_id,r.status AS run_status FROM ci_controller_rollout c JOIN ci_service_deployment s ON s.id=COALESCE(c.deployment_record_id,c.id) JOIN ci_run r ON r.id=s.run_id WHERE c.id=$1 AND c.phase<>'complete'")
        .bind(&id).fetch_optional(d.store.pool()).await.map_err(|e| e.to_string())?;
    let Some(row) = row else { return Ok(()) };
    let phase: String = row.get("phase");
    let run: String = row.get("run_id");
    let recorded: Value = row.get("request");
    if phase != "prepared" && row.get::<Option<String>,_>("application_id").is_some()
        && row.get::<Option<String>,_>("activation_hash").as_deref() != Some(etag(&recorded).as_str()) {
        return Err("adopted CI rollout has no matching durable application activation".into());
    }
    let request: Request = serde_json::from_value(recorded).map_err(|e| e.to_string())?;
    let source_boot = request.source_boot.ok_or("legacy CI rollout has no pinned source boot; explicit reconciliation is required")?;
    let deployment = request.deployment.as_str();
    let base = request.base_url.as_str();
    let attempted = matches!(phase.as_str(), "submitting" | "verifying");
    if !attempted && matches!(row.get::<String,_>("run_status").as_str(), "cancelled" | "failure") {
        return finish(d, &id, &run, false, "Release cancelled or failed before deployment; controller unchanged.").await;
    }
    let created: chrono::DateTime<chrono::Utc> = row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("activated_at").unwrap_or_else(||row.get("created_at"));
    if phase != "prepared" && !attempted && (chrono::Utc::now() - created).to_std().unwrap_or_default() > d.config.max_job_duration {
        return finish(d, &id, &run, false, "Controller drain exceeded CI_MAX_JOB_SECONDS; no update submitted and submissions reopened.").await;
    }
    match phase.as_str() {
        "prepared" => return Ok(()),
        "pending" => {
            if d.executor.boot_id() != source_boot { return Err("source boot changed before drain; refusing replacement".into()); }
            d.executor.pause(source_boot).await?;
            sqlx::query("UPDATE ci_controller_rollout SET phase='draining',updated_at=now() WHERE id=$1 AND phase='pending'")
                .bind(&id).execute(d.store.pool()).await.map_err(|e| e.to_string())?;
            d.store.update_service_deployment(&id, "running", Some("draining"), Some("Target CI instance admissions closed; its existing jobs continue. Peer admissions remain open."), None).await.map_err(|e| e.to_string())?;
            return Ok(());
        }
        "draining" => {
            if d.executor.boot_id() != source_boot { return Err("source boot changed during drain; refusing replacement".into()); }
            d.executor.quiesce(source_boot).await?;
            sqlx::query("UPDATE ci_controller_rollout SET phase='quiesced',updated_at=now() WHERE id=$1 AND phase='draining'")
                .bind(&id).execute(d.store.pool()).await.map_err(|e| e.to_string())?;
            return Ok(());
        }
        "quiesced" | "submitting" | "verifying" => {}
        _ => return Err("invalid controller rollout phase".into()),
    }
    let current = snapshot_at(base, deployment, token).await?;
    let tag = etag(&current["spec"]);
    if tag == request.previous_etag && tag != request.desired_etag && phase != "verifying" {
        // CAS makes retry after a lost response safe: only a writer observing
        // the original spec may change it. Also reject a rolled-back/new VM.
        let original = current["vms"].as_array().is_some_and(|v| v.len() == 1 && v[0]["sandbox_id"] == request.previous_vm && v[0]["healthy"] == true);
        if !original { return Err("original controller identity changed; refusing a blind deployment retry".into()); }
        let wanted = desired_spec(current["spec"].clone(), &request.artifact, &request.sha)?;
        if etag(&wanted) != request.desired_etag { return Err("controller update no longer matches recorded intent".into()); }
        if !mark_submitting(&d.store, &id, &run).await? {
            return finish(d, &id, &run, false, "Release cancelled before the deployment attempt; controller unchanged.").await;
        }
        // Keep the write guard through the PUT. Once retired, the old boot
        // cannot start new effects after this guard is released or lost.
        if d.executor.boot_id() != source_boot { return Err("only the pinned source boot may submit its replacement".into()); }
        let _quiesced = d.executor.retire_for_replacement(source_boot).await?;
        d.store.update_service_deployment(&id, "submitting", Some("replacing"), Some("All work drained; app-lb is replacing the controller and preserving its workspace."), None).await.map_err(|e| e.to_string())?;
        let result = client()?.put(format!("{base}/deployments/{deployment}")).bearer_auth(token)
            .header(reqwest::header::IF_MATCH, &request.previous_etag).json(&wanted).send().await;
        if let Ok(response) = result {
            if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
                return Err("controller spec changed concurrently; reconciling without overwriting it".into());
            }
        }
        // Never infer failure or success from PUT transport: this process may
        // disappear here. The next pass (including after restart) observes GET.
        return Ok(());
    }
    if tag != request.desired_etag {
        if !attempted { return finish(d, &id, &run, false, "Controller configuration changed before deployment; no update submitted.").await; }
        return Err("controller specification diverged after submission; reconciliation required".into());
    }
    sqlx::query("UPDATE ci_controller_rollout SET phase='verifying',updated_at=now() WHERE id=$1 AND phase<>'verifying'")
        .bind(&id).execute(d.store.pool()).await.map_err(|e| e.to_string())?;
    let ready = current["vms"].as_array().is_some_and(|v| v.len() == 1
        && (v[0]["sandbox_id"] != request.previous_vm || request.previous_etag == request.desired_etag)
        && v[0]["healthy"] == true && v[0]["draining"] == false);
    if !ready || current["workspace"]["phase"] != "idle" || current["workspace"]["push_pending"] != false { return Ok(()); }
    let response = client()?.get(format!("{}/healthz", request.public_url.trim_end_matches('/'))).send().await
        .map_err(|_| "replacement public health is unreachable")?;
    let headers = response.headers();
    if !response.status().is_success()
        || headers.get("x-ci-revision").and_then(|h| h.to_str().ok()) != Some(request.sha.as_str())
        || headers.get("x-ci-binary-sha256").and_then(|h| h.to_str().ok()) != Some(request.binary_sha256.as_str()) {
        return Err("public health does not identify the exact replacement binary".into());
    }
    finish(d, &id, &run, true, &success_message(&request)).await
}

pub fn spawn(d: Arc<Dispatcher>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(error) = reconcile(&d).await {
                tracing::warn!(%error, "controller deployment reconciliation is blocked");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::RunStatus;

    #[test]
    fn etag_sorts_nested_objects_but_preserves_array_order() {
        let input: Value = serde_json::from_str(r#"{"z":[{"z":2,"a":1},3],"a":{"z":4,"a":5}}"#).unwrap();
        let canonical = br#"{"a":{"a":5,"z":4},"z":[{"a":1,"z":2},3]}"#;
        let expected = format!("\"{:x}\"", Sha256::digest(canonical));
        assert_eq!(etag(&input), expected);
        let mut reordered = input;
        reordered["z"].as_array_mut().unwrap().reverse();
        assert_ne!(etag(&reordered), expected);
    }

    fn package(revision: &str, sum: &str, duplicate: bool) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gzip);
        let mut files = vec![("dist/REVISION", revision.as_bytes()), ("dist/ci", b"abc".as_slice()), ("dist/SHA256SUMS", sum.as_bytes())];
        if duplicate { files.push(("dist/ci", b"different")); }
        for (path, bytes) in files {
            let mut h = tar::Header::new_gnu(); h.set_size(bytes.len() as u64); h.set_mode(0o755); h.set_cksum();
            tar.append_data(&mut h, path, bytes).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn deployment_artifact_proves_revision_and_actual_executable() {
        // Independent published SHA-256 test vector, not generated by the
        // verifier or extracted from its output.
        let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let sums = format!("{hash}  ci\n");
        assert_eq!(artifact_identity(&package("source\n", &sums, false), "source").unwrap(), hash);
        assert!(artifact_identity(&package("different\n", &sums, false), "source").is_err());
        assert!(artifact_identity(&package("source\n", "bad  ci\n", false), "source").is_err());
        assert!(artifact_identity(&package("source\n", &sums, true), "source").is_err());
    }

    #[test]
    fn completed_deployment_message_identifies_what_and_where() {
        let request = Request {
            deployment: "ci-eu1".into(), base_url: "https://admin.eu1.example".into(),
            public_url: "https://ci.eu1.example/".into(), artifact: "a".repeat(64),
            sha: "8f3dc6d".into(), binary_sha256: "b".repeat(64), previous_vm: "old".into(),
            previous_etag: "before".into(), desired_etag: "after".into(),
            source_boot: None,
        };
        assert_eq!(success_message(&request),
            "Deployed CI controller `ci-eu1` at https://ci.eu1.example from revision 8f3dc6d; verified the exact executable through https://ci.eu1.example/healthz; submissions reopened.");
    }

    fn spec() -> Value {
        json!({"id":"ci-test","routes":[{"host":"ci.example.test"}],
            "scaling":{"min_replicas":1,"max_replicas":1,"warm_pool":0},
            "vm":{"driver":"firecracker","workspace":{"ref":"preserve-me"},
                "env_vars":{"OTHER":"unchanged","CI_EXPECTED_SHA":"old","CI_NATS_URL":"nats://broker.internal:4222"},
                "mounts":[{"path":"/opt/data","ref":"leave-me"},
                    {"path":"/opt/ci-release","ref":"old","digest":"old","read_only":true,"strip_components":1}]}})
    }

    #[test]
    fn promotion_preserves_broker_and_state_and_replaces_legacy_launcher() {
        let original = spec();
        let mut expected = original.clone();
        expected["vm"]["mounts"][1]["ref"] = json!("blob");
        expected["vm"]["mounts"][1]["digest"] = json!("blob");
        expected["vm"]["env_vars"]["CI_EXPECTED_SHA"] = json!("revision");
        let mut actual = desired_spec(original.clone(), "blob", "revision").unwrap();
        let command = actual["vm"].as_object_mut().unwrap().remove("start_command").unwrap();
        let encoded = command.as_str().unwrap().split_whitespace().nth(1).unwrap();
        let boot = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()).unwrap();
        assert!(boot.contains("exec ./ci"));
        assert!(!boot.contains("exec bash \"$runtime/start.sh\""));
        assert_eq!(actual, expected);
        for broker in ["ws://broker.internal:8080", "wss://ci.eu1.example/__nats"] {
            let mut websocket = original.clone();
            websocket["vm"]["env_vars"]["CI_NATS_URL"] = json!(broker);
            assert_eq!(desired_spec(websocket, "blob", "revision").unwrap()["vm"]["env_vars"]["CI_NATS_URL"], broker);
        }
        for broker in [Value::Null, json!("nats://localhost:4222"), json!("nats://127.0.0.2:4222"), json!("nats://[::1]:4222"), json!("http://broker.internal:4222")] {
            let mut invalid = original.clone(); invalid["vm"]["env_vars"]["CI_NATS_URL"] = broker;
            assert!(desired_spec(invalid, "blob", "revision").is_err());
        }
        for pointer in ["/scaling/max_replicas", "/scaling/min_replicas", "/scaling/warm_pool"] {
            let mut invalid = original.clone(); *invalid.pointer_mut(pointer).unwrap() = json!(2);
            assert!(desired_spec(invalid, "blob", "revision").is_err());
        }
        let mut invalid = original; invalid["vm"]["workspace"] = Value::Null;
        assert!(desired_spec(invalid, "blob", "revision").is_err());
    }

    struct Fixture { store: Store, _dir: tempfile::TempDir }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn application_activation_is_required_durable_and_cancellation_fenced() {
        let f = fixture().await;
        let d = dispatcher(&f, "http://127.0.0.1:1").await;
        sqlx::query("UPDATE ci_controller_rollout SET phase='prepared',application_id='ci' WHERE id='op'")
            .execute(f.store.pool()).await.unwrap();
        let hash = "\"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\"";
        assert!(d.executor.admission_permit().await.is_ok());
        assert!(d.executor.effect_permit().await.is_ok());
        assert!(activate_application_update(&d, "op", "different").await.is_err());
        let phase: String = sqlx::query_scalar("SELECT phase FROM ci_controller_rollout WHERE id='op'")
            .fetch_one(f.store.pool()).await.unwrap();
        assert_eq!(phase, "prepared");
        activate_application_update(&d, "op", hash).await.unwrap();
        let restarted = dispatcher(&f, "http://127.0.0.1:2").await;
        activate_application_update(&restarted, "op", hash).await.unwrap();
        let phase: String = sqlx::query_scalar("SELECT phase FROM ci_controller_rollout WHERE id='op'")
            .fetch_one(f.store.pool()).await.unwrap();
        assert_eq!(phase, "pending");
        assert!(activate_application_update(&restarted, "op", "different").await.is_err());
        sqlx::query("UPDATE ci_controller_rollout SET phase='prepared',activation_hash=NULL WHERE id='op'")
            .execute(f.store.pool()).await.unwrap();
        f.store.cancel_run("run").await.unwrap();
        assert!(activate_application_update(&d, "op", hash).await.is_err());
        let phase: String = sqlx::query_scalar("SELECT phase FROM ci_controller_rollout WHERE id='op'")
            .fetch_one(f.store.pool()).await.unwrap();
        assert_eq!(phase, "prepared");
    }

    async fn fixture() -> Fixture {
        let base = std::env::var("CI_TEST_DATABASE_URL").expect("disposable CI_TEST_DATABASE_URL");
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("rollout_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
        admin.close().await;
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-c search_path={schema}"));
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(url.as_str(), dir.path().join("logs"), Duration::from_secs(10)).await.unwrap();
        store.migrate().await.unwrap();
        sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('run','tests','ci.yml','running');
            INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('job','run','deploy','deploy','Deploy','success');
            INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES('step','job',0,'Request','ci/deploy-controller','success');
            INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES('op','step','run','job','ci-test','hash','running','source','refs/heads/main');
            INSERT INTO ci_controller_rollout(id,request) VALUES('op','{}');")
            .execute(store.pool()).await.unwrap();
        Fixture { store, _dir: dir }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn completed_jobs_do_not_publish_success_before_deployment_and_cancel_fences_submission() {
        let f = fixture().await; let s = &f.store;
        assert_eq!(s.roll_up_run("run").await.unwrap(), RunStatus::Running);
        assert!(s.get_run("run").await.unwrap().unwrap().finished_at.is_none());
        sqlx::query("UPDATE ci_controller_rollout SET phase='quiesced'").execute(s.pool()).await.unwrap();
        s.cancel_run("run").await.unwrap();
        assert!(!mark_submitting(s, "op", "run").await.unwrap());
        sqlx::query("UPDATE ci_controller_rollout SET phase='submitting'").execute(s.pool()).await.unwrap();
        assert!(mark_submitting(s, "op", "run").await.unwrap(), "a committed attempt must reconcile even after cancellation");
        sqlx::query("UPDATE ci_service_deployment SET status='passed'").execute(s.pool()).await.unwrap();
        assert_eq!(s.roll_up_run("run").await.unwrap(), RunStatus::Cancelled);
        sqlx::query("UPDATE ci_run SET status='running'").execute(s.pool()).await.unwrap();
        assert_eq!(s.roll_up_run("run").await.unwrap(), RunStatus::Success);
        sqlx::query("UPDATE ci_service_deployment SET status='failed'").execute(s.pool()).await.unwrap();
        assert_eq!(s.roll_up_run("run").await.unwrap(), RunStatus::Failure);
    }

    async fn dispatcher(f: &Fixture, base: &str) -> Dispatcher {
        dispatcher_with_application(f, base, true).await
    }

    async fn dispatcher_with_application(f: &Fixture, base: &str, adopted: bool) -> Dispatcher {
        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "local-test-only");
            std::env::set_var("CI_NETWORK", "local-test-only");
            std::env::set_var("CI_DATABASE_URL", std::env::var("CI_TEST_DATABASE_URL").unwrap());
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
            std::env::set_var("CI_NATS_URL", std::env::var("CI_TEST_NATS_URL").expect("disposable CI_TEST_NATS_URL"));
        }
        let mut config = crate::config::Config::from_env().unwrap();
        config.application_id = adopted.then(|| "ci".into());
        config.application_orchestrator_url = adopted.then(|| base.into());
        config.application_lifecycle_token = adopted.then(|| "test-lifecycle".into());
        config.controller_deployment = Some("ci-test".into());
        config.controller_repository = Some("https://github.com/example/ci.git".into());
        config.app_lb_url = None; config.app_lb_token = None;
        config.controller_app_lb_url = Some(base.into()); config.controller_app_lb_token = Some("test-admin".into());
        assert!(!crate::objects::Workflows::new(&config).is_configured(), "self-deployment must not enable workflow-object discovery");
        config.public_url = base.into();
        config.nats_prefix = format!("rollout{}", uuid::Uuid::new_v4().simple());
        config.artifact_sink = crate::config::ArtifactSinkKind::Disk;
        config.artifact_dir = f._dir.path().join("artifacts");
        config.artifacts = Some(crate::config::ArtifactsConfig { url:base.into(), token:None, guest_url:None });
        let config = Arc::new(config);
        Dispatcher {
            config: config.clone(), store: f.store.clone(),
            executor: Arc::new(crate::executor::ExecutorInstance::register(f.store.pool().clone(), &format!("{base}/deployments/ci-test")).await.unwrap()),
            pool: crate::pool::Pool::new(f.store.pool().clone()), images: crate::image::Catalog::new(f.store.pool().clone()),
            bus: Arc::new(crate::bus::Bus::connect(&config.nats, &config.nats_prefix).await.unwrap()),
            runners: Arc::new(crate::runners::Runners::new(config.clone())),
            vms: Arc::new(crate::vm::Vms::new()), secrets: crate::secrets::Secrets::unconfigured(),
            artifacts: Arc::from(crate::artifacts::sink_for(&config).unwrap()),
            objects: Arc::new(crate::objects::Workflows::new(&config)),
        }
    }

    #[derive(Clone)]
    struct Remote {
        snapshot: Arc<std::sync::Mutex<Value>>,
        puts: Arc<std::sync::atomic::AtomicUsize>,
        wrong_binary: Arc<std::sync::atomic::AtomicBool>,
    }

    async fn remote() -> (String, Remote, tokio::task::JoinHandle<()>) {
        use axum::{Router, Json, extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, routing::get};
        use std::sync::atomic::Ordering::SeqCst;
        let remote = Remote {
            snapshot: Arc::new(std::sync::Mutex::new(json!({"spec":spec(),"vms":[{"sandbox_id":"old-vm","healthy":true,"draining":false}],"workspace":{"phase":"idle","push_pending":false}}))),
            puts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            wrong_binary: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let app = Router::new().route("/deployments/ci-test", get(|State(r): State<Remote>, headers: HeaderMap| async move {
            assert_eq!(headers["authorization"], "Bearer test-admin");
            let body = r.snapshot.lock().unwrap().clone();
            ([("etag", etag(&body["spec"]))], Json(body))
        }).put(|State(r): State<Remote>, headers: HeaderMap, Json(spec): Json<Value>| async move {
            assert_eq!(headers["authorization"], "Bearer test-admin");
            let mut current = r.snapshot.lock().unwrap();
            if headers.get("if-match").and_then(|h| h.to_str().ok()) != Some(etag(&current["spec"]).as_str()) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            r.puts.fetch_add(1, SeqCst);
            current["spec"] = spec;
            current["vms"] = json!([{"sandbox_id":"replacement-vm","healthy":true,"draining":false}]);
            // The mutation happened but the caller did not receive success.
            StatusCode::BAD_GATEWAY.into_response()
        })).route("/healthz", get(|State(r): State<Remote>| async move {
            let binary = if r.wrong_binary.load(SeqCst) { "wrong-binary" } else { "verified-binary" };
            ([("x-ci-revision", "source"), ("x-ci-binary-sha256", binary)], "ok\n")
        })).route("/blobs/{digest}", get(|| async {
            package("source", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ci\n", false)
        })).with_state(remote.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        (url, remote, task)
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn request_supports_unadopted_app_lb_but_preserves_application_approval() {
        for (adopted, retained) in [(false, false), (true, false), (false, true), (true, true)] {
            let f = fixture().await;
            let (base, remote, server) = remote().await;
            let mut d = dispatcher_with_application(&f, &base, adopted).await;
            let original_config = d.config.clone();
            for fields in 1..7 {
                let mut partial = crate::config::Config::from_env().unwrap();
                partial.application_id = (fields & 1 != 0).then(|| "ci".into());
                partial.application_orchestrator_url = (fields & 2 != 0).then(|| base.clone());
                partial.application_lifecycle_token = (fields & 4 != 0).then(|| "test-lifecycle".into());
                d.config = Arc::new(partial);
                assert!(update_application(&d).is_err(), "partial lifecycle settings must not authorize direct updates: {fields}");
            }
            d.config = original_config;
            d.artifacts = Arc::new(crate::artifacts::ArtifactsSink::new(d.config.artifacts.clone().unwrap()));
            {
                let mut snapshot = remote.snapshot.lock().unwrap();
                snapshot["spec"]["vm"]["env_vars"]["CI_PUBLIC_URL"] = json!(base);
                snapshot["spec"]["vm"]["env_vars"]["CI_CONTROLLER_DEPLOYMENT"] = json!("ci-test");
                snapshot["spec"]["vm"]["mounts"][1]["store"] = json!(base);
            }
            sqlx::raw_sql("DELETE FROM ci_controller_rollout; DELETE FROM ci_service_deployment;
                UPDATE ci_run SET sha='source',repo_url='https://github.com/example/ci.git' WHERE id='run';
                UPDATE ci_job SET status='running' WHERE id='job';
                INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('build','run','build','build','Build','success');
                INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status)
                VALUES('run','hash','source','source','refs/heads/main','{}','source',
                '{\"source_sha\":\"source\",\"release_sha\":\"source\",\"git_ref\":\"refs/heads/main\",\"versions\":{}}','published');")
                .execute(f.store.pool()).await.unwrap();
            let bytes = package("source", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ci\n", false);
            sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri) VALUES('artifact','run','build','ci','artifacts',$1,$2,'test')")
                .bind(hex::encode(Sha256::digest(&bytes))).bind(bytes.len() as i64).execute(f.store.pool()).await.unwrap();
            let msg = JobMessage { run_id:"run".into(),job_id:"job".into(),job_key:"deploy".into() };
            // A real running step belonging to another release is not provenance
            // for the run whose repository and artifact were just verified.
            sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('other-run','tests','ci.yml','running');
                INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('other-job','other-run','deploy','deploy','Deploy','running');
                INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES('other-step','other-job',0,'Request','ci/deploy-controller','running');
                INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status)
                SELECT 'other-run',request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status FROM ci_release WHERE run_id='run';")
                .execute(f.store.pool()).await.unwrap();
            if retained {
                // A daily promotion has no Git publication of its own and no
                // artifact produced by its deployment run.
                sqlx::raw_sql("DELETE FROM ci_release WHERE run_id='run';
                    DELETE FROM ci_artifact WHERE id='artifact';
                    INSERT INTO ci_release_build(id,repository,name,revision,git_ref,policy,created_by,status)
                    VALUES('daily','https://github.com/example/ci.git','daily','source','refs/heads/main','{}','test','ready');
                    INSERT INTO ci_release_environment(name,repository)
                    VALUES('stage','https://github.com/example/ci.git');")
                    .execute(f.store.pool()).await.unwrap();
                let manifest = json!({"version":2,"retained":true,"revision":"source",
                    "repository":"https://github.com/example/ci.git","components":{"ci":{
                        "id":"retained-artifact","run_id":"daily-build",
                        "workflow":"ci.yml","job":"build","name":"ci","sink":"artifacts",
                        "sha256":hex::encode(Sha256::digest(&bytes)),"size_bytes":bytes.len(),"uri":"test"
                    }}});
                let hash = hex::encode(Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
                sqlx::query("INSERT INTO ci_release_bundle(id,repository,name,build_id,manifest,manifest_sha256,created_by)
                    VALUES('bundle','https://github.com/example/ci.git','daily','daily',$1,$2,'test')")
                    .bind(manifest).bind(hash).execute(f.store.pool()).await.unwrap();
                sqlx::raw_sql("INSERT INTO ci_release_promotion(run_id,environment,request_id,bundle_id,automatic,policy)
                    VALUES('run','stage','request','bundle',false,'{}');")
                    .execute(f.store.pool()).await.unwrap();
            }
            let workflow = retained.then_some("ci.yml");
            assert!(request(&d, &msg, "other-step", "ci", workflow).await.unwrap_err().contains("no longer running"));
            let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM ci_controller_rollout")
                .fetch_one(f.store.pool()).await.unwrap();
            assert_eq!(recorded, 0, "cross-run preparation must not record or activate an update");
            let result = request(&d, &msg, "step", "ci", workflow).await;
            result.unwrap();
            if adopted {
                let parent = format!("ci-regional-{:x}", Sha256::digest(b"step"));
                let id = crate::regional_update::child_id(&parent,&base,"ci-test");
                let request = crate::regional_update::Preparation { parent_operation_id:parent.clone(),operation_id:id.clone(),application_id:"ci".into() };
                assert!(crate::regional_update::prepare(&d,&id,&request).await.is_err(), "unsubmitted parent cannot prepare");
                sqlx::query("UPDATE ci_regional_update SET attempted=TRUE WHERE id=$1").bind(&parent).execute(f.store.pool()).await.unwrap();
                assert!(crate::regional_update::prepare(&d,&id,&request).await.is_err(), "source job must finish before preparing");
                sqlx::query("UPDATE ci_job SET status='success' WHERE id='job'").execute(f.store.pool()).await.unwrap();
                assert_eq!(f.store.roll_up_run("run").await.unwrap(),RunStatus::Running,"parent waits before children exist");
                let intent = crate::regional_update::prepare(&d,&id,&request).await.unwrap();
                assert_eq!(intent["phase"],"prepared");
                assert_eq!(crate::regional_update::prepare(&d,&id,&request).await.unwrap(),intent,"preparation is idempotent");
                let unconfigured = dispatcher_with_application(&f, &base, false).await;
                assert!(super::request(&unconfigured, &msg, "step", "ci", workflow).await.unwrap_err().contains("previously adopted"));
                crate::regional_update::cancel_child(&d,&id,&parent).await.unwrap();
                assert!(activate_application_update(&d,&id,intent["intentHash"].as_str().unwrap()).await.is_err());
                assert_eq!(f.store.roll_up_run("run").await.unwrap(),RunStatus::Running,"child cannot finish aggregate receipt");
            } else {
                let id = format!("ci-controller-{}", hex::encode(Sha256::digest(b"step")));
                let phase: String = sqlx::query_scalar("SELECT phase FROM ci_controller_rollout WHERE id=$1")
                    .bind(&id).fetch_one(f.store.pool()).await.unwrap();
                assert_eq!(phase, "pending");
                request(&d, &msg, "step", "ci", workflow).await.unwrap();
                let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ci_controller_rollout")
                    .fetch_one(f.store.pool()).await.unwrap();
                assert_eq!(count, 1, "replay must not create a second replacement");
            }
            assert_eq!(remote.puts.load(std::sync::atomic::Ordering::SeqCst), 0);
            server.abort();
        }
    }

    async fn seed_request(f: &Fixture, base: &str, source_boot: uuid::Uuid) {
        let request = Request { deployment: "ci-test".into(), base_url: base.into(), public_url: base.into(),
            artifact: "blob".into(), sha: "source".into(), binary_sha256: "verified-binary".into(),
            previous_vm: "old-vm".into(), previous_etag: etag(&spec()),
            desired_etag: etag(&desired_spec(spec(), "blob", "source").unwrap()), source_boot: Some(source_boot) };
        sqlx::query("UPDATE ci_controller_rollout SET request=$1").bind(serde_json::to_value(request).unwrap())
            .execute(f.store.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn scoped_replacement_and_lost_response_leave_peer_active() {
        use std::sync::atomic::Ordering::SeqCst;
        let f = fixture().await;
        let (base, remote, server) = remote().await;
        let d = dispatcher(&f, &base).await;
        seed_request(&f, &base, d.executor.boot_id()).await;
        // Same name in another authority must not drain or reconcile this update.
        let peer = dispatcher(&f, &format!("{base}/peer")).await;
        reconcile(&peer).await.unwrap();
        peer.executor.admission_permit().await.unwrap();
        sqlx::query("UPDATE ci_controller_rollout SET phase='prepared',application_id='ci' WHERE id='op'")
            .execute(f.store.pool()).await.unwrap();
        reconcile(&d).await.unwrap();
        assert_eq!(remote.puts.load(SeqCst),0,"prepared intent cannot replace the controller");
        assert!(d.executor.admission_permit().await.is_ok());
        let intent = application_status(&d,"op").await.unwrap();
        activate_application_update(&d,"op",intent["intentHash"].as_str().unwrap()).await.unwrap();
        reconcile(&d).await.unwrap(); // pending -> draining
        assert!(d.executor.admission_permit().await.is_err());
        assert!(d.executor.resume(d.executor.boot_id()).await.is_err(), "operator resume cannot bypass pending replacement");
        peer.executor.admission_permit().await.unwrap();
        let work = d.executor.effect_permit().await.unwrap();
        assert!(reconcile(&d).await.is_err(), "in-flight local effects must delay replacement");
        drop(work);
        sqlx::query("UPDATE ci_job SET status='running',executor_boot=$1 WHERE id='job'")
            .bind(d.executor.boot_id()).execute(f.store.pool()).await.unwrap();
        assert!(reconcile(&d).await.is_err(), "the source job must finish first");
        assert_eq!(remote.puts.load(SeqCst), 0);
        sqlx::query("UPDATE ci_job SET status='success' WHERE id='job'").execute(f.store.pool()).await.unwrap();
        sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('peer-run','test','ci.yml','running');
            INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('peer-job','peer-run','test','test','Peer','running');")
            .execute(f.store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_job SET executor_boot=$1 WHERE id='peer-job'")
            .bind(peer.executor.boot_id()).execute(f.store.pool()).await.unwrap();
        reconcile(&d).await.unwrap(); // draining -> quiesced
        assert!(d.executor.effect_permit().await.is_ok());
        reconcile(&d).await.unwrap(); // app-lb changed; response lost
        assert_eq!(remote.puts.load(SeqCst), 1);
        assert!(d.executor.effect_permit().await.is_err());
        let restarted = dispatcher(&f, &base).await;
        assert!(restarted.executor.admission_permit().await.is_err());
        peer.executor.admission_permit().await.unwrap();
        assert!(reconcile(&restarted).await.unwrap_err().contains("exact replacement"));
        assert_eq!(remote.puts.load(SeqCst), 1, "must not replace twice after a lost response");
        assert_eq!(f.store.get_run("run").await.unwrap().unwrap().status, "running");
        assert!(restarted.executor.admission_permit().await.is_err());
        remote.wrong_binary.store(false, SeqCst);
        sqlx::query("ALTER TABLE ci_event_outbox ADD CONSTRAINT reject_success CHECK (status <> 'passed')").execute(f.store.pool()).await.unwrap();
        assert!(reconcile(&restarted).await.is_err(), "simulate failure at the final durable outcome commit");
        assert!(restarted.executor.admission_permit().await.is_err(), "target admission and result must roll back together");
        peer.executor.admission_permit().await.unwrap();
        assert_eq!(f.store.get_run("run").await.unwrap().unwrap().status, "running");
        sqlx::query("ALTER TABLE ci_event_outbox DROP CONSTRAINT reject_success").execute(f.store.pool()).await.unwrap();
        // Even an operator using the same maintenance UUID on another
        // deployment must not have that independent pause cleared by finish.
        peer.executor.pause(d.executor.boot_id()).await.unwrap();
        reconcile(&restarted).await.unwrap();
        assert_eq!(f.store.get_run("run").await.unwrap().unwrap().status, "success");
        assert_eq!(f.store.service_deployments_of("run").await.unwrap()[0].status, "passed");
        assert!(restarted.executor.admission_permit().await.is_ok());
        assert!(restarted.executor.effect_permit().await.is_ok(), "verified completion opens normal execution atomically");
        assert!(d.executor.effect_permit().await.is_err(), "old boot must remain retired");
        assert!(peer.executor.admission_permit().await.is_err());
        peer.executor.resume(d.executor.boot_id()).await.unwrap();
        peer.executor.admission_permit().await.unwrap();
        assert_eq!(f.store.get_job("peer-job").await.unwrap().unwrap().status, "running");
        reconcile(&restarted).await.unwrap();
        assert_eq!(remote.puts.load(SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn concurrent_configuration_edit_is_not_overwritten() {
        use std::sync::atomic::Ordering::SeqCst;
        let f = fixture().await;
        let (base, remote, server) = remote().await;
        let d = dispatcher(&f, &base).await;
        seed_request(&f, &base, d.executor.boot_id()).await;
        reconcile(&d).await.unwrap(); reconcile(&d).await.unwrap();
        remote.snapshot.lock().unwrap()["spec"]["vm"]["env_vars"]["OTHER"] = json!("concurrent-edit");
        reconcile(&d).await.unwrap();
        assert_eq!(remote.puts.load(SeqCst), 0);
        assert_eq!(f.store.get_run("run").await.unwrap().unwrap().status, "failure");
        assert!(d.executor.admission_permit().await.is_ok());
        assert_eq!(remote.snapshot.lock().unwrap()["spec"]["vm"]["env_vars"]["OTHER"], "concurrent-edit");
        server.abort();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn rollout_uniqueness_is_scoped_to_the_app_lb_deployment() {
        let f = fixture().await;
        sqlx::raw_sql(r#"UPDATE ci_controller_rollout SET request='{"base_url":"https://us.test","deployment":"ci"}' WHERE id='op';
            INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES('peer-step','job',1,'Peer','ci/deploy-controller','success');
            INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES('peer','peer-step','run','job','ci','hash','running','source','main');"#)
            .execute(f.store.pool()).await.unwrap();
        assert!(sqlx::query("INSERT INTO ci_controller_rollout(id,request) VALUES('peer',$1)")
            .bind(json!({"base_url":"https://us.test","deployment":"ci"})).execute(f.store.pool()).await.is_err());
        sqlx::query("INSERT INTO ci_controller_rollout(id,request) VALUES('peer',$1)")
            .bind(json!({"base_url":"https://eu.test","deployment":"ci"})).execute(f.store.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn regional_children_share_one_receipt_and_cannot_complete_the_run() {
        let f=fixture().await;
        let d=dispatcher(&f,"http://127.0.0.1:1").await;
        sqlx::raw_sql("DELETE FROM ci_controller_rollout;
            INSERT INTO ci_regional_update(id,application_id,authority,request,artifact_name) VALUES('op','ci','http://127.0.0.1:1','{}','ci');
            INSERT INTO ci_controller_rollout(id,deployment_record_id,request,phase,application_id) VALUES
            ('first','op','{\"base_url\":\"https://west.test\",\"deployment\":\"ci\"}','prepared','ci'),
            ('second','op','{\"base_url\":\"https://east.test\",\"deployment\":\"ci\"}','prepared','ci');")
            .execute(f.store.pool()).await.unwrap();
        f.store.migrate().await.unwrap(); // startup replay preserves the new relationship
        finish(&d,"first","run",true,"first done").await.unwrap();
        assert_eq!(f.store.roll_up_run("run").await.unwrap(),RunStatus::Running);
        finish(&d,"second","run",true,"second done").await.unwrap();
        assert_eq!(f.store.roll_up_run("run").await.unwrap(),RunStatus::Running,"final bake belongs to parent");
        assert_eq!(f.store.service_deployments_of("run").await.unwrap().len(),1);
        sqlx::query("UPDATE ci_service_deployment SET status='passed' WHERE id='op'").execute(f.store.pool()).await.unwrap();
        assert_eq!(f.store.roll_up_run("run").await.unwrap(),RunStatus::Success);
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn legacy_unpinned_rollout_is_not_adopted_by_a_new_boot() {
        use std::sync::atomic::Ordering::SeqCst;
        let f = fixture().await;
        let (base, remote, server) = remote().await;
        let d = dispatcher(&f, &base).await;
        seed_request(&f, &base, d.executor.boot_id()).await;
        sqlx::query("UPDATE ci_controller_rollout SET request=request-'source_boot',phase='submitting'")
            .execute(f.store.pool()).await.unwrap();
        let restarted = dispatcher(&f, &base).await;
        assert!(reconcile(&restarted).await.unwrap_err().contains("no pinned source boot"));
        assert!(restarted.executor.admission_permit().await.is_err());
        let peer = dispatcher(&f, &format!("{base}/peer")).await;
        peer.executor.admission_permit().await.unwrap();
        assert_eq!(remote.puts.load(SeqCst), 0);
        assert_eq!(f.store.service_deployments_of("run").await.unwrap()[0].status, "running");
        server.abort();
    }
}
