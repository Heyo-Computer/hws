//! Runner-scoped, fail-closed host maintenance. No credentials are persisted.
//! The job remains running after yielding its VM; this reconciler owns completion.
use crate::{bus::JobMessage, dispatch::Dispatcher, plan::JobPlan, store::Store};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Duration};

const ACTION: &str = "ci/host-heyvm-maintenance";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub repository: String,
    pub runner_hd_id: String,
    pub backend_server_id: String,
    pub cloud_url: String,
    pub orchestrator_url: String,
    pub artifact_user_id: String,
    /// Opaque daemon layout target, NOT a version or runner identity.
    pub target: String,
    pub region: Option<String>,
}

#[derive(Deserialize, Serialize, PartialEq)]
struct Request {
    alias: String,
    target: Target,
    token_secret: String,
    sha: String,
    archive_sha256: String,
    body: Value,
}

pub fn validate_plan(plan: &JobPlan) -> Result<()> {
    for (index, step) in plan.steps.iter().enumerate().filter(|(_, s)| s.uses.as_deref() == Some(ACTION)) {
        ensure!(index + 1 == plan.steps.len() && !step.continue_on_error && !plan.continue_on_error,
            "host maintenance must be the final job step and may not tolerate errors");
        ensure!(!plan.target.is_existing_vm() && plan.native_labels.is_empty(),
            "host maintenance requires a CI-owned job VM");
    }
    Ok(())
}

fn endpoint(base: &str) -> Result<String> {
    let url = reqwest::Url::parse(base)?;
    let test_http = cfg!(test) && url.scheme() == "http" && url.host_str() == Some("127.0.0.1");
    ensure!((url.scheme() == "https" || test_http) && url.host_str().is_some()
        && url.username().is_empty() && url.password().is_none() && url.query().is_none()
        && url.fragment().is_none(), "maintenance URLs require HTTPS without URL credentials, query or fragment");
    Ok(base.trim_end_matches('/').into())
}

fn mapping(raw: Option<&str>, alias: &str) -> Result<Target> {
    let targets: BTreeMap<String, Target> = serde_json::from_str(raw.ok_or_else(|| anyhow::anyhow!("CI_HOST_MAINTENANCE_TARGETS is not configured"))?)?;
    let target = targets.get(alias).ok_or_else(|| anyhow::anyhow!("unknown trusted maintenance target"))?.clone();
    endpoint(&target.cloud_url)?;
    endpoint(&target.orchestrator_url)?;
    ensure!([&target.repository, &target.runner_hd_id, &target.backend_server_id, &target.artifact_user_id, &target.target]
        .iter().all(|s| !s.trim().is_empty()), "maintenance mapping has an empty identity");
    Ok(target)
}

pub fn token_secret(expression: &str) -> Result<String> {
    let name = expression.strip_prefix("${{ secrets.").and_then(|s| s.strip_suffix(" }}"))
        .ok_or_else(|| anyhow::anyhow!("maintenance token must be a direct secrets.NAME expression for restart-safe resolution"))?;
    ensure!(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "invalid token secret name");
    Ok(name.into())
}

/// Hash exactly the executable Cloud will extract. Ambiguous or unsafe archives
/// never acquire executable provenance, even if otherwise publishable as services.
pub fn executable_digest(bytes: &[u8]) -> Result<String> {
    component_executable_digest(bytes, "heyvm")
}

pub fn component_executable_digest(bytes: &[u8], component: &str) -> Result<String> {
    ensure!(matches!(component, "heyvm" | "heyvmd"), "unsupported executable component");
    const LIMIT: u64 = 512 * 1024 * 1024;
    ensure!(bytes.len() as u64 <= LIMIT, "archive exceeds verification budget");
    let decoder = flate2::read::GzDecoder::new(bytes).take(LIMIT + 1);
    let mut archive = tar::Archive::new(decoder);
    let mut digest = None;
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        total = total.checked_add(entry.size()).ok_or_else(|| anyhow::anyhow!("archive overflow"))?;
        ensure!(total <= LIMIT, "archive expansion exceeds verification budget");
        let path = entry.path()?.into_owned();
        ensure!(path.components().all(|c| matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir)), "unsafe archive member path");
        if (component == "heyvm" && path.file_name().is_some_and(|n| n == "heyvm"))
            || (component == "heyvmd" && path == std::path::Path::new(component)) {
            ensure!(digest.is_none() && entry.header().entry_type().is_file() && (4..=256*1024*1024).contains(&entry.size()),
                "ambiguous, linked or oversized host executable");
            let mut magic = [0; 4]; entry.read_exact(&mut magic)?;
            ensure!(&magic == b"\x7fELF", "host executable is not ELF");
            let mut hash = Sha256::new(); hash.update(magic);
            std::io::copy(&mut entry, &mut hash)?;
            digest = Some(hex::encode(hash.finalize()));
        }
    }
    ensure!(archive.into_inner().limit() > 0, "archive expansion exceeds verification budget");
    digest.ok_or_else(|| anyhow::anyhow!("archive has no requested host executable"))
}

pub async fn cordoned(store: &Store, runner: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_runner_drain WHERE runner_hd_id=$1) OR EXISTS(SELECT 1 FROM ci_host_maintenance WHERE runner_hd_id=$1 AND phase<>'passed') OR EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND phase NOT IN ('passed','superseded'))")
        .bind(runner).fetch_one(store.pool()).await?)
}

/// Use the same lock as job claims: after pause commits, no new job may
/// acquire this runner, including a delivery that selected it before pause.
pub async fn runner_drain(store: &Store, runner: &str, operation: uuid::Uuid, pause: bool) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 222))")
        .bind(runner).execute(&mut *tx).await?;
    let owner: Option<uuid::Uuid> = sqlx::query_scalar("SELECT operation_id FROM ci_runner_drain WHERE runner_hd_id=$1")
        .bind(runner).fetch_optional(&mut *tx).await?;
    ensure!(owner.is_none() || owner == Some(operation), "another operation owns this runner drain");
    if pause {
        sqlx::query("INSERT INTO ci_runner_drain(runner_hd_id,operation_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(runner).bind(operation).execute(&mut *tx).await?;
    } else {
        sqlx::query("DELETE FROM ci_runner_drain WHERE runner_hd_id=$1 AND operation_id=$2")
            .bind(runner).bind(operation).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn runner_drain_status(store: &Store, runner: &str) -> Result<Value> {
    // One snapshot covers admission and work on this server, regardless of
    // which regional CI process owns the jobs. Cleanup remains drain work.
    let row = sqlx::query("SELECT (SELECT operation_id FROM ci_runner_drain WHERE runner_hd_id=$1) AS operation, (SELECT count(*) FROM ci_job WHERE runner_hd_id=$1 AND status='running') AS running, (SELECT count(*) FROM ci_host_work WHERE runner_hd_id=$1) AS work, (SELECT count(*) FROM ci_vm_cleanup WHERE runner_hd_id=$1) AS cleanup")
        .bind(runner).fetch_one(store.pool()).await?;
    let operation: Option<uuid::Uuid> = row.get("operation");
    let running: i64 = row.get("running");
    let work: i64 = row.get("work");
    let cleanup: i64 = row.get("cleanup");
    Ok(json!({"runnerId":runner,"operationId":operation,"admissionClosed":operation.is_some(),
        "runningJobs":running,"hostWork":work,"cleanup":cleanup,
        "drained":operation.is_some() && running == 0 && work == 0 && cleanup == 0}))
}

pub async fn owns_job(store: &Store, job: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_service_deployment s JOIN ci_host_maintenance h ON h.id=s.id WHERE s.job_id=$1)")
        .bind(job).fetch_one(store.pool()).await?)
}

pub(crate) async fn trusted_target(d: &Dispatcher, alias: &str) -> Result<Target> {
    let managed;
    let raw = match d.config.host_maintenance_targets.as_deref() {
        Some(raw) => raw,
        None => {
            managed = d.secrets.host_maintenance_targets().await?;
            managed.as_str()
        }
    };
    mapping(Some(raw), alias)
}

pub async fn request(d: &Dispatcher, msg: &JobMessage, plan: &JobPlan, step: &str,
    alias: &str, cloud_url: &str, archive: &str, secret: &str, timeout: Duration) -> Result<String> {
    validate_plan(plan)?;
    crate::submission::authorize_publication(&d.store, &msg.run_id).await.map_err(anyhow::Error::msg)?;
    let target = trusted_target(d, alias).await?;
    if let Some(policy) = &plan.release_policy {
        ensure!(policy.maintenance.get(alias) == Some(&target), "maintenance target changed since release admission");
    }
    ensure!(endpoint(cloud_url)? == endpoint(&target.cloud_url)?, "workflow Cloud URL differs from trusted mapping");
    ensure!(d.runners.snapshot().locate(&target.runner_hd_id).is_some(), "mapped runner is not served by this controller");
    let run = d.store.get_run(&msg.run_id).await?.ok_or_else(|| anyhow::anyhow!("missing run"))?;
    ensure!(crate::repos::same_repo(&target.repository, &run.repo_url), "repository is not authorized for this host");
    let (sha, git_ref) = crate::release::deployment_source(&d.store, &msg.run_id).await.map_err(anyhow::Error::msg)?;
    let publication = sqlx::query("SELECT a.archive_sha256,a.heyvm_sha256 FROM ci_service_archive a JOIN ci_step s ON s.id=a.step_id JOIN ci_job j ON j.id=a.job_id WHERE a.run_id=$1 AND a.sha=$2 AND a.archive_id=$3 AND a.orchestrator_url=$4 AND a.archive_user_id=$5 AND s.status='success' AND (a.job_id=$6 OR j.status='success')")
        .bind(&msg.run_id).bind(&sha).bind(archive).bind(target.orchestrator_url.trim_end_matches('/'))
        .bind(&target.artifact_user_id).bind(&msg.job_id).fetch_all(d.store.pool()).await?;
    ensure!(publication.len() == 1, "archive lacks unambiguous successful publication provenance for this release and Cloud archive database");
    let archive_sha256: String = publication[0].try_get::<Option<String>,_>("archive_sha256")?.ok_or_else(|| anyhow::anyhow!("archive digest provenance missing"))?;
    let binary: String = publication[0].try_get::<Option<String>,_>("heyvm_sha256")?.ok_or_else(|| anyhow::anyhow!("verified heyvm executable provenance missing"))?;
    let id = hex::encode(Sha256::digest(step.as_bytes()));
    let mut body = json!({"maintenanceId":id,"backendServerId":target.backend_server_id,"target":target.target,
        "sha256":binary,"artifactArchiveId":archive,"artifactUserId":target.artifact_user_id,"requestedBy":id});
    if let Some(region) = &target.region { body["region"] = json!(region); }
    let request = Request { alias: alias.into(), target, token_secret: secret.into(), sha: sha.clone(), archive_sha256, body };
    let value = serde_json::to_value(&request)?;
    let hash = hex::encode(Sha256::digest(serde_json::to_vec(&value)?));
    let mut tx = d.store.pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,222))").bind(&request.target.runner_hd_id).execute(&mut *tx).await?;
    let status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE").bind(&msg.run_id).fetch_one(&mut *tx).await?;
    ensure!(!matches!(status.as_str(), "cancelled" | "failure"), "run is no longer eligible for maintenance");
    if let Some(existing) = sqlx::query_scalar::<_,Value>("SELECT request FROM ci_host_maintenance WHERE id=$1").bind(&id).fetch_optional(&mut *tx).await? {
        ensure!(existing == value, "maintenance payload changed on replay");
        return Ok(format!("[ci] maintenance {id} already recorded\n"));
    }
    let bootstrap_fenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND phase NOT IN ('passed','superseded'))",
    )
    .bind(&request.target.runner_hd_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(!bootstrap_fenced, "runner has an unresolved native heyvm bootstrap");
    let inserted = sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) SELECT $1,$2,$3,$4,$5,$6,'running','releasing',$7,$8 WHERE EXISTS(SELECT 1 FROM ci_job WHERE id=$4 AND status='running')")
        .bind(&id).bind(step).bind(&msg.run_id).bind(&msg.job_id).bind(&request.target.backend_server_id)
        .bind(hash).bind(&sha).bind(&git_ref).execute(&mut *tx).await?.rows_affected();
    ensure!(inserted == 1, "requesting job is no longer running");
    sqlx::query("INSERT INTO ci_host_maintenance(id,runner_hd_id,request,deadline) VALUES($1,$2,$3,now()+make_interval(secs=>$4))")
        .bind(&id).bind(&request.target.runner_hd_id).bind(value).bind(timeout.min(d.config.max_job_duration).as_secs() as f64).execute(&mut *tx).await?;
    Store::add_service_deployment_event(&mut tx, &id).await?;
    tx.commit().await?;
    Ok(format!("[ci] maintenance {id} fenced runner {}; releasing job VM before drain\n", request.target.runner_hd_id))
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none()).build()?)
}

fn verify(body: &Value, request: &Request) -> Result<bool> {
    for (remote, local) in [("maintenanceId","maintenanceId"), ("backendServerId","backendServerId"),
        ("target","target"), ("requestedBy","requestedBy"), ("targetSha256","sha256"),
        ("artifactArchiveId","artifactArchiveId"), ("artifactUserId","artifactUserId")] {
        ensure!(body[remote] == request.body[local], "Cloud maintenance identity/provenance mismatch: {remote}");
    }
    ensure!(matches!(body["operationType"].as_str(), Some("host_heyvm_upgrade" | "host_heyvm_upgrade_receipt_v1")),
        "wrong maintenance operation type");
    match body["status"].as_str() {
        Some("completed") => { ensure!(body["completedAt"].as_str().is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()), "completed maintenance lacks completion timestamp"); Ok(true) }
        Some("failed") => bail!("Cloud host upgrade failed; runner remains cordoned"),
        Some("pending" | "cordoned" | "draining" | "maintenance") => { ensure!(body["completedAt"].is_null(), "nonterminal maintenance has completion timestamp"); Ok(false) }
        _ => bail!("unknown Cloud maintenance status"),
    }
}

async fn set_phase(tx: &mut Transaction<'_, Postgres>, id: &str, phase: &str) -> Result<()> {
    let changed = sqlx::query("UPDATE ci_host_maintenance SET phase=$2,updated_at=now() WHERE id=$1 AND phase<>$2")
        .bind(id).bind(phase).execute(&mut **tx).await?.rows_affected();
    if changed == 0 { return Ok(()); }
    sqlx::query("UPDATE ci_service_deployment SET phase=$2,status=CASE WHEN $2='submitting' THEN 'submitting' ELSE 'running' END,updated_at=now() WHERE id=$1")
        .bind(id).bind(phase).execute(&mut **tx).await?;
    Store::add_service_deployment_event(tx, id).await?;
    Ok(())
}

async fn finish(tx: &mut Transaction<'_, Postgres>, id: &str, run: &str, job: &str, step: &str, passed: bool, note: &str) -> Result<()> {
    let phase = if passed { "passed" } else { "failed" };
    sqlx::query("UPDATE ci_host_maintenance SET phase=$2,updated_at=now() WHERE id=$1 AND phase NOT IN ('passed','failed')").bind(id).bind(phase).execute(&mut **tx).await?;
    sqlx::query("UPDATE ci_service_deployment SET status=$2,phase=$2,message=$3,updated_at=now() WHERE id=$1")
        .bind(id).bind(phase).bind(note).execute(&mut **tx).await?;
    let status = if passed { "success" } else { "failure" };
    sqlx::query("UPDATE ci_step SET status=$2,finished_at=now(),error=CASE WHEN $2='failure' THEN $3 ELSE NULL END WHERE id=$1 AND status<>'cancelled'")
        .bind(step).bind(status).bind(note).execute(&mut **tx).await?;
    sqlx::query("UPDATE ci_job SET status=$2,finished_at=now(),error=CASE WHEN $2='failure' THEN $3 ELSE NULL END WHERE id=$1 AND status NOT IN ('cancelled','failure')")
        .bind(job).bind(status).bind(note).execute(&mut **tx).await?;
    Store::add_service_deployment_event(tx, id).await?;
    Store::add_event(tx, run, Some(job), None, Some(step), "ci.step.status.v1", status, Some(note)).await?;
    Store::add_event(tx, run, Some(job), None, None, "ci.job.status.v1", status, Some(note)).await?;
    Store::roll_up_run_in(tx, run).await?;
    Ok(())
}

/// Bounded network roundtrips per pass, exclusively owned by a row lock.
/// `submitting` is committed on the previous pass, BEFORE POST. Crash/lost
/// response replays the same mandatory idempotency key on the new plural API.
pub(crate) async fn poll(store: &Store, id: &str, token: &str, configured: Option<&Target>) -> Result<()> {
    let mut tx = store.pool().begin().await?;
    // Cancellation uses run -> job lock order. Take the same order before the
    // maintenance row, including while completing an exact successful GET.
    let run: Option<String> = sqlx::query_scalar("SELECT run_id FROM ci_service_deployment WHERE id=$1").bind(id).fetch_optional(&mut *tx).await?;
    let Some(run) = run else { return Ok(()) };
    let run_status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE SKIP LOCKED").bind(&run).fetch_optional(&mut *tx).await?.unwrap_or_default();
    if run_status.is_empty() { return Ok(()); }
    let row = sqlx::query("SELECT h.*,s.job_id,s.step_id FROM ci_host_maintenance h JOIN ci_service_deployment s ON s.id=h.id WHERE h.id=$1 AND h.phase NOT IN ('passed','failed') FOR UPDATE OF h SKIP LOCKED")
        .bind(id).fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Ok(()) };
    let request: Request = serde_json::from_value(row.get("request"))?;
    let job: String = row.get("job_id"); let step: String = row.get("step_id");
    let phase: String = row.get("phase");
    let deadline: chrono::DateTime<chrono::Utc> = row.get("deadline");
    let job_status: String = sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1 FOR UPDATE").bind(&job).fetch_one(&mut *tx).await?;
    let stopped = matches!(run_status.as_str(), "cancelled" | "failure") || job_status != "running";
    if (stopped && phase != "releasing") || deadline <= chrono::Utc::now() || configured != Some(&request.target) {
        finish(&mut tx, id, &run, &job, &step, false, "Maintenance cancelled, timed out, or trusted mapping changed; runner remains cordoned. Remote operation may still require reconciliation.").await?;
        tx.commit().await?; return Ok(());
    }
    if phase == "releasing" { return Ok(()); }
    if phase == "draining" {
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_job WHERE runner_hd_id=$1 AND status='running' AND id<>$2) OR EXISTS(SELECT 1 FROM ci_host_work WHERE runner_hd_id=$1) OR EXISTS(SELECT 1 FROM ci_vm_pool WHERE runner_hd_id=$1 AND status IN ('claimed','building','draining'))")
            .bind(&request.target.runner_hd_id).bind(&job).fetch_one(&mut *tx).await?;
        if blocked { return Ok(()); }
        set_phase(&mut tx, id, "submitting").await?;
        tx.commit().await?; return Ok(());
    }
    if token.trim().is_empty() { return Ok(()); }
    let base = endpoint(&request.target.cloud_url)?;
    let http = client()?;
    let result: Result<Option<bool>> = async {
        // GET first even after restart. A completed operation is never submitted again.
        let response = http.get(format!("{base}/internal/mvm-ctrl/backend-servers/host-heyvm/upgrade/{id}"))
            .bearer_auth(token).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND && phase == "submitting" {
            let response = http.post(format!("{base}/internal/mvm-ctrl/backend-servers/host-heyvm/upgrades"))
                .bearer_auth(token).json(&request.body).send().await?;
            ensure!(!matches!(response.status().as_u16(), 404 | 405 | 409) && !response.status().is_redirection(),
                "Cloud lacks the idempotent maintenance endpoint, conflicts with this operation, or redirected authentication");
            if !response.status().is_success() { return Ok(None); }
            let body: Value = response.json().await?;
            ensure!(body["maintenanceId"] == id && body["backendServerId"] == request.target.backend_server_id && body["status"] == "accepted",
                "Cloud did not acknowledge exact maintenance identity");
            return Ok(Some(false));
        }
        ensure!(!response.status().is_redirection(), "Cloud redirected maintenance authentication");
        if !response.status().is_success() { return Ok(None); }
        Ok(Some(verify(&response.json::<Value>().await?, &request)?))
    }.await;
    if deadline <= chrono::Utc::now() {
        finish(&mut tx, id, &run, &job, &step, false, "Maintenance deadline elapsed; remote outcome requires reconciliation and runner remains cordoned.").await?;
        tx.commit().await?; return Ok(());
    }
    match result {
        Ok(Some(true)) => finish(&mut tx, id, &run, &job, &step, true, "Exact host executable and archive operation completed; runner uncordoned.").await?,
        Ok(Some(false)) => set_phase(&mut tx, id, "polling").await?,
        Ok(None) => {} // transport/server uncertainty: bounded GET/replay, never uncordon
        Err(error) if error.is::<reqwest::Error>() => {}
        Err(_) => finish(&mut tx, id, &run, &job, &step, false, "Cloud operation failed or returned mismatched identity/provenance; runner remains cordoned.").await?,
    }
    tx.commit().await?;
    Ok(())
}

/// Stop and release ONLY this job's VM under the pool-row lock. Phase and pool
/// release commit together, so restart cannot stop a VM another job has reused.
pub(crate) async fn release(d: &Dispatcher, id: &str) -> Result<()> {
    let mut tx = d.store.pool().begin().await?;
    let row = sqlx::query("SELECT s.job_id,j.sandbox_id,j.runner_hd_id,j.attempt FROM ci_host_maintenance h JOIN ci_service_deployment s ON s.id=h.id JOIN ci_job j ON j.id=s.job_id WHERE h.id=$1 AND h.phase='releasing' FOR UPDATE OF h SKIP LOCKED")
        .bind(id).fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Ok(()) };
    let job: String = row.get("job_id");
    let sandbox: String = row.try_get("sandbox_id")?;
    let runner: String = row.try_get("runner_hd_id")?;
    let pool = sqlx::query("SELECT status,claimed_by_job FROM ci_vm_pool WHERE sandbox_id=$1 FOR UPDATE")
        .bind(&sandbox).fetch_optional(&mut *tx).await?;
    let pool = pool.ok_or_else(|| anyhow::anyhow!("requesting VM lease disappeared; release is unverified"))?;
    ensure!(pool.get::<String,_>("status") == "claimed" && pool.get::<Option<String>,_>("claimed_by_job").as_deref() == Some(&job),
        "requesting VM ownership changed; release is unverified");
    let options = d.runners.options_for(&runner).await?;
    let vm = d.vms.open(options, sandbox.clone()).await?;
    tokio::time::timeout(Duration::from_secs(30), vm.stop()).await??;
    sqlx::query("UPDATE ci_vm_pool SET status='idle',claimed_by_job=NULL,leased_by=NULL,leased_until=NULL,last_used_at=now() WHERE sandbox_id=$1")
        .bind(&sandbox).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3")
        .bind(&job).bind(&runner).bind(row.get::<i32,_>("attempt")).execute(&mut *tx).await?;
    set_phase(&mut tx, id, "draining").await?;
    tx.commit().await?;
    Ok(())
}

pub fn spawn(d: Arc<Dispatcher>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let rows = sqlx::query("SELECT h.id,h.request,s.job_id,s.run_id FROM ci_host_maintenance h JOIN ci_service_deployment s ON s.id=h.id WHERE h.phase NOT IN ('passed','failed') ORDER BY h.created_at LIMIT 32").fetch_all(d.store.pool()).await;
            let Ok(rows) = rows else { continue };
            for row in rows {
                let id: String = row.get("id"); let run: String = row.get("run_id");
                let result: Result<()> = async {
                    let _effect = d.executor.effect_permit_for(Some(&id)).await.map_err(anyhow::Error::msg)?;
                    let request: Request = serde_json::from_value(row.get("request"))?;
                    let target = trusted_target(&d, &request.alias).await.ok();
                    // Local cancellation/deadline/configuration checks do not
                    // depend on either the runner or credential store working.
                    poll(&d.store, &id, "", target.as_ref()).await?;
                    release(&d, &id).await?;
                    let job = d.store.get_job(&row.get::<String,_>("job_id")).await?.ok_or_else(|| anyhow::anyhow!("missing maintenance job"))?;
                    let plan: JobPlan = serde_json::from_value(job.plan)?;
                    let run_row = d.store.get_run(&run).await?.ok_or_else(|| anyhow::anyhow!("missing maintenance run"))?;
                    let prefix = crate::secrets::Secrets::prefix(&run_row.workflow_id, plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default"));
                    let resolved = d.secrets.resolve(&prefix).await?;
                    let token = resolved.secrets.get(&request.token_secret).filter(|s| !s.trim().is_empty()).ok_or_else(|| anyhow::anyhow!("maintenance credential unavailable"))?;
                    poll(&d.store, &id, token, target.as_ref()).await
                }.await;
                if result.is_err() { tracing::warn!(operation=%id, "host maintenance blocked; runner remains cordoned"); }
                if let Err(e) = d.advance_run(&run).await { tracing::warn!(error=%e, "maintenance run advancement failed"); }
            }
        }
    });
}

/// Reconcile an exact completed operation, never POST another upgrade. Only
/// untouched skipped jobs resume; the failed outcome remains in the event log.
pub async fn recover(d: &Dispatcher, run_id: &str, id: &str) -> Result<Value> {
    let effect = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let mut tx = d.store.pool().begin().await?;
    let runner: String = sqlx::query_scalar("SELECT h.runner_hd_id FROM ci_host_maintenance h JOIN ci_service_deployment s ON s.id=h.id WHERE h.id=$1 AND s.run_id=$2")
        .bind(id).bind(run_id).fetch_one(&mut *tx).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,222))")
        .bind(&runner).fetch_one(&mut *tx).await?;
    ensure!(locked, "another operation owns the runner");
    let status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
        .bind(run_id).fetch_one(&mut *tx).await?;
    let jobs = sqlx::query("SELECT id,status,error FROM ci_job WHERE run_id=$1 ORDER BY id FOR UPDATE")
        .bind(run_id).fetch_all(&mut *tx).await?;
    let row = sqlx::query("SELECT h.*,s.job_id,s.step_id,s.status AS deployment_status FROM ci_host_maintenance h JOIN ci_service_deployment s ON s.id=h.id WHERE h.id=$1 AND s.run_id=$2 FOR UPDATE OF h")
        .bind(id).bind(run_id).fetch_one(&mut *tx).await?;
    if row.get::<String,_>("phase") == "passed" && row.get::<String,_>("deployment_status") == "passed" {
        return Ok(json!({"operation_id":id,"status":"already_passed"}));
    }
    ensure!(status == "failure" && row.get::<String,_>("phase") == "failed",
        "only failed maintenance can be recovered");
    let job_id: String = row.get("job_id");
    ensure!(jobs.iter().all(|j| if j.get::<String,_>("id") == job_id {
        j.get::<String,_>("status") == "failure"
    } else { matches!(j.get::<String,_>("status").as_str(), "success" | "skipped") }),
        "another job is active, cancelled or failed");
    let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_maintenance WHERE runner_hd_id=$1 AND id<>$2 AND phase<>'passed') OR EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND phase NOT IN ('passed','superseded')) OR EXISTS(SELECT 1 FROM ci_host_work w JOIN ci_job j ON j.id=w.job_id WHERE j.run_id=$3) OR EXISTS(SELECT 1 FROM ci_job j WHERE j.run_id=$3 AND j.status='skipped' AND (j.sandbox_id IS NOT NULL OR j.started_at IS NOT NULL OR EXISTS(SELECT 1 FROM ci_step s WHERE s.job_id=j.id)))")
        .bind(&runner).bind(id).bind(run_id).fetch_one(&mut *tx).await?;
    ensure!(!blocked, "unresolved work or previously executed skipped job blocks recovery");
    let request: Request = serde_json::from_value(row.get("request"))?;
    ensure!(request.body["maintenanceId"] == id && request.target.runner_hd_id == runner, "stored operation differs");
    ensure!(trusted_target(d, &request.alias).await? == request.target, "trusted mapping changed");
    let run = d.store.get_run(run_id).await?.ok_or_else(|| anyhow::anyhow!("missing run"))?;
    ensure!(crate::repos::same_repo(&request.target.repository, &run.repo_url), "repository does not own target");
    crate::submission::authorize_publication(&d.store, run_id).await.map_err(anyhow::Error::msg)?;
    let (sha, _) = crate::release::deployment_source(&d.store, run_id).await.map_err(anyhow::Error::msg)?;
    ensure!(sha == request.sha, "release provenance changed");
    let job = d.store.get_job(&job_id).await?.ok_or_else(|| anyhow::anyhow!("missing job"))?;
    let plan: JobPlan = serde_json::from_value(job.plan)?;
    let prefix = crate::secrets::Secrets::prefix(&run.workflow_id, plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default"));
    let resolved = d.secrets.resolve(&prefix).await?;
    let token = resolved.secrets.get(&request.token_secret).filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("maintenance credential unavailable"))?;
    let response = client()?.get(format!("{}/internal/mvm-ctrl/backend-servers/host-heyvm/upgrade/{id}", endpoint(&request.target.cloud_url)?))
        .bearer_auth(token).send().await?;
    ensure!(response.status().is_success(), "Cloud receipt unavailable");
    let receipt: Value = response.json().await?;
    ensure!(verify(&receipt, &request)?, "Cloud operation is not completed");
    ensure!(trusted_target(d, &request.alias).await? == request.target, "trusted mapping changed during recovery");
    let note = json!({"operation_id":id,"original_error":job.error,"receipt":receipt}).to_string();
    Store::add_event(&mut tx, run_id, Some(&job_id), None, None,
        "ci.host.maintenance.recovered.v1", "recovered", Some(&note)).await?;
    // The only failed job is proven complete, and no skipped job has executed.
    // Keep attempt IDs, logs, publication and prior status events intact.
    sqlx::query("UPDATE ci_job SET status='pending',finished_at=NULL,error=NULL WHERE run_id=$1 AND status='skipped'")
        .bind(run_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_run SET status='running',finished_at=NULL,error=NULL WHERE id=$1")
        .bind(run_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_job SET status='running' WHERE id=$1").bind(&job_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_host_maintenance SET phase='polling' WHERE id=$1").bind(id).execute(&mut *tx).await?;
    finish(&mut tx, id, run_id, &job_id, &row.get::<String,_>("step_id"), true,
        "Recovered from exact completed Cloud receipt; resumed untouched jobs without repeating maintenance.").await?;
    tx.commit().await?;
    drop(effect);
    d.advance_run(run_id).await?;
    Ok(json!({"operation_id":id,"status":"recovered","run_id":run_id}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_requires_every_identity_and_explicit_terminal_success() {
        let request: Request = serde_json::from_value(json!({"alias":"host","target":{
            "repository":"repo","runner_hd_id":"hd-runner","backend_server_id":"cloud-backend",
            "cloud_url":"https://cloud.test","orchestrator_url":"https://orch.test","artifact_user_id":"owner",
            "target":"stage-eu1-host-heyvm","region":null},"token_secret":"KEY","sha":"release","archive_sha256":"archive-digest",
            "body":{"maintenanceId":"operation","backendServerId":"cloud-backend","target":"stage-eu1-host-heyvm",
                "requestedBy":"operation","sha256":"binary-digest","artifactArchiveId":"archive","artifactUserId":"owner"}})).unwrap();
        let body = json!({"maintenanceId":"operation","backendServerId":"cloud-backend","operationType":"host_heyvm_upgrade",
            "target":"stage-eu1-host-heyvm","requestedBy":"operation","targetSha256":"binary-digest",
            "artifactArchiveId":"archive","artifactUserId":"owner","status":"completed","completedAt":"2026-09-16T00:00:00Z"});
        assert!(verify(&body, &request).unwrap());
        let mut versioned = body.clone();
        versioned["operationType"] = json!("host_heyvm_upgrade_receipt_v1");
        assert!(verify(&versioned, &request).unwrap());
        versioned["targetSha256"] = json!("another-binary");
        assert!(verify(&versioned, &request).is_err());
        for key in ["maintenanceId","backendServerId","operationType","target","requestedBy","targetSha256","artifactArchiveId","artifactUserId","completedAt"] {
            let mut wrong = body.clone(); wrong[key] = json!("different");
            assert!(verify(&wrong, &request).is_err(), "{key}");
        }
        for status in ["pending","cordoned","draining","maintenance"] {
            let mut pending = body.clone(); pending["status"] = json!(status); pending["completedAt"] = Value::Null;
            assert!(!verify(&pending, &request).unwrap());
        }
        for status in ["failed","success","unknown"] {
            let mut wrong = body.clone(); wrong["status"] = json!(status);
            assert!(verify(&wrong, &request).is_err());
        }
    }

    #[test]
    fn executable_provenance_rejects_ambiguity_links_and_non_elf() {
        let pack = |entries: &[(&str, &[u8], tar::EntryType)]| {
            let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
            for (path, bytes, kind) in entries {
                let mut h = tar::Header::new_gnu(); h.set_size(bytes.len() as u64); h.set_mode(0o755); h.set_entry_type(*kind);
                // Preserve exact member spelling, including deliberately unsafe
                // test paths that the normal builder would reject or normalize.
                h.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
                h.set_cksum();
                tar.append(&h, *bytes).unwrap();
            }
            tar.into_inner().unwrap().finish().unwrap()
        };
        let binary = b"\x7fELFexact-host-executable";
        let archive = pack(&[("heyvm", binary, tar::EntryType::Regular), ("heyvmd", b"other", tar::EntryType::Regular)]);
        assert_eq!(executable_digest(&archive).unwrap(), hex::encode(Sha256::digest(binary)));
        assert_ne!(executable_digest(&archive).unwrap(), hex::encode(Sha256::digest(&archive)));
        let dot_archive = pack(&[("./", b"", tar::EntryType::Directory), ("./heyvm", binary, tar::EntryType::Regular)]);
        assert_eq!(executable_digest(&dot_archive).unwrap(), hex::encode(Sha256::digest(binary)));
        for path in ["../heyvm", "/heyvm", "nested/../heyvm"] {
            assert!(executable_digest(&pack(&[(path, binary, tar::EntryType::Regular)])).is_err());
        }
        for entries in [vec![("heyvm", binary.as_slice(), tar::EntryType::Symlink)],
            vec![("heyvm", b"not ELF".as_slice(), tar::EntryType::Regular)],
            vec![("heyvm", binary.as_slice(), tar::EntryType::Regular), ("nested/heyvm", binary.as_slice(), tar::EntryType::Regular)]] {
            assert!(executable_digest(&pack(&entries)).is_err());
        }
    }

    #[test]
    fn final_step_and_restart_safe_credentials_are_required() {
        for steps in ["[{uses: ci/host-heyvm-maintenance}, {run: echo too-late}]",
            "[{uses: ci/host-heyvm-maintenance, continue-on-error: true}]",
            "[{uses: ci/host-heyvm-maintenance}, {uses: ci/host-heyvm-maintenance}]"] {
            let wf = crate::workflow::Workflow::parse("test.yml", &format!("jobs:\n  upgrade:\n    steps: {steps}\n")).unwrap();
            assert!(crate::plan::Plan::build(&wf).is_err());
        }
        assert_eq!(token_secret("${{ secrets.CLOUD_KEY }}").unwrap(), "CLOUD_KEY");
        assert!(token_secret("hardcoded-key").is_err());
        assert!(token_secret("${{ steps.key.outputs.token }}").is_err());
        for url in ["http://cloud.test", "https://key@cloud.test", "https://cloud.test?token=x", "https://cloud.test#x"] { assert!(endpoint(url).is_err()); }
    }
}
