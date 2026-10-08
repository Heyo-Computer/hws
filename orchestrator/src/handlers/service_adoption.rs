//! Attested adoption of a running application without replacing its workspace.

use std::time::Duration;

use anyhow::{Context, Result};
use axum::{extract::State, http::{HeaderMap, StatusCode}, Json};
use chrono::{DateTime, Utc};
use heyosecret_client::{HeyoSecretClient, HeyoSecretClientOptions};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{auth, config::ExternalServiceBinding, db, AppState};
use super::service_deploy;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalServiceAdoptionRequest {
    pub service_id: String,
    pub deployment_id: String,
    pub source_rollout_revision: String,
    pub artifact_digest: String,
    pub application_revision: String,
    pub binary_sha256: String,
    pub runtime_sandbox_id: String,
    pub runtime_port: u16,
}

#[derive(Debug)]
struct Observation { spec_etag: String, evidence: Value, observed_at: DateTime<Utc> }

fn configured<'a>(state: &'a AppState, r: &ExternalServiceAdoptionRequest) -> Result<&'a ExternalServiceBinding> {
    let matches: Vec<_> = state.config.external_service_bindings.iter().filter(|b|
        b.service_id == r.service_id && b.deployment_id == r.deployment_id).collect();
    anyhow::ensure!(matches.len() == 1, "service/deployment is not uniquely configured for external registration");
    let b = matches[0];
    for (name, value) in [("authority",&b.authority),("namespace",&b.namespace),("region",&b.region),
        ("healthOrigin",&b.health_origin),("tokenSecretPath",&b.token_secret_path)] {
        anyhow::ensure!(!value.trim().is_empty() && value.trim() == value, "configured {name} is invalid");
    }
    Ok(b)
}

fn validate(r: &mut ExternalServiceAdoptionRequest) -> Result<()> {
    r.service_id = service_deploy::sanitize_service_id(&r.service_id)?;
    for (name, value) in [("deploymentId",&r.deployment_id),("sourceRolloutRevision",&r.source_rollout_revision),
        ("artifactDigest",&r.artifact_digest),("applicationRevision",&r.application_revision),
        ("binarySha256",&r.binary_sha256),("runtimeSandboxId",&r.runtime_sandbox_id)] {
        anyhow::ensure!(!value.is_empty() && value.trim() == value && value.len() <= 256, "{name} is invalid");
    }
    anyhow::ensure!(r.deployment_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "deploymentId must be a single identifier");
    for digest in [&r.artifact_digest, &r.binary_sha256] {
        anyhow::ensure!(digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "artifactDigest and binarySha256 must be lowercase SHA-256 digests");
    }
    anyhow::ensure!(r.runtime_port > 0, "runtimePort must be nonzero");
    Ok(())
}

fn origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)?;
    anyhow::ensure!(matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
        && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
        && url.username().is_empty() && url.password().is_none(), "configured URL must be a credential-free origin");
    Ok(url)
}

fn etag(spec: &Value) -> String {
    let mut canonical = spec.clone(); canonical.sort_all_objects();
    format!("\"{:x}\"", Sha256::digest(serde_json::to_vec(&canonical).expect("JSON serializes")))
}

async fn token(state: &AppState, binding: &ExternalServiceBinding) -> Result<String> {
    let secrets = HeyoSecretClient::new(HeyoSecretClientOptions { base_url:state.config.heyosecret_url.clone(),
        token:if state.config.heyosecret_internal_api_key.is_empty() {state.config.internal_api_key.clone()}
            else {state.config.heyosecret_internal_api_key.clone()}, timeout:Some(Duration::from_secs(10)) })?;
    let value = String::from_utf8(secrets.read_active(&binding.token_secret_path).await?.value)
        .context("app-lb admin credential must be UTF-8")?;
    anyhow::ensure!(!value.trim().is_empty(), "app-lb admin credential is empty"); Ok(value)
}

async fn observe(binding: &ExternalServiceBinding, r: &ExternalServiceAdoptionRequest, bearer: &str) -> Result<Observation> {
    let authority = origin(&binding.authority)?;
    let health = origin(&binding.health_origin)?;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5)).build()?;
    let url = authority.join(&format!("deployments/{}", binding.deployment_id))?;
    let response = client.get(url).bearer_auth(bearer).send().await?.error_for_status()?;
    anyhow::ensure!(response.status().is_success(), "app-lb observation must not redirect");
    let header_etag = response.headers().get(reqwest::header::ETAG).and_then(|v|v.to_str().ok()).context("app-lb omitted deployment ETag")?.to_owned();
    let snapshot: Value = response.json().await.context("app-lb deployment response is not JSON")?;
    let spec = &snapshot["spec"];
    anyhow::ensure!(header_etag == etag(spec), "app-lb deployment ETag does not match spec");
    anyhow::ensure!(snapshot["rollout_revision"] == r.source_rollout_revision, "source rollout revision mismatch");
    anyhow::ensure!(spec["id"] == r.deployment_id && spec["namespace"].as_str().unwrap_or("default") == binding.namespace,
        "deployment identity or namespace mismatch");
    anyhow::ensure!(spec["vm"]["port"].as_u64() == Some(r.runtime_port.into()), "runtime port mismatch");
    anyhow::ensure!(snapshot["kind"] == "vm" && spec["vm"]["driver"] == "firecracker"
        && spec["scaling"]["min_replicas"] == 1 && spec["scaling"]["max_replicas"] == 1
        && spec["scaling"]["warm_pool"] == 0 && snapshot["pending"] == 0,
        "CI must remain one retained Firecracker controller without pending candidates");
    anyhow::ensure!(spec["vm"]["workspace"].is_object(), "external CI registration requires its app-lb workspace");
    anyhow::ensure!(snapshot["workspace"]["phase"] == "idle", "workspace handoff is in progress");
    let mounts = spec["vm"]["mounts"].as_array().context("deployment mounts are missing")?;
    let mount = mounts.iter().find(|m|m["path"] == "/opt/ci-release").context("CI artifact mount is missing")?;
    anyhow::ensure!(mount["read_only"] == true, "CI release mount must be read-only");
    anyhow::ensure!(mount.get("digest").or_else(||mount.get("ref")).and_then(Value::as_str) == Some(&r.artifact_digest), "artifact digest mismatch");
    anyhow::ensure!(snapshot["desired_replicas"] == 1 && snapshot["ready"] == 1, "deployment is not a ready singleton");
    let vms = snapshot["vms"].as_array().context("deployment VM inventory is missing")?;
    anyhow::ensure!(vms.len() == 1 && vms[0]["sandbox_id"] == r.runtime_sandbox_id
        && vms[0]["healthy"] == true && vms[0]["draining"] == false
        && vms[0]["addr"].as_str().is_some_and(|v|!v.is_empty()), "runtime is not the exact healthy singleton");
    let health_response = client.get(health.join("healthz")?).send().await?.error_for_status()?;
    anyhow::ensure!(health_response.status().is_success(), "CI health must not redirect");
    let headers = health_response.headers();
    for name in ["x-ci-revision", "x-ci-binary-sha256", "x-vm-id"] {
        anyhow::ensure!(headers.get_all(name).iter().count() == 1, "CI health identity must have exactly one {name} header");
    }
    anyhow::ensure!(headers.get("x-ci-revision").and_then(|v|v.to_str().ok()) == Some(&r.application_revision)
        && headers.get("x-ci-binary-sha256").and_then(|v|v.to_str().ok()) == Some(&r.binary_sha256)
        && headers.get("x-vm-id").and_then(|v|v.to_str().ok()) == Some(&r.runtime_sandbox_id), "CI health identity headers mismatch");
    anyhow::ensure!(health_response.text().await?.trim() == "ok", "CI health body is not ok");
    Ok(Observation { spec_etag:header_etag, observed_at:Utc::now(), evidence:json!({
        "rolloutRevision":r.source_rollout_revision,"artifactDigest":r.artifact_digest,
        "applicationRevision":r.application_revision,"binarySha256":r.binary_sha256,
        "runtimeSandboxId":r.runtime_sandbox_id,"runtimePort":r.runtime_port,"ready":1,
        "healthOrigin":health.as_str(),"region":binding.region}) })
}

pub(super) async fn ensure_managed(db: &impl ConnectionTrait, service: &str) -> Result<()> {
    anyhow::ensure!(db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM external_service_bindings WHERE service_id=$1 LIMIT 1",[service.into()])).await?.is_none(),
        "application requires retained-workspace release updates, not Cloud archive deployment"); Ok(())
}

async fn register(state: &AppState, r: &ExternalServiceAdoptionRequest) -> Result<bool> {
    let binding = configured(state,r)?; let bearer = token(state,binding).await?;
    super::application_update::verify_ready(state,binding).await?;
    let started = std::time::Instant::now();
    let first = observe(binding,r,&bearer).await?;
    let tx = service_deploy::try_service_lifecycle_lock(db::get_db()?,&r.service_id).await?.context("service lifecycle is busy")?;
    let existing = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT authority,namespace,deployment_id,source_rollout_revision,spec_etag,artifact_digest,application_revision,runtime_sandbox_id,runtime_port,evidence FROM external_service_bindings WHERE service_id=$1 AND region=$2",
        [r.service_id.clone().into(),binding.region.clone().into()])).await?;
    if let Some(row)=existing {
        let exact = row.try_get::<String>("","authority")? == origin(&binding.authority)?.as_str() && row.try_get::<String>("","namespace")? == binding.namespace
            && row.try_get::<String>("","deployment_id")? == r.deployment_id && row.try_get::<String>("","source_rollout_revision")? == r.source_rollout_revision
            && row.try_get::<String>("","spec_etag")? == first.spec_etag && row.try_get::<String>("","artifact_digest")? == r.artifact_digest
            && row.try_get::<String>("","application_revision")? == r.application_revision && row.try_get::<String>("","runtime_sandbox_id")? == r.runtime_sandbox_id
            && row.try_get::<i32>("","runtime_port")? == i32::from(r.runtime_port)
            && row.try_get::<Value>("","evidence")? == first.evidence;
        anyhow::ensure!(exact,"external service identity is immutable and does not match"); tx.commit().await?; return Ok(false)
    }
    // A previously Cloud-managed identity may still have delayed retirement or
    // restart work. This API registers new identities; it is not an ownership transfer.
    let sibling = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM external_service_bindings WHERE service_id=$1 LIMIT 1",[r.service_id.clone().into()])).await?.is_some();
    if !sibling {
        for table in ["service_deployment_states","service_discovery_sets","service_rollouts",
            "regional_service_rollouts","service_deployment_runs","service_deployment_events"] {
            let sql=format!("SELECT 1 FROM {table} WHERE service_id=$1 LIMIT 1");
            anyhow::ensure!(tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,sql,[r.service_id.clone().into()])).await?.is_none(),
                "service already has managed state or operation history");
        }
    }
    let second=observe(binding,r,&bearer).await?;
    anyhow::ensure!(first.spec_etag==second.spec_etag && first.evidence==second.evidence,"app-lb identity changed during registration");
    anyhow::ensure!(started.elapsed() <= Duration::from_secs(15), "registration observations expired");
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO external_service_bindings(service_id,authority,namespace,deployment_id,region,source_rollout_revision,spec_etag,artifact_digest,application_revision,runtime_sandbox_id,runtime_port,observed_at,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        vec![r.service_id.clone().into(),origin(&binding.authority)?.to_string().into(),binding.namespace.clone().into(),r.deployment_id.clone().into(),binding.region.clone().into(),r.source_rollout_revision.clone().into(),second.spec_etag.into(),r.artifact_digest.clone().into(),r.application_revision.clone().into(),r.runtime_sandbox_id.clone().into(),i32::from(r.runtime_port).into(),second.observed_at.into(),second.evidence.into()])).await?;
    tx.commit().await?; Ok(true)
}

pub async fn adopt_retained_deployment(headers: HeaderMap, State(state):State<AppState>, Json(mut r):Json<ExternalServiceAdoptionRequest>) -> (StatusCode,Json<Value>) {
    if let Err(status)=auth::require_internal_api_key(&headers,&state.config.internal_api_key) { return (status,Json(json!({"error":"Unauthorized"}))) }
    if let Err(e)=validate(&mut r) { return (StatusCode::BAD_REQUEST,Json(json!({"error":e.to_string()}))) }
    match register(&state,&r).await { Ok(created)=>(if created {StatusCode::CREATED}else{StatusCode::OK},Json(json!({"created":created,"serviceId":r.service_id,
        "deploymentId":r.deployment_id,"lifecycleOwner":"orchestrator","capabilities":["release-update"]}))),
        Err(e)=>(StatusCode::CONFLICT,Json(json!({"error":e.to_string()}))) }
}

#[cfg(test)] mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use axum::{Router, routing::{get, post}, response::IntoResponse};
    use base64::Engine;

    fn request() -> ExternalServiceAdoptionRequest {
        ExternalServiceAdoptionRequest { service_id:"ci".into(),deployment_id:"ci-eu1".into(),
            source_rollout_revision:"generation-8".into(),artifact_digest:"a".repeat(64),
            application_revision:"b".repeat(40),binary_sha256:"c".repeat(64),
            runtime_sandbox_id:"sb-exact".into(),runtime_port:9500 }
    }

    #[test]
    fn request_rejects_unpinned_identity() {
        let mut r = request();
        assert!(validate(&mut r).is_ok());
        r.runtime_port = 0;
        assert!(validate(&mut r).is_err());
        let mut r = request(); r.deployment_id = "../another".into();
        assert!(validate(&mut r).is_err());
        let mut r = request(); r.artifact_digest = "mutable-name".into();
        assert!(validate(&mut r).is_err());
        assert!(origin("https://admin.example/path").is_err());
        assert!(origin("https://user:password@admin.example").is_err());
        assert_eq!(origin("https://admin.example").unwrap().as_str(), "https://admin.example/");
    }

    async fn fixture() -> Result<(AppState, ExternalServiceBinding, Arc<AtomicUsize>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
        let mode = Arc::new(AtomicUsize::new(0));
        let reads = Arc::new(AtomicUsize::new(0));
        let request_mode = mode.clone(); let request_reads = reads.clone();
        let health_mode = mode.clone();
        let app = Router::new()
            .route("/v1/secrets/read", post(|| async {
                Json(json!({"path":"test/admin","version":1,"status":"active",
                    "valueBase64":base64::engine::general_purpose::STANDARD.encode("test-admin"),
                    "createdAt":Utc::now(),"metadata":{}}))
            }))
            .route("/api/lifecycle", get(|| async {
                Json(json!({"applicationId":"ci","deploymentId":"ci-eu1","capabilities":["release-update"]}))
            }))
            .route("/deployments/ci-eu1", get(move |headers: HeaderMap| {
                let mode = request_mode.clone(); let reads = request_reads.clone();
                async move {
                    assert_eq!(headers.get("authorization").unwrap(), "Bearer test-admin");
                    let count = reads.fetch_add(1, Ordering::SeqCst);
                    if mode.load(Ordering::SeqCst) == 3 {
                        return (StatusCode::TEMPORARY_REDIRECT, [("location", "/should-not-follow")]).into_response();
                    }
                    let spec = json!({"id":"ci-eu1","vm":{"driver":"firecracker","port":9500,
                        "workspace":{"store":"https://artifacts.example","ref":"retained-state"},
                        "mounts":[{"path":"/opt/ci-release","digest":"a".repeat(64),"read_only":true}]},
                        "scaling":{"min_replicas":1,"max_replicas":1,"warm_pool":0}});
                    let generation = if mode.load(Ordering::SeqCst) == 2 && count % 2 == 1 { "generation-9" } else { "generation-8" };
                    let snapshot = json!({"spec":spec,"rollout_revision":generation,"kind":"vm",
                        "desired_replicas":1,"ready":1,"pending":0,"workspace":{"phase":"idle"},
                        "vms":[{"sandbox_id":"sb-exact","addr":"10.0.1.2:9500","healthy":true,"draining":false}]});
                    ([("etag", etag(&snapshot["spec"]))], Json(snapshot)).into_response()
                }
            }))
            .route("/healthz", get(move || {
                let mode = health_mode.clone();
                async move { ([("x-ci-revision", "b".repeat(40)), ("x-ci-binary-sha256", "c".repeat(64)),
                    ("x-vm-id", if mode.load(Ordering::SeqCst) == 1 { "sb-other".into() } else { "sb-exact".into() })], "ok\n") }
            }))
            .route("/should-not-follow", get(|| async { panic!("redirect followed"); #[allow(unreachable_code)] StatusCode::OK }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let binding = ExternalServiceBinding { lifecycle_token_secret_path:"test/lifecycle".into(),
            service_id:"ci".into(),authority:base.clone(),region:"eu1".into(),
            namespace:"default".into(),deployment_id:"ci-eu1".into(),health_origin:base.clone(),token_secret_path:"test/admin".into() };
        let config = serde_json::from_value(json!({"server_port":0,
            "database_url":std::env::var("ORCHESTRATOR_TEST_DATABASE_URL").unwrap_or_default(),
            "agent_provider":"test","agent_model":"test","agent_api_key":"","agent_timeout_seconds":1,
            "agent_max_iterations":1,"jwt_secret":"test-key","cloud_internal_url":base,
            "internal_api_key":"test-key","heyosecret_url":base,"external_service_bindings":[binding]}))?;
        Ok((AppState { config:Arc::new(config),http_client:reqwest::Client::new(),worker_id:Arc::new("test".into()),
            ci_workspace_cache:Default::default() }, binding, mode, reads, task))
    }

    #[tokio::test]
    async fn observation_matches_runtime_and_never_follows_redirects() -> Result<()> {
        let (state, binding, mode, _, task) = fixture().await?;
        assert!(observe(&binding, &request(), "test-admin").await.is_ok());
        mode.store(1, Ordering::SeqCst);
        assert!(observe(&binding, &request(), "test-admin").await.is_err());
        mode.store(3, Ordering::SeqCst);
        assert!(observe(&binding, &request(), "test-admin").await.is_err());
        let (status, _) = adopt_retained_deployment(HeaderMap::new(), State(state), Json(request())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires ORCHESTRATOR_TEST_DATABASE_URL (disposable PostgreSQL)"]
    async fn adoption_postgres_atomic_replay_drift_and_owner_guard() -> Result<()> {
        let (state, _, mode, reads, task) = fixture().await?;
        db::init_database(&state.config).await?;
        let database = db::get_db()?;
        database.execute_unprepared(include_str!("../../migrations/042_add_external_service_bindings.sql")).await?;
        let r = request();
        mode.store(2, Ordering::SeqCst);
        assert!(register(&state, &r).await.is_err());
        service_deploy::wait_for_test_lifecycle_rollback(database,"ci").await?;
        assert!(ensure_managed(database, "ci").await.is_ok());
        mode.store(0, Ordering::SeqCst); reads.store(0, Ordering::SeqCst);
        assert!(register(&state, &r).await?);
        let before = database.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT observed_at FROM external_service_bindings WHERE service_id='ci'")) .await?.unwrap()
            .try_get::<DateTime<Utc>>("", "observed_at")?;
        assert!(!register(&state, &r).await?);
        let after = database.query_one(Statement::from_string(DbBackend::Postgres,
            "SELECT observed_at FROM external_service_bindings WHERE service_id='ci'")) .await?.unwrap()
            .try_get::<DateTime<Utc>>("", "observed_at")?;
        assert_eq!(before, after);
        assert!(ensure_managed(database, "ci").await.is_err());
        let lock = service_deploy::try_service_lifecycle_lock(database,"ci").await?.unwrap();
        assert!(ensure_managed(&lock,"ci").await.is_err());
        lock.commit().await?;
        let inventory = super::super::service_discovery::read_inventory(database, None).await?;
        assert_eq!(inventory["services"][0]["external"]["lifecycleOwner"], "orchestrator");
        assert!(inventory["services"][0]["endpoints"].is_null());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-key".parse()?);
        let spec = serde_json::from_value(json!({"id":"ci","user_id":"test",
            "vm":{"driver":"firecracker","image":"immutable-test","port":9500},
            "deploy":{"async":true,"archive_id":"must-not-create"}}))?;
        let (status, body) = service_deploy::deploy_service(headers, State(state.clone()), Json(spec)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{}", body.0);
        assert!(body.0["error"].as_str().unwrap().contains("retained-workspace"));
        service_deploy::wait_for_test_lifecycle_rollback(database,"ci").await?;
        for table in ["service_deployment_states", "service_discovery_sets", "service_deployment_runs"] {
            assert!(database.query_one(Statement::from_string(DbBackend::Postgres,
                format!("SELECT 1 FROM {table} WHERE service_id='ci'"))).await?.is_none());
        }
        let mut changed = r.clone(); changed.binary_sha256 = "d".repeat(64);
        assert!(register(&state, &changed).await.is_err());
        service_deploy::wait_for_test_lifecycle_rollback(database,"ci").await?;
        super::super::application_update::test_durable_updates(&state).await.context("legacy application update scenario")?;
        super::super::application_update::test_regional_updates(&state).await.context("regional application update scenario")?;
        task.abort();
        Ok(())
    }
}
