//! Correlated systemd host self-update through app-lb, never shell/SSH.
use crate::{bus::JobMessage, dispatch::Dispatcher, secrets::Masker, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::BTreeMap, time::Duration};

#[path = "../../app-lb/src/host_bundle.rs"]
pub(crate) mod bundle;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub repository: String, pub url: String, pub deployment: String, pub namespace: String, pub health_url: String,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Intent { target: Target, request: Value, store: String }

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20)).build()?)
}

async fn fetch_bundle(store: &str, digest: &str, size: u64) -> Result<Vec<u8>> {
    ensure!(bundle::valid_sha(digest,64) && size <= bundle::LIMIT, "invalid validated artifact metadata");
    crate::cd::app_lb_endpoint(store).map_err(anyhow::Error::msg)?;
    ensure!(store.starts_with("https://") || cfg!(test) && store.starts_with("http://127.0.0.1:"), "artifact store requires HTTPS");
    // This action deliberately requires the public blob. Do not reuse the
    // legacy authenticated, unbounded artifact downloader for host executables.
    let mut response = client()?.get(format!("{}/blobs/{digest}",store.trim_end_matches('/'))).send().await?;
    ensure!(response.status().is_success(), "public artifact download refused; redirects forbidden");
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len() as u64 + chunk.len() as u64 <= size, "artifact exceeds validated size");
        bytes.extend_from_slice(&chunk);
    }
    ensure!(bytes.len() as u64 == size && bundle::sha(&bytes) == digest, "validated artifact size/digest mismatch");
    Ok(bytes)
}

pub(crate) fn mapping(raw: Option<&str>, alias: &str) -> Result<Target> {
    let targets: BTreeMap<String, Target> = serde_json::from_str(raw.ok_or_else(|| anyhow::anyhow!("CI_HOST_APP_LB_TARGETS is not configured"))?)?;
    let target = targets.get(alias).ok_or_else(|| anyhow::anyhow!("unknown host app-lb target"))?.clone();
    crate::cd::app_lb_endpoint(&target.url).map_err(anyhow::Error::msg)?;
    crate::cd::app_lb_endpoint(&target.health_url).map_err(anyhow::Error::msg)?;
    ensure!([&target.url, &target.health_url].iter().all(|s| s.starts_with("https://") || cfg!(test) && s.starts_with("http://127.0.0.1:")),
        "host rollout requires HTTPS");
    ensure!(!target.repository.is_empty() && !target.namespace.is_empty() && !target.deployment.is_empty()
        && target.deployment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "invalid host mapping identity");
    Ok(target)
}

pub(crate) async fn trusted(d: &Dispatcher, alias: &str) -> Result<Target> {
    let managed;
    let raw = match d.config.host_app_lb_targets.as_deref() {
        Some(raw) => raw,
        None => {
            managed = d.secrets.host_app_lb_targets().await?;
            managed.as_str()
        }
    };
    mapping(Some(raw), alias)
}

pub async fn deploy(d: &Dispatcher, msg: &JobMessage, plan: &crate::plan::JobPlan, step: &str, alias: &str, token: &str,
    workflow: &str, artifact: &str, timeout: Duration, masker: &Masker) -> Result<String> {
    crate::submission::authorize_publication(&d.store, &msg.run_id).await.map_err(anyhow::Error::msg)?;
    ensure!(!token.trim().is_empty(), "host rollout requires a credential");
    let target = trusted(d, alias).await?;
    if let Some(policy) = &plan.release_policy {
        ensure!(policy.app_lbs.get(alias) == Some(&target), "app-lb target changed since release admission");
    }
    let run = d.store.get_run(&msg.run_id).await?.ok_or_else(|| anyhow::anyhow!("missing run"))?;
    ensure!(crate::repos::same_repo(&target.repository, &run.repo_url), "repository is not authorized for this host");
    let (release_sha, git_ref) = crate::release::deployment_source(&d.store, &msg.run_id).await.map_err(anyhow::Error::msg)?;
    ensure!(release_sha == run.sha, "artifact must match exact merged revision");
    let artifact = crate::submission::artifact(&d.store, &msg.run_id, workflow, artifact, None).await.map_err(anyhow::Error::msg)?;
    ensure!(artifact.sink == "artifacts" && artifact.size_bytes <= bundle::LIMIT, "host rollout requires a bounded HTTP artifact");
    let blob = artifact.digest.as_ref().ok_or_else(|| anyhow::anyhow!("missing artifact digest"))?;
    let store = d.config.artifacts.as_ref().ok_or_else(|| anyhow::anyhow!("missing artifact store"))?.url.trim_end_matches('/').to_string();
    let id = format!("ci-host-{}", bundle::sha(step.as_bytes()));
    let existing: Option<Value> = sqlx::query_scalar("SELECT intent FROM ci_host_app_lb WHERE id=$1").bind(&id).fetch_optional(d.store.pool()).await?;
    let intent: Intent = if let Some(value) = existing {
        let saved: Intent = serde_json::from_value(value)?;
        ensure!(saved.target == target && saved.store == store && saved.request["artifact_sha256"] == *blob
            && saved.request["revision"] == run.sha, "host rollout inputs changed on replay");
        saved
    } else {
        let bytes = fetch_bundle(&store,blob,artifact.size_bytes).await?;
        let binary = bundle::executable(&bytes, &run.sha).map_err(anyhow::Error::msg)?;
        let endpoint = format!("{}/deployments/{}/update/rollouts", target.url.trim_end_matches('/'), target.deployment);
        let response = client()?.get(endpoint).bearer_auth(token).send().await?;
        ensure!(response.status().is_success(), "host lacks correlated update support");
        let snapshot: Value = response.json().await?;
        ensure!(snapshot["protocol"] == "host-app-lb-v1" && snapshot["deployment"] == target.deployment && snapshot["namespace"] == target.namespace
            && snapshot["artifact_store"].as_str().map(|s| s.trim_end_matches('/')) == Some(store.as_str()) && snapshot["health_url"] == target.health_url,
            "host mapping identity differs from trusted CI mapping");
        let intent = Intent { target, store, request: json!({"operation_id":id,"artifact_sha256":blob,"binary_sha256":bundle::sha(&binary),
            "revision":run.sha,"expected_binary_sha256":snapshot["binary_sha256"],"expected_config_sha256":snapshot["config_sha256"]}) };
        let value = serde_json::to_value(&intent)?;
        let mut tx = d.store.pool().begin().await?;
        eligible(&mut tx, msg).await?;
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES($1,$2,$3,$4,$5,$6,'submitting',$7,$8) ON CONFLICT(step_id) DO NOTHING")
            .bind(&id).bind(step).bind(&msg.run_id).bind(&msg.job_id).bind(&intent.target.deployment).bind(bundle::sha(&serde_json::to_vec(&value)?))
            .bind(&run.sha).bind(&git_ref).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO ci_host_app_lb(id,intent,deadline) VALUES($1,$2,now()+make_interval(secs=>$3)) ON CONFLICT(id) DO NOTHING")
            .bind(&id).bind(&value).bind(timeout.min(d.config.max_job_duration).as_secs() as f64).execute(&mut *tx).await?;
        let saved: Value = sqlx::query_scalar("SELECT intent FROM ci_host_app_lb WHERE id=$1").bind(&id).fetch_one(&mut *tx).await?;
        ensure!(saved == value, "concurrent host rollout differs");
        Store::add_service_deployment_event(&mut tx, &id).await?;
        tx.commit().await?;
        intent
    };
    reconcile(&d.store, msg, &id, &intent, token, masker).await
}

async fn eligible(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, msg: &JobMessage) -> Result<()> {
    let run: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE").bind(&msg.run_id).fetch_one(&mut **tx).await?;
    let job: String = sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1 FOR UPDATE").bind(&msg.job_id).fetch_one(&mut **tx).await?;
    ensure!(!matches!(run.as_str(), "cancelled" | "failure") && job == "running", "CI stopped waiting; remote update may continue");
    Ok(())
}

fn verify(value: &Value, intent: &Intent) -> Result<bool> {
    ensure!(value["request"] == intent.request && value["deployment"] == intent.target.deployment && value["namespace"] == intent.target.namespace,
        "host operation identity mismatch");
    match value["status"].as_str() {
        Some("running") => Ok(false),
        Some("succeeded") => { ensure!(value["readiness_verified"] == true && value["phase"] == "complete", "host did not verify exact replacement"); Ok(true) }
        _ => anyhow::bail!("host update requires operator reconciliation"),
    }
}

async fn reconcile(store: &Store, msg: &JobMessage, id: &str, intent: &Intent, token: &str, masker: &Masker) -> Result<String> {
    let endpoint = format!("{}/deployments/{}/update/rollouts", intent.target.url.trim_end_matches('/'), intent.target.deployment);
    let http = client()?;
    loop {
        let row = sqlx::query("SELECT h.deadline,d.status FROM ci_host_app_lb h JOIN ci_service_deployment d ON d.id=h.id WHERE h.id=$1")
            .bind(id).fetch_one(store.pool()).await?;
        let deadline = row.get::<chrono::DateTime<chrono::Utc>,_>("deadline");
        if row.get::<String,_>("status") == "passed" { return Ok(format!("[ci] host app-lb operation {id} verified at {}\n", intent.request["revision"])); }
        ensure!(row.get::<String,_>("status") != "failed", "host rollout failed; reconcile operation {id}");
        ensure!(deadline > chrono::Utc::now() && !store.is_job_cancelled(&msg.job_id).await?, "CI stopped waiting; reconcile remote operation {id}");
        let attempt: Result<bool> = async {
            let response = http.get(format!("{endpoint}/{id}")).bearer_auth(token).send().await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                // Locks serialize cancellation against admission. Lost response
                // rolls back only CI locks, never forgets the persisted intent.
                let mut tx = store.pool().begin().await?;
                eligible(&mut tx, msg).await?;
                ensure!(deadline > chrono::Utc::now(), "rollout deadline elapsed");
                let response = http.post(&endpoint).bearer_auth(token).json(&intent.request).send().await?;
                ensure!(!response.status().is_client_error() && !response.status().is_redirection(), "host refused correlated update");
                tx.commit().await?;
                return Ok(false);
            }
            ensure!(!response.status().is_client_error() && !response.status().is_redirection(), "host refused operation lookup");
            if !response.status().is_success() { return Ok(false); }
            if !verify(&response.json::<Value>().await?, intent)? { return Ok(false); }
            let health = http.get(&intent.target.health_url).send().await?;
            ensure!(health.status().is_success() && health.headers().get_all("x-heyo-revision").iter().count() == 1
                && health.headers().get("x-heyo-revision").and_then(|v| v.to_str().ok()) == intent.request["revision"].as_str(),
                "public health does not report exact intended build");
            Ok(true)
        }.await;
        match attempt {
            Ok(true) => {
                let mut tx = store.pool().begin().await?;
                eligible(&mut tx, msg).await?;
                ensure!(deadline > chrono::Utc::now(), "rollout deadline elapsed");
                let changed = sqlx::query("UPDATE ci_service_deployment SET status='passed',phase='complete',message='Exact host executable and public build verified.',updated_at=now() WHERE id=$1 AND status NOT IN ('passed','failed')")
                    .bind(id).execute(&mut *tx).await?.rows_affected();
                if changed == 1 { Store::add_service_deployment_event(&mut tx, id).await?; }
                tx.commit().await?;
            }
            Ok(false) => {}
            Err(e) if e.is::<reqwest::Error>() => {} // restart/lost response: GET same ID again
            Err(e) => {
                store.update_service_deployment(id, "failed", Some("reconciliation"), None, Some(&masker.mask(&e.to_string()).replace(token,"***"))).await?;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::State, routing::{get,post}, Json, http::StatusCode, response::IntoResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn host_rollout_identity_mapping_and_validation_gate_are_strict() {
        assert!(mapping(None,"eu1").is_err());
        let raw = json!({"eu1":{"repository":"https://repo.test/source.git","url":"https://admin.test","deployment":"host",
            "namespace":"default","health_url":"https://admin.test/healthz"}}).to_string();
        let target = mapping(Some(&raw),"eu1").unwrap();
        assert!(mapping(Some(&raw),"us3").is_err());
        let intent = Intent {target,store:"https://art.test".into(),request:json!({"operation_id":"id","revision":"a".repeat(40)})};
        let mut reply = json!({"request":intent.request,"deployment":"host","namespace":"default","status":"succeeded","phase":"complete","readiness_verified":true});
        assert!(verify(&reply,&intent).unwrap());
        reply["request"]["revision"] = json!("b".repeat(40)); assert!(verify(&reply,&intent).is_err());
        reply["request"] = intent.request.clone(); reply["readiness_verified"] = json!(false); assert!(verify(&reply,&intent).is_err());
        let plan = crate::plan::Plan::build(&crate::workflow::Workflow::parse("check.yml","jobs:\n  build:\n    steps: [{uses: ci/rollout-host-app-lb}]\n").unwrap()).unwrap();
        assert!(crate::submission::validate_validation_plan(&plan).is_err());
        for yaml in ["jobs:\n  deploy:\n    continue-on-error: true\n    steps: [{uses: ci/rollout-host-app-lb}]\n",
            "jobs:\n  deploy:\n    steps: [{uses: ci/rollout-host-app-lb, continue-on-error: true}]\n"] {
            assert!(crate::plan::Plan::build(&crate::workflow::Workflow::parse("host.yml",yaml).unwrap()).is_err());
        }
    }

    #[tokio::test]
    async fn host_artifact_download_is_bounded_pinned_and_never_redirects() {
        let mode = Arc::new(Mutex::new(false));
        let app = Router::new().route("/blobs/{digest}",get(|State(redirect):State<Arc<Mutex<bool>>>,headers:axum::http::HeaderMap| async move {
            assert!(!headers.contains_key("authorization"));
            if *redirect.lock().unwrap() { (StatusCode::TEMPORARY_REDIRECT,[("location","/unexpected")]).into_response() }
            else { b"exact blob".to_vec().into_response() }
        })).route("/unexpected",get(|| async { b"exact blob".to_vec() })).with_state(mode.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}",listener.local_addr().unwrap());
        let server = tokio::spawn(async move {axum::serve(listener,app).await.unwrap();});
        let digest = bundle::sha(b"exact blob");
        assert_eq!(fetch_bundle(&base,&digest,10).await.unwrap(),b"exact blob");
        assert!(fetch_bundle(&base,&digest,9).await.is_err());
        assert!(fetch_bundle(&base,&"a".repeat(64),10).await.is_err());
        assert!(fetch_bundle(&base,"../escape",10).await.is_err());
        *mode.lock().unwrap() = true;
        assert!(fetch_bundle(&base,&digest,10).await.is_err());
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires disposable CI_TEST_DATABASE_URL"]
    async fn host_rollout_postgres_http_restart_cancellation_and_exact_success() {
        #[derive(Default)]
        struct Remote { mode: String, request: Option<Value>, posts: usize, installs: usize }
        let workspace = tempfile::tempdir().unwrap();
        let database = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let store = Store::connect(&database,workspace.path().into(),Duration::from_secs(30)).await.unwrap();
        store.migrate().await.unwrap();
        let plan = crate::plan::Plan::build(&crate::workflow::Workflow::parse("host.yml","jobs:\n  deploy:\n    steps: [{uses: ci/rollout-host-app-lb}]\n").unwrap()).unwrap();
        for mode in ["success","lost","concurrent","wrong-identity","wrong-header","missing-header","non-2xx","failed","redirect","cancelled","cancel-late","expired"] {
            let run = crate::vm::new_id();
            store.create_run(&run,&crate::store::RunRequest {repo_url:"https://repo.test/source.git".into(),git_ref:"refs/heads/main".into(),sha:"a".repeat(40),..Default::default()},&plan).await.unwrap();
            let job = store.jobs_of(&run).await.unwrap().remove(0);
            store.set_job_status(&job.id,crate::store::JobStatus::Running,None).await.unwrap();
            let step = crate::store::step_id(&job.id,0);
            store.create_step(&step,&job.id,0,"Host",Some("ci/rollout-host-app-lb")).await.unwrap();
            let msg = JobMessage {run_id:run.clone(),job_id:job.id.clone(),job_key:job.job_key.clone()};
            let remote = Arc::new(Mutex::new(Remote {mode:mode.into(),..Default::default()}));
            let cancellation_store = store.clone(); let cancellation_run = run.clone();
            let app = Router::new()
                .route("/deployments/host/update/rollouts",post(|State(remote):State<Arc<Mutex<Remote>>>,Json(body):Json<Value>| async move {
                    let mut r = remote.lock().unwrap(); r.posts += 1;
                    if let Some(old) = &r.request { if old != &body { return StatusCode::CONFLICT.into_response(); } }
                    else { r.request = Some(body.clone()); r.installs += 1; }
                    if r.mode == "lost" { StatusCode::INTERNAL_SERVER_ERROR.into_response() } else { Json(body).into_response() }
                }))
                .route("/deployments/host/update/rollouts/{id}",get(|State(remote):State<Arc<Mutex<Remote>>>| async move {
                    let r = remote.lock().unwrap();
                    if r.mode == "redirect" { return (StatusCode::TEMPORARY_REDIRECT,[("location","/unexpected")]).into_response(); }
                    let Some(request) = &r.request else { return StatusCode::NOT_FOUND.into_response(); };
                    let mut result = json!({"request":request,"deployment":"host","namespace":"default","status":"succeeded","phase":"complete","readiness_verified":true});
                    if r.mode == "wrong-identity" { result["request"]["binary_sha256"] = json!("wrong"); }
                    if r.mode == "failed" { result["status"] = json!("reconciliation_required"); }
                    Json(result).into_response()
                }))
                .route("/healthz",get(move |State(remote):State<Arc<Mutex<Remote>>>| {
                    let store = cancellation_store.clone(); let run = cancellation_run.clone();
                    async move {
                        let mode = remote.lock().unwrap().mode.clone();
                        if mode == "cancel-late" { store.cancel_run(&run).await.unwrap(); }
                        if mode == "missing-header" { return "ok".into_response(); }
                        let value = if mode == "wrong-header" {"b".repeat(40)} else {"a".repeat(40)};
                        (if mode == "non-2xx" {StatusCode::INTERNAL_SERVER_ERROR} else {StatusCode::OK},[("x-heyo-revision",value)],"ok").into_response()
                    }
                })).with_state(remote.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}",listener.local_addr().unwrap());
            let server = tokio::spawn(async move {axum::serve(listener,app).await.unwrap();});
            let id = format!("ci-host-{run}");
            let intent = Intent {target:Target {repository:"https://repo.test/source.git".into(),url:base.clone(),deployment:"host".into(),namespace:"default".into(),health_url:format!("{base}/healthz")},store:"https://art.test".into(),
                request:json!({"operation_id":id,"revision":"a".repeat(40),"binary_sha256":"b".repeat(64),"artifact_sha256":"c".repeat(64),"expected_binary_sha256":"d".repeat(64),"expected_config_sha256":"e".repeat(64)})};
            store.begin_service_deployment(&id,&step,"host","hash").await.unwrap();
            sqlx::query("INSERT INTO ci_host_app_lb(id,intent,deadline) VALUES($1,$2,now()+interval '30 seconds')")
                .bind(&id).bind(serde_json::to_value(&intent).unwrap()).execute(store.pool()).await.unwrap();
            if mode == "cancelled" {store.cancel_run(&run).await.unwrap();}
            if mode == "expired" {sqlx::query("UPDATE ci_host_app_lb SET deadline=now()-interval '1 second' WHERE id=$1").bind(&id).execute(store.pool()).await.unwrap();}
            let masker = Masker::new(["token"].into_iter());
            if mode == "lost" {
                assert!(tokio::time::timeout(Duration::from_millis(300),reconcile(&store,&msg,&id,&intent,"token",&masker)).await.is_err());
                assert_eq!(remote.lock().unwrap().installs,1);
            }
            let restarted = Store::connect(&database,workspace.path().into(),Duration::from_secs(30)).await.unwrap();
            let result = if mode == "concurrent" {
                let (a,b) = tokio::join!(reconcile(&restarted,&msg,&id,&intent,"token",&masker),reconcile(&restarted,&msg,&id,&intent,"token",&masker));
                assert!(a.is_ok()); b
            } else { reconcile(&restarted,&msg,&id,&intent,"token",&masker).await };
            let success = matches!(mode,"success"|"lost"|"concurrent");
            assert_eq!(result.is_ok(),success,"{mode}: {result:?}");
            assert_eq!(store.service_deployments_of(&run).await.unwrap()[0].status == "passed",success,"{mode}");
            let r = remote.lock().unwrap();
            assert!(r.installs <= 1,"{mode}: duplicate install");
            if matches!(mode,"cancelled"|"expired"|"redirect") { assert_eq!(r.posts,0); }
            if mode == "lost" { assert_eq!(r.posts,1,"GET reconciles lost acknowledgment without POST replay"); }
            server.abort();
        }
    }
}
