//! Disposable PostgreSQL + two actual Pingora processes + authenticated reports.
use super::{regional_admission, regional_policy, regional_reports, regional_rollout, service_discovery};
use anyhow::{Context, Result};
use axum::{Router, Json, extract::{State, Query}, http::{HeaderMap, StatusCode}, routing::{get, post}};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration, path::{Path, PathBuf}};

struct Proxies(Vec<std::process::Child>);
impl Drop for Proxies {
    fn drop(&mut self) { for child in &mut self.0 { let _ = child.kill(); let _ = child.wait(); } }
}

fn free_port() -> u16 { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

fn forwarding_children(parent: u32) -> Result<Vec<u32>> {
    let mut children = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{parent}/task"))? {
        let path = task?.path().join("children");
        let Ok(contents) = std::fs::read_to_string(path) else { continue; };
        for pid in contents.split_whitespace() {
            let pid: u32 = pid.parse()?;
            let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if cmd.split(|b| *b == 0).any(|arg| arg == b"--forwarding-worker") { children.push(pid); }
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

fn openssl(root: &Path, args: &[&str]) {
    let output = std::process::Command::new("openssl").args(args).current_dir(root).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

async fn phase(db: &sea_orm::DatabaseConnection, operation: &str) -> Result<String> {
    Ok(db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT phase FROM regional_service_rollouts WHERE operation_id=$1", [operation.into()])).await?
        .context("missing operation")?.try_get("", "phase")?)
}

async fn reach(state: &crate::AppState, db: &sea_orm::DatabaseConnection, operation: &str, expected: &str) -> Result<()> {
    let mut last = String::new();
    for _ in 0..200 {
        if phase(db, operation).await? == expected { return Ok(()); }
        if let Err(error) = regional_rollout::tick_in(state, db, operation).await { last = format!("{error:#}"); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("did not reach {expected}: phase={} last error={last}", phase(db, operation).await?)
}

// Exercise the production v3 dispatcher. Cloud is a fixture, not a complete VM
// lifecycle acceptance test.
async fn reach_application_policy(state: &crate::AppState, db: &sea_orm::DatabaseConnection,
    operation: &str, expected: &str) -> Result<()> {
    let mut last = String::new();
    // A complete rollback crosses several distinct five-second discovery polls,
    // unlike a single policy gate. Each product phase keeps its own timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    while std::time::Instant::now() < deadline {
        if phase(db,operation).await? == expected { return Ok(()); }
        if let Err(error) = regional_rollout::tick_in(state,db,operation).await { last = format!("{error:#}"); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("application policy did not reach {expected}: phase={} last error={last}",phase(db,operation).await?)
}

async fn preflight_ready(state: &crate::AppState, db: &sea_orm::DatabaseConnection, operation: &str) -> Result<()> {
    let mut last=String::new();
    for _ in 0..100 {
        match super::regional_application::preflight(state,db,"smoke",operation).await {
            Ok(true)=>return Ok(()), Ok(false)=>{}, Err(error)=>last=format!("{error:#}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("preflight did not complete: {last}")
}

async fn probe_ready(state: &crate::AppState, db: &sea_orm::DatabaseConnection,
    operation: &str, deployment: &str, revision: &str) -> Result<Vec<Value>> {
    let mut last = String::new();
    for _ in 0..100 {
        match super::regional_observers::probe_candidate(state,db,"smoke",operation,deployment,revision).await {
            Ok(receipts) => return Ok(receipts),
            Err(error) => last=format!("{error:#}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("probe of {deployment} at {revision} did not become ready: {last}")
}

async fn draft(db: &sea_orm::DatabaseConnection, operation: &str,
    policy: &regional_policy::RegionalPolicy, target: Option<&str>, predecessor: Option<i64>) -> Result<regional_admission::Request> {
    let version: i64 = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT version FROM service_discovery_sets WHERE service_id='smoke'")).await?.unwrap().try_get("","version")?;
    let version = regional_policy::store(db,"smoke",&regional_policy::PutPolicy {
        expected_version:version.try_into()?,policy:Some(policy.clone()) }).await?.context("draft update conflicted")?;
    Ok(regional_admission::Request {operation_id:operation.into(),service_id:"smoke".into(),environment:"test".into(),
        namespace:"default".into(),host:"smoke.example".into(),expected_version:version.try_into()?,
        expected_predecessor:predecessor,withdraw_region:target.map(str::to_owned)})
}

async fn publish(state: &crate::AppState, db: &sea_orm::DatabaseConnection, operation: &str,
    policy: &regional_policy::RegionalPolicy, target: Option<&str>, predecessor: Option<i64>) -> Result<regional_admission::Request> {
    let request = draft(db,operation,policy,target,predecessor).await?;
    assert!(regional_admission::admit(state,db,&request).await?.created);
    Ok(request)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires disposable ORCHESTRATOR_TEST_DATABASE_URL and APP_LB_TEST_BINARY built with reqwest/rustls-tls-native-roots"]
async fn two_real_gateways_drain_through_authenticated_durable_barriers() -> Result<()> {
    // Keep this whole-path scenario off the test thread's small stack. It owns
    // several HTTP servers and controllers across many injected-failure awaits.
    Box::pin(two_real_gateways_scenario()).await
}

async fn two_real_gateways_scenario() -> Result<()> {
    let binary = std::env::var("APP_LB_TEST_BINARY").context("build app-lb and set APP_LB_TEST_BINARY")?;
    let db_url = std::env::var("ORCHESTRATOR_TEST_DATABASE_URL")?;
    let root_db = sea_orm::Database::connect(db_url.clone()).await?;
    let schema = format!("regional_live_{}", uuid::Uuid::new_v4().simple());
    root_db.execute_unprepared(&format!("CREATE SCHEMA {schema}")).await?;
    let mut options = sea_orm::ConnectOptions::new(db_url);
    options.set_schema_search_path(schema.clone());
    let db = sea_orm::Database::connect(options.clone()).await?;
    for migration in [include_str!("../../migrations/028_add_service_deployment_state.sql"),
        include_str!("../../migrations/030_add_service_deployment_runs.sql"),
        include_str!("../../migrations/031_add_service_discovery.sql"), include_str!("../../migrations/032_add_service_rollout_state.sql"),
        include_str!("../../migrations/033_add_service_replica_placement.sql"), include_str!("../../migrations/035_add_regional_service_rollouts.sql"),
        include_str!("../../migrations/034_cancel_reactivated_service_retirements.sql"),
        include_str!("../../migrations/036_add_service_deployment_environment.sql"),
        include_str!("../../migrations/037_add_regional_routing_policy.sql"), include_str!("../../migrations/038_add_regional_policy_proposals.sql"),
        include_str!("../../migrations/039_add_regional_candidate_receipts.sql"), include_str!("../../migrations/040_add_application_plan_journal.sql"),
        include_str!("../../migrations/041_add_application_probe_claims.sql"), include_str!("../../migrations/041_add_application_probe_claims.sql"),
        include_str!("../../migrations/042_add_external_service_bindings.sql"),
        include_str!("../../migrations/043_application_updates.sql"),
        include_str!("../../migrations/044_regional_lifecycle_barriers.sql"),
        include_str!("../../migrations/045_service_creation_recipes.sql")] {
        db.execute_unprepared(migration).await?;
    }
    db.execute_unprepared("INSERT INTO service_discovery_sets(service_id) VALUES('smoke')").await?;
    db.execute_unprepared("INSERT INTO service_deployment_states(service_id,deployment_environment) VALUES('smoke','test')").await?;
    let root: PathBuf = std::env::temp_dir().join(&schema);
    std::fs::create_dir_all(&root)?;
    println!("fixture logs: {}", root.display());
    std::fs::write(root.join("extensions"), "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")?;
    openssl(&root, &["req","-x509","-newkey","rsa:2048","-nodes","-keyout","ca-key.pem","-out","ca.pem","-days","1","-subj","/CN=Disposable test CA","-addext","basicConstraints=critical,CA:TRUE"]);
    openssl(&root, &["req","-new","-newkey","rsa:2048","-nodes","-keyout","key.pem","-out","leaf.csr","-subj","/CN=localhost"]);
    openssl(&root, &["x509","-req","-in","leaf.csr","-CA","ca.pem","-CAkey","ca-key.pem","-CAcreateserial","-out","cert.pem","-days","1","-extfile","extensions"]);
    let token_id = "0123456789ab";
    let token = format!("applb_{token_id}_disposable");
    let authority_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let authority = format!("http://{}", authority_listener.local_addr()?);
    let secret_token = token.clone();
    let cloud_receipt = Arc::new(tokio::sync::Mutex::new(Value::Null));
    let recovery_receipt = cloud_receipt.clone();
    let create_count = Arc::new(AtomicUsize::new(0));
    let cloud_creates = create_count.clone();
    let archive_drift = Arc::new(AtomicUsize::new(0));
    let drift_on_download = archive_drift.clone();
    let discovery_unavailable = Arc::new(AtomicUsize::new(0));
    let discovery_failure = discovery_unavailable.clone();
    let control = Router::new().route("/snapshot", get(move |State(db): State<sea_orm::DatabaseConnection>, headers: HeaderMap,
        Query(query): Query<service_discovery::DiscoveryQuery>| {
        let discovery_failure = discovery_failure.clone();
        async move {
        if headers.get("authorization").is_none_or(|v| v != "Bearer discovery-test") { return (StatusCode::UNAUTHORIZED, Json(json!({}))); }
        if discovery_failure.load(Ordering::SeqCst) != 0 { return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({}))); }
        match service_discovery::read_regional_snapshot(&db, "smoke", query.region.as_deref().unwrap_or(""),
            query.gateway_id.as_deref().unwrap_or(""), query.boot_id.as_deref().unwrap_or("")).await {
            Ok(snapshot) => (StatusCode::OK, Json(snapshot)),
            Err(_) => (StatusCode::CONFLICT, Json(json!({"error":"unpublished or unpinned"}))),
        }
        }
    })).route("/v1/secrets/read", post(move |headers: HeaderMap| {
        let token = secret_token.clone();
        async move {
            use base64::Engine;
            assert_eq!(headers["authorization"], "Bearer secret-reader");
            Json(json!({"path":"test/observer","version":1,"status":"active","valueBase64":base64::engine::general_purpose::STANDARD.encode(token),
                "createdAt":"2026-09-21T00:00:00Z","metadata":{}}))
        }
    })).route("/internal/orchestration/archives/archive-a",get(move |State(db):State<sea_orm::DatabaseConnection>,headers:HeaderMap| {
        let drift = drift_on_download.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer secret-reader");
            if drift.swap(0,Ordering::SeqCst) == 1 {
                db.execute_unprepared("UPDATE service_discovery_sets SET version=version+1 WHERE service_id='smoke'").await.unwrap();
            }
            "fixture"
        }
    })).route("/internal/orchestration/deployments",post(move |headers:HeaderMap,Json(body):Json<Value>| {
        let count=cloud_creates.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer secret-reader");
            let region = match body["deploymentId"].as_str() {
                Some("new-eu-owned") => "eu1",
                Some(id) if id == regional_rollout::candidate_id("full-forward",1) => "eu1",
                Some(id) if id == regional_rollout::candidate_id("full-forward",0) => "us3",
                other => panic!("unexpected candidate: {other:?}"),
            };
            assert_eq!(body["allowedBackendServerIds"],json!([region]));
            assert_eq!(body["region"],region);
            assert_eq!(body["image"],"fixture-image");
            if body["deploymentId"] == "new-eu-owned" {
                assert!(body["archiveId"].is_null());
                assert_eq!(body["archiveBytesBase64"],"Zml4dHVyZQ==");
            } else {
                assert_eq!(body["archiveId"],"archive-a");
                assert_eq!(body["archiveBytesBase64"],"");
            }
            count.fetch_add(1,Ordering::SeqCst);
            StatusCode::BAD_GATEWAY // durable create happened, response was lost
        }
    })).route("/internal/orchestration/deployments/{id}",get(move |headers:HeaderMap| {
        let receipt=recovery_receipt.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer secret-reader");
            Json(receipt.lock().await.clone())
        }
    })).with_state(db.clone());
    let control_task = tokio::spawn(async move { axum::serve(authority_listener, control).await.unwrap(); });
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let hold_preflight=Arc::new(AtomicUsize::new(0));
    let preflight_entered=Arc::new(tokio::sync::Notify::new());
    let preflight_release=Arc::new(tokio::sync::Notify::new());
    let mut proxies = Proxies(Vec::new());
    let mut commands = Vec::new();
    let mut observers = Vec::new();
    let mut participants = Vec::new();
    let mut gateways = Vec::new();
    let mut proxy_ports = Vec::new();
    let mut app_tasks = Vec::new();
    let eu_admissions = Arc::new(AtomicUsize::new(0));
    let us_admissions = Arc::new(AtomicUsize::new(0));
    for region in ["eu1", "us3"] {
        let app_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let app_port = app_listener.local_addr()?.port();
        let (start, finish, admissions) = (entered.clone(), release.clone(), if region == "eu1" { eu_admissions.clone() } else { us_admissions.clone() });
        let (holding,pref_start,pref_finish)=(hold_preflight.clone(),preflight_entered.clone(),preflight_release.clone());
        let app = Router::new().fallback(get(move |headers: HeaderMap, uri: axum::http::Uri| {
            let (start, finish, admissions) = (start.clone(), finish.clone(), admissions.clone());
            let (holding,pref_start,pref_finish)=(holding.clone(),pref_start.clone(),pref_finish.clone());
            async move {
                if uri.path() != "/health" {
                    assert_eq!(headers["host"], "smoke.example");
                    assert_eq!(headers["authorization"], "Bearer application-value");
                    assert!(!headers.keys().any(|h| h.as_str().starts_with("x-heyo-peer")));
                    admissions.fetch_add(1, Ordering::SeqCst);
                }
                let held = uri.path() == "/held";
                let preflight_held=region == "us3" && uri.path() == "/health" && headers.get("host").is_some_and(|h| h == "smoke.example")
                    && holding.compare_exchange(1,0,Ordering::SeqCst,Ordering::SeqCst).is_ok();
                if held { start.notify_one(); }
                if preflight_held {pref_start.notify_one();}
                ([("x-heyo-revision","fixture-v1")], axum::body::Body::from_stream(futures::stream::once(async move {
                    if held { finish.notified().await; }
                    if preflight_held {pref_finish.notified().await;}
                    Ok::<_, std::io::Error>(format!("{region}:fixture-v1"))
                })))
            }
        }));
        app_tasks.push(tokio::spawn(async move { axum::serve(app_listener, app).await.unwrap(); }));
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO service_discovery_endpoints(service_id,deployment_id,backend_server_id,region,revision,backend_url,health_status)
             VALUES('smoke',$1,$1,$1,'fixture-v1',$2,'healthy')", vec![region.into(), format!("http://127.0.0.1:{app_port}").into()])).await?;
        let directory = root.join(region);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(directory.join("tokens.json"), serde_json::to_vec(&json!({"version":1,"tokens":[{
            "id":token_id,"name":"fixture","admin":"admin","deployments":["*"],"created_at":0,
            "secret_sha256":format!("{:x}",Sha256::digest(b"disposable"))}]}))?)?;
        let (proxy, admin, tls) = (free_port(), free_port(), free_port());
        let mut command = std::process::Command::new(&binary);
        for (key, _) in std::env::vars().filter(|(k,_)| k.starts_with("APP_LB_")) { command.env_remove(key); }
        let log = std::fs::File::create(directory.join("log"))?;
        command.current_dir(&directory).stdout(log.try_clone()?).stderr(log)
            .env("APP_LB_PROXY_ADDR",format!("127.0.0.1:{proxy}")).env("APP_LB_ADMIN_ADDR",format!("127.0.0.1:{admin}"))
            .env("APP_LB_PROXY_TLS_ADDR",format!("[::1]:{tls}")).env("APP_LB_TLS_CERT",root.join("cert.pem")).env("APP_LB_TLS_KEY",root.join("key.pem"))
            .env("APP_LB_INSTANCE_LOCK",directory.join("instance.lock"))
            .env("SSL_CERT_FILE",root.join("ca.pem")).env("APP_LB_SIEM","0").env("APP_LB_DAEMON_URL","http://127.0.0.1:9")
            .env("APP_LB_ADMIN_AUTH","1").env("APP_LB_DASHBOARD_PASSWORD","unused-fixture-password").env("APP_LB_TOKENS_PATH",directory.join("tokens.json"));
        for (key, name) in [("MOUNTS","mounts"),("WORKSPACES","workspaces"),("IMAGES","images"),("BUILD","build")] {
            command.env(format!("APP_LB_{key}_DIR"), directory.join(name));
        }
        proxies.0.push(command.spawn()?);
        commands.push(command);
        let base = format!("http://127.0.0.1:{admin}");
        for attempt in 0..100 {
            if client.get(format!("{base}/healthz")).send().await.is_ok() { break; }
            let exited = proxies.0.last_mut().unwrap().try_wait()?;
            if exited.is_some() || attempt == 99 {
                let log = std::fs::read_to_string(directory.join("log"))?;
                anyhow::bail!("gateway startup failed (exit={exited:?}):\n{log}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for (id, value) in [("peer","peer-test"),("reader","discovery-test")] {
            client.post(format!("{base}/secrets")).bearer_auth(&token).json(&json!({"id":id,"data":{"token":value}})).send().await?.error_for_status()?;
        }
        observers.push(json!({"service_id":"smoke","region":region,"gateway_id":region,"deployment_id":"smoke","base_url":base,
            "discovery_url":format!("{authority}/snapshot?region={region}"),"token_secret_path":"test/observer",
            "discovery_token_secret":"reader","regional_peer_token_secret":"peer"}));
        gateways.push(regional_policy::Region { region:region.into(),weight:if region=="eu1" {1} else {0},gateways:vec![regional_policy::Gateway {
            id:region.into(),backend_server_id:region.into(),url:format!("https://localhost:{tls}") }] });
        proxy_ports.push(proxy);
    }
    let config = serde_json::from_value(json!({"server_port":0,"database_url":"unused","agent_provider":"test","agent_model":"test","agent_api_key":"",
        "agent_timeout_seconds":1,"agent_max_iterations":1,"jwt_secret":"test","cloud_internal_url":authority,"internal_api_key":"secret-reader",
        "heyosecret_url":authority,"discovery_observers":observers,"discovery_routed_services":"smoke"}))?;
    let state = crate::AppState { config:Arc::new(config),http_client:client.clone(),worker_id:Arc::new("fixture".into()),ci_workspace_cache:Default::default() };
    let mut policy = regional_policy::RegionalPolicy {version:1,regions:gateways};
    let initial = draft(&db,"initial",&policy,None,None).await?;
    let first_status = format!("{}/deployments/smoke/discovery-status",state.config.discovery_observers[0].base_url);
    let mut incomplete = state.clone();
    Arc::make_mut(&mut incomplete.config).discovery_observers[1].regional_peer_token_secret = None;
    assert!(regional_admission::enroll_cold_fleet(&incomplete,&db,&initial,"/health").await.is_err());
    assert_eq!(client.get(&first_status).bearer_auth(&token).send().await?.status(),StatusCode::NOT_FOUND);
    let mut partial = state.clone();
    Arc::make_mut(&mut partial.config).discovery_observers[1].base_url = "http://127.0.0.1:9".into();
    assert!(regional_admission::enroll_cold_fleet(&partial,&db,&initial,"/health").await.is_err());
    let before: Value = client.get(&first_status).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
    regional_admission::enroll_cold_fleet(&state,&db,&initial,"/health").await?;
    regional_admission::enroll_cold_fleet(&state,&db,&initial,"/health").await?;
    assert!(regional_admission::enroll_cold_fleet(&state,&db,&initial,"/different-health").await.unwrap_err().to_string().contains("refusing replacement"));
    let after: Value = client.get(&first_status).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
    assert_eq!(before["regional"]["bootId"],after["regional"]["bootId"]);
    Arc::make_mut(&mut incomplete.config).discovery_observers[1].regional_peer_token_secret = Some("other-peer".into());
    assert!(regional_admission::enroll_cold_fleet(&incomplete,&db,&initial,"/health").await.unwrap_err().to_string().contains("refusing replacement"));
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,"SELECT 1 FROM regional_policy_proposals")).await?.is_none());
    for (observer,port) in state.config.discovery_observers.iter().zip(&proxy_ports) {
        let url = format!("{}/deployments/smoke/discovery-status",observer.base_url);
        let status: Value = client.get(&url).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
        assert!(status["regional"]["report"].is_null());
        assert_eq!(client.get(&url).send().await?.status(),StatusCode::UNAUTHORIZED);
        assert_eq!(client.get(format!("http://127.0.0.1:{port}/cold")).header("host","smoke.example").send().await?.status(),StatusCode::SERVICE_UNAVAILABLE);
        participants.push(regional_reports::Participant {gateway_id:observer.gateway_id.clone().unwrap(),region:observer.region.clone(),
            boot_id:status["regional"]["bootId"].as_str().context("boot ID absent")?.into()});
    }
    let mut unavailable = state.clone();
    Arc::make_mut(&mut unavailable.config).discovery_observers[0].base_url = "http://127.0.0.1:9".into();
    assert!(regional_admission::admit(&unavailable,&db,&initial).await.is_err());
    let mut invalid = initial.clone();
    invalid.expected_version -= 1;
    assert!(regional_admission::admit(&state,&db,&invalid).await.unwrap_err().to_string().contains("version changed"));
    invalid = initial.clone();
    invalid.environment = "production".into();
    assert!(regional_admission::admit(&state,&db,&invalid).await.unwrap_err().to_string().contains("environment"));
    let lock = super::service_deploy::try_service_lifecycle_lock(&db,"smoke").await?.unwrap();
    assert!(regional_admission::admit(&state,&db,&initial).await.unwrap_err().to_string().contains("lifecycle busy"));
    lock.commit().await?;
    db.execute_unprepared("INSERT INTO service_rollouts(service_id,rollout_id,desired_replicas,status,stage,lease_expires_at)
        VALUES('smoke','ordinary',1,'running','health',NOW())").await?;
    assert!(regional_admission::admit(&state,&db,&initial).await.unwrap_err().to_string().contains("ordinary rollout"));
    db.execute_unprepared("DELETE FROM service_rollouts WHERE rollout_id='ordinary'").await?;
    let mut duplicate = state.clone();
    let observers = &mut Arc::make_mut(&mut duplicate.config).discovery_observers;
    observers[1].gateway_id = observers[0].gateway_id.clone();
    assert!(regional_admission::admit(&duplicate,&db,&initial).await.unwrap_err().to_string().contains("duplicate observer"));
    db.execute_unprepared("CREATE FUNCTION fail_admission_journal() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected admission failure'; END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_admission_journal BEFORE INSERT ON regional_rollout_events FOR EACH ROW EXECUTE FUNCTION fail_admission_journal()").await?;
    assert!(regional_admission::admit(&state,&db,&initial).await.is_err());
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,"SELECT 1 FROM regional_service_rollouts")).await?.is_none());
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,"SELECT 1 FROM regional_policy_proposals")).await?.is_none());
    db.execute_unprepared("DROP TRIGGER fail_admission_journal ON regional_rollout_events").await?;
    assert_eq!(regional_admission::admit(&state,&db,&initial).await?,regional_admission::Receipt {generation:1,created:true});
    // A new controller connection and an unavailable gateway must not cause
    // retry to re-pin a new boot or allocate a second proposal.
    let restarted = sea_orm::Database::connect(options.clone()).await?;
    assert_eq!(regional_admission::admit(&unavailable,&restarted,&initial).await?,regional_admission::Receipt {generation:1,created:false});
    invalid = initial.clone();
    invalid.namespace = "other".into();
    assert!(regional_admission::admit(&state,&db,&invalid).await.unwrap_err().to_string().contains("different intent"));
    invalid = initial.clone();
    invalid.operation_id = "competing-operation".into();
    assert!(regional_admission::admit(&state,&db,&invalid).await.unwrap_err().to_string().contains("active or blocked"));
    reach(&state,&db,"initial","passed").await?;
    assert!(regional_admission::enroll_cold_fleet(&state,&db,&initial,"/health").await.is_err());
    assert!(super::regional_observers::observe_policy(&unavailable,&db,"smoke","initial",1,&participants)
        .await.unwrap_err().to_string().contains("binding changed"));
    let request = |port, path: &str| client.get(format!("http://127.0.0.1:{port}{path}")).header("host","smoke.example").bearer_auth("application-value");
    assert_eq!(request(proxy_ports[1],"/before").send().await?.error_for_status()?.text().await?,"eu1:fixture-v1");
    // Replacing forwarding must not replace the manager, its route state, or
    // its regional boot identity. This intentionally tests crash recovery, not
    // a zero-interruption hot takeover (a separate protocol).
    let manager_pid = proxies.0[1].id();
    let children = forwarding_children(manager_pid)?;
    assert_eq!(children.len(), 1, "exactly one forwarding child per manager");
    let old_worker = children[0];
    assert_eq!(request(proxy_ports[1],"/oversized-head").header("x-large", "x".repeat(300_000))
        .send().await?.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    assert_eq!(request(proxy_ports[1],"/after-oversized-head").send().await?.error_for_status()?.text().await?, "eu1:fixture-v1");
    assert_eq!(forwarding_children(manager_pid)?, vec![old_worker], "oversized headers must not restart the worker");
    let observer = &state.config.discovery_observers[1];
    let status_url = format!("{}/deployments/smoke/discovery-status", observer.base_url);
    let before: Value = client.get(&status_url).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
    assert!(std::process::Command::new("kill").args(["-KILL", &old_worker.to_string()]).status()?.success());
    let mut recovered = false;
    for _ in 0..100 {
        assert!(proxies.0[1].try_wait()?.is_none(), "manager must survive worker failure");
        let after: Value = client.get(&status_url).bearer_auth(&token).send().await?.error_for_status()?.json().await?;
        assert_eq!(before["regional"]["bootId"], after["regional"]["bootId"]);
        let children = forwarding_children(manager_pid)?;
        if children.len() == 1 && children[0] != old_worker {
            if let Ok(response) = request(proxy_ports[1],"/worker-replaced").send().await {
                if response.status().is_success() {
                    assert_eq!(response.text().await?, "eu1:fixture-v1");
                    recovered = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(recovered, "replacement worker must serve through the unchanged manager");
    let held_request = request(proxy_ports[1],"/held").timeout(Duration::from_secs(60));
    let held = tokio::spawn(async move { held_request.send().await?.error_for_status()?.text().await });
    tokio::time::timeout(Duration::from_secs(5),entered.notified()).await?;
    policy.regions[0].weight=0;
    policy.regions[1].weight=7;
    publish(&state,&db,"withdraw-eu",&policy,Some("eu1"),Some(1)).await?;
    reach(&state,&db,"withdraw-eu","wait_assignments_drained").await?;
    let admissions = eu_admissions.load(Ordering::SeqCst);
    for _ in 0..6 {
        regional_reports::reconcile(&state,&db,"smoke","withdraw-eu").await?;
        assert_eq!(phase(&db,"withdraw-eu").await?,"wait_assignments_drained");
        for port in &proxy_ports { assert_eq!(request(*port,"/during").send().await?.error_for_status()?.text().await?,"us3:fixture-v1"); }
    }
    assert_eq!(eu_admissions.load(Ordering::SeqCst),admissions,"withdrawn region admitted new application work");
    assert!(!held.is_finished(),"policy replacement terminated the existing response");
    release.notify_one();
    assert_eq!(held.await??,"eu1:fixture-v1");
    reach(&state,&db,"withdraw-eu","passed").await?;
    let snapshot = service_discovery::read_regional_snapshot(&db,"smoke","eu1","eu1",&participants[0].boot_id).await?;
    assert_eq!(snapshot["closedThroughGeneration"],2);
    assert_eq!(snapshot["activeGeneration"],2);
    assert!(regional_reports::ready(&db,"smoke","withdraw-eu",2,regional_reports::Gate::AdmissionDrained).await?);
    // Keep the authenticated admin endpoints reachable while discovery fails.
    // Fresh polling must not turn an expired routing snapshot into permission
    // for maintenance, even when every request counter is zero.
    discovery_unavailable.store(1,Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(31)).await;
    super::regional_observers::observe_policy(&state,&db,"smoke","withdraw-eu",2,&participants).await?;
    for gate in [regional_reports::Gate::Prepared,regional_reports::Gate::Adopted,
        regional_reports::Gate::AssignmentsDrained,regional_reports::Gate::AdmissionDrained] {
        assert!(!regional_reports::ready(&db,"smoke","withdraw-eu",2,gate).await?,
            "fresh admin responses must not attest stale discovery");
    }
    for port in &proxy_ports {
        assert_eq!(request(*port,"/authority-unavailable").send().await?.error_for_status()?.text().await?,"us3:fixture-v1");
    }
    assert_eq!(eu_admissions.load(Ordering::SeqCst),admissions);
    discovery_unavailable.store(0,Ordering::SeqCst);
    let mut renewed = false;
    for _ in 0..100 {
        super::regional_observers::observe_policy(&state,&db,"smoke","withdraw-eu",2,&participants).await?;
        if regional_reports::ready(&db,"smoke","withdraw-eu",2,regional_reports::Gate::AdmissionDrained).await? {
            renewed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(renewed,"valid discovery must renew evidence without another withdrawal");
    // The new candidate is deliberately unknown/draining in discovery and
    // distinct from the healthy retained replica. Probe it through real HTTPS
    // gateways, never through a controller-to-VM health request.
    let candidate_mode = Arc::new(AtomicUsize::new(0));
    let candidate_hits = Arc::new(AtomicUsize::new(0));
    let probe_entered = Arc::new(tokio::sync::Notify::new());
    let probe_release = Arc::new(tokio::sync::Notify::new());
    let candidate_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let candidate_url = format!("http://{}",candidate_listener.local_addr()?);
    let candidate_health_host = candidate_listener.local_addr()?.to_string();
    let (mode,hits) = (candidate_mode.clone(),candidate_hits.clone());
    let (probe_start,probe_finish) = (probe_entered.clone(),probe_release.clone());
    let candidate_app = Router::new().route("/health",get(move |headers:HeaderMap| {
        let (mode,hits) = (mode.clone(),hits.clone());
        let (probe_start,probe_finish) = (probe_start.clone(),probe_finish.clone());
        let local_host = candidate_health_host.clone();
        async move {
            // Exact-target probes carry the public host; after staging, app-lb
            // also performs its ordinary backend-local health checks.
            assert!(headers["host"] == "smoke.example" || headers["host"] == local_host);
            assert!(!headers.contains_key("authorization"));
            assert!(!headers.keys().any(|h| h.as_str().starts_with("x-heyo-peer")));
            hits.fetch_add(1,Ordering::SeqCst);
            if headers["host"] == "smoke.example" && mode.compare_exchange(3,2,Ordering::SeqCst,Ordering::SeqCst).is_ok() {
                probe_start.notify_one();
                probe_finish.notified().await;
            }
            let mode = mode.load(Ordering::SeqCst);
            (if mode == 0 {StatusCode::SERVICE_UNAVAILABLE} else {StatusCode::OK},
                [("x-heyo-revision",if mode == 1 {"fixture-v1"} else {"fixture-v2"})],"candidate")
        }
    })).fallback(get(|headers:HeaderMap| async move {
        assert_eq!(headers["host"],"smoke.example");
        assert_eq!(headers["authorization"],"Bearer application-value");
        assert!(!headers.keys().any(|h| h.as_str().starts_with("x-heyo-peer")));
        "eu1:fixture-v2"
    }));
    app_tasks.push(tokio::spawn(async move {axum::serve(candidate_listener,candidate_app).await.unwrap();}));
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO service_discovery_endpoints(service_id,deployment_id,backend_server_id,region,revision,backend_url,health_status,draining)
         VALUES('smoke','new-eu','eu1','eu1','fixture-v2',$1,'unknown',TRUE)",[candidate_url.clone().into()])).await?;
    db.execute_unprepared("UPDATE service_discovery_sets SET version=version+1 WHERE service_id='smoke'").await?;
    let mut last_probe = String::new();
    for _ in 0..100 {
        let result = super::regional_observers::probe_candidate(&state,&db,"smoke","withdraw-eu","new-eu","fixture-v2").await;
        assert!(result.is_err(),"unhealthy candidate must not pass via a retained healthy replica");
        last_probe = format!("{:#}",result.unwrap_err());
        if candidate_hits.load(Ordering::SeqCst) > 0 {break;}
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::ensure!(candidate_hits.load(Ordering::SeqCst) > 0,"candidate was never probed: {last_probe}");
    candidate_mode.store(1,Ordering::SeqCst);
    assert!(super::regional_observers::probe_candidate(&state,&db,"smoke","withdraw-eu","new-eu","fixture-v2").await.is_err(),"wrong revision cannot satisfy readiness");
    candidate_mode.store(2,Ordering::SeqCst);
    let receipts = super::regional_observers::probe_candidate(&state,&db,"smoke","withdraw-eu","new-eu","fixture-v2").await?;
    assert_eq!(receipts.len(),2);
    assert!(receipts.iter().all(|r| r["request"]["deploymentId"] == "new-eu" && r["request"]["revision"] == "fixture-v2"));
    assert!(super::regional_observers::probe_candidate(&state,&db,"smoke","withdraw-eu","eu1","fixture-v2").await.is_err());
    assert!(super::regional_observers::probe_candidate(&state,&db,"smoke","initial","new-eu","fixture-v2").await.is_err());
    let probe_url = format!("{}/deployments/smoke/regional-probe",state.config.discovery_observers[1].base_url);
    assert_eq!(client.post(probe_url).json(&receipts[0]["request"]).send().await?.status(),StatusCode::UNAUTHORIZED);
    assert_eq!(client.get(format!("http://127.0.0.1:{}/health",proxy_ports[0])).header("host","smoke.example")
        .header("x-heyo-peer-probe",serde_json::to_string(&receipts[0]["request"])?).send().await?.status(),StatusCode::FORBIDDEN);
    for port in &proxy_ports {assert_eq!(request(*port,"/after-candidate-probe").send().await?.error_for_status()?.text().await?,"us3:fixture-v1");}
    let stale_probe_report = super::regional_observers::poll_gateway(&state,&state.config.discovery_observers[0])
        .await?.0.regional.unwrap().report.unwrap();
    // Reverse direction also proves that the old eu1 admission fence does not
    // block a newly authorized generation when capacity returns there.
    let held_request = request(proxy_ports[0],"/held").timeout(Duration::from_secs(60));
    let held = tokio::spawn(async move { held_request.send().await?.error_for_status()?.text().await });
    tokio::time::timeout(Duration::from_secs(5),entered.notified()).await?;
    policy.regions[0].weight=9;
    policy.regions[1].weight=0;
    publish(&state,&db,"withdraw-us",&policy,Some("us3"),Some(2)).await?;
    assert!(regional_reports::record(&db,"smoke","withdraw-eu",&stale_probe_report,0).await.is_err(),
        "a new proposal must prevent completed predecessor evidence from refreshing");
    reach(&state,&db,"withdraw-us","wait_assignments_drained").await?;
    let admissions = us_admissions.load(Ordering::SeqCst);
    for _ in 0..6 {
        regional_reports::reconcile(&state,&db,"smoke","withdraw-us").await?;
        assert_eq!(phase(&db,"withdraw-us").await?,"wait_assignments_drained");
        for port in &proxy_ports { assert_eq!(request(*port,"/reverse").send().await?.error_for_status()?.text().await?,"eu1:fixture-v1"); }
    }
    assert_eq!(us_admissions.load(Ordering::SeqCst),admissions);
    assert!(!held.is_finished());
    release.notify_one();
    assert_eq!(held.await??,"us3:fixture-v1");
    reach(&state,&db,"withdraw-us","passed").await?;
    assert!(regional_reports::ready(&db,"smoke","withdraw-us",3,regional_reports::Gate::AdmissionDrained).await?);

    // Establish explicit positive weights before pinning an application baseline.
    policy.regions[1].weight=7;
    publish(&state,&db,"restore-us",&policy,None,Some(3)).await?;
    reach(&state,&db,"restore-us","passed").await?;

    // Real PostgreSQL and gateways, but a mock Cloud boundary: lose the create
    // response, recover its identity, publish excluded membership and peer-probe
    // the exact application revision within the same nonterminal operation.
    let regions = vec!["eu1".into(),"us3".into()];
    let plan = super::regional_plan::Plan::application(&regions,&[
        ("eu1".into(),"new-eu-owned".into()),("us3".into(),"new-us-owned".into())])?;
    let retained = regional_admission::pin_retained(&service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap(),&policy,&regions,1)?;
    let archive_sha = format!("{:x}",Sha256::digest(b"fixture"));
    let baseline = super::service_deploy::ServiceDeploymentState {service_id:"smoke".into(),deployment_environment:Some("test".into()),
        active_deployment_id:Some("us3".into()),active_archive_id:Some("old-archive".into()),
        active_backend_url:Some(retained.iter().find(|e| e.region == "us3").unwrap().url.clone()),
        active_metadata:json!({"baselineMarker":true,"runtime":{"healthPath":"/health"}}),desired_replicas:2,
        replica_regions:regions.clone(),route:Some(serde_json::from_value(json!({"host":"smoke.example","stripPrefix":false}))?),
        ingress_backend_url:Some(format!("http://127.0.0.1:{}",proxy_ports[0])),..Default::default()};
    super::service_deploy::write_service_state_in(&db,&baseline).await?;
    let mut baseline_value = serde_json::to_value(&baseline)?;
    baseline_value["regionalRetained"] = json!(retained);
    baseline_value["regionalPolicy"] = json!(policy);
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO regional_service_rollouts(operation_id,service_id,request_hash,deployment_request,target_revision,observer_topology,baseline_state,regions,slots,plan,minimum_serving_replicas,bake_seconds,drain_timeout_seconds,status,phase)
         SELECT 'probe-owned',service_id,'probe-owned',$2,$3,observer_topology,baseline_state || $4::jsonb,$5,$6,$1,minimum_serving_replicas,bake_seconds,drain_timeout_seconds,'running','preflight'
         FROM regional_service_rollouts WHERE operation_id='withdraw-us'",vec![serde_json::to_value(plan)?.into(),
            json!({"serviceId":"smoke","userId":"operator","accountId":"account","archiveId":"archive-a",
                "archiveBytesBase64":"Zml4dHVyZQ==","image":"not-the-slot-image","ports":[8080],"guestPort":8080,
                "deploymentEnvironment":"test","placementPool":"shared","expectedRuntimeRevision":"fixture-v2"}).into(),archive_sha.clone().into(),
            baseline_value.into(),json!(regions).into(),
            json!([{"candidateId":"new-eu-owned","region":"eu1","runtime":{"driver":"libvirt","image":"fixture-image","sizeClass":"small"}}]).into()])).await?;
    assert_eq!(phase(&db,"probe-owned").await?,"preflight");
    assert!(db.execute_unprepared("UPDATE regional_service_rollouts SET baseline_state='{}' WHERE operation_id='probe-owned'").await.is_err());
    for replace_claim in [false,true] {
        hold_preflight.store(1,Ordering::SeqCst);
        let (probing_state,probing_db,holding)=(state.clone(),db.clone(),hold_preflight.clone());
        let held_preflight=tokio::spawn(async move {
            for _ in 0..100 {
                let result=super::regional_application::preflight(&probing_state,&probing_db,"smoke","probe-owned").await;
                if holding.load(Ordering::SeqCst) == 0 {return result;}
                anyhow::ensure!(!result.is_ok_and(|v| v), "preflight bypassed the held survivor");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::bail!("preflight did not reach survivor")
        });
        tokio::time::timeout(Duration::from_secs(10),preflight_entered.notified()).await?;
        assert!(!super::regional_application::preflight(&state,&restarted,"smoke","probe-owned").await?,"unresolved claim blocks C2");
        if replace_claim {
            db.execute_unprepared("UPDATE regional_service_rollouts SET probe_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id='probe-owned'").await?;
            preflight_ready(&state,&restarted,"probe-owned").await?;
        } else {
            db.execute_unprepared("UPDATE service_discovery_sets SET version=version+1 WHERE service_id='smoke'").await?;
        }
        preflight_release.notify_one();
        assert!(!held_preflight.await?.is_ok_and(|v| v),"stale preflight cannot publish or overwrite a newer claim");
        assert_eq!(phase(&db,"probe-owned").await?,if replace_claim {"wait_policy_prepared"} else {"preflight"});
    }
    let proof: Value=db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT evidence FROM regional_rollout_items WHERE operation_id='probe-owned' AND step_id='0:preflight:0'"))
        .await?.unwrap().try_get("","evidence")?;
    assert_eq!(proof["claim"]["generation"],4);
    assert_eq!(proof["receipts"].as_array().unwrap().len(),2,"every source must attest the surviving US member");
    // A pending withdrawal must not make the still-active generation's healthy
    // capacity unprobeable. These read-only receipts are not rollout admission.
    let active_snapshot=service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap();
    for source in &state.config.discovery_observers {
        for destination in &participants {
            let endpoint=retained.iter().find(|e| e.region == destination.region).unwrap();
            let proof=json!({"operationId":"preflight-correlation","stepId":"0:preflight:0","epoch":1,
                "challenge":format!("{:x}",Sha256::digest(format!("{}:{}",source.region,destination.region))),
                "generation":4,"version":active_snapshot.version,"region":destination.region,"gatewayId":destination.gateway_id,
                "gatewayBootId":destination.boot_id,"backendServerId":endpoint.backend_server_id,
                "deploymentId":endpoint.deployment_id,"revision":endpoint.revision});
            let url=format!("{}/deployments/smoke/regional-active-probe",source.base_url);
            assert_eq!(client.post(&url).json(&proof).send().await?.status(),StatusCode::UNAUTHORIZED);
            let mut result=None;
            for _ in 0..100 {
                let response=client.post(&url).bearer_auth(&token).json(&proof).send().await?;
                if response.status().is_success() {result=Some(response.json::<Value>().await?);break;}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let receipt=result.context("pending-proposal active-capacity probe failed")?;
            assert_eq!(receipt["request"],proof);
            assert_eq!(receipt["sourceGatewayId"],source.gateway_id.as_deref().unwrap());
            assert_eq!(receipt["sourceBootId"],participants.iter().find(|p| p.region == source.region).unwrap().boot_id);
            assert_eq!(receipt["destination"]["request"],proof);
            assert_eq!(receipt["destination"]["backendUrl"],endpoint.url);
        }
    }
    assert_eq!(phase(&db,"probe-owned").await?,"wait_policy_prepared","capacity probes cannot advance rollout policy");
    reach_application_policy(&state,&db,"probe-owned","create_candidate").await?;
    assert!(super::regional_candidates::create_or_recover(&state,&db,"smoke","probe-owned").await.is_err());
    assert_eq!(create_count.load(Ordering::SeqCst),1);
    assert!(super::regional_candidates::create_or_recover(&state,&restarted,"smoke","probe-owned").await.is_err());
    let intent: super::regional_candidates::Intent = serde_json::from_value(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT intent FROM regional_candidate_creations WHERE operation_id='probe-owned'")).await?.unwrap().try_get("","intent")?)?;
    *cloud_receipt.lock().await = json!({"deploymentId":"new-eu-owned","requestDigest":intent.request_digest,"archiveId":"archive-a",
        "backendServerId":"eu1","backendSandboxId":"runtime-owned","status":"running","guestPort":8080,"hostLocalUrl":candidate_url,
        "placement":{"nodeId":"physical-eu","region":"eu1","deploymentEnvironment":"test","placementPool":"shared"}});
    super::regional_candidates::create_or_recover(&state,&restarted,"smoke","probe-owned").await?;
    assert_eq!(create_count.load(Ordering::SeqCst),1,"uncertain create recovery must not send another POST");
    let error = super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","new-eu","fixture-v2").await.unwrap_err();
    assert!(error.to_string().contains("durable creation receipt"),"{error:#}");
    let mut owned_receipts = None;
    for _ in 0..100 {
        match super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","new-eu-owned","fixture-v2").await {
            Ok(receipts) => { owned_receipts=Some(receipts); break; }
            Err(error) => last_probe=format!("{error:#}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(owned_receipts.context(format!("owning probe failed: {last_probe}"))?.len(),2);
    assert_eq!(phase(&db,"probe-owned").await?,"probe_candidates","probing must not complete the operation itself");
    for port in &proxy_ports {assert_eq!(request(*port,"/during-owned-probe").send().await?.error_for_status()?.text().await?,"us3:fixture-v1");}
    candidate_mode.store(1,Ordering::SeqCst);
    assert!(super::regional_application::probe_and_stage(&state,&db,"smoke","probe-owned").await.is_err());
    assert_eq!(phase(&db,"probe-owned").await?,"probe_candidates");
    for resume in [true,false] {
        candidate_mode.store(3,Ordering::SeqCst);
        let (probing_state,probing_db) = (state.clone(),restarted.clone());
        let probing = tokio::spawn(async move {
            super::regional_application::probe_and_stage(&probing_state,&probing_db,"smoke","probe-owned").await
        });
        tokio::time::timeout(Duration::from_secs(5),probe_entered.notified()).await?;
        if resume {
            db.execute_unprepared("UPDATE regional_service_rollouts SET status='blocked' WHERE operation_id='probe-owned';
                UPDATE regional_service_rollouts SET status='running' WHERE operation_id='probe-owned'").await?;
        } else {
            db.execute_unprepared("UPDATE service_discovery_sets SET version=version+1 WHERE service_id='smoke'").await?;
        }
        probe_release.notify_one();
        let error = probing.await?.unwrap_err();
        assert!(error.to_string().contains(if resume {"attempt or policy changed"} else {"membership changed"}),"{error:#}");
        assert_eq!(phase(&db,"probe-owned").await?,"probe_candidates","stale probe results cannot stage membership");
    }
    super::regional_application::probe_and_stage(&state,&restarted,"smoke","probe-owned").await?;
    assert_eq!(phase(&db,"probe-owned").await?,"publish_policy");
    assert!(super::regional_application::probe_and_stage(&state,&db,"smoke","probe-owned").await.is_err(),"stale probe worker cannot repeat staging");
    let staged = service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap();
    assert!(staged.endpoints.iter().find(|e| e.deployment_id == "eu1").unwrap().draining);
    assert!(!staged.endpoints.iter().find(|e| e.deployment_id == "new-eu-owned").unwrap().draining);
    for port in &proxy_ports {assert_eq!(request(*port,"/staged-withdrawn").send().await?.error_for_status()?.text().await?,"us3:fixture-v1");}
    assert_eq!(super::regional_application::publish_policy(&db,"smoke","probe-owned").await?,6);
    reach_application_policy(&state,&db,"probe-owned","bake").await?;
    assert_eq!(probe_ready(&state,&db,"probe-owned","new-eu-owned","fixture-v2").await?.len(),2);
    let error = super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","eu1","fixture-v1").await.unwrap_err();
    assert!(error.to_string().contains("restored eligible membership"),"{error:#}");
    for port in &proxy_ports { for _ in 0..16 {
        let body = request(*port,"/restored-candidate").send().await?.error_for_status()?.text().await?;
        assert!(matches!(body.as_str(),"eu1:fixture-v2" | "us3:fixture-v1"),"unexpected restored response: {body}");
    }}
    assert!(!super::regional_application::verify_serving(&state,&db,"smoke","probe-owned").await?,"first observation starts bake, never completes it");
    // Lose C1's isolated DB connection while its HTTP work is still running.
    // C2 must wait, then reset an expired claim even with a recent observation
    // and an already-expired old bake deadline. C1's late result cannot finish
    // the item or overwrite C2's new window.
    let mut isolated_options = options.clone();
    isolated_options.max_connections(1);
    let isolated = sea_orm::Database::connect(isolated_options).await?;
    let backend_pid: i32 = isolated.query_one(Statement::from_string(DbBackend::Postgres,"SELECT pg_backend_pid() AS pid"))
        .await?.unwrap().try_get("","pid")?;
    candidate_mode.store(3,Ordering::SeqCst);
    let (probing_state,probing_db) = (state.clone(),isolated.clone());
    let abandoned = tokio::spawn(async move {
        super::regional_application::verify_serving(&probing_state,&probing_db,"smoke","probe-owned").await
    });
    tokio::time::timeout(Duration::from_secs(5),probe_entered.notified()).await?;
    assert!(db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT pg_terminate_backend($1) AS stopped",[backend_pid.into()])).await?.unwrap().try_get::<bool>("","stopped")?);
    assert!(!super::regional_application::verify_serving(&state,&restarted,"smoke","probe-owned").await?,"unresolved claim blocks another probe set");
    db.execute_unprepared("UPDATE regional_service_rollouts SET probe_expires_at=clock_timestamp()-interval '1 second',
        deadline_at=clock_timestamp()-interval '1 second',last_observed_at=clock_timestamp() WHERE operation_id='probe-owned'").await?;
    assert!(!super::regional_application::verify_serving(&state,&restarted,"smoke","probe-owned").await?,"abandoned work invalidates the old elapsed window");
    let new_deadline: chrono::DateTime<chrono::Utc> = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT deadline_at FROM regional_service_rollouts WHERE operation_id='probe-owned'")).await?.unwrap().try_get("","deadline_at")?;
    probe_release.notify_one();
    assert!(!abandoned.await?.is_ok_and(|advanced| advanced),"a late worker cannot advance bake");
    let deadline: chrono::DateTime<chrono::Utc> = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT deadline_at FROM regional_service_rollouts WHERE operation_id='probe-owned'")).await?.unwrap().try_get("","deadline_at")?;
    assert_eq!(deadline,new_deadline,"late completion cannot reset or extend the new epoch's window");
    isolated.close().await?;
    // A successful sample after an observation gap must start over even if the
    // old deadline has elapsed; a wrong revision must reset the window as well.
    db.execute_unprepared("UPDATE regional_service_rollouts SET deadline_at=clock_timestamp()-interval '1 second',
        last_observed_at=clock_timestamp()-interval '6 seconds' WHERE operation_id='probe-owned'").await?;
    assert!(!super::regional_application::verify_serving(&state,&db,"smoke","probe-owned").await?);
    candidate_mode.store(1,Ordering::SeqCst);
    assert!(super::regional_application::verify_serving(&state,&db,"smoke","probe-owned").await.is_err());
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT 1 FROM regional_service_rollouts WHERE operation_id='probe-owned' AND deadline_at IS NULL
         AND last_observed_at IS NULL AND probe_expires_at IS NULL")).await?.is_some());
    candidate_mode.store(2,Ordering::SeqCst);
    // Explicit rollback before entering US. The retained identity was pinned
    // before forward execution; a new candidate is not an eligible substitute.
    assert_eq!(super::regional_application::begin_rollback(&db,"smoke","probe-owned").await?,"rollback_entry");
    preflight_ready(&state,&db,"probe-owned").await?;
    reach_application_policy(&state,&db,"probe-owned","probe_retained").await?;
    let error = super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","new-eu-owned","fixture-v2").await.unwrap_err();
    assert!(error.to_string().contains("pinned retained baseline"),"{error:#}");
    let mut retained_receipts = None;
    for _ in 0..100 {
        match super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","eu1","fixture-v1").await {
            Ok(receipts) => { retained_receipts=Some(receipts); break; }
            Err(error) => last_probe=format!("{error:#}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(retained_receipts.context(format!("retained probe failed: {last_probe}"))?.len(),2);
    db.execute_unprepared("INSERT INTO service_deployment_runs(deployment_id,service_id,status,phase) VALUES('historical','smoke','passed','completed');
        INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata)
        VALUES('historical','smoke','previous-retire-wait','running','old cleanup intent','{\"response\":{\"previousDeploymentId\":\"eu1\"}}')").await?;
    db.execute_unprepared("CREATE FUNCTION fail_staging_journal() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected staging failure'; END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_staging_journal BEFORE INSERT ON regional_rollout_events FOR EACH ROW EXECUTE FUNCTION fail_staging_journal()").await?;
    let error = super::regional_application::probe_and_stage(&state,&db,"smoke","probe-owned").await.unwrap_err();
    assert!(format!("{error:#}").contains("injected staging failure"),"{error:#}");
    assert_eq!(phase(&db,"probe-owned").await?,"probe_retained");
    assert!(service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap().endpoints.iter().find(|e| e.deployment_id == "eu1").unwrap().draining,
        "failed journal must roll back membership eligibility");
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT 1 FROM service_deployment_events WHERE phase='previous-retire-cancelled'")).await?.is_none(),"failed staging rolls back retirement cancellation too");
    db.execute_unprepared("DROP TRIGGER fail_staging_journal ON regional_rollout_events").await?;
    super::regional_application::probe_and_stage(&state,&restarted,"smoke","probe-owned").await?;
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT 1 FROM service_deployment_events WHERE phase='previous-retire-cancelled' AND metadata->'response'->>'previousDeploymentId'='eu1'")).await?.is_some(),
        "restoring a non-scalar replica must revoke its historical retirement");
    let restored = service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap();
    assert!(!restored.endpoints.iter().find(|e| e.deployment_id == "eu1").unwrap().draining);
    assert!(restored.endpoints.iter().find(|e| e.deployment_id == "new-eu-owned").unwrap().draining);
    assert!(!restored.endpoints.iter().find(|e| e.deployment_id == "us3").unwrap().draining);
    assert_eq!(super::regional_application::publish_policy(&db,"smoke","probe-owned").await?,8);
    reach_application_policy(&state,&db,"probe-owned","bake").await?;
    assert_eq!(probe_ready(&state,&db,"probe-owned","eu1","fixture-v1").await?.len(),2);
    let error = super::regional_observers::probe_candidate(&state,&db,"smoke","probe-owned","new-eu-owned","fixture-v2").await.unwrap_err();
    assert!(error.to_string().contains("restored eligible membership"),"{error:#}");
    for port in &proxy_ports { for _ in 0..16 {
        let body = request(*port,"/restored-retained").send().await?.error_for_status()?.text().await?;
        assert!(matches!(body.as_str(),"eu1:fixture-v1" | "us3:fixture-v1"),"unexpected rollback response: {body}");
    }}
    // The internal verification primitive executes a real bake interval and
    // verifies both retained regions before terminal progress. The production
    // admission/dispatcher remains closed and is not exercised by this fixture.
    db.execute_unprepared("UPDATE service_deployment_states SET active_metadata='{\"incompleteCompatibilityState\":true}' WHERE service_id='smoke'").await?;
    for _ in 0..100 {
        if phase(&db,"probe-owned").await? == "rolled_back" {break;}
        if let Err(error) = super::regional_application::verify_serving(&state,&db,"smoke","probe-owned").await {
            last_probe=format!("{error:#}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(phase(&db,"probe-owned").await?,"rolled_back","verification did not complete: {last_probe}");
    let restored_state = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT active_deployment_id,active_archive_id,active_metadata,ingress_backend_url FROM service_deployment_states WHERE service_id='smoke'")).await?.unwrap();
    assert_eq!(restored_state.try_get::<String>("","active_deployment_id")?,"us3");
    assert_eq!(restored_state.try_get::<String>("","active_archive_id")?,"old-archive");
    assert_eq!(restored_state.try_get::<Value>("","active_metadata")?,baseline.active_metadata);
    assert_eq!(restored_state.try_get::<Option<String>>("","ingress_backend_url")?,baseline.ingress_backend_url);
    assert_eq!(probe_ready(&state,&db,"probe-owned","eu1","fixture-v1").await?.len(),2);
    let terminal_report = super::regional_observers::poll_gateway(&state,&state.config.discovery_observers[0])
        .await?.0.regional.unwrap().report.unwrap();
    // Interrupt a forward publication before activation. Rollback must probe
    // active N, not pending N+1, and publish N+2 with N as its predecessor.
    db.execute_unprepared("INSERT INTO regional_service_rollouts(operation_id,service_id,request_hash,deployment_request,
        target_revision,observer_topology,baseline_state,regions,slots,plan,minimum_serving_replicas,bake_seconds,drain_timeout_seconds,status,phase)
        SELECT 'interrupt-pending',service_id,'interrupt-pending',deployment_request,target_revision,observer_topology,
        baseline_state,regions,slots,plan,minimum_serving_replicas,bake_seconds,drain_timeout_seconds,'running','preflight'
        FROM regional_service_rollouts WHERE operation_id='probe-owned'").await?;
    preflight_ready(&state,&db,"interrupt-pending").await?;
    let active = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT generation FROM service_active_regional_policies WHERE service_id='smoke'")).await?.unwrap();
    assert_eq!(active.try_get::<i64>("","generation")?,8);
    assert_eq!(super::regional_application::begin_rollback(&db,"smoke","interrupt-pending").await?,"rollback_entry");
    preflight_ready(&state,&restarted,"interrupt-pending").await?;
    let rollback = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT expected_predecessor FROM regional_policy_proposals WHERE service_id='smoke' AND generation=10")).await?.unwrap();
    assert_eq!(rollback.try_get::<i64>("","expected_predecessor")?,8);
    let error = regional_policy::activate_proposal(&db,"smoke","interrupt-pending",9).await.unwrap_err();
    assert!(error.to_string().contains("operation has not completed target preparation"),
        "interrupted forward occurrence must fail its owning cursor gate: {error:#}");
    reach_application_policy(&state,&restarted,"interrupt-pending","rolled_back").await?;
    let active = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT generation FROM service_active_regional_policies WHERE service_id='smoke'")).await?.unwrap();
    assert_eq!(active.try_get::<i64>("","generation")?,11);
    // Execute both regions entirely through the internal dispatcher, alternating
    // controller connections. Cloud still models uncertain creation, not VMs.
    let mut full_urls = std::collections::HashMap::new();
    for region in ["eu1","us3"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        full_urls.insert(region,format!("http://{}",listener.local_addr()?));
        let app = Router::new().fallback(get(move || async move {
            ([("x-heyo-revision","fixture-v2")],format!("{region}:fixture-v2"))
        }));
        app_tasks.push(tokio::spawn(async move {axum::serve(listener,app).await.unwrap();}));
    }
    let version = service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap().version;
    let mut admission: regional_admission::ApplicationRequest = serde_json::from_value(json!({
        "expectedVersion":version,"expectedGeneration":11,"namespace":"default","runtimeRevision":"fixture-v2","guestPort":8080,
        "rollout":{"operationId":"full-forward","minimumServingReplicas":1,"bakeSeconds":1,"drainTimeoutSeconds":60,
            "runtimeByRegion":{"us3":{"driver":"libvirt","image":"fixture-image","sizeClass":"small"},
                "eu1":{"driver":"libvirt","image":"fixture-image","sizeClass":"small"}},
            "deployment":{"serviceId":"smoke","userId":"operator","accountId":"account","archiveId":"archive-a",
                "ports":[8080],"healthPath":"/health","deploymentEnvironment":"test","placementPool":"shared",
                "desiredReplicas":2,"replicaRegions":["us3","eu1"],"route":{"host":"smoke.example","stripPrefix":false}}}
    }))?;
    let mut invalid = admission.clone();
    invalid.expected_generation = 10;
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("predecessor changed"));
    invalid = admission.clone(); invalid.expected_version -= 1;
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("version changed"));
    invalid = admission.clone(); invalid.rollout.deployment.placement_pool = None;
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("placement pool"));
    invalid = admission.clone(); invalid.rollout.deployment.replica_regions.push("us3".into());
    invalid.rollout.deployment.desired_replicas = Some(3);
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("distinct candidate slots"));
    archive_drift.store(1,Ordering::SeqCst);
    assert!(regional_admission::admit_application(&state,&db,&admission).await.unwrap_err().to_string().contains("version changed"),
        "remote work must not commit a stale admission baseline");
    admission.expected_version += 1;
    let mut unavailable = state.clone();
    Arc::make_mut(&mut unavailable.config).discovery_observers[1].base_url = "http://127.0.0.1:9".into();
    assert!(regional_admission::admit_application(&unavailable,&db,&admission).await.is_err());
    invalid = admission.clone(); invalid.namespace = "foreign".into();
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("mismatch"));
    assert!(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT 1 FROM regional_service_rollouts WHERE operation_id='full-forward'")).await?.is_none(),"rejected admission leaves no owner");
    assert!(regional_admission::admit_application(&state,&db,&admission).await?);
    Arc::make_mut(&mut unavailable.config).cloud_internal_url = "http://127.0.0.1:9".into();
    assert!(!regional_admission::admit_application(&unavailable,&restarted,&admission).await?,"durable retry needs no available gateway or archive");
    invalid = admission.clone(); invalid.runtime_revision = "different-intent".into();
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.unwrap_err().to_string().contains("different intent"));
    invalid = admission.clone(); invalid.rollout.operation_id = "competing".into();
    assert!(regional_admission::admit_application(&state,&db,&invalid).await.is_err(),"one application owner per service");
    db.execute_unprepared("INSERT INTO service_deployment_runs(deployment_id,service_id,status,phase) VALUES('forward-history','smoke','passed','completed');
        INSERT INTO service_deployment_events(deployment_id,service_id,phase,status,message,metadata)
        SELECT 'forward-history','smoke','previous-retire-wait','running','historical baseline cleanup',
            jsonb_build_object('response',jsonb_build_object('previousDeploymentId',target)) FROM unnest(ARRAY['eu1','us3']) target").await?;
    db.execute_unprepared("CREATE FUNCTION fail_completion_journal() RETURNS trigger AS $$ BEGIN
        IF NEW.operation_id='full-forward' AND NEW.step_id='1:passed:1' THEN RAISE EXCEPTION 'injected completion failure'; END IF;
        RETURN NEW; END; $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_completion_journal BEFORE INSERT ON regional_rollout_events FOR EACH ROW EXECUTE FUNCTION fail_completion_journal()").await?;
    let mut completion_rolled_back = false;
    let mut recovered = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let mut ticks = 0;
    let mut last_error = String::new();
    while phase(&db,"full-forward").await? != "passed" && std::time::Instant::now() < deadline {
        let connection = if ticks % 2 == 0 {&db} else {&restarted};
        if let Err(error) = super::regional_application::tick(&state,connection,"smoke","full-forward").await {
            last_error = format!("{error:#}");
            if last_error.contains("injected completion failure") {
                assert_eq!(phase(&db,"full-forward").await?,"verify");
                let unchanged = db.query_one(Statement::from_string(DbBackend::Postgres,
                    "SELECT active_deployment_id,active_archive_id FROM service_deployment_states WHERE service_id='smoke'")).await?.unwrap();
                assert_eq!(unchanged.try_get::<String>("","active_deployment_id")?,"us3");
                assert_eq!(unchanged.try_get::<String>("","active_archive_id")?,"old-archive");
                assert!(db.query_one(Statement::from_string(DbBackend::Postgres,
                    "SELECT 1 FROM service_deployment_events WHERE deployment_id='forward-history' AND phase='previous-retire-cancelled'")).await?.is_none(),
                    "terminal failure must roll back retirement protection as well as service state");
                db.execute_unprepared("DROP TRIGGER fail_completion_journal ON regional_rollout_events").await?;
                completion_rolled_back = true;
            }
        }
        for row in db.query_all(Statement::from_string(DbBackend::Postgres,
            "SELECT intent FROM regional_candidate_creations WHERE operation_id='full-forward' AND receipt IS NULL")).await? {
            let intent: super::regional_candidates::Intent = serde_json::from_value(row.try_get("","intent")?)?;
            if recovered.insert(intent.deployment_id.clone()) {
                assert_eq!(create_count.load(Ordering::SeqCst),1+recovered.len(),"one POST per candidate despite lost replies");
            }
            *cloud_receipt.lock().await = json!({"deploymentId":intent.deployment_id,"requestDigest":intent.request_digest,
                "archiveId":"archive-a","backendServerId":intent.region,"backendSandboxId":format!("runtime-{}",intent.region),
                "status":"running","guestPort":8080,"hostLocalUrl":full_urls[intent.region.as_str()],
                "placement":{"nodeId":format!("physical-{}",intent.region),"region":intent.region,"deploymentEnvironment":"test","placementPool":"shared"}});
        }
        for port in &proxy_ports {
            let body = request(*port,"/continuous-forward").send().await?.error_for_status()?.text().await?;
            assert!(matches!(body.as_str(),"eu1:fixture-v1" | "us3:fixture-v1" | "eu1:fixture-v2" | "us3:fixture-v2"),"{body}");
        }
        ticks += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(phase(&db,"full-forward").await?,"passed","dispatcher failed: {last_error}");
    assert!(completion_rolled_back,"fixture must exercise atomic terminal failure");
    assert_eq!(create_count.load(Ordering::SeqCst),3);
    assert_eq!(recovered.len(),2);
    assert_eq!(db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT count(*) AS count FROM service_deployment_events WHERE deployment_id='forward-history' AND phase='previous-retire-cancelled'"))
        .await?.unwrap().try_get::<i64>("","count")?,2,"terminal success permanently protects both retained baselines");
    let completed = db.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT * FROM service_deployment_states WHERE service_id='smoke'")).await?.unwrap();
    assert_eq!(completed.try_get::<String>("","active_deployment_id")?,regional_rollout::candidate_id("full-forward",0));
    assert_eq!(completed.try_get::<String>("","active_archive_id")?,"archive-a");
    assert_eq!(completed.try_get::<String>("","active_backend_url")?,full_urls["us3"]);
    assert_eq!(completed.try_get::<String>("","previous_deployment_id")?,"us3");
    assert_eq!(completed.try_get::<String>("","previous_archive_id")?,"old-archive");
    assert_eq!(completed.try_get::<Value>("","previous_metadata")?,baseline.active_metadata);
    assert_eq!(completed.try_get::<Option<String>>("","ingress_backend_url")?,baseline.ingress_backend_url);
    assert_eq!(completed.try_get::<Value>("","route")?,serde_json::to_value(&baseline.route)?);
    assert_eq!(completed.try_get::<i32>("","desired_replicas")?,2);
    assert_eq!(completed.try_get::<Value>("","replica_regions")?,json!(["us3","eu1"]));
    let metadata: Value = completed.try_get("","active_metadata")?;
    assert_eq!(metadata["regionalReplicas"][0]["deploymentId"],regional_rollout::candidate_id("full-forward",0));
    assert_eq!(metadata["regionalReplicas"][1]["deploymentId"],regional_rollout::candidate_id("full-forward",1));
    assert_eq!(metadata["runtime"]["healthPath"],"/health");
    for region in ["eu1","us3"] {
        let final_snapshot = service_discovery::read_snapshot_in(&db,"smoke",true).await?.unwrap();
        let serving: Vec<_> = final_snapshot.endpoints.iter().filter(|e| e.region.as_deref() == Some(region) && !e.draining).collect();
        assert_eq!(serving.len(),1);
        assert_eq!(serving[0].revision.as_deref(),Some("fixture-v2"));
        assert_eq!(serving[0].url,full_urls[region]);
    }
    publish(&state,&db,"restart-fence",&policy,None,Some(15)).await?;
    assert!(regional_reports::record(&db,"smoke","probe-owned",&terminal_report,0).await.is_err(),
        "terminal rollback observations cannot outlive their active proposal");
    reach(&state,&db,"restart-fence","activate_policy").await?;
    proxies.0[0].kill()?;
    proxies.0[0].wait()?;
    proxies.0[0] = commands[0].spawn()?;
    let mut invalidated = false;
    for _ in 0..100 {
        let _ = regional_reports::reconcile(&state,&db,"smoke","restart-fence").await;
        invalidated = db.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT 1 FROM regional_gateway_reports WHERE service_id='smoke' AND gateway_id='eu1' AND boot_id=$1 AND invalidated",
            [participants[0].boot_id.clone().into()])).await?.is_some();
        if invalidated { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(invalidated,"authenticated cold-boot observation must invalidate predecessor reports");
    assert_eq!(phase(&db,"restart-fence").await?,"activate_policy");
    assert!(!regional_reports::ready(&db,"smoke","restart-fence",16,regional_reports::Gate::Prepared).await?);
    assert_eq!(request(proxy_ports[0],"/cold").send().await?.status(),StatusCode::SERVICE_UNAVAILABLE);
    println!("PASS: actual bidirectional HTTPS forwarding, authenticated report polls, preserved application identity, held responses across both withdrawals, 24 successful requests to surviving regions, durable drain/peer closure, restarted gateway fails closed and invalidates predecessor evidence");
    drop(proxies);
    control_task.abort();
    for task in app_tasks { task.abort(); }
    restarted.close().await?;
    db.close().await?;
    root_db.execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    root_db.close().await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
