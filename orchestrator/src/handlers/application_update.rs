//! Durable application commands. CI executes its own job drain; only app-lb
//! replaces its retained workspace. This dispatcher never creates a second VM.
use anyhow::{Context, Result};
use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, Json};
use heyosecret_client::{HeyoSecretClient, HeyoSecretClientOptions};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use crate::{auth, config::ExternalServiceBinding, db, AppState};
use super::service_deploy;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRequest { operation_id: String, intent_hash: String }

fn binding<'a>(state: &'a AppState, service: &str) -> Result<&'a ExternalServiceBinding> {
    let matches: Vec<_> = state.config.external_service_bindings.iter().filter(|b| b.service_id == service).collect();
    anyhow::ensure!(matches.len() == 1, "legacy application update requires exactly one configured binding");
    Ok(matches[0])
}

fn bindings<'a>(state: &'a AppState, service: &str) -> Result<Vec<&'a ExternalServiceBinding>> {
    let matches: Vec<_> = state.config.external_service_bindings.iter().filter(|b| b.service_id == service).collect();
    anyhow::ensure!(!matches.is_empty(), "application lifecycle is not configured");
    // First appearance defines operator region order. Finish every deployment
    // in that region before advancing, even if configuration interleaves them.
    let mut regions = std::collections::HashSet::new();
    let mut ordered = Vec::with_capacity(matches.len());
    for binding in &matches {
        if regions.insert(&binding.region) {
            ordered.extend(matches.iter().copied().filter(|b| b.region == binding.region));
        }
    }
    Ok(ordered)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegionalUpdateRequest {
    api_version: String,
    operation_id: String,
    release: ReleaseIdentity,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseIdentity { run_id: String, target_revision: String, artifact_digest: String, binary_sha256: String }

fn request_hash(r: &RegionalUpdateRequest) -> Result<String> {
    let mut value = serde_json::to_value(r)?; value.sort_all_objects();
    Ok(format!("{:x}",Sha256::digest(serde_json::to_vec(&value)?)))
}

fn child_id(parent: &str, authority: &str, deployment: &str) -> Result<String> {
    let encoded=serde_json::to_vec(&json!([parent,authority.trim_end_matches('/'),deployment]))?;
    Ok(format!("ci-region-{:x}",Sha256::digest(encoded)))
}

async fn token(state: &AppState, binding: &ExternalServiceBinding) -> Result<String> {
    anyhow::ensure!(!binding.lifecycle_token_secret_path.trim().is_empty(), "application lifecycle credential is not configured");
    let secrets = HeyoSecretClient::new(HeyoSecretClientOptions {
        base_url:state.config.heyosecret_url.clone(),
        token:if state.config.heyosecret_internal_api_key.is_empty() {state.config.internal_api_key.clone()}
            else {state.config.heyosecret_internal_api_key.clone()}, timeout:Some(Duration::from_secs(10)) })?;
    let value = String::from_utf8(secrets.read_active(&binding.lifecycle_token_secret_path).await?.value)?;
    anyhow::ensure!(!value.is_empty(), "application lifecycle credential is empty");
    Ok(value)
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10)).build()?)
}

pub(super) async fn verify_ready(state: &AppState, binding: &ExternalServiceBinding) -> Result<()> {
    let bearer = token(state,binding).await?;
    let url = endpoint(binding,"probe")?.join("/api/lifecycle")?;
    let response = client()?.get(url).bearer_auth(bearer).send().await?;
    anyhow::ensure!(response.status().is_success(), "application lifecycle endpoint is not ready");
    let identity: Value = response.json().await?;
    anyhow::ensure!(identity["applicationId"] == binding.service_id
        && identity["deploymentId"] == binding.deployment_id
        && identity["capabilities"].as_array().is_some_and(|v|v.iter().any(|c|c == "release-update" || c == "regional-release-update-v1")),
        "application lifecycle identity or capability mismatch");
    Ok(())
}

fn endpoint(binding: &ExternalServiceBinding, id: &str) -> Result<reqwest::Url> {
    anyhow::ensure!(!id.is_empty() && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)), "invalid operation ID");
    let url = reqwest::Url::parse(&binding.health_origin)?;
    anyhow::ensure!(matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
        && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
        && url.username().is_empty() && url.password().is_none(), "invalid application origin");
    Ok(url.join(&format!("api/lifecycle/updates/{id}"))?)
}

fn verify(binding: &ExternalServiceBinding, id: &str, hash: &str, intent: &Value) -> Result<()> {
    anyhow::ensure!(intent["operationId"] == id && intent["applicationId"] == binding.service_id
        && intent["intentHash"] == hash && intent["deploymentId"] == binding.deployment_id,
        "application update identity mismatch");
    anyhow::ensure!(intent["authority"].as_str().map(|s| s.trim_end_matches('/'))
        == Some(binding.authority.trim_end_matches('/')), "application runtime authority mismatch");
    Ok(())
}

async fn read(binding: &ExternalServiceBinding, id: &str, bearer: &str) -> Result<Value> {
    let response = client()?.get(endpoint(binding,id)?).bearer_auth(bearer).send().await?;
    anyhow::ensure!(response.status().is_success(), "application update status unavailable");
    Ok(response.json().await?)
}

async fn prepare(binding: &ExternalServiceBinding, parent: &str, child: &str, bearer: &str) -> Result<Value> {
    let response=client()?.post(endpoint(binding,child)?.join(&format!("{child}/prepare"))?)
        .bearer_auth(bearer).json(&json!({"parentOperationId":parent,"operationId":child,
            "applicationId":binding.service_id})).send().await?;
    anyhow::ensure!(response.status().is_success(),"regional child preparation unavailable");
    Ok(response.json().await?)
}

fn verify_release(binding:&ExternalServiceBinding,parent:&RegionalUpdateRequest,child:&str,value:&Value)->Result<()> {
    anyhow::ensure!(value["operationId"]==child && value["applicationId"]==binding.service_id
        && value["deploymentId"]==binding.deployment_id
        && value["authority"].as_str().map(|v|v.trim_end_matches('/'))==Some(binding.authority.trim_end_matches('/'))
        && value["runId"]==parent.release.run_id && value["targetRevision"]==parent.release.target_revision
        && value["artifactDigest"]==parent.release.artifact_digest && value["binarySha256"]==parent.release.binary_sha256,
        "prepared child immutable identity does not match parent");
    anyhow::ensure!(value["intentHash"].as_str().is_some_and(|v|!v.is_empty()),"prepared child omitted intentHash"); Ok(())
}

async fn accept(binding: &ExternalServiceBinding, r: &UpdateRequest, bearer: &str) -> Result<Value> {
    let intent = read(binding,&r.operation_id,bearer).await?;
    verify(binding,&r.operation_id,&r.intent_hash,&intent)?;
    let tx = service_deploy::try_service_lifecycle_lock(db::get_db()?,&binding.service_id).await?
        .context("application lifecycle is busy")?;
    let registered = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT authority,deployment_id,namespace,region FROM external_service_bindings WHERE service_id=$1 AND region=$2 AND deployment_id=$3",
        vec![binding.service_id.clone().into(),binding.region.clone().into(),binding.deployment_id.clone().into()])).await?
        .context("application has not been adopted")?;
    anyhow::ensure!(registered.try_get::<String>("","authority")?.trim_end_matches('/') == binding.authority.trim_end_matches('/')
        && registered.try_get::<String>("","deployment_id")? == binding.deployment_id
        && registered.try_get::<String>("","namespace")? == binding.namespace, "application binding changed after adoption");
    let receipt = json!({"operationId":r.operation_id,"intentHash":r.intent_hash});
    if let Some(row) = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT service_id,intent_hash FROM application_updates WHERE operation_id=$1",[r.operation_id.clone().into()])).await? {
        anyhow::ensure!(row.try_get::<String>("","service_id")? == binding.service_id
            && row.try_get::<String>("","intent_hash")? == r.intent_hash, "application update changed on replay");
        tx.commit().await?;
        return Ok(receipt);
    }
    anyhow::ensure!(tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM regional_application_updates WHERE service_id=$1 AND status IN ('preparing','running','cancelling') LIMIT 1",
        [binding.service_id.clone().into()])).await?.is_none(),"a regional application update is active");
    anyhow::ensure!(intent["phase"] == "prepared", "application update must be a prepared release intent");
    // The adoption row was checked above; the partial index serializes updates.
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO application_updates(operation_id,service_id,intent_hash,intent) VALUES($1,$2,$3,$4)",
        vec![r.operation_id.clone().into(),binding.service_id.clone().into(),r.intent_hash.clone().into(),intent.into()])).await?;
    tx.commit().await?;
    Ok(receipt)
}

async fn accept_regional(state: &AppState, service: &str, r: &RegionalUpdateRequest) -> Result<Value> {
    anyhow::ensure!(r.api_version == "regional-v1", "unsupported regional update API version");
    for (name,value) in [("operationId",&r.operation_id),("runId",&r.release.run_id),
        ("targetRevision",&r.release.target_revision),("artifactDigest",&r.release.artifact_digest),
        ("binarySha256",&r.release.binary_sha256)] {
        anyhow::ensure!(!value.is_empty() && value.trim()==value && value.len()<=256,"{name} is invalid");
    }
    for digest in [&r.release.artifact_digest,&r.release.binary_sha256] {
        anyhow::ensure!(digest.len()==64 && digest.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "release digests must be lowercase SHA-256");
    }
    let configured = bindings(state,service)?;
    anyhow::ensure!(configured.iter().map(|b| &b.region).collect::<std::collections::HashSet<_>>().len() >= 2,
        "regional updates require at least two configured regions");
    let tx = service_deploy::try_service_lifecycle_lock(db::get_db()?,service).await?.context("application lifecycle is busy")?;
    let hash = request_hash(r)?;
    if let Some(row) = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT service_id,request_hash FROM regional_application_updates WHERE operation_id=$1",[r.operation_id.clone().into()])).await? {
        anyhow::ensure!(row.try_get::<String>("","service_id")? == service
            && row.try_get::<String>("","request_hash")? == hash,"regional application update changed on replay");
        tx.commit().await?;
        return status_value(db::get_db()?,service,&r.operation_id).await;
    }
    anyhow::ensure!(tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM application_updates WHERE service_id=$1 AND status IN ('accepted','running') LIMIT 1",
        [service.into()])).await?.is_none(),"a legacy application update is active");
    let mut frozen = Vec::with_capacity(configured.len());
    for (ordinal,binding) in configured.iter().enumerate() {
        let registered = tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT authority,namespace,deployment_id,evidence FROM external_service_bindings WHERE service_id=$1 AND region=$2 AND deployment_id=$3",
            vec![service.into(),binding.region.clone().into(),binding.deployment_id.clone().into()])).await?.context("configured regional application has not been adopted")?;
        let evidence: Value=registered.try_get("","evidence")?;
        anyhow::ensure!(registered.try_get::<String>("","authority")?.trim_end_matches('/') == binding.authority.trim_end_matches('/')
            && registered.try_get::<String>("","namespace")? == binding.namespace
            && registered.try_get::<String>("","deployment_id")? == binding.deployment_id
            && evidence["healthOrigin"].as_str().map(|v|v.trim_end_matches('/'))==Some(binding.health_origin.trim_end_matches('/')),
            "regional application binding changed after adoption");
        frozen.push(json!({"ordinal":ordinal,"region":binding.region,"deploymentId":binding.deployment_id,
            "authority":binding.authority,"healthOrigin":binding.health_origin,"namespace":binding.namespace,
            "adoptionEvidence":evidence,"operationId":child_id(&r.operation_id,&binding.authority,&binding.deployment_id)?}));
    }
    let request=serde_json::to_value(r)?;
    tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO regional_application_updates(operation_id,service_id,request_hash,request,release_run_id,target_revision,artifact_digest,binary_sha256,bake_seconds,targets) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        vec![r.operation_id.clone().into(),service.into(),hash.clone().into(),request.into(),r.release.run_id.clone().into(),r.release.target_revision.clone().into(),r.release.artifact_digest.clone().into(),r.release.binary_sha256.clone().into(),(state.config.regional_application_bake_seconds as i32).into(),Value::Array(frozen.clone()).into()])).await?;
    for (ordinal,binding) in configured.iter().enumerate() {
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO regional_application_update_targets(parent_operation_id,ordinal,service_id,region,deployment_id,authority,health_origin,namespace,adoption_evidence,child_operation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            vec![r.operation_id.clone().into(),(ordinal as i32).into(),service.into(),binding.region.clone().into(),binding.deployment_id.clone().into(),binding.authority.clone().into(),binding.health_origin.clone().into(),binding.namespace.clone().into(),frozen[ordinal]["adoptionEvidence"].clone().into(),frozen[ordinal]["operationId"].as_str().unwrap().into()])).await?;
    }
    tx.commit().await?;
    status_value(db::get_db()?,service,&r.operation_id).await
}

pub async fn create(State(state): State<AppState>, Path(service): Path<String>, headers: HeaderMap,
    Json(body): Json<Value>) -> (StatusCode,Json<Value>) {
    let Ok(configured) = bindings(&state,&service) else {
        return (StatusCode::NOT_FOUND,Json(json!({"error":"application lifecycle is not configured"})));
    };
    let Ok(bearer) = token(&state,configured[0]).await else {
        return (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"application credential unavailable"})));
    };
    if let Err(status) = auth::require_internal_api_key(&headers,&bearer) {
        return (status,Json(json!({"error":"Unauthorized"})));
    }
    let result = if body.get("apiVersion").is_some() {
        match serde_json::from_value::<RegionalUpdateRequest>(body) {
            Ok(r) => accept_regional(&state,&service,&r).await,
            Err(error) => Err(error.into()),
        }
    } else {
        match (binding(&state,&service),serde_json::from_value::<UpdateRequest>(body)) {
            (Ok(binding),Ok(r)) => accept(binding,&r,&bearer).await,
            (Err(error),_) => Err(error),
            (_,Err(error)) => Err(error.into()),
        }
    };
    match result {
        Ok(receipt) => (StatusCode::ACCEPTED,Json(receipt)),
        Err(error) => { tracing::warn!(%error,service,"application update not accepted");
            (StatusCode::CONFLICT,Json(json!({"error":"application update was not accepted"}))) }
    }
}

async fn reconcile(state: &AppState, service: &str, id: &str, hash: &str) -> Result<()> {
    let persisted = db::get_db()?.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT intent FROM application_updates WHERE operation_id=$1 AND service_id=$2",vec![id.into(),service.into()])).await?
        .context("legacy application update is missing")?.try_get::<Value>("","intent")?;
    let matches: Vec<_> = bindings(state,service)?.into_iter().filter(|candidate|
        persisted["deploymentId"] == candidate.deployment_id
        && persisted["authority"].as_str().map(|v|v.trim_end_matches('/')) == Some(candidate.authority.trim_end_matches('/'))).collect();
    anyhow::ensure!(matches.len()==1,"legacy application update binding is not uniquely configured");
    let binding=matches[0];
    let bearer = token(state,binding).await?;
    let mut observed = read(binding,id,&bearer).await?;
    verify(binding,id,hash,&observed)?;
    if observed["phase"] == "prepared" {
        let response = client()?.post(endpoint(binding,id)?).bearer_auth(&bearer)
            .json(&json!({"intentHash":hash})).send().await?;
        anyhow::ensure!(response.status().is_success(), "application activation unresolved");
        observed = read(binding,id,&bearer).await?;
        verify(binding,id,hash,&observed)?;
    }
    let status = match observed["status"].as_str() {
        Some("passed") if observed["phase"] == "complete" => "passed",
        Some("failed") if observed["phase"] == "complete" => "failed",
        _ => "running",
    };
    db::get_db()?.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE application_updates SET status=$2,observation=$3,observed_at=now(),updated_at=now(),error=NULL WHERE operation_id=$1 AND status IN ('accepted','running')",
        vec![id.into(),status.into(),observed.into()])).await?;
    Ok(())
}

async fn live_healthy(state: &AppState, binding: &ExternalServiceBinding, expected: Option<&Value>) -> Result<()> {
    let lifecycle:Value=client()?.get(reqwest::Url::parse(&binding.health_origin)?.join("api/lifecycle")?)
        .bearer_auth(token(state,binding).await?).send().await?.error_for_status()?.json().await?;
    anyhow::ensure!(lifecycle["applicationId"]==binding.service_id && lifecycle["deploymentId"]==binding.deployment_id
        && lifecycle["authority"].as_str().map(|v|v.trim_end_matches('/'))==Some(binding.authority.trim_end_matches('/'))
        && lifecycle["bootId"].as_str().is_some_and(|v|!v.is_empty()) && lifecycle["revision"].as_str().is_some_and(|v|!v.is_empty())
        && lifecycle["binarySha256"].as_str().is_some_and(|v|!v.is_empty()) && lifecycle["admissionsOpen"]==true
        && lifecycle["capabilities"].as_array().is_some_and(|v|v.iter().any(|c|c=="regional-release-update-v1")),
        "regional lifecycle survivor identity is not healthy");
    let secrets = HeyoSecretClient::new(HeyoSecretClientOptions { base_url:state.config.heyosecret_url.clone(),
        token:if state.config.heyosecret_internal_api_key.is_empty(){state.config.internal_api_key.clone()}else{state.config.heyosecret_internal_api_key.clone()},
        timeout:Some(Duration::from_secs(10)) })?;
    let admin=String::from_utf8(secrets.read_active(&binding.token_secret_path).await?.value)?;
    let snapshot:Value=client()?.get(reqwest::Url::parse(&binding.authority)?.join(&format!("deployments/{}",binding.deployment_id))?)
        .bearer_auth(admin).send().await?.error_for_status()?.json().await?;
    anyhow::ensure!(snapshot["spec"]["id"]==binding.deployment_id
        && snapshot["spec"]["namespace"].as_str().unwrap_or("default")==binding.namespace
        && snapshot["desired_replicas"]==1 && snapshot["ready"]==1 && snapshot["pending"]==0
        && snapshot["workspace"]["phase"]=="idle","configured regional deployment is not an idle ready singleton");
    let vms=snapshot["vms"].as_array().context("deployment VM inventory is missing")?;
    anyhow::ensure!(vms.len()==1 && vms[0]["healthy"]==true && vms[0]["draining"]==false,
        "configured regional deployment is unhealthy or admissions are draining");
    let response=client()?.get(reqwest::Url::parse(&binding.health_origin)?.join("healthz")?).send().await?.error_for_status()?;
    anyhow::ensure!(response.status().is_success(),"regional deployment health redirected");
    if let Some(result)=expected {
        anyhow::ensure!(result["admissionsOpen"]==true,"updated target has not reopened admissions");
        anyhow::ensure!(lifecycle["revision"]==result["applicationRevision"]
            && lifecycle["binarySha256"]==result["binarySha256"]
            && response.headers().get("x-ci-revision").and_then(|v|v.to_str().ok())==result["applicationRevision"].as_str()
            && response.headers().get("x-ci-binary-sha256").and_then(|v|v.to_str().ok())==result["binarySha256"].as_str()
            && response.headers().get("x-vm-id").and_then(|v|v.to_str().ok())==result["runtimeSandboxId"].as_str()
            && vms[0]["sandbox_id"]==result["runtimeSandboxId"],"live target does not match child observed result");
    }
    anyhow::ensure!(response.text().await?.trim()=="ok","regional deployment health body is not ok");
    Ok(())
}

fn continuous_bake_start(started: Option<chrono::DateTime<chrono::Utc>>,
    last_observed: Option<chrono::DateTime<chrono::Utc>>, now: chrono::DateTime<chrono::Utc>) -> Option<chrono::DateTime<chrono::Utc>> {
    // Reconciliation normally samples every three seconds. Controller downtime
    // or a failed sample cannot count as successful bake time.
    started.filter(|_| last_observed.is_some_and(|last| last <= now && now - last <= chrono::Duration::seconds(15)))
}

async fn reconcile_regional(state: &AppState, service: &str, parent: &str) -> Result<()> {
    let configured = bindings(state,service)?;
    let database = db::get_db()?;
    let Some(tx)=service_deploy::try_service_lifecycle_lock(database,service).await? else { return Ok(()); };
    let parent_row=tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT request,current_target,bake_seconds,status,stop_requested,targets FROM regional_application_updates WHERE operation_id=$1 AND service_id=$2 FOR UPDATE",
        vec![parent.into(),service.into()])).await?.context("regional parent is missing")?;
    let status:String=parent_row.try_get("","status")?;
    if !matches!(status.as_str(),"preparing"|"running"|"cancelling") { tx.commit().await?; return Ok(()); }
    let request:RegionalUpdateRequest=serde_json::from_value(parent_row.try_get("","request")?)?;
    let ordinal:Option<i32>=parent_row.try_get("","current_target")?;
    let bake_seconds:i32=parent_row.try_get("","bake_seconds")?;
    let frozen:Value=parent_row.try_get("","targets")?;
    anyhow::ensure!(frozen.as_array().is_some_and(|v|v.len()==configured.len()),"configured target count changed after acceptance");
    for (index,b) in configured.iter().enumerate() { let f=&frozen[index]; anyhow::ensure!(f["ordinal"]==index && f["region"]==b.region
        && f["deploymentId"]==b.deployment_id && f["namespace"]==b.namespace
        && f["authority"].as_str().map(|v|v.trim_end_matches('/'))==Some(b.authority.trim_end_matches('/'))
        && f["healthOrigin"].as_str().map(|v|v.trim_end_matches('/'))==Some(b.health_origin.trim_end_matches('/')),
        "configured regional target set or order changed after acceptance"); }

    let stop:bool=parent_row.try_get("","stop_requested")?;
    if stop {
        let rows=tx.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT ordinal,child_operation_id,status,activated FROM regional_application_update_targets WHERE parent_operation_id=$1 ORDER BY ordinal FOR UPDATE",[parent.into()])).await?;
        if let Some(row)=rows.iter().find(|r| !r.try_get::<bool>("","activated").unwrap_or(true)
            && !matches!(r.try_get::<String>("","status").unwrap_or_default().as_str(),"cancelled"|"failed")) {
            let i:i32=row.try_get("","ordinal")?; let id:String=row.try_get("","child_operation_id")?;
            let binding=configured.get(usize::try_from(i)?).context("cancel target missing")?;
            let response=client()?.post(endpoint(binding,&id)?.join(&format!("{id}/cancel"))?).bearer_auth(token(state,binding).await?)
                .json(&json!({"parentOperationId":parent})).send().await?;
            anyhow::ensure!(response.status().is_success(),"regional child cancellation unavailable");
            let observed:Value=response.json().await?;
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET status='cancelled',observation=$3,observed_at=now(),error=NULL WHERE parent_operation_id=$1 AND ordinal=$2",
                vec![parent.into(),i.into(),observed.into()])).await?;
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_updates SET status='cancelling',updated_at=now() WHERE operation_id=$1",[parent.into()])).await?;
            tx.commit().await?; return Ok(())
        }
        if let Some(i)=ordinal {
            let row=&rows[usize::try_from(i)?];
            if row.try_get::<bool>("","activated")? && !matches!(row.try_get::<String>("","status")?.as_str(),"passed"|"failed") {
                // Never classify an outcome-unknown mutation as cancelled: normal observation below settles it.
            } else {
                tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                    "UPDATE regional_application_updates SET status='failed',error='regional update cancelled',updated_at=now() WHERE operation_id=$1",[parent.into()])).await?;
                tx.commit().await?; return Ok(())
            }
        } else {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_updates SET status='cancelled',error='regional update cancelled before activation',updated_at=now() WHERE operation_id=$1",[parent.into()])).await?;
            tx.commit().await?; return Ok(())
        }
    }

    if status=="preparing" {
        let row=tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT ordinal,child_operation_id FROM regional_application_update_targets WHERE parent_operation_id=$1 AND status IN ('frozen','preparing') ORDER BY ordinal LIMIT 1 FOR UPDATE",[parent.into()])).await?;
        if let Some(row)=row {
            let i:i32=row.try_get("","ordinal")?; let id:String=row.try_get("","child_operation_id")?;
            let binding=configured[usize::try_from(i)?];
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET status='preparing',error=NULL WHERE parent_operation_id=$1 AND ordinal=$2",
                vec![parent.into(),i.into()])).await?;
            // Freeze the durable attempt before transport and do not retain a
            // database transaction while CI performs preparation.
            tx.commit().await?;
            let prepared=prepare(binding,parent,&id,&token(state,binding).await?).await?;
            verify_release(binding,&request,&id,&prepared)?;
            let hash=prepared["intentHash"].as_str().unwrap().to_owned();
            let persist=service_deploy::try_service_lifecycle_lock(database,service).await?
                .context("application lifecycle is busy after preparation")?;
            persist.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET status='prepared',intent_hash=$3,observation=$4,observed_at=now() WHERE parent_operation_id=$1 AND ordinal=$2 AND status='preparing' AND EXISTS(SELECT 1 FROM regional_application_updates p WHERE p.operation_id=$1 AND p.status='preparing' AND NOT p.stop_requested)",
                vec![parent.into(),i.into(),hash.into(),prepared.into()])).await?;
            persist.commit().await?; return Ok(())
        }
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_updates SET status='running',current_target=0,updated_at=now(),error=NULL WHERE operation_id=$1",[parent.into()])).await?;
        tx.commit().await?; return Ok(())
    }

    let ordinal=ordinal.context("running regional parent omitted current target")?;
    let binding=configured.get(usize::try_from(ordinal)?).context("frozen target ordinal is no longer configured")?;
    let row=tx.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT child_operation_id,intent_hash,status,activated,bake_started_at,observed_at FROM regional_application_update_targets WHERE parent_operation_id=$1 AND ordinal=$2 FOR UPDATE",
        vec![parent.into(),ordinal.into()])).await?.context("regional target is missing")?;
    for survivor in configured.iter().enumerate().filter(|(i,_)| *i != ordinal as usize).map(|(_,b)|b) { live_healthy(state,survivor,None).await?; }
    let id: String = row.try_get("","child_operation_id")?;
    let hash: String = row.try_get::<Option<String>>("","intent_hash")?.context("regional target was not prepared")?;
    let bearer = token(state,binding).await?;
    let mut observed = read(binding,&id,&bearer).await?;
    verify(binding,&id,&hash,&observed)?;
    verify_release(binding,&request,&id,&observed)?;
    if observed["phase"] == "prepared" && stop {
        let response=client()?.post(endpoint(binding,&id)?.join(&format!("{id}/cancel"))?).bearer_auth(&bearer)
            .json(&json!({"parentOperationId":parent})).send().await?;
        anyhow::ensure!(response.status().is_success(),"unactivated child cancellation unresolved");
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_update_targets SET activated=false,status='cancelled',observed_at=now() WHERE parent_operation_id=$1 AND ordinal=$2",
            vec![parent.into(),ordinal.into()])).await?;
        tx.commit().await?; return Ok(());
    }
    if observed["phase"] == "prepared" && !stop {
        if !row.try_get::<bool>("","activated")? {
            // Record the possible external effect before transport. On the
            // next cycle cancellation must observe this child, not skip it.
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET activated=true,status='activating',observed_at=now() WHERE parent_operation_id=$1 AND ordinal=$2",
                vec![parent.into(),ordinal.into()])).await?;
            tx.commit().await?; return Ok(());
        }
        let response = client()?.post(endpoint(binding,&id)?).bearer_auth(&bearer)
            .json(&json!({"intentHash":hash})).send().await?;
        if response.status().is_success() { observed=read(binding,&id,&bearer).await?; verify(binding,&id,&hash,&observed)?; }
    }
    if observed["phase"] == "complete" && observed["status"] == "failed" {
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_update_targets SET status='failed',observation=$3,observed_at=now(),error='regional child failed' WHERE parent_operation_id=$1 AND ordinal=$2",
            vec![parent.into(),ordinal.into(),observed.into()])).await?;
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_updates SET status='cancelling',stop_requested=true,error='regional child failed; settling unactivated children',updated_at=now() WHERE operation_id=$1 AND current_target=$2",
            vec![parent.into(),ordinal.into()])).await?;
        tx.commit().await?; return Ok(());
    }
    if observed["phase"] == "complete" && observed["status"] == "passed" {
        let result=observed.get("result").filter(|v|v.is_object()).context("passed child omitted live result identity")?;
        anyhow::ensure!(result["applicationRevision"]==request.release.target_revision
            && result["binarySha256"]==request.release.binary_sha256,"child result does not match parent release");
        live_healthy(state,binding,Some(result)).await?;
        let now = chrono::Utc::now();
        let started = continuous_bake_start(row.try_get("","bake_started_at")?,row.try_get("","observed_at")?,now);
        if started.is_some_and(|time| now >= time + chrono::Duration::seconds(i64::from(bake_seconds))) {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET status='passed',observation=$3,observed_at=now(),error=NULL WHERE parent_operation_id=$1 AND ordinal=$2",
                vec![parent.into(),ordinal.into(),observed.into()])).await?;
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_updates SET current_target=CASE WHEN stop_requested OR current_target+1=jsonb_array_length(targets) THEN NULL ELSE current_target+1 END,status=CASE WHEN stop_requested THEN 'failed' WHEN current_target+1=jsonb_array_length(targets) THEN 'passed' ELSE 'running' END,updated_at=now(),error=CASE WHEN stop_requested THEN 'regional update cancelled after active child settled' ELSE NULL END WHERE operation_id=$1 AND current_target=$2",
                vec![parent.into(),ordinal.into()])).await?;
        } else {
            tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE regional_application_update_targets SET status='baking',observation=$3,observed_at=now(),bake_started_at=$4,error=NULL WHERE parent_operation_id=$1 AND ordinal=$2",
                vec![parent.into(),ordinal.into(),observed.into(),started.unwrap_or(now).into()])).await?;
        }
    } else {
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_update_targets SET status='activating',observation=$3,observed_at=now(),bake_started_at=NULL,error=NULL WHERE parent_operation_id=$1 AND ordinal=$2",
            vec![parent.into(),ordinal.into(),observed.into()])).await?;
        tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_updates SET status='running',updated_at=now(),error=NULL WHERE operation_id=$1 AND current_target=$2",
            vec![parent.into(),ordinal.into()])).await?;
    }
    tx.commit().await?; Ok(())
}

async fn status_value(database:&impl ConnectionTrait,service:&str,id:&str)->Result<Value> {
    let parent=database.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT operation_id,service_id,request_hash,request,status,current_target,error FROM regional_application_updates WHERE operation_id=$1 AND service_id=$2",
        vec![id.into(),service.into()])).await?.context("regional update not found")?;
    let rows=database.query_all(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT region,deployment_id,authority,health_origin,child_operation_id,intent_hash,status,observation FROM regional_application_update_targets WHERE parent_operation_id=$1 ORDER BY ordinal",[id.into()])).await?;
    let targets:Result<Vec<Value>>=rows.into_iter().map(|r|Ok(json!({"region":r.try_get::<String>("","region")?,
        "deploymentId":r.try_get::<String>("","deployment_id")?,"authority":r.try_get::<String>("","authority")?,
        "healthOrigin":r.try_get::<String>("","health_origin")?,"operationId":r.try_get::<String>("","child_operation_id")?,
        "intentHash":r.try_get::<Option<String>>("","intent_hash")?,"status":r.try_get::<String>("","status")?,
        "observation":r.try_get::<Option<Value>>("","observation")?}))).collect();
    Ok(json!({"apiVersion":"regional-v1","operationId":parent.try_get::<String>("","operation_id")?,
        "serviceId":parent.try_get::<String>("","service_id")?,"requestHash":parent.try_get::<String>("","request_hash")?,
        "request":parent.try_get::<Value>("","request")?,"status":parent.try_get::<String>("","status")?,
        "targets":targets?,"currentTarget":parent.try_get::<Option<i32>>("","current_target")?,
        "reason":parent.try_get::<Option<String>>("","error")?}))
}

async fn authorize(state:&AppState,service:&str,headers:&HeaderMap)->Result<(),StatusCode> {
    let configured=bindings(state,service).map_err(|_|StatusCode::NOT_FOUND)?;
    let bearer=token(state,configured[0]).await.map_err(|_|StatusCode::SERVICE_UNAVAILABLE)?;
    auth::require_internal_api_key(headers,&bearer)
}

pub async fn get(State(state): State<AppState>, Path((service,id)): Path<(String,String)>, headers: HeaderMap) -> (StatusCode,Json<Value>) {
    if let Err(status)=authorize(&state,&service,&headers).await {return (status,Json(json!({"error":"Unauthorized"})))}
    match db::get_db().and_then(|db|Ok(db)) { Ok(database)=>match status_value(database,&service,&id).await {
        Ok(value)=>(StatusCode::OK,Json(value)),Err(_)=>(StatusCode::NOT_FOUND,Json(json!({"error":"Not found"})))},
        Err(_)=>(StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"Update status unavailable"}))) }
}

pub async fn cancel(State(state):State<AppState>,Path((service,id)):Path<(String,String)>,headers:HeaderMap)->(StatusCode,Json<Value>) {
    if let Err(status)=authorize(&state,&service,&headers).await {return (status,Json(json!({"error":"Unauthorized"})))}
    let result:Result<Value>=async {
        let tx=service_deploy::try_service_lifecycle_lock(db::get_db()?,&service).await?.context("application lifecycle is busy")?;
        let changed=tx.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_updates SET stop_requested=true,status=CASE WHEN status IN ('preparing','running') THEN 'cancelling' ELSE status END,error=CASE WHEN status IN ('preparing','running') THEN 'cancellation requested' ELSE error END,updated_at=now() WHERE operation_id=$1 AND service_id=$2",
            vec![id.clone().into(),service.clone().into()])).await?.rows_affected();
        anyhow::ensure!(changed==1,"regional update not found"); tx.commit().await?;
        status_value(db::get_db()?,&service,&id).await
    }.await;
    match result {Ok(v)=>(StatusCode::ACCEPTED,Json(v)),Err(e)=>(StatusCode::CONFLICT,Json(json!({"error":e.to_string()})))}
}

pub async fn run_reconciler(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let result: Result<()> = async {
            let database = db::get_db()?;
            let rows = database.query_all(Statement::from_string(DbBackend::Postgres,
                "SELECT operation_id,service_id,intent_hash FROM application_updates WHERE status IN ('accepted','running') ORDER BY updated_at LIMIT 100")).await?;
            for row in rows {
                let id: String = row.try_get("","operation_id")?;
                let service: String = row.try_get("","service_id")?;
                let hash: String = row.try_get("","intent_hash")?;
                if let Err(error) = reconcile(&state,&service,&id,&hash).await {
                    tracing::warn!(%error,%id,"application update reconciliation blocked");
                    database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                        "UPDATE application_updates SET error='Application lifecycle unavailable; outcome unknown',updated_at=now() WHERE operation_id=$1 AND status IN ('accepted','running')",[id.into()])).await?;
                }
            }
            let regional = database.query_all(Statement::from_string(DbBackend::Postgres,
                "SELECT operation_id,service_id FROM regional_application_updates WHERE status IN ('preparing','running','cancelling') ORDER BY updated_at LIMIT 100")).await?;
            for row in regional {
                let id:String=row.try_get("","operation_id")?; let service:String=row.try_get("","service_id")?;
                if let Err(error)=reconcile_regional(&state,&service,&id).await {
                    tracing::warn!(%error,%id,"regional application update reconciliation blocked");
                    database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                        "UPDATE regional_application_update_targets SET bake_started_at=NULL WHERE parent_operation_id=$1 AND status='baking'",[id.clone().into()])).await?;
                    database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
                        "UPDATE regional_application_updates SET error='Regional lifecycle unavailable; outcome unknown',updated_at=now() WHERE operation_id=$1 AND status IN ('preparing','running','cancelling')",[id.into()])).await?;
                }
            }
            Ok(())
        }.await;
        if let Err(error) = result { tracing::warn!(%error,"application reconciler unavailable"); }
    }
}

#[cfg(test)]
mod regional_request_tests {
    use super::*;

    #[test]
    fn missed_observations_restart_bake_instead_of_counting_downtime() {
        let now = chrono::Utc::now();
        let start = Some(now - chrono::Duration::seconds(90));
        assert_eq!(continuous_bake_start(start,Some(now - chrono::Duration::seconds(15)),now),start);
        assert_eq!(continuous_bake_start(start,Some(now - chrono::Duration::seconds(16)),now),None);
        assert_eq!(continuous_bake_start(start,None,now),None);
        assert_eq!(continuous_bake_start(start,Some(now + chrono::Duration::seconds(1)),now),None);
    }

    fn request() -> RegionalUpdateRequest {
        RegionalUpdateRequest { api_version:"regional-v1".into(),operation_id:"parent-1".into(),
            release:ReleaseIdentity {run_id:"run-1".into(),target_revision:"rev-1".into(),
                artifact_digest:"a".repeat(64),binary_sha256:"b".repeat(64)} }
    }

    #[test]
    fn regional_parent_hash_and_child_identity_are_stable() {
        let original=request_hash(&request()).unwrap();
        let mut changed=request(); changed.release.binary_sha256="c".repeat(64);
        assert_ne!(original,request_hash(&changed).unwrap());
        assert_eq!(child_id("parent-1","https://us.example/","ci-us").unwrap(),
            child_id("parent-1","https://us.example","ci-us").unwrap());
        assert_ne!(child_id("parent-1","https://us.example","ci-us").unwrap(),
            child_id("parent-1","https://eu.example","ci-eu").unwrap());
        let invalid=json!({"apiVersion":"regional-v1","operationId":"parent-1","release":{"runId":"run-1",
            "targetRevision":"rev-1","artifactDigest":"digest","binarySha256":"binary"},"targets":[]});
        assert!(serde_json::from_value::<RegionalUpdateRequest>(invalid).is_err());
    }
}

/// Runs in the adoption test's disposable database after installing the binding.
#[cfg(test)]
pub(super) async fn test_durable_updates(state: &AppState) -> Result<()> {
    use axum::{Router, routing::get};
    use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
    let binding = binding(state,"ci")?.clone();
    let observed = Arc::new(Mutex::new(json!({"applicationId":"ci","deploymentId":"ci-eu1",
        "authority":binding.authority,"intentHash":"exact-hash","phase":"prepared","status":"running",
        "targetRevision":"next-revision","artifactDigest":"next-artifact","runId":"release-run"})));
    let activations = Arc::new(AtomicUsize::new(0));
    let read_state = observed.clone();
    let write_state = observed.clone();
    let count = activations.clone();
    let app = Router::new().route("/api/lifecycle/updates/{id}", get(move |Path(id): Path<String>, headers: HeaderMap| {
        let status = read_state.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer test-admin");
            let mut status = status.lock().unwrap().clone(); status["operationId"] = json!(id);
            Json(status)
        }
    }).post(move |headers: HeaderMap, Json(body): Json<Value>| {
        let status = write_state.clone(); let count = count.clone();
        async move {
            assert_eq!(headers["authorization"],"Bearer test-admin");
            assert_eq!(body["intentHash"],"exact-hash");
            count.fetch_add(1,Ordering::SeqCst);
            status.lock().unwrap()["phase"] = json!("draining");
            StatusCode::BAD_GATEWAY // Mutation committed but its response was lost.
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut binding = binding;
    binding.health_origin = format!("http://{}",listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
    let mut config = (*state.config).clone();
    config.external_service_bindings = vec![binding.clone()];
    let state = AppState { config:Arc::new(config), ..state.clone() };
    let r = UpdateRequest { operation_id:"app-update-1".into(),intent_hash:"exact-hash".into() };
    let (status, _) = create(State(state.clone()),Path("ci".into()),HeaderMap::new(),
        Json(serde_json::to_value(UpdateRequest { operation_id:r.operation_id.clone(),intent_hash:r.intent_hash.clone() })?)).await;
    assert_eq!(status,StatusCode::UNAUTHORIZED);
    observed.lock().unwrap()["applicationId"] = json!("another-app");
    assert!(accept(&binding,&r,"test-admin").await.is_err());
    observed.lock().unwrap()["applicationId"] = json!("ci");
    let receipt = accept(&binding,&r,"test-admin").await?;
    assert_eq!(activations.load(Ordering::SeqCst),0,"acceptance cannot replace the controller inline");
    assert_eq!(accept(&binding,&r,"test-admin").await?,receipt);
    let changed = UpdateRequest { operation_id:r.operation_id.clone(),intent_hash:"changed".into() };
    assert!(accept(&binding,&changed,"test-admin").await.is_err());
    let competing = UpdateRequest { operation_id:"app-update-2".into(),intent_hash:r.intent_hash.clone() };
    let error = accept(&binding,&competing,"test-admin").await.unwrap_err();
    assert!(format!("{error:#}").contains("application_updates_active"), "{error:#}");
    service_deploy::wait_for_test_lifecycle_rollback(db::get_db()?,"ci").await?;
    assert!(reconcile(&state,"ci",&r.operation_id,&r.intent_hash).await.is_err());
    reconcile(&state.clone(),"ci",&r.operation_id,&r.intent_hash).await?;
    assert_eq!(activations.load(Ordering::SeqCst),1);
    let inventory = super::service_discovery::read_inventory(db::get_db()?,None).await?;
    assert_eq!(inventory["services"][0]["update"]["phase"],"draining");
    {
        let mut status = observed.lock().unwrap();
        status["phase"] = json!("complete"); status["status"] = json!("passed");
    }
    reconcile(&state,"ci",&r.operation_id,&r.intent_hash).await?;
    let row = db::get_db()?.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT status FROM application_updates WHERE operation_id='app-update-1'")).await?.unwrap();
    assert_eq!(row.try_get::<String>("","status")?,"passed");
    assert_eq!(activations.load(Ordering::SeqCst),1);
    server.abort();
    Ok(())
}

/// Exercises the regional protocol against real PostgreSQL and two HTTP peers.
/// This deliberately lives in the adoption fixture so the rows are created in
/// the same database and under the same lifecycle lock as production.
#[cfg(test)]
pub(super) async fn test_regional_updates(state: &AppState) -> Result<()> {
    use axum::{Router, routing::{get, post}};
    use base64::Engine;
    use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

    #[derive(Default)]
    struct Peer { phase: AtomicUsize, prepares: AtomicUsize, activations: AtomicUsize, cancels: AtomicUsize }
    async fn peer(region: &'static str, deployment: &'static str, peer: Arc<Peer>)
        -> Result<(ExternalServiceBinding,tokio::task::JoinHandle<()>)> {
        let lifecycle=peer.clone(); let health=peer.clone(); let reads=peer.clone();
        let prepares=peer.clone(); let activates=peer.clone(); let cancels=peer.clone();
        let origin=Arc::new(Mutex::new(String::new()));
        let lifecycle_origin=origin.clone(); let read_origin=origin.clone(); let prepare_origin=origin.clone();
        let app=Router::new()
            .route("/v1/secrets/read",post(||async { Json(json!({"path":"test/token","version":1,
                "status":"active","valueBase64":base64::engine::general_purpose::STANDARD.encode("test-admin"),
                "createdAt":chrono::Utc::now(),"metadata":{}})) }))
            .route("/api/lifecycle",get(move || { let p=lifecycle.clone(); let origin=lifecycle_origin.clone(); async move { Json(json!({
                "applicationId":"ci","deploymentId":deployment,"authority":origin.lock().unwrap().clone(),"bootId":"boot-1",
                "revision":if p.phase.load(Ordering::SeqCst)==3{"rev-regional"}else{"old-revision"},
                "binarySha256":if p.phase.load(Ordering::SeqCst)==3{"b".repeat(64)}else{"c".repeat(64)},
                "admissionsOpen":true,"capabilities":["regional-release-update-v1"]})) }}))
            .route("/healthz",get(move || { let p=health.clone(); async move {
                let updated=p.phase.load(Ordering::SeqCst)==3;
                ([("x-ci-revision",if updated{"rev-regional".into()}else{"old-revision".into()}),
                  ("x-ci-binary-sha256",if updated{"b".repeat(64)}else{"c".repeat(64)}),
                  ("x-vm-id",format!("sb-{region}"))],"ok") }}))
            .route("/deployments/{id}",get(move |Path(id):Path<String>,headers:HeaderMap| async move {
                assert_eq!(headers["authorization"],"Bearer test-admin");
                Json(json!({"spec":{"id":id,"namespace":"default"},"desired_replicas":1,"ready":1,"pending":0,
                    "workspace":{"phase":"idle"},"vms":[{"sandbox_id":format!("sb-{region}"),"healthy":true,"draining":false}]}))
            }))
            .route("/api/lifecycle/updates/{id}",get(move |Path(id):Path<String>,headers:HeaderMap| {
                let p=reads.clone(); let origin=read_origin.clone(); async move { assert_eq!(headers["authorization"],"Bearer test-admin");
                    let phase=p.phase.load(Ordering::SeqCst); Json(json!({"operationId":id,"applicationId":"ci",
                        "deploymentId":deployment,"authority":origin.lock().unwrap().clone(),"intentHash":format!("intent-{region}"),
                        "runId":"run-regional","targetRevision":"rev-regional","artifactDigest":"a".repeat(64),
                        "binarySha256":"b".repeat(64),"phase":match phase {0=>"new",1=>"prepared",2=>"draining",_=>"complete"},
                        "status":if phase==3{"passed"}else{"running"},"result":if phase==3 {json!({"applicationRevision":"rev-regional",
                            "binarySha256":"b".repeat(64),"runtimeSandboxId":format!("sb-{region}"),"admissionsOpen":true})} else {Value::Null}})) }
            }).post(move |headers:HeaderMap,Json(body):Json<Value>| { let p=activates.clone(); async move {
                assert_eq!(headers["authorization"],"Bearer test-admin"); assert_eq!(body["intentHash"],format!("intent-{region}"));
                p.activations.fetch_add(1,Ordering::SeqCst); p.phase.store(2,Ordering::SeqCst);
                StatusCode::BAD_GATEWAY // committed mutation, lost response
            }}))
            .route("/api/lifecycle/updates/{id}/prepare",post(move |Path(id):Path<String>,headers:HeaderMap| {
                let p=prepares.clone(); let origin=prepare_origin.clone(); async move { assert_eq!(headers["authorization"],"Bearer test-admin");
                    p.prepares.fetch_add(1,Ordering::SeqCst); p.phase.store(1,Ordering::SeqCst);
                    Json(json!({"operationId":id,"applicationId":"ci","deploymentId":deployment,"authority":origin.lock().unwrap().clone(),
                        "intentHash":format!("intent-{region}"),"runId":"run-regional","targetRevision":"rev-regional",
                        "artifactDigest":"a".repeat(64),"binarySha256":"b".repeat(64),"phase":"prepared","status":"running"})) }
            }))
            .route("/api/lifecycle/updates/{id}/cancel",post(move |Path(id):Path<String>| { let p=cancels.clone(); async move {
                p.cancels.fetch_add(1,Ordering::SeqCst); Json(json!({"operationId":id,"phase":"cancelled"})) }}));
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base=format!("http://{}",listener.local_addr()?);
        *origin.lock().unwrap()=base.clone();
        let task=tokio::spawn(async move { axum::serve(listener,app).await.unwrap() });
        Ok((ExternalServiceBinding { service_id:"ci".into(),authority:base.clone(),region:region.into(),namespace:"default".into(),
            deployment_id:deployment.into(),health_origin:base,lifecycle_token_secret_path:"test/token".into(),token_secret_path:"test/token".into() },task))
    }

    let us=Arc::new(Peer::default()); let eu=Arc::new(Peer::default());
    let (us_binding,us_task)=peer("us3","ci-us3",us.clone()).await?;
    let (eu_binding,eu_task)=peer("eu1","ci-eu1",eu.clone()).await?;
    let database=db::get_db()?;
    database.execute(Statement::from_string(DbBackend::Postgres,"DELETE FROM external_service_bindings WHERE service_id='ci'")).await?;
    for (binding,sandbox) in [(&us_binding,"sb-us3"),(&eu_binding,"sb-eu1")] {
        database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO external_service_bindings(service_id,authority,namespace,deployment_id,region,source_rollout_revision,spec_etag,artifact_digest,application_revision,runtime_sandbox_id,runtime_port,observed_at,evidence) VALUES($1,$2,'default',$3,$4,'generation-8','etag',$5,'old-revision',$6,9500,now(),$7)",
            vec!["ci".into(),binding.authority.clone().into(),binding.deployment_id.clone().into(),binding.region.clone().into(),"c".repeat(64).into(),sandbox.into(),json!({"healthOrigin":binding.health_origin}).into()])).await?;
    }
    // Startup migrations must remain replayable after the PK contains two regional rows.
    database.execute_unprepared(include_str!("../../migrations/046_regional_external_application_updates.sql")).await?;
    let mut config=(*state.config).clone(); config.external_service_bindings=vec![us_binding,eu_binding];
    config.heyosecret_url=config.external_service_bindings[0].health_origin.clone(); config.regional_application_bake_seconds=1;
    let state=AppState { config:Arc::new(config),..state.clone() };
    let request=RegionalUpdateRequest { api_version:"regional-v1".into(),operation_id:"regional-main".into(),release:ReleaseIdentity {
        run_id:"run-regional".into(),target_revision:"rev-regional".into(),artifact_digest:"a".repeat(64),binary_sha256:"b".repeat(64)}};
    accept_regional(&state,"ci",&request).await?;
    let frozen=status_value(database,"ci","regional-main").await?;
    assert_eq!(frozen["targets"].as_array().unwrap().len(),2,"acceptance must freeze both configured targets");
    reconcile_regional(&state,"ci","regional-main").await?;
    assert_eq!((us.activations.load(Ordering::SeqCst),eu.activations.load(Ordering::SeqCst)),(0,0),"preparation activated a target");
    reconcile_regional(&state,"ci","regional-main").await?;
    reconcile_regional(&state,"ci","regional-main").await?; // preparing -> running only after both children
    reconcile_regional(&state,"ci","regional-main").await?; // durable pre-activation marker
    reconcile_regional(&state,"ci","regional-main").await?; // lost response after committed activation
    assert_eq!((us.activations.load(Ordering::SeqCst),eu.activations.load(Ordering::SeqCst)),(1,0),"unknown first outcome activated peer");
    let restarted=state.clone(); // no process-local controller state may be required
    us.phase.store(3,Ordering::SeqCst);
    reconcile_regional(&restarted,"ci","regional-main").await?;
    assert_eq!(eu.activations.load(Ordering::SeqCst),0,"first target bake did not block peer");
    database.execute(Statement::from_string(DbBackend::Postgres,"UPDATE regional_application_update_targets SET bake_started_at=now()-interval '2 seconds',observed_at=now() WHERE parent_operation_id='regional-main' AND ordinal=0")).await?;
    reconcile_regional(&state,"ci","regional-main").await?;
    reconcile_regional(&state,"ci","regional-main").await?;
    reconcile_regional(&state,"ci","regional-main").await?;
    assert_eq!(eu.activations.load(Ordering::SeqCst),1,"healthy completed first target did not release peer");
    eu.phase.store(3,Ordering::SeqCst); reconcile_regional(&state,"ci","regional-main").await?;
    assert_eq!(status_value(database,"ci","regional-main").await?["status"],"running","parent passed before second bake");
    database.execute(Statement::from_string(DbBackend::Postgres,"UPDATE regional_application_update_targets SET bake_started_at=now()-interval '2 seconds',observed_at=now() WHERE parent_operation_id='regional-main' AND ordinal=1")).await?;
    reconcile_regional(&state,"ci","regional-main").await?;
    assert_eq!(status_value(database,"ci","regional-main").await?["status"],"passed");
    let mut altered=request.clone(); altered.release.binary_sha256="d".repeat(64);
    let error = accept_regional(&state,"ci",&altered).await.unwrap_err();
    assert_eq!(error.to_string(),"regional application update changed on replay");
    service_deploy::wait_for_test_lifecycle_rollback(database,"ci").await?;

    let mut cancelled=request; cancelled.operation_id="regional-cancelled".into();
    let held = service_deploy::try_service_lifecycle_lock(database,"ci").await?.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(2),
        accept_regional(&state,"ci",&cancelled)).await?.unwrap_err();
    assert_eq!(error.to_string(),"application lifecycle is busy");
    assert!(database.query_one(Statement::from_string(DbBackend::Postgres,
        "SELECT 1 FROM regional_application_updates WHERE operation_id='regional-cancelled'")).await?.is_none());
    held.rollback().await?;
    accept_regional(&state,"ci",&cancelled).await.context("accept cancellation scenario after rollback")?;
    database.execute(Statement::from_string(DbBackend::Postgres,"UPDATE regional_application_updates SET stop_requested=true,status='cancelling' WHERE operation_id='regional-cancelled'")).await?;
    reconcile_regional(&state,"ci","regional-cancelled").await?;
    reconcile_regional(&state,"ci","regional-cancelled").await?;
    reconcile_regional(&state,"ci","regional-cancelled").await?;
    assert_eq!(status_value(database,"ci","regional-cancelled").await?["status"],"cancelled","pre-prepare cancellation stranded parent");

    // A second deployment in the first region must finish before the next
    // region starts. Interleave configuration to catch flat-list execution.
    let second=Arc::new(Peer::default());
    let (second_binding,second_task)=peer("us3","ci-us5",second.clone()).await?;
    database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO external_service_bindings(service_id,authority,namespace,deployment_id,region,source_rollout_revision,spec_etag,artifact_digest,application_revision,runtime_sandbox_id,runtime_port,observed_at,evidence) VALUES('ci',$1,'default',$2,$3,'generation-8','etag',$4,'old-revision','sb-us5',9500,now(),$5)",
        vec![second_binding.authority.clone().into(),second_binding.deployment_id.clone().into(),second_binding.region.clone().into(),
            "c".repeat(64).into(),json!({"healthOrigin":second_binding.health_origin}).into()])).await?;
    database.execute_unprepared(include_str!("../../migrations/046_regional_external_application_updates.sql")).await?;
    database.execute_unprepared(include_str!("../../migrations/047_regional_deployment_membership.sql")).await?;
    let mut config=(*state.config).clone();
    config.external_service_bindings.push(second_binding);
    let state=AppState {config:Arc::new(config),..state};
    let mut request=cancelled; request.operation_id="regional-multiple".into();
    accept_regional(&state,"ci",&request).await?;
    let frozen=status_value(database,"ci",&request.operation_id).await?;
    assert_eq!(frozen["targets"].as_array().unwrap().iter().map(|t|t["deploymentId"].as_str().unwrap()).collect::<Vec<_>>(),
        vec!["ci-us3","ci-us5","ci-eu1"]);
    for peer in [&us,&second,&eu] { peer.activations.store(0,Ordering::SeqCst); }
    for _ in 0..4 { reconcile_regional(&state,"ci",&request.operation_id).await?; }
    for (ordinal,peer) in [&us,&second,&eu].into_iter().enumerate() {
        reconcile_regional(&state,"ci",&request.operation_id).await?;
        reconcile_regional(&state,"ci",&request.operation_id).await?;
        for (index,p) in [&us,&second,&eu].into_iter().enumerate() {
            assert_eq!(p.activations.load(Ordering::SeqCst),usize::from(index<=ordinal),"target activated out of regional order");
        }
        peer.phase.store(3,Ordering::SeqCst);
        reconcile_regional(&state,"ci",&request.operation_id).await?;
        assert_eq!(status_value(database,"ci",&request.operation_id).await?["status"],"running");
        database.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE regional_application_update_targets SET bake_started_at=now()-interval '2 seconds',observed_at=now() WHERE parent_operation_id=$1 AND ordinal=$2",
            vec![request.operation_id.clone().into(),(ordinal as i32).into()])).await?;
        reconcile_regional(&state,"ci",&request.operation_id).await?;
    }
    assert_eq!(status_value(database,"ci",&request.operation_id).await?["status"],"passed");
    us_task.abort(); eu_task.abort(); second_task.abort(); Ok(())
}
