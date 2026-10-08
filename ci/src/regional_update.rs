//! One durable release receipt; platform-owned regional membership and order.
//! The release job exits before any instance closes admissions.
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{sync::Arc, time::Duration};
use crate::{bus::JobMessage, controller_rollout as child, dispatch::Dispatcher, store::Store};

pub(crate) fn child_id(parent: &str, authority: &str, deployment: &str) -> String {
    let bytes = serde_json::to_vec(&json!([parent, authority.trim_end_matches('/'), deployment])).unwrap();
    format!("ci-region-{:x}", Sha256::digest(bytes))
}

fn hash(value: &Value) -> String {
    let mut value = value.clone(); value.sort_all_objects();
    format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()))
}

pub async fn request(d: &Dispatcher, msg: &JobMessage, step: &str, artifact: &str,
    workflow: Option<&str>) -> Result<String, String> {
    request_inner(d, msg, step, artifact, workflow).await.map_err(|e|e.to_string())
}

async fn request_inner(d: &Dispatcher, msg: &JobMessage, step: &str, artifact: &str,
    workflow: Option<&str>) -> Result<String> {
    let (application, authority, _) = child::application_target(d).map_err(anyhow::Error::msg)?;
    let (sha, stored) = child::published_artifact(&d.store, &msg.run_id,
        d.config.controller_repository.as_deref(), artifact, workflow).await.map_err(anyhow::Error::msg)?;
    let (_, git_ref) = crate::release::deployment_source(&d.store, &msg.run_id)
        .await.map_err(anyhow::Error::msg)?;
    anyhow::ensure!((1..=256 * 1024 * 1024).contains(&stored.size_bytes), "CI artifact exceeds verification budget");
    let digest = stored.digest.as_deref().context("artifact omitted digest")?;
    let bytes = d.artifacts.get(&stored).await?;
    anyhow::ensure!(format!("{:x}",Sha256::digest(&bytes)) == digest, "CI artifact digest mismatch");
    let binary = child::artifact_identity(&bytes, &sha).map_err(anyhow::Error::msg)?;
    let id = format!("ci-regional-{:x}",Sha256::digest(step.as_bytes()));
    let command = json!({"apiVersion":"regional-v1","operationId":id,
        "release":{"runId":msg.run_id,"targetRevision":sha,"artifactDigest":digest,"binarySha256":binary}});
    let mut tx = d.store.pool().begin().await?;
    // Lock run before receipt, matching cancellation and terminal roll-up.
    let status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
        .bind(&msg.run_id).fetch_one(&mut *tx).await?;
    anyhow::ensure!(!matches!(status.as_str(),"cancelled"|"failure"), "release is no longer eligible");
    let inserted = sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) SELECT $1,s.id,r.id,j.id,$3,$4,'running','preparing',$5,$8 FROM ci_step s JOIN ci_job j ON j.id=s.job_id JOIN ci_run r ON r.id=j.run_id WHERE s.id=$2 AND r.id=$6 AND j.id=$7 AND j.status='running' ON CONFLICT(step_id) DO NOTHING")
        .bind(&id).bind(step).bind(application).bind(hash(&command)).bind(&sha).bind(&msg.run_id).bind(&msg.job_id).bind(&git_ref)
        .execute(&mut *tx).await?.rows_affected();
    if inserted == 1 {
        sqlx::query("INSERT INTO ci_regional_update(id,application_id,authority,request,artifact_name,workflow) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(&id).bind(application).bind(authority.trim_end_matches('/')).bind(&command).bind(artifact).bind(workflow)
            .execute(&mut *tx).await?;
        Store::add_service_deployment_event(&mut tx,&id).await?;
    } else {
        let saved = sqlx::query("SELECT request,application_id,authority,artifact_name,workflow FROM ci_regional_update WHERE id=$1")
            .bind(&id).fetch_optional(&mut *tx).await?.context("release step is no longer running or already has another receipt")?;
        anyhow::ensure!(saved.get::<Value,_>("request") == command
            && saved.get::<String,_>("application_id") == application
            && saved.get::<String,_>("authority") == authority.trim_end_matches('/')
            && saved.get::<String,_>("artifact_name") == artifact
            && saved.get::<Option<String>,_>("workflow").as_deref() == workflow, "regional request changed on replay");
    }
    tx.commit().await?;
    Ok(format!("[ci] regional update {id} recorded; run waits for every configured region and final health bake\n"))
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Preparation { pub parent_operation_id: String, pub operation_id: String, pub application_id: String }

pub async fn prepare(d: &Dispatcher, id: &str, r: &Preparation) -> Result<Value> {
    let (application, authority, _) = child::application_target(d).map_err(anyhow::Error::msg)?;
    let (deployment, base, token) = child::target(d).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(r.application_id == application && r.operation_id == id
        && child_id(&r.parent_operation_id,base,deployment) == id, "preparation target identity mismatch");
    let _permit = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let row = sqlx::query("SELECT u.*,s.run_id,s.step_id FROM ci_regional_update u JOIN ci_service_deployment s ON s.id=u.id WHERE u.id=$1 AND u.attempted")
        .bind(&r.parent_operation_id).fetch_optional(d.store.pool()).await?.context("regional parent unavailable")?;
    anyhow::ensure!(row.get::<String,_>("application_id") == application
        && row.get::<String,_>("authority") == authority.trim_end_matches('/'), "regional authority changed");
    let run: String = row.get("run_id"); let step: String = row.get("step_id");
    let artifact: String = row.get("artifact_name"); let workflow: Option<String> = row.get("workflow");
    child::prepare(child::PreparationInputs {
        store:&d.store,artifacts:d.artifacts.as_ref(),run_id:&run,step_id:&step,artifact_name:&artifact,
        workflow:workflow.as_deref(),controller_repository:d.config.controller_repository.as_deref(),
        artifact_store_url:d.config.artifacts.as_ref().map(|a|a.url.as_str()), application_id:Some(application),
        parent_operation_id:Some(&r.parent_operation_id), target:child::PreparationTarget {
            deployment,base_url:base,token,public_url:&d.config.public_url,source_boot:d.executor.boot_id(),
        },
    }).await.map_err(anyhow::Error::msg)?;
    child::application_status(d,id).await.map_err(anyhow::Error::msg)
}

pub async fn cancel_child(d: &Dispatcher, id: &str, parent: &str) -> Result<Value> {
    let (application, _, _) = child::application_target(d).map_err(anyhow::Error::msg)?;
    let (deployment, base, _) = child::target(d).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(child_id(parent,base,deployment) == id, "cancellation target mismatch");
    let _permit = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let mut tx = d.store.pool().begin().await?;
    // A parent tombstone prevents a delayed preparation callback from creating
    // a new child after cancellation was acknowledged.
    let row = sqlx::query("SELECT application_id FROM ci_regional_update WHERE id=$1 FOR UPDATE")
        .bind(parent).fetch_optional(&mut *tx).await?.context("parent unavailable")?;
    anyhow::ensure!(row.get::<String,_>("application_id") == application, "application mismatch");
    sqlx::query("INSERT INTO ci_regional_cancelled_child(id,parent_id) VALUES($1,$2) ON CONFLICT(id) DO NOTHING")
        .bind(id).bind(parent).execute(&mut *tx).await?;
    if let Some(row) = sqlx::query("SELECT deployment_record_id,activation_hash,phase FROM ci_controller_rollout WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await? {
        anyhow::ensure!(row.get::<Option<String>,_>("deployment_record_id").as_deref() == Some(parent), "child parent mismatch");
        anyhow::ensure!(row.get::<Option<String>,_>("activation_hash").is_none(), "activated child must finish through reconciliation");
        sqlx::query("UPDATE ci_controller_rollout SET phase='complete',result='failed',message='Cancelled before activation',updated_at=now() WHERE id=$1")
            .bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(json!({"operationId":id,"parentOperationId":parent,"status":"cancelled"}))
}

fn verify_observation(observed: &Value, command: &Value, application: &str, previous: Option<&Value>) -> Result<Option<&'static str>> {
    anyhow::ensure!(observed["apiVersion"] == "regional-v1" && observed["request"] == *command
        && observed["requestHash"] == hash(command) && observed["operationId"] == command["operationId"]
        && observed["serviceId"] == application, "regional receipt identity mismatch");
    let targets = observed["targets"].as_array().context("regional membership missing")?;
    let mut regions = std::collections::HashSet::new();
    let mut children = std::collections::HashSet::new();
    let identities = |values: &[Value]| -> Vec<Value> { values.iter().map(|t|json!([
        t["region"],t["deploymentId"],t["authority"],t["healthOrigin"],t["operationId"]])).collect() };
    for t in targets {
        let region = t["region"].as_str().filter(|s|!s.is_empty()).context("region missing")?;
        let deployment = t["deploymentId"].as_str().filter(|s|!s.is_empty()).context("deployment missing")?;
        let authority = t["authority"].as_str().context("authority missing")?;
        regions.insert(region);
        let child = child_id(command["operationId"].as_str().unwrap(),authority,deployment);
        anyhow::ensure!(t["operationId"] == child && children.insert(child), "regional child identity mismatch");
    }
    anyhow::ensure!(regions.len() >= 2, "regional update requires multiple regions");
    if let Some(previous) = previous {
        anyhow::ensure!(identities(previous["targets"].as_array().context("saved targets missing")?) == identities(targets), "regional membership changed on replay");
    }
    match observed["status"].as_str() {
        Some("passed") => {
            anyhow::ensure!(targets.iter().all(|t|t["status"] == "passed"
                && t["observation"]["status"] == "passed" && t["observation"]["phase"] == "complete"
                && t["observation"]["result"]["applicationRevision"] == command["release"]["targetRevision"]
                && t["observation"]["result"]["binarySha256"] == command["release"]["binarySha256"]
                && t["observation"]["result"]["admissionsOpen"] == true), "regional success omitted completed target evidence");
            Ok(Some("passed"))
        }
        Some("failed" | "cancelled") => Ok(Some("failed")),
        Some("preparing" | "running" | "cancelling") => Ok(None),
        _ => anyhow::bail!("unknown regional update status"),
    }
}

async fn reconcile(d: &Dispatcher) -> Result<()> {
    if d.config.managed_deployment.is_some() || d.config.application_id.is_none() { return Ok(()); }
    let (application, authority, token) = child::application_target(d).map_err(anyhow::Error::msg)?;
    let id: Option<String> = sqlx::query_scalar("SELECT id FROM ci_regional_update WHERE result IS NULL AND application_id=$1 ORDER BY created_at LIMIT 1")
        .bind(application).fetch_optional(d.store.pool()).await?;
    let Some(id) = id else { return Ok(()); };
    let _permit = d.executor.effect_permit_for(Some(&id)).await.map_err(anyhow::Error::msg)?;
    let row = sqlx::query("SELECT u.*,s.run_id,j.status AS job_status,r.status AS run_status FROM ci_regional_update u JOIN ci_service_deployment s ON s.id=u.id JOIN ci_job j ON j.id=s.job_id JOIN ci_run r ON r.id=s.run_id WHERE u.id=$1 AND u.result IS NULL")
        .bind(&id).fetch_optional(d.store.pool()).await?;
    let Some(row) = row else { return Ok(()); };
    anyhow::ensure!(row.get::<String,_>("authority") == authority.trim_end_matches('/'), "regional authority changed");
    let run: String = row.get("run_id"); let job: String = row.get("job_status");
    if !matches!(job.as_str(),"success"|"failure"|"cancelled"|"skipped") { return Ok(()); }
    let command: Value = row.get("request");
    let previous: Option<Value> = row.get("observation");
    if !row.get::<bool,_>("attempted") {
        let mut tx = d.store.pool().begin().await?;
        let run_status: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
            .bind(&run).fetch_one(&mut *tx).await?;
        if job != "success" || matches!(run_status.as_str(),"failure"|"cancelled") {
            tx.rollback().await?;
            return finish(d,&id,&run,Some("failed"),None).await;
        }
        sqlx::query("UPDATE ci_regional_update SET attempted=TRUE WHERE id=$1").bind(&id).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(20)).build()?;
    let url = format!("{}/orchestration/services/{application}/updates",authority.trim_end_matches('/'));
    let response = if previous.is_none() {
        client.post(&url).bearer_auth(token).json(&command).send().await?
    } else { client.get(format!("{url}/{id}")).bearer_auth(token).send().await? };
    anyhow::ensure!(response.status().is_success(), "regional platform request unresolved ({})",response.status());
    let mut observed: Value = response.json().await?;
    verify_observation(&observed,&command,application,previous.as_ref())?;
    if matches!(row.get::<String,_>("run_status").as_str(),"failure"|"cancelled")
        && !matches!(observed["status"].as_str(),Some("passed"|"failed"|"cancelled")) {
        let response = client.post(format!("{url}/{id}/cancel")).bearer_auth(token).send().await?;
        anyhow::ensure!(response.status().is_success(),"regional cancellation unresolved");
        observed = response.json().await?;
    }
    let result = verify_observation(&observed,&command,application,previous.as_ref())?;
    finish(d,&id,&run,result,Some(observed)).await
}

async fn finish(d: &Dispatcher, id: &str, run: &str, result: Option<&str>, observation: Option<Value>) -> Result<()> {
    let mut tx = d.store.pool().begin().await?;
    sqlx::query("SELECT id FROM ci_run WHERE id=$1 FOR UPDATE").bind(run).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_regional_update SET result=$2,observation=COALESCE($3,observation) WHERE id=$1 AND result IS NULL")
        .bind(id).bind(result).bind(&observation).execute(&mut *tx).await?;
    let phase = observation.as_ref().and_then(|o|o["status"].as_str()).unwrap_or("complete");
    sqlx::query("UPDATE ci_service_deployment SET status=$2,phase=$3,message=$4,updated_at=now() WHERE id=$1 AND status NOT IN ('passed','failed')")
        .bind(id).bind(result.unwrap_or("running")).bind(phase)
        .bind(if result == Some("passed") { "Every configured region updated and baked" } else if result == Some("failed") { "Regional update stopped; see platform target evidence" } else { "Waiting for platform regional update" })
        .execute(&mut *tx).await?;
    Store::add_service_deployment_event(&mut tx,id).await?;
    Store::roll_up_run_in(&mut tx,run).await?;
    tx.commit().await?; Ok(())
}

pub fn spawn(d: Arc<Dispatcher>) {
    tokio::spawn(async move { loop {
        if let Err(error) = reconcile(&d).await { tracing::warn!(%error,"regional CI update remains unresolved"); }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }});
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_finished_region_or_changed_membership_is_not_release_success() {
        let command=json!({"apiVersion":"regional-v1","operationId":"parent",
            "release":{"runId":"run","targetRevision":"release-8","artifactDigest":"a".repeat(64),"binarySha256":"b".repeat(64)}});
        let targets:Vec<Value>=[("west","ci-west-1"),("west","ci-west-2"),("east","ci-east")].into_iter().map(|(region,deployment)|json!({
            "region":region,"deploymentId":deployment,"authority":"https://admin.test","healthOrigin":format!("https://{region}.test"),
            "operationId":child_id("parent","https://admin.test",deployment),"status":"passed",
            "observation":{"status":"passed","phase":"complete","result":{"applicationRevision":"release-8",
                "binarySha256":"b".repeat(64),"admissionsOpen":true}}
        })).collect();
        let observation=json!({"apiVersion":"regional-v1","operationId":"parent","serviceId":"ci",
            "request":command,"requestHash":hash(&command),"status":"passed","targets":targets});
        assert_eq!(verify_observation(&observation,&command,"ci",None).unwrap(),Some("passed"));
        let mut single_region=observation.clone(); single_region["targets"].as_array_mut().unwrap().pop();
        assert!(verify_observation(&single_region,&command,"ci",None).is_err());
        let mut duplicate=observation.clone(); duplicate["targets"][1]=duplicate["targets"][0].clone();
        assert!(verify_observation(&duplicate,&command,"ci",None).is_err());
        let mut incomplete=observation.clone(); incomplete["targets"][1]["status"]=json!("baking");
        assert!(verify_observation(&incomplete,&command,"ci",None).is_err());
        incomplete["status"]=json!("running");
        assert_eq!(verify_observation(&incomplete,&command,"ci",None).unwrap(),None);
        let mut wrong_binary=observation.clone(); wrong_binary["targets"][1]["observation"]["result"]["binarySha256"]=json!("c".repeat(64));
        assert!(verify_observation(&wrong_binary,&command,"ci",None).is_err());
        let mut closed=observation.clone(); closed["targets"][0]["observation"]["result"]["admissionsOpen"]=json!(false);
        assert!(verify_observation(&closed,&command,"ci",None).is_err());
        let mut reordered=observation.clone(); reordered["targets"].as_array_mut().unwrap().reverse();
        assert!(verify_observation(&reordered,&command,"ci",Some(&observation)).is_err());
        let mut changed=command.clone(); changed["release"]["runId"]=json!("another-run");
        assert!(verify_observation(&observation,&changed,"ci",None).is_err());
    }
}
