//! Durable, fail-closed phase-two native heyvm bootstrap coordinator.
use crate::{bus::JobMessage, dispatch::Dispatcher, host_heyvm_bootstrap::Artifact, plan::JobPlan, store::Store};
use anyhow::{Result, ensure, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Duration};

pub const ACTION: &str = "ci/bootstrap-host-heyvm";
pub const HEYVMD_ACTION: &str = "ci/rollout-host-heyvmd";
const REPOSITORY: &str = "https://github.com/Heyo-Computer/heyo.git";
const LIMIT: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    repository: String, app_lb_admin_url: String, app_lb_deployment: String, app_lb_namespace: String,
    runner_hd_id: String, backend_server_id: String, executable: String, unit: String, state_dir: String,
    config_json_path: String, systemd_drop_in_path: String, local_health_url: String, target_alias: String, region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_manager: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request { alias: String, target: Target, token_secret: String, artifact: Artifact,
    request_sha256: String, config_sha256: String, systemd_drop_in_sha256: String }

fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn canonical(value:&Value)->Value { match value { Value::Object(m)=>Value::Object(m.iter().map(|(k,v)|(k.clone(),canonical(v))).collect::<BTreeMap<_,_>>().into_iter().collect()), Value::Array(a)=>Value::Array(a.iter().map(canonical).collect()), v=>v.clone() } }
fn terminal_phase(phase:&str)->bool { matches!(phase,"passed"|"failed"|"superseded") }
async fn reconnect_daemon(d:&Dispatcher,req:&Request)->Result<()> {
    if req.artifact.component.as_deref()==Some("heyvmd") {
        ensure!(d.config.heyvm.local_runner.is_none(),"daemon rollout requires a real runner tunnel, not local-runner mode");
        d.runners.evict(&req.target.runner_hd_id).await;
        d.runners.options_for(&req.target.runner_hd_id).await?;
    }
    Ok(())
}

impl Target {
    pub(crate) fn validate_admission(&self, repository: &str, coordinator: Option<&str>, heyvmd: bool) -> Result<()> {
        ensure!(crate::repos::same_repo(repository, &self.repository), "host target is not authorized for this repository");
        ensure!(coordinator.is_some_and(|runner| runner != self.runner_hd_id),
            "host replacement requires a mapped coordinator on a different runner");
        if heyvmd {
            ensure!(matches!(self.process_manager.as_deref(), Some("systemd" | "supervisor")),
                "heyvmd target requires an explicit process manager");
            ensure!(std::path::Path::new(&self.executable).file_name().is_some_and(|name| name == "heyvmd"),
                "daemon rollout target must name heyvmd");
        }
        Ok(())
    }
}

pub fn validate_plan(plan: &JobPlan) -> Result<()> {
    for (i, step) in plan.steps.iter().enumerate().filter(|(_,s)| matches!(s.uses.as_deref(),Some(ACTION|HEYVMD_ACTION))) {
        ensure!(i+1==plan.steps.len() && !step.continue_on_error && !plan.continue_on_error,
            "host heyvm bootstrap must be the final job step and may not tolerate errors");
        ensure!(!plan.target.is_existing_vm() && plan.native_labels.is_empty(), "host heyvm bootstrap requires a CI-owned VM");
        ensure!(step.with.keys().all(|k| matches!(k.as_str(),"target"|"token"|"workflow"|"artifact")), "host heyvm bootstrap has unsupported inputs");
        for key in ["target","token","workflow","artifact"] { ensure!(step.with.get(key).is_some_and(|v|!v.trim().is_empty()), "host heyvm bootstrap requires with.{key}"); }
        crate::host_maintenance::token_secret(&step.with["token"])?;
    }
    Ok(())
}

fn mapping(raw: &str, alias: &str) -> Result<Target> {
    let all:BTreeMap<String,Target>=serde_json::from_str(raw)?;
    let t=all.get(alias).cloned().ok_or_else(||anyhow::anyhow!("unknown host heyvm bootstrap target"))?;
    ensure!(t.target_alias==alias && t.repository==REPOSITORY, "bootstrap target identity differs");
    crate::cd::app_lb_endpoint(&t.app_lb_admin_url).map_err(anyhow::Error::msg)?;
    ensure!(t.app_lb_admin_url.starts_with("https://") || cfg!(test)&&t.app_lb_admin_url.starts_with("http://127.0.0.1:"), "bootstrap launcher requires HTTPS");
    ensure!([&t.runner_hd_id,&t.backend_server_id,&t.app_lb_deployment,&t.app_lb_namespace,&t.region].iter().all(|v|!v.is_empty()), "bootstrap target identity is empty");
    Ok(t)
}

pub(crate) async fn trusted(d:&Dispatcher, alias:&str)->Result<Target>{
    let managed;
    let raw=match d.config.host_heyvm_bootstrap_targets.as_deref(){Some(v)=>v,None=>{managed=d.secrets.host_heyvm_bootstrap_targets().await?;managed.as_str()}};
    mapping(raw,alias)
}

fn inspect_component(bytes:&[u8],component:&str)->Result<(String,String,String)> {
    ensure!(bytes.len()<=LIMIT,"bootstrap artifact exceeds bound");
    let mut unpacked=Vec::new();
    flate2::read::GzDecoder::new(bytes).take((LIMIT+1) as u64).read_to_end(&mut unpacked)?;
    ensure!(unpacked.len()<=LIMIT,"decompressed bootstrap artifact exceeds bound");
    let mut outer=tar::Archive::new(std::io::Cursor::new(unpacked));
    let mut found=None;
    for entry in outer.entries()? { let e=entry?; let p=e.path()?.into_owned();
        ensure!(p.components().all(|c|matches!(c,std::path::Component::Normal(_)|std::path::Component::CurDir)),"unsafe artifact path");
        let name=p.file_name().and_then(|v|v.to_str()).unwrap_or("");
        if name.starts_with("heyvm-") && name.ends_with("-unknown-linux-gnu-x86_64.tar.gz") { ensure!(found.is_none()&&e.header().entry_type().is_file(),"ambiguous inner heyvm archive"); let mut b=Vec::new(); e.take((LIMIT+1) as u64).read_to_end(&mut b)?; ensure!(b.len()<=LIMIT,"inner archive exceeds bound"); found=Some((p.to_string_lossy().into_owned(),b)); }
    }
    let (path,inner)=found.ok_or_else(||anyhow::anyhow!("exactly one inner heyvm tarball is required"))?;
    let elf=crate::host_maintenance::component_executable_digest(&inner,component)?;
    Ok((path,sha(&inner),elf))
}

fn expected_files(t:&Target,component:&str)->(String,String){
    if component=="heyvmd" { return (sha(b""),sha(b"")); }
    let config=(serde_json::to_string(&json!({"executable":t.executable,"maintenanceStateDirectory":t.state_dir,"systemdUnit":t.unit,"target":t.target_alias})).unwrap()+"\n").into_bytes();
    let drop=format!("[Service]\nEnvironment=HEYVM_HOST_UPDATE_CONFIG={}\n",t.config_json_path);
    (sha(&config),sha(drop.as_bytes()))
}

fn launcher_spec(id:&str, namespace:&str, command:String)->Value { json!({"id":id,"namespace":namespace,
    "routes":[{"host":format!("{id}.invalid")}],"maintenance":true,"upstreams":["bootstrap-unreachable.invalid:1"],
    "health":{"path":null,"timeout_secs":2},"update":{"working_dir":"/","commands":[command],"timeout_secs":600,"verify_timeout_secs":0}}) }

pub async fn request(d:&Dispatcher,msg:&JobMessage,plan:&JobPlan,step:&str,alias:&str,token_expression:&str,workflow:&str,name:&str,timeout:Duration,component:&str)->Result<String>{
    validate_plan(plan)?; crate::submission::authorize_publication(&d.store,&msg.run_id).await.map_err(anyhow::Error::msg)?;
    let target=trusted(d,alias).await?; let secret=crate::host_maintenance::token_secret(token_expression)?;
    if let Some(policy) = &plan.release_policy {
        ensure!(policy.hosts.get(alias) == Some(&target), "host target changed since release admission");
    }
    let run=d.store.get_run(&msg.run_id).await?.ok_or_else(||anyhow::anyhow!("missing run"))?;
    ensure!(crate::repos::same_repo(REPOSITORY,&run.repo_url),"only the private Heyo repository may bootstrap hosts");
    let (revision, git_ref)=crate::release::deployment_source(&d.store,&msg.run_id).await.map_err(anyhow::Error::msg)?;
    ensure!(revision==run.sha,"host release does not match frozen source");
    let stored=crate::submission::artifact(&d.store,&msg.run_id,workflow,name,None).await.map_err(anyhow::Error::msg)?;
    ensure!(stored.sink=="artifacts"&&stored.size_bytes as usize<=LIMIT,"bootstrap requires a bounded CI HTTP artifact");
    let digest=stored.digest.clone().ok_or_else(||anyhow::anyhow!("artifact digest missing"))?;
    let store=d.config.artifacts.as_ref().ok_or_else(||anyhow::anyhow!("CI artifact HTTP sink is not configured"))?.url.trim_end_matches('/');
    let expected_url=format!("{store}/blobs/{digest}");
    // Retained bundles intentionally carry no public_url. Verify that the
    // configured immutable blob endpoint is readable by the host instead.
    let response=client()?.head(&expected_url).send().await?;
    let size=response.headers().get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    ensure!(response.status().is_success() && size==Some(stored.size_bytes),
        "host artifact must be public from the configured CI HTTP sink with its exact size");
    let bytes=d.artifacts.get(&stored).await.map_err(|e|anyhow::anyhow!(e.to_string()))?; ensure!(sha(&bytes)==digest,"artifact digest mismatch");
    ensure!(matches!(component,"heyvm"|"heyvmd"),"unsupported host component");
    if component=="heyvmd" {
        ensure!(matches!(target.process_manager.as_deref(),Some("systemd"|"supervisor")),"heyvmd target requires an explicit process manager");
        ensure!(d.config.heyvm.local_runner.is_none(),"daemon rollout requires a real runner tunnel, not local-runner mode");
        ensure!(std::path::Path::new(&target.executable).file_name().is_some_and(|name|name=="heyvmd"),"daemon rollout target must name heyvmd");
    }
    let (inner_path,inner_archive_sha256,heyvm_sha256)=inspect_component(&bytes,component)?;
    let id=format!("ci-heyvm-{}",sha(step.as_bytes())); let launcher=format!("heyvm-bootstrap-{}",sha(id.as_bytes())[..32].to_string());
    let artifact=Artifact{operation_id:id.clone(),artifact_url:expected_url,artifact_sha256:digest,artifact_size:stored.size_bytes,inner_path,inner_archive_sha256,heyvm_sha256,component:(component=="heyvmd").then(||component.into())};
    let request_hash=sha(&serde_json::to_vec(&canonical(&serde_json::to_value(&artifact)?))?); let (config_sha256,systemd_drop_in_sha256)=expected_files(&target,component);
    let req=Request{alias:alias.into(),target:target.clone(),token_secret:secret,artifact,request_sha256:request_hash,config_sha256,systemd_drop_in_sha256};
    let command=crate::host_heyvm_bootstrap::recipe(&serde_json::to_string(&BTreeMap::from([(alias.to_string(),target.clone())]))?,alias,&req.artifact)?;
    let spec=launcher_spec(&launcher,&target.app_lb_namespace,command); let value=serde_json::to_value(&req)?;
    let runner:Option<String>=sqlx::query_scalar("SELECT runner_hd_id FROM ci_job WHERE id=$1").bind(&msg.job_id).fetch_one(d.store.pool()).await?;
    ensure!(runner.as_deref()!=Some(&target.runner_hd_id),"bootstrap coordinator must run on a different runner");
    let mut tx=d.store.pool().begin().await?; sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,222))").bind(&target.runner_hd_id).execute(&mut *tx).await?;
    if let Some(old)=sqlx::query_scalar::<_,Value>("SELECT request FROM ci_host_heyvm_bootstrap WHERE id=$1").bind(&id).fetch_optional(&mut *tx).await? { ensure!(old==value,"bootstrap request changed on replay"); return Ok(format!("[ci] bootstrap {id} already persisted\n")); }
    let maintenance_fenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_maintenance WHERE runner_hd_id=$1 AND phase<>'passed')").bind(&target.runner_hd_id).fetch_one(&mut *tx).await?;
    ensure!(!maintenance_fenced,"runner has unresolved host maintenance");
    let active_bootstrap:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND phase NOT IN ('passed','failed','superseded'))").bind(&target.runner_hd_id).fetch_one(&mut *tx).await?;
    ensure!(!active_bootstrap,"runner has an active host heyvm bootstrap");
    sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='superseded',updated_at=now() WHERE runner_hd_id=$1 AND phase='failed'").bind(&target.runner_hd_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) VALUES($1,$2,$3,$4,$5,$6,'running','draining',$7,$8)")
        .bind(&id).bind(step).bind(&msg.run_id).bind(&msg.job_id).bind(&target.backend_server_id).bind(sha(&serde_json::to_vec(&value)?)).bind(&run.sha).bind(&git_ref).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO ci_host_heyvm_bootstrap(id,runner_hd_id,request,launcher_recipe,deadline,launcher_deployment_id,phase) VALUES($1,$2,$3,$4,now()+make_interval(secs=>$5),$6,'releasing')")
        .bind(&id).bind(&target.runner_hd_id).bind(value).bind(spec).bind(timeout.min(d.config.max_job_duration).as_secs() as f64).bind(launcher).execute(&mut *tx).await?;
    Store::add_service_deployment_event(&mut tx,&id).await?; tx.commit().await?;
    Ok(format!("[ci] bootstrap {id} durably fenced {}; coordinator reconciliation owns completion\n",target.runner_hd_id))
}

fn client()->Result<reqwest::Client>{Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(20)).build()?)}
async fn body(mut r:reqwest::Response)->Result<Value>{ensure!(r.status().is_success(),"launcher returned {}",r.status());let mut b=Vec::new();while let Some(c)=r.chunk().await?{ensure!(b.len()+c.len()<=8*1024*1024,"launcher response exceeds bound");b.extend_from_slice(&c);}Ok(serde_json::from_slice(&b)?)}
fn registration_probe_requires_create(status:reqwest::StatusCode)->bool { matches!(status,reqwest::StatusCode::NOT_FOUND|reqwest::StatusCode::FORBIDDEN) }
fn same_spec(actual:&Value,want:&Value)->bool{
    let actual=actual.get("spec").unwrap_or(actual);
    let (Some(fields),Some(expected))=(actual.as_object(),want.as_object()) else{return false};
    expected.iter().all(|(key,value)|(key=="namespace"&&value=="default"&&actual.get(key).is_none())||actual.get(key)==Some(value))
        && fields.iter().all(|(key,value)|expected.contains_key(key)
            || (key=="scaling"&&value==&json!({"min_replicas":0,"max_replicas":5,"warm_pool":0,"target_concurrency":10,"scale_to_zero_after_secs":300,"cold_start_timeout_secs":120,"drain_timeout_secs":30,"boot_timeout_secs":300,"idle_action":"destroy"}))
            || value.is_null()||value==&json!([]))
}

async fn launcher_job(http:&reqwest::Client,base:&str,token:&str,launcher:&str,job_id:&str)->Result<Value>{
    // The global /jobs/{id} route requires fleet access; bootstrap tokens are confined.
    let response=body(http.get(format!("{base}/deployments/{launcher}/jobs")).bearer_auth(token).send().await?).await?;
    let jobs=response.as_array().ok_or_else(||anyhow::anyhow!("launcher job list is invalid"))?;
    let mut matches=jobs.iter().filter(|job|job["id"].as_str()==Some(job_id));
    let job=matches.next().ok_or_else(||anyhow::anyhow!("launcher job missing; target remains fenced"))?;
    ensure!(matches.next().is_none(),"launcher job ambiguity; target remains fenced");
    ensure!(job["deployment"]==launcher && matches!(job["kind"].as_str(),Some("update"|"host-update")),"launcher job identity differs");
    Ok(job.clone())
}

fn receipt(job:&Value,req:&Request,launcher:&str,allow_rollback:bool)->Result<Value>{
    ensure!(job["deployment"]==launcher && matches!(job["kind"].as_str(),Some("update"|"host-update")),"launcher job identity differs");
    ensure!(job["status"]=="succeeded","launcher did not succeed");
    let logs=job["log"].as_array().ok_or_else(||anyhow::anyhow!("launcher logs missing"))?;
    let lines:Vec<_>=logs.iter().filter_map(Value::as_str).flat_map(str::lines).filter_map(|s|s.strip_prefix("HEYO_HEYVM_BOOTSTRAP_RESULT=")).collect();
    ensure!(lines.len()==1,"exactly one bootstrap receipt is required"); let value:Value=serde_json::from_slice(&STANDARD.decode(lines[0])?)?;
    for (key,want) in [("protocol","host-heyvm-bootstrap-v1"),("operation_id",req.artifact.operation_id.as_str()),("request_sha256",req.request_sha256.as_str()),
        ("target_alias",req.alias.as_str()),("backend_server_id",req.target.backend_server_id.as_str()),("region",req.target.region.as_str())]{ensure!(value[key]==want,"bootstrap receipt {key} differs");}
    if allow_rollback && matches!(value["status"].as_str(),Some("rolled_back"|"rollback_failed")) { return Ok(value); }
    ensure!(value["status"]=="succeeded","bootstrap rolled back or failed");
    for (key,want) in [("heyvm_sha256",req.artifact.heyvm_sha256.as_str()),("config_sha256",req.config_sha256.as_str()),
        ("systemd_drop_in_sha256",req.systemd_drop_in_sha256.as_str())]{ensure!(value[key]==want,"bootstrap receipt {key} differs");}
    Ok(value)
}

async fn finish(store:&Store,id:&str,passed:bool,note:&str,result:Option<&Value>)->Result<()> {
    let mut tx=store.pool().begin().await?;
    let identity=sqlx::query("SELECT run_id,job_id,step_id FROM ci_service_deployment WHERE id=$1").bind(id).fetch_one(&mut *tx).await?;
    let run:String=identity.get("run_id");let job:String=identity.get("job_id");let step:String=identity.get("step_id");
    let run_status:String=sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE").bind(&run).fetch_one(&mut *tx).await?;
    let job_status:String=sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1 FOR UPDATE").bind(&job).fetch_one(&mut *tx).await?;
    let operation=sqlx::query("SELECT phase,deadline FROM ci_host_heyvm_bootstrap WHERE id=$1 FOR UPDATE").bind(id).fetch_one(&mut *tx).await?;
    let phase:String=operation.get("phase");let deadline:chrono::DateTime<chrono::Utc>=operation.get("deadline");
    if terminal_phase(&phase){return Ok(())}
    let eligible=run_status=="running"&&job_status=="running"&&deadline>chrono::Utc::now()&&phase=="polling";
    let passed=passed&&eligible;
    let status=if passed{"success"}else{"failure"}; let phase=if passed{"passed"}else{"failed"};
    sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase=$2,result=COALESCE($3,result),updated_at=now() WHERE id=$1").bind(id).bind(phase).bind(result).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_service_deployment SET status=$2,phase=$3,message=$4,updated_at=now() WHERE id=$1").bind(id).bind(if passed{"passed"}else{"failed"}).bind(phase).bind(note).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_step SET status=$2,finished_at=now(),error=CASE WHEN $2='failure' THEN $3 END WHERE id=$1 AND status NOT IN ('cancelled','failure')").bind(&step).bind(status).bind(note).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_job SET status=$2,finished_at=now(),error=CASE WHEN $2='failure' THEN $3 END WHERE id=$1 AND status NOT IN ('cancelled','failure')").bind(&job).bind(status).bind(note).execute(&mut *tx).await?;
    Store::add_service_deployment_event(&mut tx,id).await?; Store::add_event(&mut tx,&run,Some(&job),None,Some(&step),"ci.step.status.v1",status,Some(note)).await?; Store::add_event(&mut tx,&run,Some(&job),None,None,"ci.job.status.v1",status,Some(note)).await?; Store::roll_up_run_in(&mut tx,&run).await?;tx.commit().await?;Ok(())
}

async fn reconcile(d:&Dispatcher,id:&str,token:&str,configured:Option<&Target>)->Result<()> {
    let _effect = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let row=sqlx::query("SELECT h.*,d.run_id,d.job_id FROM ci_host_heyvm_bootstrap h JOIN ci_service_deployment d ON d.id=h.id WHERE h.id=$1 AND h.phase NOT IN ('passed','failed','superseded')").bind(id).fetch_optional(d.store.pool()).await?;let Some(row)=row else{return Ok(())};
    let req:Request=serde_json::from_value(row.get("request"))?;let phase:String=row.get("phase");let deadline:chrono::DateTime<chrono::Utc>=row.get("deadline");
    let run:String=row.get("run_id");let job:String=row.get("job_id");
    let lifecycle=sqlx::query("SELECT j.status AS job_status,r.status AS run_status FROM ci_job j JOIN ci_run r ON r.id=j.run_id WHERE j.id=$1").bind(&job).fetch_one(d.store.pool()).await?;
    let stopped=lifecycle.get::<String,_>("job_status")!="running"||matches!(lifecycle.get::<String,_>("run_status").as_str(),"failure"|"cancelled");
    if stopped||deadline<=chrono::Utc::now()||configured!=Some(&req.target){finish(&d.store,id,false,"Bootstrap cancelled, timed out, lost identity, or configuration drifted; target remains fenced.",None).await?;return Ok(())}
    if phase=="releasing"{return Ok(())}
    if phase=="draining" { let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_job WHERE runner_hd_id=$1 AND status='running') OR EXISTS(SELECT 1 FROM ci_host_work WHERE runner_hd_id=$1) OR EXISTS(SELECT 1 FROM ci_vm_pool WHERE runner_hd_id=$1 AND status IN ('claimed','building','draining'))").bind(&req.target.runner_hd_id).fetch_one(d.store.pool()).await?;if blocked{return Ok(())}
        sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='registering',updated_at=now() WHERE id=$1 AND phase='draining'").bind(id).execute(d.store.pool()).await?;return Ok(()) }
    if token.trim().is_empty(){return Ok(())}let base=req.target.app_lb_admin_url.trim_end_matches('/');let launcher:String=row.get("launcher_deployment_id");let spec:Value=row.get("launcher_recipe");let http=client()?;
    if phase=="registering" {let r=http.get(format!("{base}/deployments/{launcher}")).bearer_auth(token).send().await?;if registration_probe_requires_create(r.status()){body(http.post(format!("{base}/deployments")).bearer_auth(token).json(&spec).send().await?).await?;}else{ensure!(same_spec(&body(r).await?,&spec),"launcher recipe conflict");}
        let exact=body(http.get(format!("{base}/deployments/{launcher}")).bearer_auth(token).send().await?).await?;ensure!(same_spec(&exact,&spec),"registered launcher differs");
        let changed=sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='delivery_ready',updated_at=now() WHERE id=$1 AND phase='registering'").bind(id).execute(d.store.pool()).await?.rows_affected();ensure!(changed<=1,"invalid phase transition");return Ok(())}
    let mut job_id:Option<String>=row.try_get("launcher_job_id")?;
    if phase=="delivery_ready" {let changed=sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='armed',delivery_armed=true,updated_at=now() WHERE id=$1 AND phase='delivery_ready'").bind(id).execute(d.store.pool()).await?.rows_affected();if changed!=1{return Ok(())}
        let response=http.post(format!("{base}/deployments/{launcher}/update")).bearer_auth(token).send().await?;
        if response.status().is_success(){let j=body(response).await?;if let Some(job)=j["id"].as_str(){sqlx::query("UPDATE ci_host_heyvm_bootstrap SET launcher_job_id=$2,phase='polling',updated_at=now() WHERE id=$1 AND phase='armed' AND launcher_job_id IS NULL").bind(id).bind(job).execute(d.store.pool()).await?;}}return Ok(())}
    if phase=="armed" && job_id.is_none(){let jobs=body(http.get(format!("{base}/deployments/{launcher}/jobs")).bearer_auth(token).send().await?).await?;let matches:Vec<_>=jobs.as_array().into_iter().flatten().filter(|j|matches!(j["kind"].as_str(),Some("update"|"host-update"))).collect();
        if matches.len()==1 {job_id=matches[0]["id"].as_str().map(str::to_string);} else if matches.is_empty(){return Ok(())} else {bail!("launcher job ambiguity; target remains fenced")}
        if let Some(j)=&job_id{sqlx::query("UPDATE ci_host_heyvm_bootstrap SET launcher_job_id=$2,phase='polling',updated_at=now() WHERE id=$1 AND phase='armed' AND launcher_job_id IS NULL").bind(id).bind(j).execute(d.store.pool()).await?;}return Ok(())}
    let Some(job_id)=job_id else{return Ok(())};let jobv=launcher_job(&http,base,token,&launcher,&job_id).await?;
    match jobv["status"].as_str(){Some("queued"|"running")=>{},Some("succeeded")=>match receipt(&jobv,&req,&launcher,false){Ok(r)=>{
        reconnect_daemon(d,&req).await?;
        finish(&d.store,id,true,"Exact native host executable receipt and runner tunnel reconnection verified; target uncordoned.",Some(&r)).await?},Err(_)=>finish(&d.store,id,false,"Launcher receipt was missing, ambiguous, mismatched, or reported rollback; target remains fenced.",None).await?},_=>finish(&d.store,id,false,"Launcher/bootstrap failed or rolled back; target remains fenced.",None).await?};
    let _=run;Ok(())
}

/// Stop and release the coordinator VM before host drain/network activity.
pub(crate) async fn release(d:&Dispatcher,id:&str)->Result<()> {
    let _effect = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let mut tx=d.store.pool().begin().await?;
    let row=sqlx::query("SELECT s.job_id,j.sandbox_id,j.runner_hd_id,j.attempt FROM ci_host_heyvm_bootstrap h JOIN ci_service_deployment s ON s.id=h.id JOIN ci_job j ON j.id=s.job_id WHERE h.id=$1 AND h.phase='releasing' FOR UPDATE OF h SKIP LOCKED").bind(id).fetch_optional(&mut *tx).await?;
    let Some(row)=row else{return Ok(())};let job:String=row.get("job_id");let sandbox:String=row.try_get("sandbox_id")?;let runner:String=row.try_get("runner_hd_id")?;
    let pool=sqlx::query("SELECT status,claimed_by_job FROM ci_vm_pool WHERE sandbox_id=$1 FOR UPDATE").bind(&sandbox).fetch_one(&mut *tx).await?;
    ensure!(pool.get::<String,_>("status")=="claimed"&&pool.get::<Option<String>,_>("claimed_by_job").as_deref()==Some(&job),"bootstrap coordinator VM ownership changed");
    let vm=d.vms.open(d.runners.options_for(&runner).await?,sandbox.clone()).await?;tokio::time::timeout(Duration::from_secs(30),vm.stop()).await??;
    sqlx::query("UPDATE ci_vm_pool SET status='idle',claimed_by_job=NULL,leased_by=NULL,leased_until=NULL,last_used_at=now() WHERE sandbox_id=$1").bind(&sandbox).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3").bind(&job).bind(&runner).bind(row.get::<i32,_>("attempt")).execute(&mut *tx).await?;
    sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='draining',updated_at=now() WHERE id=$1 AND phase='releasing'").bind(id).execute(&mut *tx).await?;tx.commit().await?;Ok(())
}

pub async fn owns_job(store:&Store,job:&str)->Result<bool>{Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_service_deployment d JOIN ci_host_heyvm_bootstrap h ON h.id=d.id WHERE d.job_id=$1)").bind(job).fetch_one(store.pool()).await?)}

/// Explicit receipt-only recovery. Never redeliver the original installer or rewrite run history.
pub async fn recover(d:&Dispatcher,run_id:&str,id:&str)->Result<Value> {
    let _effect = d.executor.effect_permit_for(Some(id)).await.map_err(anyhow::Error::msg)?;
    let run=d.store.get_run(run_id).await?.ok_or_else(||anyhow::anyhow!("missing run"))?;
    ensure!(crate::repos::same_repo(REPOSITORY,&run.repo_url),"only the private Heyo repository may recover hosts");
    let mut tx=d.store.pool().begin().await?;
    let runner:String=sqlx::query_scalar("SELECT h.runner_hd_id FROM ci_host_heyvm_bootstrap h JOIN ci_service_deployment s ON s.id=h.id WHERE h.id=$1 AND s.run_id=$2")
        .bind(id).bind(run_id).fetch_one(&mut *tx).await?;
    let locked:bool=sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,222))").bind(&runner).fetch_one(&mut *tx).await?;
    ensure!(locked,"host recovery or maintenance is already in progress");
    let row=sqlx::query("SELECT h.*,s.job_id FROM ci_host_heyvm_bootstrap h JOIN ci_service_deployment s ON s.id=h.id WHERE h.id=$1 AND s.run_id=$2 FOR UPDATE OF h")
        .bind(id).bind(run_id).fetch_one(&mut *tx).await?;
    let phase:String=row.get("phase");
    if phase=="passed" { return Ok(json!({"operation_id":id,"status":"already_passed"})); }
    if phase=="superseded" && row.get::<Option<Value>,_>("result").is_some_and(|r|r["status"]=="rollback_verified") {
        return Ok(json!({"operation_id":id,"status":"rollback_verified"}));
    }
    ensure!(phase=="failed"&&row.get::<bool,_>("delivery_armed"),"only failed, delivered bootstrap operations can be recovered");
    let other:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_maintenance WHERE runner_hd_id=$1 AND phase<>'passed') OR EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND id<>$2 AND phase NOT IN ('passed','superseded'))")
        .bind(&runner).bind(id).fetch_one(&mut *tx).await?;
    ensure!(!other,"another operation owns the host fence");
    let req:Request=serde_json::from_value(row.get("request"))?;
    ensure!(req.artifact.operation_id==id&&req.target.runner_hd_id==runner,"stored operation identity differs");
    ensure!(trusted(d,&req.alias).await?==req.target,"bootstrap target configuration drifted");
    let job=d.store.get_job(&row.get::<String,_>("job_id")).await?.ok_or_else(||anyhow::anyhow!("missing bootstrap job"))?;
    ensure!(job.status=="failure"&&run.status=="failure","original run and job must remain failed");
    let plan:JobPlan=serde_json::from_value(job.plan)?;
    let resolved = d.secrets.resolve_run(&run, plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default")).await?;
    let token=resolved.secrets.get(&req.token_secret).filter(|s|!s.is_empty()).ok_or_else(||anyhow::anyhow!("bootstrap token unavailable"))?;
    let http=client()?; let base=req.target.app_lb_admin_url.trim_end_matches('/');
    let launcher:String=row.get("launcher_deployment_id");
    let original_job:String=row.try_get("launcher_job_id")?;
    let original=receipt(&launcher_job(&http,base,token,&launcher,&original_job).await?,&req,&launcher,true)?;

    // A fresh, isolated launcher runs only read-only verification. Retrying this request
    // may repeat verification, but can never repeat installation or service restart.
    let verifier=format!("heyvm-verify-{}",uuid::Uuid::new_v4().simple());
    let mapping=serde_json::to_string(&BTreeMap::from([(req.alias.clone(),req.target.clone())]))?;
    let command=crate::host_heyvm_bootstrap::verification_recipe(&mapping,&req.alias,&req.artifact)?;
    let mut spec=launcher_spec(&verifier,&req.target.app_lb_namespace,command);
    spec["update"]["timeout_secs"]=json!(90);
    body(http.post(format!("{base}/deployments")).bearer_auth(token).json(&spec).send().await?).await?;
    let actual=body(http.get(format!("{base}/deployments/{verifier}")).bearer_auth(token).send().await?).await?;
    ensure!(same_spec(&actual,&spec),"verification launcher differs");
    let started=body(http.post(format!("{base}/deployments/{verifier}/update")).bearer_auth(token).send().await?).await?;
    let verify_job=started["id"].as_str().ok_or_else(||anyhow::anyhow!("verification job ID missing"))?;
    let live=tokio::time::timeout(Duration::from_secs(100),async {
        loop {
            let job=launcher_job(&http,base,token,&verifier,verify_job).await?;
            if matches!(job["status"].as_str(),Some("queued"|"running")) {tokio::time::sleep(Duration::from_secs(1)).await;continue}
            return receipt(&job,&req,&verifier,true);
        }
    }).await??;
    let mut expected=original.clone();
    // A failed rollback is evidence to investigate, never evidence of recovery.
    // The read-only verifier must now prove the exact saved predecessor is live.
    if expected["status"]=="rollback_failed" { expected["status"]=json!("rolled_back"); }
    ensure!(live==expected,"live verification differs from original receipt");
    ensure!(trusted(d,&req.alias).await?==req.target,"bootstrap target configuration drifted during recovery");
    reconnect_daemon(d,&req).await?;
    let rolled_back=live["status"]=="rolled_back";
    let result=json!({"operation_id":id,"status":if rolled_back{"rollback_verified"}else{"recovered"},"receipt":live,"original_job_id":original_job,
        "verification_deployment":verifier,"verification_job_id":verify_job,"recovered_at":chrono::Utc::now()});
    sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase=$3,result=$2,updated_at=now() WHERE id=$1").bind(id).bind(&result)
        .bind(if rolled_back{"superseded"}else{"passed"}).execute(&mut *tx).await?;
    let note=format!("Bootstrap {id} {} by explicit receipt and live-state verification; host fence released. Original failed run preserved. Verification job: {verify_job}",if rolled_back{"rollback verified"}else{"recovered"});
    Store::add_event(&mut tx,run_id,Some(&job.id),None,None,"ci.host.bootstrap.recovered.v1","recovered",Some(&note)).await?;
    tx.commit().await?;
    Ok(result)
}

pub fn spawn(d:Arc<Dispatcher>){tokio::spawn(async move{let mut tick=tokio::time::interval(Duration::from_secs(3));loop{tick.tick().await;let rows=sqlx::query("SELECT h.id,h.request,d.run_id,d.job_id FROM ci_host_heyvm_bootstrap h JOIN ci_service_deployment d ON d.id=h.id WHERE h.phase NOT IN ('passed','failed','superseded') ORDER BY h.created_at LIMIT 32").fetch_all(d.store.pool()).await;let Ok(rows)=rows else{continue};for row in rows{let id:String=row.get("id");let run:String=row.get("run_id");let result:Result<()>=async{let req:Request=serde_json::from_value(row.get("request"))?;release(&d,&id).await?;let target=trusted(&d,&req.alias).await.ok();reconcile(&d,&id,"",target.as_ref()).await?;let job=d.store.get_job(&row.get::<String,_>("job_id")).await?.ok_or_else(||anyhow::anyhow!("missing bootstrap job"))?;let plan:JobPlan=serde_json::from_value(job.plan)?;let rr=d.store.get_run(&run).await?.ok_or_else(||anyhow::anyhow!("missing bootstrap run"))?;let resolved=d.secrets.resolve_run(&rr, plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default")).await?;let token=resolved.secrets.get(&req.token_secret).filter(|s|!s.is_empty()).ok_or_else(||anyhow::anyhow!("bootstrap token unavailable"))?;reconcile(&d,&id,token,target.as_ref()).await}.await;if let Err(error)=result{tracing::warn!(operation=%id,error=%error,"host heyvm bootstrap blocked; fence retained");}let _=d.advance_run(&run).await;}}});}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn polling_uses_scoped_route_and_exact_job_identity() {
        use axum::{Json, Router, extract::State, http::{HeaderMap, StatusCode}, routing::get};
        let wanted=json!({"id":"job-target","deployment":"launcher","kind":"update","status":"succeeded","log":["receipt retained"]});
        let other=json!({"id":"job-other","deployment":"launcher","kind":"update","status":"failed"});
        let records=Arc::new(tokio::sync::RwLock::new(json!([other,wanted])));
        let app=Router::new().route("/deployments/launcher/jobs",get(
            |State(records):State<Arc<tokio::sync::RwLock<Value>>>,headers:HeaderMap| async move {
                assert_eq!(headers["authorization"],"Bearer scoped-test-token");
                Json(records.read().await.clone())
            }
        )).fallback(|| async { StatusCode::FORBIDDEN }).with_state(records.clone());
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base=format!("http://{}",listener.local_addr().unwrap());
        let server=tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
        let http=client().unwrap();
        let got=launcher_job(&http,&base,"scoped-test-token","launcher","job-target").await.unwrap();
        assert_eq!(got,wanted);
        assert!(launcher_job(&http,&base,"scoped-test-token","launcher","missing").await.is_err());
        for invalid in [
            json!([wanted,wanted]),
            json!([{"id":"job-target","deployment":"another-launcher","kind":"update","status":"succeeded"}]),
            json!([{"id":"job-target","deployment":"launcher","kind":"deploy","status":"succeeded"}]),
            json!({"jobs":[wanted]}),
        ] {
            *records.write().await=invalid;
            assert!(launcher_job(&http,&base,"scoped-test-token","launcher","job-target").await.is_err());
        }
        server.abort();
    }

    #[test]
    fn superseded_bootstrap_is_terminal() {
        assert!(terminal_phase("passed"));
        assert!(terminal_phase("failed"));
        assert!(terminal_phase("superseded"));
        assert!(!terminal_phase("draining"));
    }

    #[test]
    fn rollback_receipt_is_recovery_only_and_keeps_identity_checks() {
        let req:Request=serde_json::from_value(json!({
            "alias":"daemon", "token_secret":"ADMIN", "request_sha256":"request",
            "config_sha256":"config", "systemd_drop_in_sha256":"drop",
            "artifact":{"operation_id":"op", "artifact_url":"https://example/artifact",
                "artifact_sha256":"artifact", "artifact_size":1, "inner_path":"heyvm.tar.gz",
                "inner_archive_sha256":"inner", "heyvm_sha256":"binary", "component":"heyvmd"},
            "target":{"repository":REPOSITORY, "app_lb_admin_url":"https://example/admin",
                "app_lb_deployment":"host", "app_lb_namespace":"default", "runner_hd_id":"runner",
                "backend_server_id":"backend", "executable":"/usr/local/bin/heyvmd", "unit":"heyvmd.service",
                "state_dir":"/state", "config_json_path":"/config", "systemd_drop_in_path":"/drop",
                "local_health_url":"http://127.0.0.1/health", "target_alias":"daemon", "region":"region-a"}
        })).unwrap();
        let mut value=json!({"protocol":"host-heyvm-bootstrap-v1", "operation_id":"op",
            "request_sha256":"request", "target_alias":"daemon", "backend_server_id":"backend",
            "region":"region-a", "status":"rolled_back"});
        let job=|v:&Value| json!({"deployment":"launcher", "kind":"host-update", "status":"succeeded",
            "log":[format!("HEYO_HEYVM_BOOTSTRAP_RESULT={}",STANDARD.encode(serde_json::to_vec(v).unwrap()))]});
        assert!(receipt(&job(&value),&req,"launcher",false).is_err());
        assert_eq!(receipt(&job(&value),&req,"launcher",true).unwrap(),value);
        value["region"]=json!("other");
        assert!(receipt(&job(&value),&req,"launcher",true).is_err());
        value["region"]=json!("region-a");
        value["status"]=json!("rollback_failed");
        assert!(receipt(&job(&value),&req,"launcher",false).is_err());
        assert_eq!(receipt(&job(&value),&req,"launcher",true).unwrap(),value);
        value["status"]=json!("succeeded");
        assert!(receipt(&job(&value),&req,"launcher",true).is_err());
    }

    #[test]
    fn namespace_private_missing_probe_attempts_confined_create() {
        assert!(registration_probe_requires_create(reqwest::StatusCode::NOT_FOUND));
        assert!(registration_probe_requires_create(reqwest::StatusCode::FORBIDDEN));
        assert!(!registration_probe_requires_create(reqwest::StatusCode::UNAUTHORIZED));
        assert!(!registration_probe_requires_create(reqwest::StatusCode::OK));
    }

    #[test]
    fn plan_and_receipt_are_closed() {
        for action in [ACTION,HEYVMD_ACTION] {
            let yaml="jobs:\n  x:\n    vm: {driver: firecracker}\n    steps:\n      - uses: ACTION\n        with: {target: eu1, token: '${{ secrets.ADMIN }}', workflow: build.yml, artifact: heyvm}\n".replace("ACTION",action);
            let wf=crate::workflow::Workflow::parse("x.yml",&yaml).unwrap();
            let plan=crate::plan::Plan::build(&wf).unwrap();
            assert!(validate_plan(&plan.jobs[0]).is_ok());
            assert!(crate::submission::validate_validation_plan(&plan).is_err());
            let mut bad=wf.clone();
            let step=bad.jobs[0].1.steps[0].clone();
            bad.jobs[0].1.steps.push(step);
            assert!(crate::plan::Plan::build(&bad).is_err());
        }
    }

    #[test]
    fn validation_artifact_selects_the_real_release_tarball_name() {
        let mut inner=Vec::new();
        {
            let encoder=flate2::write::GzEncoder::new(&mut inner,flate2::Compression::default());
            let mut archive=tar::Builder::new(encoder);
            let binary=b"\x7fELFbootstrap";
            let mut header=tar::Header::new_gnu();
            header.set_size(binary.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            archive.append_data(&mut header,"heyvm",&binary[..]).unwrap();
            let daemon=b"\x7fELFnetwork-daemon";
            header.set_size(daemon.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header,"heyvmd",&daemon[..]).unwrap();
            archive.into_inner().unwrap().finish().unwrap();
        }
        let mut outer_tar=Vec::new();
        {
            let mut archive=tar::Builder::new(&mut outer_tar);
            let mut header=tar::Header::new_gnu();
            header.set_size(inner.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header,"dist/heyvm-0.48.1-unknown-linux-gnu-x86_64.tar.gz",&inner[..]).unwrap();
            archive.finish().unwrap();
        }
        let mut encoder=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::default());
        std::io::Write::write_all(&mut encoder,&outer_tar).unwrap();
        let outer=encoder.finish().unwrap();
        let (path,archive_sha,binary_sha)=inspect_component(&outer,"heyvm").unwrap();
        assert_eq!(path,"dist/heyvm-0.48.1-unknown-linux-gnu-x86_64.tar.gz");
        assert_eq!(archive_sha,sha(&inner));
        assert_eq!(binary_sha,sha(b"\x7fELFbootstrap"));
        assert_eq!(inspect_component(&outer,"heyvmd").unwrap().2,sha(b"\x7fELFnetwork-daemon"));

        let mut ambiguous_tar=Vec::new();
        {
            let mut archive=tar::Builder::new(&mut ambiguous_tar);
            for version in ["0.48.1","0.48.2"] {
                let mut header=tar::Header::new_gnu();
                header.set_size(inner.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive.append_data(&mut header,format!("dist/heyvm-{version}-unknown-linux-gnu-x86_64.tar.gz"),&inner[..]).unwrap();
            }
            archive.finish().unwrap();
        }
        let mut encoder=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::default());
        std::io::Write::write_all(&mut encoder,&ambiguous_tar).unwrap();
        let ambiguous=encoder.finish().unwrap();
        assert!(inspect_component(&ambiguous,"heyvm").is_err());
    }

    #[test]
    fn deployment_readback_allows_only_materialized_defaults() {
        let want=launcher_spec("launcher","default","echo ok".into());
        let mut actual=want.clone();actual.as_object_mut().unwrap().remove("namespace");actual["scaling"]=json!({"min_replicas":0,"max_replicas":5,"warm_pool":0,"target_concurrency":10,"scale_to_zero_after_secs":300,"cold_start_timeout_secs":120,"drain_timeout_secs":30,"boot_timeout_secs":300,"idle_action":"destroy"});actual["observed"]=Value::Null;
        assert!(same_spec(&json!({"spec":actual}),&want));
        let mut extra=want.clone();extra["public_paths"]=json!(["/"]);assert!(!same_spec(&extra,&want));
        let mut behavior=want.clone();behavior["scaling"]=json!({"min_replicas":1});assert!(!same_spec(&behavior,&want));
    }
}
