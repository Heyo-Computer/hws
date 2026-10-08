//! Durable, pull-based native runner protocol.
use crate::plan::JobPlan;
use crate::store::Store;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 1;
const LEASE_SECONDS: i64 = 90;

#[derive(Debug)]
pub enum PollError {
    Rejected(String),
    Internal(String),
}

impl std::fmt::Display for PollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) | Self::Internal(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub runner_id: String,
    pub name: String,
    pub labels: Vec<String>,
    pub platform: String,
    pub arch: String,
    pub protocol_version: u32,
    #[serde(default = "one")]
    pub max_concurrent_jobs: i32,
}
fn one() -> i32 {
    1
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Poll {
    pub runner_id: String,
    pub protocol_version: u32,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseUpdate {
    pub runner_id: String,
    pub lease_token: Uuid,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Completion {
    pub runner_id: String,
    pub lease_token: Uuid,
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub outputs: serde_json::Value,
    #[serde(default)]
    pub steps: Vec<StepResult>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepResult {
    pub index: usize,
    pub status: String,
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub log: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub outputs: serde_json::Value,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    pub job_id: String,
    pub run_id: String,
    pub lease_token: Uuid,
    pub lease_expires_at: DateTime<Utc>,
    pub plan: JobPlan,
    pub source_url: String,
    pub context: serde_json::Value,
    /// Values are used only by the agent's in-memory log masker and are never persisted.
    pub mask_values: Vec<String>,
}

fn validate_protocol(v: u32) -> Result<(), String> {
    if v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(format!(
            "unsupported protocol {v}; expected {PROTOCOL_VERSION}"
        ))
    }
}
fn normalize(labels: &[String]) -> Vec<String> {
    let mut v: Vec<_> = labels
        .iter()
        .map(|x| x.trim().to_ascii_lowercase())
        .filter(|x| !x.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

pub async fn register(store: &Store, r: Registration) -> Result<(), String> {
    validate_protocol(r.protocol_version)?;
    if r.runner_id.trim().is_empty() || r.name.trim().is_empty() {
        return Err("runner id and name are required".into());
    }
    if r.arch != "x86_64" || !matches!(r.platform.as_str(), "macos" | "windows") {
        return Err("native runners must be Windows x86_64 or macOS x86_64".into());
    }
    let labels = normalize(&r.labels);
    let platform_label = if r.platform == "macos" {
        "macos"
    } else {
        "windows"
    };
    if !labels.iter().any(|x| x == platform_label) || !labels.iter().any(|x| x.contains("x86_64")) {
        return Err("labels must identify the declared platform and x86_64 architecture".into());
    }
    sqlx::query("INSERT INTO ci_native_runner(id,name,labels,platform,arch,max_concurrent,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,now()) ON CONFLICT(id) DO UPDATE SET name=$2,labels=$3,platform=$4,arch=$5,max_concurrent=$6,last_seen_at=now()")
        .bind(r.runner_id).bind(r.name).bind(labels).bind(r.platform).bind(r.arch).bind(r.max_concurrent_jobs.max(1)).execute(store.pool()).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn enqueue(
    store: &Store,
    job_id: &str,
    run_id: &str,
    labels: &[String],
) -> Result<(), String> {
    // Native runners are fleet hosts outside any VM boundary. A namespace run
    // is refused `runs-on` at submit; this is the second door.
    let tenant: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_run WHERE id=$1 AND namespace<>'')")
        .bind(run_id).fetch_one(store.pool()).await.map_err(|e| e.to_string())?;
    if tenant {
        return Err("native runners are not available to namespace runs".into());
    }
    let mut tx = store.pool().begin().await.map_err(|e| e.to_string())?;
    let row = sqlx::query("UPDATE ci_job SET status='queued',queued_at=now() WHERE id=$1 AND run_id=$2 AND status='pending' RETURNING job_key")
        .bind(job_id).bind(run_id).fetch_optional(&mut *tx).await.map_err(|e| e.to_string())?;
    if let Some(row) = row {
        sqlx::query("INSERT INTO ci_native_job(job_id,run_id,required_labels) VALUES($1,$2,$3) ON CONFLICT(job_id) DO NOTHING")
            .bind(job_id).bind(run_id).bind(normalize(labels)).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        Store::add_event(&mut tx, run_id, Some(job_id), Some(&row.get::<String,_>("job_key")), None,
            "ci.job.status.v1", "queued", None).await.map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn poll(
    store: &Store,
    p: Poll,
    public_url: &str,
    secrets: &crate::secrets::Secrets,
) -> Result<Option<Lease>, PollError> {
    validate_protocol(p.protocol_version).map_err(PollError::Rejected)?;
    let internal = |e: Box<dyn std::fmt::Display>| PollError::Internal(e.to_string());
    let mut tx = store.pool().begin().await.map_err(|e| internal(Box::new(e)))?;
    let quarantined: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_native_quarantine WHERE runner_id=$1)")
        .bind(&p.runner_id).fetch_one(&mut *tx).await.map_err(|e| internal(Box::new(e)))?;
    if quarantined { return Err(PollError::Rejected("native runner is quarantined pending operator cleanup".into())); }
    let runner = sqlx::query("UPDATE ci_native_runner SET last_seen_at=now() WHERE id=$1 RETURNING labels,max_concurrent")
        .bind(&p.runner_id).fetch_optional(&mut *tx).await.map_err(|e| internal(Box::new(e)))?
        .ok_or_else(|| PollError::Rejected("runner is not registered".into()))?;
    // Expiry revokes writes, not execution already running on a disconnected
    // native host. Keep its capacity and job reserved until quiescence is known.
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM ci_native_job WHERE runner_id=$1 AND state='leased'")
        .bind(&p.runner_id).fetch_one(&mut *tx).await.map_err(|e| internal(Box::new(e)))?;
    if active >= runner.get::<i32, _>("max_concurrent") as i64 {
        tx.commit().await.map_err(|e| internal(Box::new(e)))?;
        return Ok(None);
    }
    let labels: Vec<String> = runner.get("labels");
    let token = Uuid::new_v4();
    let row = sqlx::query("WITH candidate AS (SELECT n.job_id FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.state='queued' AND r.namespace='' AND n.required_labels <@ $2 AND j.status='queued' AND r.status NOT IN ('success','failure','cancelled') AND ((j.plan->>'max_parallel') IS NULL OR (SELECT count(*) FROM ci_native_job peer JOIN ci_job pj ON pj.id=peer.job_id WHERE pj.run_id=j.run_id AND pj.base_id=j.base_id AND peer.state='leased') < (j.plan->>'max_parallel')::int) ORDER BY n.created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE ci_native_job n SET state='leased',runner_id=$1,lease_token=$3,lease_expires_at=now()+make_interval(secs=>$4) FROM candidate WHERE n.job_id=candidate.job_id RETURNING n.job_id,n.run_id,n.lease_expires_at")
        .bind(&p.runner_id).bind(labels).bind(token).bind(LEASE_SECONDS as f64).fetch_optional(&mut *tx).await.map_err(|e| internal(Box::new(e)))?;
    let Some(row) = row else {
        tx.commit().await.map_err(|e| internal(Box::new(e)))?;
        return Ok(None);
    };
    let job_id: String = row.get("job_id");
    let plan_value: serde_json::Value = sqlx::query_scalar("SELECT plan FROM ci_job WHERE id=$1")
        .bind(&job_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| internal(Box::new(e)))?;
    let plan: JobPlan = serde_json::from_value(plan_value).map_err(|e| internal(Box::new(e)))?;
    let claimed = sqlx::query("UPDATE ci_job SET status='running',runner_hd_id=$2,started_at=COALESCE(started_at,now()) WHERE id=$1 AND status IN ('queued','running') RETURNING job_key")
        .bind(&job_id).bind(&p.runner_id).fetch_optional(&mut *tx).await.map_err(|e|internal(Box::new(e)))?;
    let Some(claimed) = claimed else { tx.rollback().await.map_err(|e|internal(Box::new(e)))?; return Ok(None) };
    let job_key: String = claimed.get("job_key");
    Store::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(&job_id), Some(&job_key), None, "ci.job.status.v1", "running", None).await.map_err(|e|internal(Box::new(e)))?;
    for (index, step) in plan.steps.iter().enumerate() {
        let sid=crate::store::step_id(&job_id,index);
        let inserted=sqlx::query("INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES($1,$2,$3,$4,$5,'pending') ON CONFLICT(job_id,idx) DO NOTHING")
            .bind(&sid).bind(&job_id).bind(index as i32).bind(step.label(index)).bind(step.uses.as_deref()).execute(&mut *tx).await.map_err(|e|internal(Box::new(e)))?;
        if inserted.rows_affected()==1 { Store::add_event(&mut tx,&row.get::<String,_>("run_id"),Some(&job_id),Some(&job_key),Some(&sid),"ci.step.status.v1","pending",None).await.map_err(|e|internal(Box::new(e)))?; }
    }
    tx.commit().await.map_err(|e| internal(Box::new(e)))?;
    let run_id: String = row.get("run_id");
    let run=store.get_run(&run_id).await.map_err(|e|internal(Box::new(e)))?;
    let workflow=run.as_ref().map(|r|r.workflow_id.as_str()).unwrap_or("");
    let environment=plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default");
    let namespace=run.as_ref().map(|r|r.namespace.as_str()).unwrap_or("");
    let resolved=secrets.resolve(&crate::secrets::Secrets::prefix_in(namespace,workflow,environment)).await.map_err(|e|internal(Box::new(e)))?;
    let (secret_scope,var_scope)=resolved.scopes();
    let mut context=plan.base_context();
    context.set("ci", crate::dispatch::Dispatcher::ci_scope(run.as_ref()));
    context.set("needs",store.needs_context(&run_id).await.map_err(|e|internal(Box::new(e)))?)
        .set("secrets",secret_scope).set("vars",var_scope);
    Ok(Some(Lease {
        job_id,
        run_id,
        lease_token: token,
        lease_expires_at: row.get("lease_expires_at"),
        plan,
        source_url: format!("{public_url}/api/native/jobs/{token}/source"),
        context: context.into_value(),
        mask_values: resolved.secrets.values().cloned().collect(),
    }))
}

pub async fn heartbeat(store: &Store, u: &LeaseUpdate) -> Result<bool, String> {
    let n=sqlx::query("UPDATE ci_native_job n SET lease_expires_at=now()+make_interval(secs=>$3) FROM ci_job j,ci_run r WHERE n.job_id=j.id AND n.run_id=r.id AND n.runner_id=$1 AND n.lease_token=$2 AND n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled')")
        .bind(&u.runner_id).bind(u.lease_token).bind(LEASE_SECONDS as f64).execute(store.pool()).await.map_err(|e|e.to_string())?.rows_affected();
    Ok(n == 1)
}

pub async fn source_run(store: &Store, token: Uuid) -> Result<Option<String>, String> {
    sqlx::query_scalar("SELECT n.run_id FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.lease_token=$1 AND n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled')") .bind(token).fetch_optional(store.pool()).await.map_err(|e|e.to_string())
}

/// Resolve the immutable, published release source for one explicitly planned
/// checkout step. The lease predicate deliberately matches every other native
/// side effect so a stale token cannot fetch release bytes.
pub async fn release_source_context(
    store: &Store,
    token: Uuid,
    index: usize,
) -> Result<Option<(String, String)>, String> {
    let row = sqlx::query("SELECT n.run_id,j.plan,rel.status,rel.prepared FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id LEFT JOIN ci_release rel ON rel.run_id=n.run_id WHERE n.lease_token=$1 AND n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled')")
        .bind(token).fetch_optional(store.pool()).await.map_err(|e|e.to_string())?;
    let Some(row) = row else { return Ok(None) };
    let plan: JobPlan = serde_json::from_value(row.get("plan")).map_err(|e|e.to_string())?;
    if plan.steps.get(index).and_then(|s|s.uses.as_deref()) != Some("ci/checkout-release") {
        return Err("release source is not the leased step".into());
    }
    if row.get::<Option<String>,_>("status").as_deref() != Some("published") {
        return Err("release checkout requires a confirmed published release".into());
    }
    let prepared: crate::release_git::PreparedRelease = serde_json::from_value(
        row.get::<Option<serde_json::Value>,_>("prepared").ok_or("published release has no prepared source")?
    ).map_err(|e|e.to_string())?;
    Ok(Some((row.get("run_id"), prepared.release_sha)))
}

pub async fn artifact_context(store:&Store,token:Uuid,index:usize)->Result<Option<(String,String,String,String)>,String>{
    let row=sqlx::query("SELECT n.run_id,n.job_id,j.job_key,j.plan,r.workflow_id FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.lease_token=$1 AND n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled')")
        .bind(token).fetch_optional(store.pool()).await.map_err(|e|e.to_string())?;
    let Some(row)=row else{return Ok(None)}; let plan:JobPlan=serde_json::from_value(row.get("plan")).map_err(|e|e.to_string())?;
    if plan.steps.get(index).and_then(|s|s.uses.as_deref())!=Some("ci/upload-artifact"){return Err("artifact upload is not the leased step".into())}
    Ok(Some((row.get("run_id"),row.get("job_id"),row.get("job_key"),row.get("workflow_id"))))
}

pub async fn record_artifact(store:&Store,token:Uuid,index:usize,name:&str,stored:&crate::artifacts::StoredArtifact)->Result<bool,String>{
    let mut tx=store.pool().begin().await.map_err(|e|e.to_string())?;
    let row=sqlx::query("SELECT n.run_id,n.job_id,j.job_key,j.plan FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.lease_token=$1 AND n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled') FOR UPDATE OF n,j,r")
        .bind(token).fetch_optional(&mut *tx).await.map_err(|e|e.to_string())?;
    let Some(row)=row else{return Ok(false)};
    let plan:JobPlan=serde_json::from_value(row.get("plan")).map_err(|e|e.to_string())?;
    if plan.steps.get(index).and_then(|s|s.uses.as_deref())!=Some("ci/upload-artifact"){return Err("artifact upload is not the leased step".into())}
    let run:String=row.get("run_id");let job:String=row.get("job_id");let key:String=row.get("job_key");let sid=crate::store::step_id(&job,index);
    let artifact_id=crate::vm::new_id();
    let inserted=sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri,public_url,step_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(step_id) DO NOTHING")
        .bind(&artifact_id).bind(&run).bind(&job).bind(name).bind(stored.sink).bind(&stored.digest).bind(stored.size_bytes as i64).bind(&stored.uri).bind(&stored.public_url).bind(&sid).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    if inserted.rows_affected()==0 {
        let same:bool=sqlx::query_scalar("SELECT name=$2 AND sink=$3 AND digest IS NOT DISTINCT FROM $4 AND size_bytes=$5 AND uri=$6 AND public_url IS NOT DISTINCT FROM $7 FROM ci_artifact WHERE step_id=$1")
            .bind(&sid).bind(name).bind(stored.sink).bind(&stored.digest).bind(stored.size_bytes as i64).bind(&stored.uri).bind(&stored.public_url).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
        if !same{return Err("artifact publication changed on retry".into())}
    } else {
        let event=Store::add_event(&mut tx,&run,Some(&job),Some(&key),Some(&sid),"ci.artifact.published.v1","published",None).await.map_err(|e|e.to_string())?;
        let artifact=serde_json::json!({"id":artifact_id,"name":name,"sink":stored.sink,"digest":stored.digest,"size_bytes":stored.size_bytes,"uri":stored.uri,"public_url":stored.public_url});
        sqlx::query("UPDATE ci_event_outbox SET payload=payload || jsonb_build_object('artifact',$2::jsonb) WHERE id=$1").bind(event).bind(artifact).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    }
    tx.commit().await.map_err(|e|e.to_string())?;Ok(true)
}

pub async fn complete(store: &Store, secrets:&crate::secrets::Secrets, c: Completion) -> Result<Option<String>, String> {
    let bytes=serde_json::to_vec(&c).map_err(|e|e.to_string())?;
    let completion_hash=hex::encode(Sha256::digest(bytes));
    let scope=sqlx::query("SELECT r.workflow_id,r.namespace,j.plan FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.runner_id=$1 AND n.lease_token=$2")
        .bind(&c.runner_id).bind(c.lease_token).fetch_optional(store.pool()).await.map_err(|e|e.to_string())?;
    let Some(scope)=scope else{return Ok(None)};
    let scope_plan:JobPlan=serde_json::from_value(scope.get("plan")).map_err(|e|e.to_string())?;
    let environment=scope_plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default");
    let resolved=secrets.resolve(&crate::secrets::Secrets::prefix_in(scope.get("namespace"),scope.get("workflow_id"),environment)).await.map_err(|e|e.to_string())?;
    let masker=resolved.masker();
    let mut tx = store.pool().begin().await.map_err(|e| e.to_string())?;
    let row=sqlx::query("SELECT n.job_id,n.run_id,n.state,n.completion_hash,j.job_key,j.plan FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.runner_id=$1 AND n.lease_token=$2 FOR UPDATE OF n,j,r")
        .bind(&c.runner_id).bind(c.lease_token).fetch_optional(&mut *tx).await.map_err(|e|e.to_string())?;
    let Some(row) = row else { return Ok(None) };
    if row.get::<String,_>("state")=="completed" { return if row.get::<Option<String>,_>("completion_hash").as_deref()==Some(&completion_hash){Ok(Some(row.get("run_id")))}else{Err("completion payload changed on retry".into())}; }
    let valid:bool=sqlx::query_scalar("SELECT n.state='leased' AND n.lease_expires_at>now() AND j.status='running' AND r.status NOT IN ('success','failure','cancelled') FROM ci_native_job n JOIN ci_job j ON j.id=n.job_id JOIN ci_run r ON r.id=n.run_id WHERE n.job_id=$1").bind(row.get::<String,_>("job_id")).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
    if !valid{return Ok(None)}
    let job_id: String = row.get("job_id");
    let run_id: String = row.get("run_id");
    let job_key:String=row.get("job_key");
    let plan:JobPlan=serde_json::from_value(row.get("plan")).map_err(|e|e.to_string())?;
    if c.steps.len()!=plan.steps.len() || c.steps.iter().enumerate().any(|(i,s)|s.index!=i || !matches!(s.status.as_str(),"success"|"failure"|"skipped")) { return Err("completion must contain exactly one valid result for every planned step in index order".into()); }
    let mut blocking_failure=false;
    let mut confirmed_release_sha: Option<String> = None;
    let mut step_scope=serde_json::Map::new();
    for (s,planned) in c.steps.iter().zip(&plan.steps) {
        if s.status=="success" && s.exit_code.is_some_and(|x|x!=0) { return Err(format!("step {} claims success with non-zero exit",s.index)); }
        if s.status=="success" && planned.uses.as_deref()==Some("ci/upload-artifact") {
            let published:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_artifact WHERE step_id=$1 AND job_id=$2)")
                .bind(crate::store::step_id(&job_id,s.index)).bind(&job_id).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
            if !published { return Err("native artifact step has no recorded publication".into()); }
        }
        if s.status=="success" && planned.uses.as_deref()==Some("ci/checkout-release") {
            let supplied=s.outputs.get("sha").and_then(|v|v.as_str()).ok_or("release checkout success requires sha output")?;
            let release=crate::release::get(store,&run_id).await?
                .filter(|r|r.status=="published")
                .ok_or("release checkout requires a confirmed published release")?;
            if supplied != release.prepared.release_sha { return Err("release checkout sha does not match the confirmed release".into()); }
            if confirmed_release_sha.as_deref().is_some_and(|sha|sha!=supplied) { return Err("release checkout steps disagree on sha".into()); }
            confirmed_release_sha=Some(supplied.into());
        }
        if s.status=="failure" && !planned.continue_on_error { blocking_failure=true; }
        if let Some(id)=&planned.id { step_scope.insert(id.clone(),serde_json::json!({"outcome":s.status,"conclusion":s.status,"outputs":s.outputs})); }
    }
    let final_status=if blocking_failure {"failure"} else {"success"};
    if c.status!=final_status{return Err(format!("completion status {} disagrees with step evidence {final_status}",c.status))}
    let mut ctx=plan.base_context(); ctx.set("steps",serde_json::Value::Object(step_scope));
    let outputs=serde_json::Value::Object(plan.outputs.iter().map(|(k,v)|(k.clone(),serde_json::Value::String(ctx.substitute(v)))).collect());
    for s in &c.steps {
        let sid = crate::store::step_id(&job_id, s.index);
        let step_error=s.error.as_deref().map(|e|masker.mask(e));
        if !s.log.is_empty() {
            Store::append_log_in(&mut tx, &sid, &masker.mask(&s.log)).await.map_err(|e|e.to_string())?;
        }
        sqlx::query("UPDATE ci_step SET status=$2,exit_code=$3,error=$4,operation_id=$5,started_at=COALESCE(started_at,now()),finished_at=now() WHERE id=$1 AND job_id=$6")
            .bind(&sid).bind(&s.status).bind(s.exit_code).bind(step_error.as_deref()).bind(format!("native-{}",c.lease_token)).bind(&job_id).execute(&mut *tx).await.map_err(|e|e.to_string())?;
        Store::add_event(&mut tx,&run_id,Some(&job_id),Some(&job_key),Some(&sid),"ci.step.status.v1",&s.status,step_error.as_deref()).await.map_err(|e|e.to_string())?;
    }
    let completion_error=c.error.as_deref().map(|e|masker.mask(e));
    sqlx::query("UPDATE ci_job SET status=$2,outputs=$3,error=$4,release_sha=COALESCE($5,release_sha),finished_at=now() WHERE id=$1 AND status='running'").bind(&job_id).bind(final_status).bind(outputs).bind(completion_error.as_deref()).bind(confirmed_release_sha).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    Store::add_event(&mut tx,&run_id,Some(&job_id),Some(&job_key),None,"ci.job.status.v1",final_status,completion_error.as_deref()).await.map_err(|e|e.to_string())?;
    if blocking_failure && plan.fail_fast && !plan.continue_on_error && !plan.matrix.is_empty() {
        let peers = sqlx::query("UPDATE ci_job SET status='cancelled',error='matrix fail-fast',finished_at=now() WHERE run_id=$1 AND base_id=$2 AND id<>$3 AND status IN ('pending','queued','running') RETURNING id,job_key")
            .bind(&run_id).bind(&plan.base_id).bind(&job_id).fetch_all(&mut *tx).await.map_err(|e|e.to_string())?;
        for peer in peers {
            Store::add_event(&mut tx,&run_id,Some(&peer.get::<String,_>("id")),Some(&peer.get::<String,_>("job_key")),None,
                "ci.job.status.v1","cancelled",Some("matrix fail-fast")).await.map_err(|e|e.to_string())?;
        }
    }
    sqlx::query("UPDATE ci_native_job SET state='completed',completed_at=now(),completion_hash=$3,advancement_pending=true WHERE job_id=$1 AND lease_token=$2").bind(&job_id).bind(c.lease_token).bind(completion_hash).execute(&mut *tx).await.map_err(|e|e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(Some(run_id))
}

pub async fn pending_advancements(store:&Store)->Result<Vec<String>,String>{sqlx::query_scalar("SELECT DISTINCT run_id FROM ci_native_job WHERE advancement_pending ORDER BY run_id LIMIT 100").fetch_all(store.pool()).await.map_err(|e|e.to_string())}
pub async fn advancement_done(store:&Store,run:&str)->Result<(),String>{sqlx::query("UPDATE ci_native_job SET advancement_pending=false WHERE run_id=$1 AND advancement_pending AND EXISTS(SELECT 1 FROM ci_run WHERE id=$1 AND status IN ('success','failure','cancelled'))").bind(run).execute(store.pool()).await.map_err(|e|e.to_string()).map(|_|())}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels_are_normalized() {
        assert_eq!(
            normalize(&[" Windows ".into(), "windows".into(), "X86_64".into()]),
            vec!["windows", "x86_64"]
        );
    }
    #[test]
    fn protocol_is_fenced() {
        assert!(validate_protocol(0).is_err());
        assert!(validate_protocol(1).is_ok());
    }

    #[test]
    fn smoke_workflow_has_native_targets_and_artifact_steps() {
        let workflow=crate::workflow::Workflow::parse("native-smoke.yml",include_str!("../native-smoke.yml")).unwrap();
        let plan=crate::plan::Plan::build(&workflow).unwrap();
        assert_eq!(plan.jobs.len(),2);
        assert!(plan.jobs.iter().all(|j|j.native_labels.len()==4 && j.steps.last().unwrap().uses.as_deref()==Some("ci/upload-artifact")));
        assert!(plan.jobs.iter().any(|j|j.native_labels.contains(&"macos-intel".into())));
        assert!(plan.jobs.iter().any(|j|j.native_labels.contains(&"windows-x64".into())));
    }

    #[test]
    fn system_workflow_gates_release_on_real_builds_and_defaults_to_no_publication() {
        let workflow=crate::workflow::Workflow::parse("system.yml",include_str!("../system.yml")).unwrap();
        let plan=crate::plan::Plan::build(&workflow).unwrap();
        assert_eq!(plan.jobs.len(),10);
        let job=|key:&str| plan.jobs.iter().find(|j|j.key==key).unwrap();
        let release=job("release");
        assert_eq!(release.needs,vec!["linux","platform","mac-intel","windows"]);
        let components:std::collections::BTreeSet<_>=plan.jobs.iter()
            .filter(|j|j.base_id=="platform")
            .map(|j|j.matrix["component"].as_str().unwrap()).collect();
        assert_eq!(components,std::collections::BTreeSet::from(["app-lb","artifacts","heyosecret","orchestrator"]));
        let merge=release.steps.iter().find(|s|s.uses.as_deref()==Some("ci/merge-release")).unwrap();
        assert!(!merge.with.contains_key("tags"),"merging must not implicitly publish tags");
        for validation in plan.jobs.iter().filter(|j|release.needs.contains(&j.base_id)) {
            assert!(validation.condition.is_none());
            assert!(!validation.continue_on_error);
            assert!(validation.steps.iter().all(|s|!s.continue_on_error));
            assert!(validation.steps.iter().any(|s|s.run.as_deref().is_some_and(|r|r.contains("cargo test --locked"))));
            assert!(validation.steps.iter().any(|s|s.run.as_deref().is_some_and(|r|r.contains("cargo build --locked --release"))));
        }
        let compile_steps:Vec<_>=job("linux").steps.iter().filter(|s|s.run.as_deref().is_some_and(|r|r.contains("cargo test")||r.contains("cargo build"))).collect();
        assert_eq!(compile_steps.len(),2,"tests and release compilation need separate progress and timeout budgets");
        assert!(compile_steps.iter().all(|s|s.timeout_minutes==Some(60)),"job timeout alone does not override the default 30-minute step timeout");
        assert!(job("mac-intel").native_labels.contains(&"macos-intel".into()));
        assert!(job("windows").native_labels.contains(&"windows-x64".into()));
        let ctx=crate::expr::Context::new();
        assert!(!ctx.eval_condition(release.condition.as_deref().unwrap()).unwrap());
        assert!(!ctx.eval_condition(job("deploy").condition.as_deref().unwrap()).unwrap());
        let archive_condition=job("release-archive").condition.as_deref();
        assert!(archive_condition.is_some(),"release archives must be gated, not just depend on a possibly skipped release");
        assert!(!ctx.eval_condition(archive_condition.unwrap()).unwrap());
        for (enabled,source,expected) in [("false","validated-source",false),("true","validated-source",true),("true","another-source",false),("true","",false)] {
            let mut ctx=crate::expr::Context::new();
            ctx.set("ci",serde_json::json!({"sha":"validated-source"}));
            ctx.set("vars",serde_json::json!({"RELEASE_ENABLED":enabled,"RELEASE_SOURCE_SHA":source}));
            assert_eq!(ctx.eval_condition(release.condition.as_deref().unwrap()).unwrap(),expected);
            assert_eq!(ctx.eval_condition(archive_condition.unwrap()).unwrap(),expected);
        }
        assert_eq!(job("release-archive").needs,vec!["release"]);
        assert_eq!(job("release-archive").steps[0].uses.as_deref(),Some("ci/checkout-release"));
        assert!(job("release-archive").steps.iter().any(|s|s.uses.as_deref()==Some("ci/upload-artifact") && s.with.get("name").map(String::as_str)==Some("ci-linux-release")));
        let publish=job("release-archive").steps.iter().find(|s|s.uses.as_deref()==Some("ci/publish-service-archive")).unwrap();
        assert!(publish.condition.as_deref().unwrap().contains("DEPLOY_ENABLED"));
        assert_eq!(job("deploy").needs,vec!["release-archive"]);
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL; disposable PostgreSQL only"]
    async fn native_leases_fence_concurrency_expiry_cancellation_and_completion_rollback() {
        let store = Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(),
            std::env::temp_dir().join(crate::vm::new_id()), std::time::Duration::from_secs(30)).await.unwrap();
        store.migrate().await.unwrap();
        let secrets = crate::secrets::Secrets::unconfigured();
        let runner = crate::vm::new_id();
        let label = format!("isolated-{runner}");
        register(&store, Registration { runner_id:runner.clone(),name:runner.clone(),
            labels:vec![label.clone(),"macos".into(),"x86_64".into()], platform:"macos".into(),arch:"x86_64".into(),
            protocol_version:1,max_concurrent_jobs:1 }).await.unwrap();
        let workflow = crate::workflow::Workflow::parse("native.yml", &format!("jobs:\n  native:\n    runs-on: [{label}]\n    steps:\n      - run: exit 0\n")).unwrap();
        let plan = crate::plan::Plan::build(&workflow).unwrap();
        let run = crate::vm::new_id();
        store.create_run(&run,&crate::store::RunRequest::default(),&plan).await.unwrap();
        let job = store.jobs_of(&run).await.unwrap().remove(0);
        enqueue(&store,&job.id,&run,&[label.clone()]).await.unwrap();
        let request = || Poll{runner_id:runner.clone(),protocol_version:1};
        let (a,b) = tokio::join!(poll(&store,request(),"http://localhost",&secrets),poll(&store,request(),"http://localhost",&secrets));
        let (a,b) = (a.unwrap(),b.unwrap());
        assert_ne!(a.is_some(),b.is_some(),"one runner cannot acquire concurrent leases beyond capacity");
        let first = a.or(b).unwrap();
        assert!(release_source_context(&store,first.lease_token,0).await.is_err(),"wrong action must be refused");
        sqlx::query("UPDATE ci_native_job SET lease_expires_at=now()-interval '1 second' WHERE job_id=$1")
            .bind(&job.id).execute(store.pool()).await.unwrap();
        assert!(release_source_context(&store,first.lease_token,0).await.unwrap().is_none(),"expired lease must be fenced");
        assert!(poll(&store,request(),"http://localhost",&secrets).await.unwrap().is_none(), "expiry cannot free the old runner's capacity");
        let peer = crate::vm::new_id();
        register(&store, Registration { runner_id:peer.clone(),name:peer.clone(),
            labels:vec![label.clone(),"macos".into(),"x86_64".into()], platform:"macos".into(),arch:"x86_64".into(),
            protocol_version:1,max_concurrent_jobs:1 }).await.unwrap();
        assert!(poll(&store,Poll{runner_id:peer.clone(),protocol_version:1},"http://localhost",&secrets).await.unwrap().is_none(),
            "another runner cannot take over an expired execution");
        assert!(!heartbeat(&store,&LeaseUpdate{runner_id:runner.clone(),lease_token:first.lease_token}).await.unwrap());
        let report = |token,status:&str,step_status:&str,exit| Completion{runner_id:runner.clone(),lease_token:token,
            status:status.into(),error:None,outputs:serde_json::json!({}),steps:vec![StepResult{index:0,status:step_status.into(),exit_code:Some(exit),log:"native test log".into(),error:None,outputs:serde_json::json!({})}]};
        assert!(complete(&store,&secrets,report(first.lease_token,"success","success",0)).await.unwrap().is_none());
        let retained: Uuid = sqlx::query_scalar("SELECT lease_token FROM ci_native_job WHERE job_id=$1")
            .bind(&job.id).fetch_one(store.pool()).await.unwrap();
        assert_eq!(retained, first.lease_token, "no replacement execution identity was issued");
        // Restore the fixture's clock boundary to test valid completion below;
        // this is not a production recovery operation or a replacement lease.
        sqlx::query("UPDATE ci_native_job SET lease_expires_at=now()+interval '10 minutes' WHERE job_id=$1")
            .bind(&job.id).execute(store.pool()).await.unwrap();
        let second = first;
        assert!(complete(&store,&secrets,report(second.lease_token,"success","failure",7)).await.is_err());
        assert_eq!(store.get_job(&job.id).await.unwrap().unwrap().status,"running");
        let constraint = format!("reject_native_{run}");
        sqlx::query(&format!("ALTER TABLE ci_event_outbox ADD CONSTRAINT \"{constraint}\" CHECK(run_id<>'{run}' OR status<>'success')"))
            .execute(store.pool()).await.unwrap();
        assert!(complete(&store,&secrets,report(second.lease_token,"success","success",0)).await.is_err());
        assert_eq!(store.get_job(&job.id).await.unwrap().unwrap().status,"running");
        let step = store.steps_of(&job.id).await.unwrap().remove(0);
        assert_eq!(store.read_log(&step).await.unwrap(), None, "failed completion must roll back its log bytes");
        assert!(heartbeat(&store,&LeaseUpdate{runner_id:runner.clone(),lease_token:second.lease_token}).await.unwrap());
        sqlx::query(&format!("ALTER TABLE ci_event_outbox DROP CONSTRAINT \"{constraint}\""))
            .execute(store.pool()).await.unwrap();
        assert_eq!(complete(&store,&secrets,report(second.lease_token,"success","success",0)).await.unwrap(),Some(run.clone()));
        assert_eq!(complete(&store,&secrets,report(second.lease_token,"success","success",0)).await.unwrap(),Some(run.clone()),"identical completion retries must resume DAG advancement");
        assert_eq!(store.get_job(&job.id).await.unwrap().unwrap().status,"success");
        assert_eq!(store.read_log(&step).await.unwrap().as_deref(), Some("native test log"), "completion retry must not duplicate logs");
        let cancelled_run=crate::vm::new_id();
        store.create_run(&cancelled_run,&crate::store::RunRequest::default(),&plan).await.unwrap();
        let cancelled=store.jobs_of(&cancelled_run).await.unwrap().remove(0);
        enqueue(&store,&cancelled.id,&cancelled_run,&[label.clone()]).await.unwrap();
        let lease=poll(&store,request(),"http://localhost",&secrets).await.unwrap().unwrap();
        store.set_job_status(&cancelled.id,crate::store::JobStatus::Cancelled,None).await.unwrap();
        assert!(!heartbeat(&store,&LeaseUpdate{runner_id:runner.clone(),lease_token:lease.lease_token}).await.unwrap());
        assert!(complete(&store,&secrets,report(lease.lease_token,"success","success",0)).await.unwrap().is_none());
        assert_eq!(store.get_job(&cancelled.id).await.unwrap().unwrap().status,"cancelled");
        // Cancellation and expiry cannot prove that the native process stopped.
        sqlx::query("UPDATE ci_native_job SET lease_expires_at=now()-interval '1 second' WHERE job_id=$1")
            .bind(&cancelled.id).execute(store.pool()).await.unwrap();
        assert!(poll(&store,request(),"http://localhost",&secrets).await.unwrap().is_none());
        // Independent work can still execute on the unused peer runner.
        let runner = peer;
        let request = || Poll{runner_id:runner.clone(),protocol_version:1};

        let release_workflow=crate::workflow::Workflow::parse("native-release.yml",&format!("jobs:\n  native:\n    runs-on: [{label}]\n    steps:\n      - id: checkout\n        uses: ci/checkout-release\n")).unwrap();
        let release_plan=crate::plan::Plan::build(&release_workflow).unwrap();let release_run=crate::vm::new_id();
        store.create_run(&release_run,&crate::store::RunRequest::default(),&release_plan).await.unwrap();let release_job=store.jobs_of(&release_run).await.unwrap().remove(0);
        enqueue(&store,&release_job.id,&release_run,&[label]).await.unwrap();let release_lease=poll(&store,request(),"http://localhost",&secrets).await.unwrap().unwrap();
        assert!(release_source_context(&store,Uuid::new_v4(),0).await.unwrap().is_none(),"foreign lease must be fenced");
        assert!(release_source_context(&store,release_lease.lease_token,1).await.is_err(),"wrong step index must be refused");
        assert!(release_source_context(&store,release_lease.lease_token,0).await.is_err(),"unpublished release must be refused");
        let sha="0123456789abcdef0123456789abcdef01234567";let source_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let prepared=crate::release_git::PreparedRelease{source_sha:source_sha.into(),release_sha:sha.into(),git_ref:"refs/heads/main".into(),versions:serde_json::json!({}),tags:vec![]};
        sqlx::query("INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status) VALUES($1,'request',$2,$2,'refs/heads/main','{}',$2,$3,'published')").bind(&release_run).bind(sha).bind(serde_json::to_value(&prepared).unwrap()).execute(store.pool()).await.unwrap();
        assert_eq!(release_source_context(&store,release_lease.lease_token,0).await.unwrap(),Some((release_run.clone(),sha.into())));
        let completion=|reported_sha: &str| Completion{runner_id:runner.clone(),lease_token:release_lease.lease_token,status:"success".into(),error:None,outputs:serde_json::json!({}),steps:vec![StepResult{index:0,status:"success".into(),exit_code:None,log:String::new(),error:None,outputs:serde_json::json!({"sha":reported_sha})}]};
        assert!(complete(&store,&secrets,completion(source_sha)).await.unwrap_err().contains("does not match"));
        assert!(sqlx::query_scalar::<_,Option<String>>("SELECT release_sha FROM ci_job WHERE id=$1").bind(&release_job.id).fetch_one(store.pool()).await.unwrap().is_none());
        assert_eq!(complete(&store,&secrets,completion(sha)).await.unwrap(),Some(release_run));
        assert_eq!(sqlx::query_scalar::<_,Option<String>>("SELECT release_sha FROM ci_job WHERE id=$1").bind(&release_job.id).fetch_one(store.pool()).await.unwrap().as_deref(),Some(sha));
    }
}
