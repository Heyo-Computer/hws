//! Independent CI process lifetimes. There is no elected execution owner.
//! Jobs claim their own rows; shared reconcilers lock only their operation ID.
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ExecutorInstance {
    pool: PgPool,
    boot_id: Uuid,
    deployment_id: String,
    local: Arc<RwLock<()>>,
}

#[derive(Debug)]
pub struct EffectPermit {
    _local: OwnedRwLockReadGuard<()>,
    // Dropping the transaction releases the operation lock, including on error.
    _operation: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
}

pub fn identity(config: &crate::config::Config) -> String {
    config.managed_deployment.clone().unwrap_or_else(|| match (&config.controller_deployment, &config.controller_app_lb_url) {
        (Some(id), Some(base)) => format!("{}/deployments/{id}", base.trim_end_matches('/')),
        _ => config.instance_id.clone(),
    })
}

impl ExecutorInstance {
    pub async fn register(pool: PgPool, deployment_id: &str) -> Result<Self, String> {
        if deployment_id.is_empty() { return Err("executor deployment identity must not be empty".into()); }
        let boot_id = Uuid::new_v4();
        // A replacement verifies its own unfinished rollout before taking jobs.
        // Other deployment identities are unaffected, including other regions.
        // Lock the matching rollout so finish cannot reopen admissions between
        // observing the drain and committing this new boot.
        let mut tx = pool.begin().await.map_err(db)?;
        let drain: Option<Option<Uuid>> = sqlx::query_scalar("SELECT (request->>'source_boot')::uuid FROM ci_controller_rollout WHERE phase NOT IN ('prepared','complete') AND (request->>'base_url')||'/deployments/'||(request->>'deployment')=$1 FOR SHARE")
            .bind(deployment_id).fetch_optional(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO ci_executor_boot(boot_id,deployment_id,execution_protocol,draining,maintenance_operation) VALUES($1,$2,'job-claims-v1',$3,$4)")
            .bind(boot_id).bind(deployment_id).bind(drain.is_some()).bind(drain.flatten())
            .execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Self { pool, boot_id, deployment_id: deployment_id.into(), local: Arc::new(RwLock::new(())) })
    }

    pub fn boot_id(&self) -> Uuid { self.boot_id }

    pub async fn mark_ready(&self) -> Result<(), String> {
        sqlx::query("UPDATE ci_executor_boot SET ready_at=now() WHERE boot_id=$1 AND NOT retired")
            .bind(self.boot_id).execute(&self.pool).await.map_err(db)?;
        Ok(())
    }

    /// Existing jobs and durable cleanup continue while this boot drains.
    pub async fn effect_permit(&self) -> Result<EffectPermit, String> {
        let local = self.local.clone().read_owned().await;
        let retired: bool = sqlx::query_scalar("SELECT retired FROM ci_executor_boot WHERE boot_id=$1")
            .bind(self.boot_id).fetch_one(&self.pool).await.map_err(db)?;
        if retired { return Err("CI instance is retired".into()); }
        Ok(EffectPermit { _local: local, _operation: None })
    }

    /// This is not job ownership: claim_job_for_boot rechecks admission under
    /// the boot row lock in the same transaction as claiming the job.
    pub async fn admission_permit(&self) -> Result<EffectPermit, String> {
        let permit = self.effect_permit().await?;
        let draining: bool = sqlx::query_scalar("SELECT draining FROM ci_executor_boot WHERE boot_id=$1")
            .bind(self.boot_id).fetch_one(&self.pool).await.map_err(db)?;
        if draining { return Err("CI instance is draining; submit to another instance".into()); }
        Ok(permit)
    }

    pub async fn effect_permit_for(&self, operation: Option<&str>) -> Result<EffectPermit, String> {
        let mut permit = self.effect_permit().await?;
        if let Some(id) = operation {
            if id.is_empty() { return Err("operation identity is empty".into()); }
            let mut tx = self.pool.begin().await.map_err(db)?;
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 734))")
                .bind(id).fetch_one(&mut *tx).await.map_err(db)?;
            if !acquired { return Err("operation is being reconciled by another instance".into()); }
            permit._operation = Some(tx);
        }
        Ok(permit)
    }

    /// Local work only. Never transfers authority to another region.
    #[cfg(test)]
    pub async fn idle_guard(&self) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, String> {
        Ok(self.local.clone().write_owned().await)
    }

    pub async fn pause(&self, id: Uuid) -> Result<(), String> {
        let changed = sqlx::query("UPDATE ci_executor_boot SET draining=TRUE,maintenance_operation=$2 WHERE boot_id=$1 AND NOT retired AND (maintenance_operation IS NULL OR maintenance_operation=$2)")
            .bind(self.boot_id).bind(id).execute(&self.pool).await.map_err(db)?.rows_affected();
        if changed != 1 { return Err("another maintenance operation owns this instance or it is retired".into()); }
        Ok(())
    }

    pub async fn resume(&self, id: Uuid) -> Result<(), String> {
        let changed = sqlx::query("UPDATE ci_executor_boot SET draining=FALSE,maintenance_operation=NULL WHERE boot_id=$1 AND maintenance_operation=$2 AND NOT retired AND NOT EXISTS(SELECT 1 FROM ci_application_retirement WHERE target_boot=$1) AND NOT EXISTS(SELECT 1 FROM ci_controller_rollout WHERE phase<>'complete' AND request->>'source_boot'=($2::uuid)::text AND (request->>'base_url')||'/deployments/'||(request->>'deployment')=$3)")
            .bind(self.boot_id).bind(id).bind(&self.deployment_id).execute(&self.pool).await.map_err(db)?.rows_affected();
        if changed != 1 { return Err("maintenance operation does not match or retirement/replacement is pending".into()); }
        Ok(())
    }

    pub async fn has_work(&self) -> Result<bool, String> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_job j WHERE j.executor_boot=$1 AND (j.status='running' OR EXISTS(SELECT 1 FROM ci_host_work w WHERE w.job_id=j.id) OR EXISTS(SELECT 1 FROM ci_vm_cleanup c WHERE c.job_id=j.id)))")
            .bind(self.boot_id).fetch_one(&self.pool).await.map_err(db)
    }

    pub async fn quiesce(&self, id: Uuid) -> Result<(), String> {
        let _local = self.local.clone().try_write_owned().map_err(|_| "this CI instance has work in flight".to_owned())?;
        let draining: bool = sqlx::query_scalar("SELECT draining AND maintenance_operation IS NOT DISTINCT FROM $2 FROM ci_executor_boot WHERE boot_id=$1")
            .bind(self.boot_id).bind(id).fetch_one(&self.pool).await.map_err(db)?;
        if !draining { return Err("maintenance operation does not match this instance".into()); }
        if self.has_work().await? { return Err("this CI instance still owns job or cleanup work".into()); }
        Ok(())
    }

    /// The app-lb replacement operation outlives this boot. Do not transfer
    /// global authority; stop only this boot's effects, under its local guard.
    pub async fn retire_for_replacement(&self, id: Uuid) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, String> {
        let local = self.local.clone().try_write_owned().map_err(|_| "this CI instance has work in flight".to_owned())?;
        if self.has_work().await? { return Err("this CI instance still owns job or cleanup work".into()); }
        let changed = sqlx::query("UPDATE ci_executor_boot SET retired=TRUE WHERE boot_id=$1 AND draining AND maintenance_operation=$2")
            .bind(self.boot_id).bind(id).execute(&self.pool).await.map_err(db)?.rows_affected();
        if changed != 1 { return Err("replacement does not own this instance drain".into()); }
        Ok(local)
    }

    /// Operator configuration replacement has no release receipt. Fence this
    /// boot permanently, but never take over an unfinished regional release.
    pub async fn retire_for_configuration(&self, id: Uuid, expected_boot: Uuid) -> Result<(), String> {
        if expected_boot != self.boot_id { return Err("configuration retirement targets another boot".into()); }
        let _local = self.local.clone().try_write_owned().map_err(|_| "this CI instance has work in flight".to_owned())?;
        if self.has_work().await? { return Err("this CI instance still owns job or cleanup work".into()); }
        // Preparation and activation also acquire a local effect permit. Keep
        // the write guard through the check and retirement so neither can race
        // us. Reconciliation can bypass retirement for an existing receipt.
        let rollout: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_controller_rollout WHERE phase<>'complete' AND (request->>'base_url')||'/deployments/'||(request->>'deployment')=$1)")
            .bind(&self.deployment_id).fetch_one(&self.pool).await.map_err(db)?;
        if rollout { return Err("regional release must finish before configuration replacement".into()); }
        let changed = sqlx::query("UPDATE ci_executor_boot SET retired=TRUE WHERE boot_id=$1 AND draining AND maintenance_operation=$2")
            .bind(self.boot_id).bind(id).execute(&self.pool).await.map_err(db)?.rows_affected();
        if changed != 1 { return Err("configuration replacement does not own this instance drain".into()); }
        Ok(())
    }

    pub async fn status(&self) -> Result<serde_json::Value, String> {
        let (draining, retired, operation): (bool, bool, Option<Uuid>) = sqlx::query_as(
            "SELECT draining,retired,maintenance_operation FROM ci_executor_boot WHERE boot_id=$1")
            .bind(self.boot_id).fetch_one(&self.pool).await.map_err(db)?;
        let _local = self.local.clone().try_write_owned().ok();
        let busy = _local.is_none() || self.has_work().await?;
        Ok(serde_json::json!({"bootId":self.boot_id,"deploymentId":self.deployment_id,
            "operationId":operation,"phase":if retired {"retired"} else if draining {"draining"} else {"running"},
            "admissionClosed":draining || retired,"quiesced":draining && !busy,
            "safeToReplace":retired,"blockers":if busy {vec!["instance work"]} else {vec![]}}))
    }

    pub async fn retire_application(&self, request: &crate::application_lifecycle::Retirement) -> anyhow::Result<()> {
        anyhow::ensure!(request.target.boot_id == self.boot_id && request.target.deployment_id == self.deployment_id,
            "retirement target is not this process");
        // Serializes with claims of this boot only. Other regions keep claiming.
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT boot_id FROM ci_executor_boot WHERE boot_id=$1 FOR UPDATE")
            .bind(self.boot_id).execute(&mut *tx).await?;
        let (phase, hash): (String, String) = sqlx::query_as(
            "SELECT phase,request_hash FROM ci_application_retirement WHERE command_id=$1 AND target_boot=$2 FOR UPDATE")
            .bind(&request.command_id).bind(self.boot_id).fetch_one(&mut *tx).await?;
        anyhow::ensure!(hash == request.hash()?, "retirement payload changed");
        if phase == "safe" { return Ok(()); }
        sqlx::query("UPDATE ci_executor_boot SET draining=TRUE WHERE boot_id=$1")
            .bind(self.boot_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE ci_application_retirement SET phase='draining' WHERE command_id=$1")
            .bind(&request.command_id).execute(&mut *tx).await?;
        tx.commit().await?;
        let Ok(_local) = self.local.clone().try_write_owned() else { return Ok(()); };
        if self.has_work().await.map_err(anyhow::Error::msg)? { return Ok(()); }
        let mut survivor_ready = false;
        for candidate in &request.survivors {
            anyhow::ensure!(candidate.region != request.target.region && candidate.deployment_id != self.deployment_id,
                "survivor belongs to the retiring region or deployment");
            survivor_ready |= sqlx::query_scalar::<_,bool>(
                "SELECT EXISTS(SELECT 1 FROM ci_executor_boot WHERE boot_id=$1 AND deployment_id=$2 AND execution_protocol='job-claims-v1' AND NOT retired AND NOT draining AND ready_at>now()-interval '30 seconds')")
                .bind(candidate.boot_id).bind(&candidate.deployment_id).fetch_one(&self.pool).await?;
        }
        anyhow::ensure!(survivor_ready, "no approved surviving CI instance is ready");
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE ci_executor_boot SET retired=TRUE WHERE boot_id=$1 AND draining")
            .bind(self.boot_id).execute(&mut *tx).await?;
        let receipt = serde_json::json!({"commandId":request.command_id,"operationId":request.operation_id,
            "stepId":request.step_id,"serviceId":request.service_id,"target":request.target,"requestHash":hash});
        sqlx::query("UPDATE ci_application_retirement SET phase='safe',receipt=$2 WHERE command_id=$1 AND receipt IS NULL")
            .bind(&request.command_id).bind(receipt).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

fn db(error: sqlx::Error) -> String { format!("CI instance database error: {error}") }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL"]
    async fn both_regions_active_and_only_target_drains() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = PgPool::connect(&base).await.unwrap();
        let schema = format!("active_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-c search_path={schema}"));
        let pool = PgPool::connect(url.as_str()).await.unwrap();
        for migration in crate::store::embedded_migrations() {
            sqlx::raw_sql(&migration.sql).execute(&pool).await.unwrap();
        }
        let us = ExecutorInstance::register(pool.clone(), "us").await.unwrap();
        let eu = ExecutorInstance::register(pool.clone(), "eu").await.unwrap();
        us.admission_permit().await.unwrap();
        eu.admission_permit().await.unwrap();
        let work = us.effect_permit().await.unwrap();
        let operation = Uuid::new_v4();
        us.pause(operation).await.unwrap();
        assert!(us.admission_permit().await.is_err());
        eu.admission_permit().await.unwrap();
        us.effect_permit().await.unwrap();
        assert!(us.quiesce(operation).await.is_err());
        drop(work);
        us.quiesce(operation).await.unwrap();
        assert!(us.resume(Uuid::new_v4()).await.is_err());
        us.resume(operation).await.unwrap();
        us.admission_permit().await.unwrap();
        let same = us.effect_permit_for(Some("deployment-a")).await.unwrap();
        assert!(eu.effect_permit_for(Some("deployment-a")).await.is_err());
        eu.effect_permit_for(Some("deployment-b")).await.unwrap();
        drop(same);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if eu.effect_permit_for(Some("deployment-a")).await.is_ok() { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        // Restarting one deployment does not require transferring global authority.
        ExecutorInstance::register(pool.clone(), "us").await.unwrap().admission_permit().await.unwrap();
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM ci_executor_owner").fetch_one(&pool).await.unwrap(), 0);

        // EU-owned running work must not prevent US retirement.
        sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('peer-run','test','ci.yml','running');
            INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('peer-job','peer-run','test','test','Test','running');")
            .execute(&pool).await.unwrap();
        sqlx::query("UPDATE ci_job SET executor_boot=$1 WHERE id='peer-job'")
            .bind(eu.boot_id()).execute(&pool).await.unwrap();
        eu.mark_ready().await.unwrap();

        let configured = ExecutorInstance::register(pool.clone(), "https://admin.example/deployments/ci-a").await.unwrap();
        let configuration = Uuid::new_v4();
        configured.pause(configuration).await.unwrap();
        assert!(configured.retire_for_configuration(configuration, eu.boot_id()).await.is_err());
        assert!(configured.retire_for_configuration(Uuid::new_v4(), configured.boot_id()).await.is_err());
        let effect = configured.effect_permit().await.unwrap();
        assert!(configured.retire_for_configuration(configuration, configured.boot_id()).await.is_err());
        drop(effect);
        configured.quiesce(configuration).await.unwrap();
        assert_eq!(configured.status().await.unwrap()["safeToReplace"], false);
        sqlx::raw_sql("INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES('config-step','peer-job',0,'Release','ci/deploy-controller','success');
            INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref)
            VALUES('config-release','config-step','peer-run','peer-job','ci','hash','running','source','refs/heads/main');
            INSERT INTO ci_controller_rollout(id,request,phase) VALUES('config-release','{\"base_url\":\"https://admin.example\",\"deployment\":\"ci-a\"}','prepared');")
            .execute(&pool).await.unwrap();
        for phase in ["prepared", "pending", "draining", "quiesced", "submitting", "verifying"] {
            sqlx::query("UPDATE ci_controller_rollout SET phase=$1 WHERE id='config-release'")
                .bind(phase).execute(&pool).await.unwrap();
            assert!(configured.retire_for_configuration(configuration, configured.boot_id()).await.is_err(), "{phase}");
            configured.effect_permit().await.unwrap();
        }
        // A different regional rollout and the peer's running job do not fence
        // this idle boot. Matching authority alone is not deployment identity.
        sqlx::query("UPDATE ci_controller_rollout SET phase='prepared',request=jsonb_set(request,'{deployment}','\"ci-b\"') WHERE id='config-release'")
            .execute(&pool).await.unwrap();
        configured.retire_for_configuration(configuration, configured.boot_id()).await.unwrap();
        configured.retire_for_configuration(configuration, configured.boot_id()).await.unwrap();
        assert_eq!(configured.status().await.unwrap()["safeToReplace"], true);
        assert!(configured.effect_permit().await.is_err());
        assert!(configured.resume(configuration).await.is_err());
        eu.admission_permit().await.unwrap();
        ExecutorInstance::register(pool.clone(), "https://admin.example/deployments/ci-a").await.unwrap()
            .admission_permit().await.unwrap();

        let instance = |boot_id, region: &str| crate::application_lifecycle::Instance {
            boot_id, region: region.into(), deployment_id: region.into(),
            backend_server_id: format!("host-{region}"), backend_sandbox_id: format!("sb-{region}"),
        };
        let request = crate::application_lifecycle::Retirement {
            command_id: "retire-us".into(), operation_id: "update".into(), step_id: "us".into(), service_id: "ci".into(),
            target: instance(us.boot_id(), "us"), survivors: vec![instance(eu.boot_id(), "eu")],
        };
        sqlx::query("INSERT INTO ci_application_retirement(command_id,target_boot,request_hash,request,phase) VALUES($1,$2,$3,$4,'pending')")
            .bind(&request.command_id).bind(us.boot_id()).bind(request.hash().unwrap())
            .bind(serde_json::to_value(&request).unwrap()).execute(&pool).await.unwrap();
        us.retire_application(&request).await.unwrap();
        us.retire_application(&request).await.unwrap();
        assert!(us.effect_permit().await.is_err());
        eu.admission_permit().await.unwrap();
        assert_eq!(crate::application_lifecycle::status(&pool, &request.command_id, &request.hash().unwrap()).await.unwrap()["status"], "safe-to-retire");
    }
}
