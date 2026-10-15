//! Durable post-execution cleanup. Terminal job status alone never authorizes it.
use crate::{dispatch::Dispatcher, store::{JobStatus, Store}, vm::VmError};
use anyhow::{Result, ensure};
use heyo_sdk::{HeyoError, SandboxStatus};
use sqlx::Row;
use std::time::Duration;

/// Called only after this executor has stopped issuing commands to its owned VM.
/// Publish the job result and cleanup obligation together, before attempting IO.
pub async fn handoff(d: &Dispatcher, job: &str, runner: &str, attempt: i32,
    sandbox: &str, status: JobStatus, error: Option<&str>) -> Result<()> {
    ensure!(status.is_terminal(), "cleanup requires a terminal executor outcome");
    handoff_inner(d, job, runner, attempt, sandbox, status, error, false).await
}

/// Admission was conclusively rejected before checkout or execution. Keep the
/// job nonterminal until cleanup proves it is safe to request another VM.
pub async fn wait_for_capacity(d: &Dispatcher, job: &str, runner: &str, attempt: i32,
    sandbox: &str, error: &str) -> Result<()> {
    handoff_inner(d, job, runner, attempt, sandbox, JobStatus::Running, Some(error), true).await
}

async fn handoff_inner(d: &Dispatcher, job: &str, runner: &str, attempt: i32,
    sandbox: &str, status: JobStatus, error: Option<&str>, requeue: bool) -> Result<()> {
    let mut tx = d.store.pool().begin().await?;
    let j = sqlx::query("SELECT run_id,job_key,attempt,status,executor_boot FROM ci_job WHERE id=$1 FOR UPDATE")
        .bind(job).fetch_one(&mut *tx).await?;
    ensure!(j.get::<i32,_>("attempt") == attempt, "cleanup attempt changed");
    ensure!(j.get::<Option<uuid::Uuid>,_>("executor_boot") == Some(d.executor.boot_id()),
        "cleanup executor ownership changed");
    let p = sqlx::query("SELECT status,claimed_by_job,runner_hd_id,leased_by FROM ci_vm_pool WHERE sandbox_id=$1 FOR UPDATE")
        .bind(sandbox).fetch_one(&mut *tx).await?;
    ensure!(p.get::<String,_>("status") == "claimed"
        && p.get::<Option<String>,_>("claimed_by_job").as_deref() == Some(job)
        && p.get::<String,_>("runner_hd_id") == runner
        && p.get::<Option<String>,_>("leased_by").as_deref() == Some(&d.config.instance_id), "cleanup ownership changed");
    let work: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3)")
        .bind(job).bind(runner).bind(attempt).fetch_one(&mut *tx).await?;
    ensure!(work, "cleanup has no executor ownership evidence");
    sqlx::query("INSERT INTO ci_vm_cleanup(sandbox_id,job_id,runner_hd_id,attempt,destroy,requeue,next_attempt_at) VALUES($1,$2,$3,$4,true,$5,now()+CASE WHEN $5 THEN interval '60 seconds' ELSE interval '0 seconds' END)")
        .bind(sandbox).bind(job).bind(runner).bind(attempt).bind(requeue).execute(&mut *tx).await?;
    if requeue {
        sqlx::query("INSERT INTO ci_runner_capacity_wait(runner_hd_id,until_at) VALUES($1,now()+interval '5 minutes') ON CONFLICT(runner_hd_id) DO UPDATE SET until_at=EXCLUDED.until_at")
            .bind(runner).execute(&mut *tx).await?;
    }
    // Change the pool tuple too: an orphan UPDATE already waiting on this row
    // must recheck a non-expiring lease, even if its snapshot predates the intent.
    // Cleanup now owns release; process heartbeats no longer own this lease.
    sqlx::query("UPDATE ci_vm_pool SET leased_until='infinity'::timestamptz WHERE sandbox_id=$1")
        .bind(sandbox).execute(&mut *tx).await?;
    // Acquisition may finish after cancellation or another terminal outcome.
    // Cleanup must preserve that outcome, not overwrite it.
    let existing = j.get::<String,_>("status");
    let final_status = if JobStatus::parse(&existing).is_some_and(|s| s.is_terminal()) { existing.as_str() } else { status.as_str() };
    let updated = sqlx::query("UPDATE ci_job SET status=$2,error=COALESCE($3,error),finished_at=CASE WHEN $2='running' THEN NULL ELSE now() END WHERE id=$1 AND attempt=$4 AND executor_boot=$5")
        .bind(job).bind(final_status).bind(error).bind(attempt).bind(d.executor.boot_id())
        .execute(&mut *tx).await?;
    ensure!(updated.rows_affected() == 1, "cleanup executor ownership changed");
    Store::add_event(&mut tx, &j.get::<String,_>("run_id"), Some(job), Some(&j.get::<String,_>("job_key")),
        None, "ci.job.status.v1", final_status, error).await?;
    crate::debug_report::enqueue(&mut tx, job, sandbox).await?;
    tx.commit().await?;
    Ok(())
}

pub fn spawn(d: std::sync::Arc<Dispatcher>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(_effect) = d.executor.effect_permit().await else { continue };
            if let Err(e) = reconcile(&d).await {
                tracing::warn!("could not reconcile VM cleanup: {e}");
            }
        }
    });
}

/// Run during ordinary operation and drain. Independent of the originating
/// process lifetime; the durable handoff is the authority after restart.
pub async fn reconcile(d: &Dispatcher) -> Result<()> {
    let runners: Vec<String> = d.runners.snapshot().all_runners().map(|r| r.id.clone()).collect();
    // Bound pool-lock contention per pass so lease renewal is not held behind
    // a whole batch of unreachable daemons. Retry timestamps keep this fair.
    let pending = sqlx::query("SELECT sandbox_id,job_id,runner_hd_id,attempt FROM ci_vm_cleanup WHERE runner_hd_id=ANY($1) AND next_attempt_at<=now() ORDER BY next_attempt_at LIMIT 1")
        .bind(&runners).fetch_all(d.store.pool()).await?;
    for row in pending {
        let sandbox: String = row.get("sandbox_id");
        // Keep the phase outside the cancelled future so a deadline identifies
        // the blocked operation rather than hiding every failure as verification.
        let mut phase = "begin ownership transaction";
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), finish(d, &sandbox, &mut phase)).await;
        let error = match result { Ok(Ok(())) => continue, Ok(Err(e)) => format!("{phase}: {e}"), Err(_) => format!("cleanup timed out during {phase}") };
        let runner: String = row.get("runner_hd_id");
        tracing::warn!(%sandbox, %runner, %phase, elapsed_ms = started.elapsed().as_millis() as u64,
            %error, "VM cleanup unresolved; retaining claim and retrying");
        // Existing operations own their tunnel independently (PR77).
        d.runners.evict(&runner).await;
        sqlx::query("UPDATE ci_vm_cleanup SET last_error=$4,next_attempt_at=now()+interval '30 seconds' WHERE sandbox_id=$1 AND job_id=$2 AND attempt=$3")
            .bind(&sandbox).bind(row.get::<String,_>("job_id")).bind(row.get::<i32,_>("attempt")).bind(&error)
            .execute(d.store.pool()).await?;
    }
    Ok(())
}

async fn finish(d: &Dispatcher, sandbox: &str, phase: &mut &'static str) -> Result<()> {
    let mut tx = d.store.pool().begin().await?;
    *phase = "lock cleanup intent";
    let Some(c) = sqlx::query("SELECT * FROM ci_vm_cleanup WHERE sandbox_id=$1 FOR UPDATE SKIP LOCKED")
        .bind(sandbox).fetch_optional(&mut *tx).await? else { return Ok(()) };
    let job: String = c.get("job_id"); let runner: String = c.get("runner_hd_id"); let attempt: i32 = c.get("attempt");
    *phase = "verify pool ownership";
    let p = sqlx::query("SELECT status,claimed_by_job,runner_hd_id FROM ci_vm_pool WHERE sandbox_id=$1 FOR UPDATE")
        .bind(sandbox).fetch_one(&mut *tx).await?;
    ensure!(p.get::<String,_>("status") == "claimed"
        && p.get::<Option<String>,_>("claimed_by_job").as_deref() == Some(job.as_str())
        && p.get::<String,_>("runner_hd_id") == runner, "cleanup pool ownership changed");
    *phase = "verify job ownership";
    let requeue: bool = c.get("requeue");
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_job WHERE id=$1 AND attempt=$2 AND (status IN ('success','failure','skipped','cancelled') OR ($3 AND status='running'))) AND NOT EXISTS(SELECT 1 FROM ci_service_deployment s JOIN ci_host_maintenance h ON h.id=s.id WHERE s.job_id=$1)")
        .bind(&job).bind(attempt).bind(requeue).fetch_one(&mut *tx).await?;
    ensure!(valid, "cleanup job identity or lifecycle owner changed");
    // Covers cleanup intents created by older controllers that requested a
    // stopped warm cache. CI-owned job VMs are now always ephemeral.
    *phase = "retain debug report";
    crate::debug_report::enqueue(&mut tx, &job, sandbox).await?;
    *phase = "open runner connection";
    let vm = d.vms.open(d.runners.options_for(&runner).await?, sandbox.to_string()).await?;
    *phase = "read initial VM status";
    let already_removed = match vm.info().await {
        Err(VmError::Daemon { source: HeyoError::NotFound(_), .. }) => true,
        result => {
            let info = result?;
            ensure!(info.id == sandbox, "cleanup daemon returned another VM");
            if info.status != SandboxStatus::Stopped {
                *phase = "stop VM";
                vm.stop().await?;
            }
            *phase = "verify stopped VM";
            let stopped = vm.info().await?;
            ensure!(stopped.id == sandbox && stopped.status == SandboxStatus::Stopped, "daemon has not confirmed the exact VM stopped");
            false
        }
    };
    if !already_removed {
        *phase = "destroy VM";
        vm.destroy().await?;
        *phase = "verify VM removal";
        ensure!(matches!(vm.info().await, Err(VmError::Daemon { source: HeyoError::NotFound(_), .. })), "daemon has not confirmed VM removal");
    }
    *phase = "release verified ownership";
    sqlx::query("DELETE FROM ci_vm_pool WHERE sandbox_id=$1").bind(sandbox).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3")
        .bind(&job).bind(&runner).bind(attempt).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM ci_vm_cleanup WHERE sandbox_id=$1").bind(sandbox).execute(&mut *tx).await?;
    if requeue {
        // Cancellation wins. No pending job is visible until its exact VM and
        // executor obligation have both been removed in this transaction.
        let row = sqlx::query("UPDATE ci_job SET status='pending',runner_hd_id=NULL,sandbox_id=NULL,fingerprint=NULL,executor_boot=NULL,finished_at=NULL WHERE id=$1 AND attempt=$2 AND status='running' RETURNING run_id,job_key")
            .bind(&job).bind(attempt).fetch_optional(&mut *tx).await?;
        if let Some(row) = row {
            Store::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(&job), Some(&row.get::<String,_>("job_key")),
                None, "ci.job.status.v1", "pending", Some("Waiting for host memory capacity; rejected VM removed")).await?;
        }
    }
    *phase = "commit cleanup";
    tx.commit().await?;
    Ok(())
}
