//! Postgres persistence for runs, jobs, steps, artifacts and the VM pool.
//!
//! Runtime `sqlx::query()` with `.bind()`, not the `query!` macros — so the
//! crate compiles with no database reachable, which is what heyosecret does and
//! what makes a CI build of this CI system possible.
//!
//! Step logs live in a separate chunk table, shared by all controllers without
//! loading large bodies into `SELECT * FROM ci_step` status queries. Retained
//! local files are imported before serving and are never removed by import.
//!
//! Migrations are applied by re-executing `migrations/*.sql` in filename order
//! on every startup, with no tracking table — heyosecret's approach. It puts one
//! obligation on the SQL (every statement idempotent) in exchange for removing a
//! whole class of "the migration table disagrees with the schema" incidents.
//!
//! **The files are compiled into the binary** (`build.rs`), so a deployed `ci`
//! cannot be separated from its schema: the failure that motivated it was a
//! binary installed without its newest `.sql`, refused by Postgres on the first
//! query for a column its own migration adds. `CI_MIGRATIONS_DIR` still exists
//! as an explicit override for running SQL from disk, and is no longer a
//! default that quietly points at whatever happens to be in the working
//! directory.

use crate::plan::{JobPlan, Plan};
use chrono::{DateTime, Utc};

use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

/// One schema migration: its file name, which orders it and names it in
/// errors, and its SQL.
#[derive(Debug, Clone)]
pub struct Migration {
    pub name: String,
    pub sql: String,
}

/// The migrations this binary was built with.
pub fn embedded_migrations() -> Vec<Migration> {
    EMBEDDED_MIGRATIONS
        .iter()
        .map(|(name, sql)| Migration {
            name: name.to_string(),
            sql: sql.to_string(),
        })
        .collect()
}

/// Advisory-lock key serializing migrations across processes. An arbitrary
/// constant; it only has to be the same in every instance and unlikely to
/// collide with another application sharing the database.
const MIGRATION_LOCK_KEY: i64 = 0x0c19_3a7e;

/// How many times to retry a migration that lost a lock race with a running
/// instance. Contention is transient — the other side is a build finishing —
/// so a few short retries beat both failing the start and waiting forever.
const MIGRATION_ATTEMPTS: u32 = 5;

/// Whether a migration failure is the kind that retrying fixes.
///
/// Matched on the message because `sqlx::Error::Database` only exposes the
/// SQLSTATE through a downcast to the driver's error type, and both of these
/// arrive as plain database errors. The two codes are `40P01` (deadlock
/// detected) and `55P03` (lock not available).
fn is_lock_contention(e: &StoreError) -> bool {
    let text = e.to_string();
    text.contains("deadlock detected")
        || text.contains("lock timeout")
        || text.contains("canceling statement due to lock timeout")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Queued,
    Running,
    Success,
    Failure,
    Cancelled,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success | Self::Failure | Self::Cancelled)
    }

    /// The inverse of [`Self::as_str`], for the columns that store a status as
    /// text.
    ///
    /// `None` for anything this build does not know, and every caller must
    /// treat that as "not finished" rather than defaulting it to a variant. A
    /// row written by a newer binary is the case that matters: guessing
    /// `Success` there would report somebody's failed deploy as green.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "success" => Self::Success,
            "failure" => Self::Failure,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Queued,
    Running,
    Success,
    Failure,
    Skipped,
    Cancelled,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Success | Self::Failure | Self::Skipped | Self::Cancelled
        )
    }

    /// The inverse of [`Self::as_str`]. `None` for an unrecognised status, for
    /// the reason [`RunStatus::parse`] gives.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "queued" => Self::Queued,
            "running" => Self::Running,
            "success" => Self::Success,
            "failure" => Self::Failure,
            "skipped" => Self::Skipped,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    /// What `needs.<job>.result` reports. A skipped dependency is not a failure
    /// — GitHub's `needs` context reports it as `skipped`, and a downstream
    /// `if:` may legitimately want to run anyway.
    pub fn result_name(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
            _ => "pending",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobClaim {
    Claimed,
    InstanceDraining,
    RunnerCordoned,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Success,
    Failure,
    Skipped,
    /// The job was cancelled while this step was running; the dispatcher
    /// abandoned the wait. Distinct from `Failure` so the run page says what
    /// happened rather than implying the step's command was at fault.
    Cancelled,
}

impl StepStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Skipped => "skipped",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Run {
    pub id: String,
    pub workflow_id: String,
    pub workflow_path: String,
    pub workflow_name: Option<String>,
    pub repo_url: String,
    /// The registration this run was submitted under, when the credential (or
    /// the payload's URL) resolved to one. `None` for pre-registration rows
    /// and shared-secret submits of unregistered repositories.
    pub repo_id: Option<String>,
    /// `ci_repo.name`, joined in by every query that builds a `Run` — the
    /// display half of `repo_id`, denormalized here so pages never do a
    /// second lookup per row.
    pub repo_name: Option<String>,
    pub git_ref: String,
    pub sha: String,
    pub before_sha: String,
    pub default_branch: Option<String>,
    pub release_base_sha: Option<String>,
    /// What this run's commit changed, as the submit worked it out. Read by the
    /// scheduler for the `ci` expression scope, so a job's `if:` can gate on a
    /// subtree of a monorepo.
    pub changes: crate::paths::Changes,
    pub actor_email: Option<String>,
    pub status: String,
    pub error: Option<String>,
    /// The run this one re-plays, when it was started from the dashboard's
    /// "Run again" or "Re-run failed jobs" rather than by a submit.
    pub rerun_of: Option<String>,
    /// The app-lb namespace this run belongs to; `""` is the fleet. Copied
    /// from the registration at submit time rather than joined, so a run whose
    /// registration is later deleted still knows whose it was.
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl Run {
    fn from_row(r: &PgRow) -> Self {
        Self {
            id: r.get("id"),
            workflow_id: r.get("workflow_id"),
            workflow_path: r.get("workflow_path"),
            workflow_name: r.get("workflow_name"),
            repo_url: r.get("repo_url"),
            repo_id: r.get("repo_id"),
            // Not a column on `ci_run` — an alias every `Run` query joins in.
            // A query that forgets the join loses the display name, which the
            // page already renders as `None`; it does not take the page down.
            repo_name: r.try_get("repo_name").ok().flatten(),
            git_ref: r.get("git_ref"),
            sha: r.get("sha"),
            before_sha: r.get("before_sha"),
            default_branch: r.try_get("default_branch").ok().flatten(),
            release_base_sha: r.try_get("release_base_sha").ok().flatten(),
            // A row whose JSON does not deserialize falls back to "no answer",
            // which builds everything. The alternative — failing the query —
            // would take the dashboard down over a column nothing renders.
            changes: r
                .try_get::<serde_json::Value, _>("changes")
                .ok()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default(),
            actor_email: r.get("actor_email"),
            status: r.get("status"),
            error: r.get("error"),
            // Absent on a row read before migration 012 ran; "not a re-run" is
            // the right reading of that.
            rerun_of: r.try_get("rerun_of").ok().flatten(),
            // Absent before migration 053, and every row from then is fleet.
            namespace: r.try_get("namespace").unwrap_or_default(),
            created_at: r.get("created_at"),
            started_at: r.get("started_at"),
            finished_at: r.get("finished_at"),
        }
    }

    /// How long the run took, or has been going.
    pub fn duration(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.finished_at.unwrap_or_else(Utc::now);
        (end - start).to_std().ok()
    }
}

#[derive(Debug, Clone)]
pub struct JobRow {
    pub id: String,
    pub run_id: String,
    pub job_key: String,
    pub base_id: String,
    pub display: String,
    pub network: Option<String>,
    pub runner_hd_id: Option<String>,
    pub fingerprint: Option<String>,
    pub sandbox_id: Option<String>,
    pub status: String,
    pub attempt: i32,
    /// Process boot that atomically claimed this execution attempt. Historical
    /// rows and non-executor status transitions intentionally remain NULL.
    pub executor_boot: Option<Uuid>,
    pub matrix: serde_json::Value,
    pub outputs: serde_json::Value,
    /// The expanded `JobPlan` this job runs. The queue message carries only
    /// ids, so this is what a redelivery executes.
    pub plan: serde_json::Value,
    pub error: Option<String>,
    /// Set when this job never ran here: its run re-ran only the failed jobs of
    /// the run named, and this one had succeeded there, so its status and
    /// outputs were copied across to satisfy `needs:`.
    pub carried_from: Option<String>,
    /// When the job went on the queue. Distinct from `started_at`, and the
    /// difference is the point: every timeout a job has is measured from
    /// `started_at`, the moment a consumer claimed it — never from here.
    pub queued_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl JobRow {
    fn from_row(r: &PgRow) -> Self {
        Self {
            id: r.get("id"),
            run_id: r.get("run_id"),
            job_key: r.get("job_key"),
            base_id: r.get("base_id"),
            display: r.get("display"),
            network: r.get("network"),
            runner_hd_id: r.get("runner_hd_id"),
            fingerprint: r.get("fingerprint"),
            sandbox_id: r.get("sandbox_id"),
            status: r.get("status"),
            attempt: r.get("attempt"),
            executor_boot: r.get("executor_boot"),
            matrix: r.get("matrix"),
            outputs: r.get("outputs"),
            plan: r.get("plan"),
            error: r.get("error"),
            carried_from: r.try_get("carried_from").ok().flatten(),
            // Older rows predate the column's backfill; a missing value reads
            // as "not queued" rather than taking the query down.
            queued_at: r.try_get("queued_at").ok().flatten(),
            started_at: r.get("started_at"),
            finished_at: r.get("finished_at"),
        }
    }

    /// How long the job sat on the queue before a consumer claimed it — or has
    /// sat so far. `None` until it has been queued.
    pub fn queue_wait(&self) -> Option<std::time::Duration> {
        let queued = self.queued_at?;
        let end = self.started_at.unwrap_or_else(Utc::now);
        Some((end - queued).to_std().unwrap_or_default())
    }
}

#[derive(Debug, Clone)]
pub struct StepRow {
    pub id: String,
    pub job_id: String,
    pub idx: i32,
    pub name: String,
    pub uses: Option<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub operation_id: Option<String>,
    pub log_path: Option<String>,
    pub log_bytes: i64,
    pub error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl StepRow {
    fn from_row(r: &PgRow) -> Self {
        Self {
            id: r.get("id"),
            job_id: r.get("job_id"),
            idx: r.get("idx"),
            name: r.get("name"),
            uses: r.get("uses"),
            status: r.get("status"),
            exit_code: r.get("exit_code"),
            operation_id: r.get("operation_id"),
            log_path: r.get("log_path"),
            log_bytes: r.get("log_bytes"),
            error: r.get("error"),
            started_at: r.get("started_at"),
            finished_at: r.get("finished_at"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactRow {
    pub name: String,
    pub sink: String,
    pub digest: Option<String>,
    pub size_bytes: i64,
    pub uri: String,
    /// The credential-free download link, for an artifact uploaded with
    /// `public: true` to a sink that could grant it.
    pub public_url: Option<String>,
}

/// A registered repository.
#[derive(Debug, Clone)]
pub struct Repo {
    pub id: String,
    pub url: String,
    pub normalized: String,
    pub name: String,
    /// Overrides `CI_WORKFLOW_PATH` for this repository. A workflow object,
    /// where one exists, still wins.
    pub workflow_path: Option<String>,
    /// The heyvm network this repository's builds run in, by name. `None` is the
    /// installation default; a workflow's `uses:` still overrides it per job.
    pub network: Option<String>,
    pub enabled: bool,
    /// The app-lb namespace that registered it; `""` is the fleet. A tenant
    /// registration's submits are planned under [`crate::tenancy`].
    pub namespace: String,
    pub created_email: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Repo {
    pub fn is_tenant(&self) -> bool {
        !self.namespace.is_empty()
    }

    fn from_row(r: &PgRow) -> Self {
        Self {
            id: r.get("id"),
            url: r.get("url"),
            normalized: r.get("normalized"),
            name: r.get("name"),
            workflow_path: r.get("workflow_path"),
            network: r.get("network"),
            enabled: r.get("enabled"),
            namespace: r.try_get("namespace").unwrap_or_default(),
            created_email: r.get("created_email"),
            created_at: r.get("created_at"),
        }
    }
}

/// One submit token, as everything except the authentication path sees it.
///
/// **There is deliberately no `secret_hash` field.** The digest is read by one
/// query, compared, and dropped; keeping it on the struct that the dashboard
/// renders would make leaking it a matter of one careless `(token.hash)` in a
/// template.
#[derive(Debug, Clone)]
pub struct RepoToken {
    pub id: String,
    pub repo_id: String,
    pub name: String,
    pub created_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RepoToken {
    fn from_row(r: &PgRow) -> Self {
        Self {
            id: r.get("id"),
            repo_id: r.get("repo_id"),
            name: r.get("name"),
            created_email: r.get("created_email"),
            created_at: r.get("created_at"),
            last_used_at: r.get("last_used_at"),
            revoked_at: r.get("revoked_at"),
        }
    }

    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// What a run is being started for.
#[derive(Debug, Clone, Default)]
pub struct RunRequest {
    pub workflow_id: String,
    /// The registration this submit authenticated as, when it authenticated as
    /// one. `None` for the shared-secret path, which cannot say.
    pub repo_id: Option<String>,
    pub repo_url: String,
    pub git_ref: String,
    pub sha: String,
    pub before_sha: String,
    pub default_branch: Option<String>,
    pub release_base_sha: Option<String>,
    /// What the submit changed, relative to `before_sha`. Defaults to "no
    /// answer", which is what a caller that cannot work it out should leave it
    /// as — that reads as "build everything" downstream.
    pub changes: crate::paths::Changes,
    pub actor_subject: Option<String>,
    pub actor_email: Option<String>,
    pub source: String,
    /// The run this one re-plays, for a re-run started from the dashboard.
    pub rerun_of: Option<String>,
    /// The namespace the run belongs to — the registration's, never the
    /// payload's. `""` (the default) is the fleet.
    pub namespace: String,
}

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
    log_dir: PathBuf,
    /// Restored on the migration connection, which clears it for its own use.
    statement_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub id: uuid::Uuid,
    pub subject: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ServiceDeploymentRow {
    pub id: String,
    pub step_id: String,
    pub run_id: String,
    pub job_id: String,
    pub service_id: String,
    pub status: String,
    pub phase: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub sha: String,
    pub git_ref: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RunEvent {
    pub id: uuid::Uuid,
    pub revision: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub job_id: Option<String>,
    pub job_key: Option<String>,
    pub step_id: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub transitioned_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub attempts: i32,
    pub last_error: Option<String>,
}

impl Store {
    pub(crate) async fn add_event(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        run_id: &str,
        job_id: Option<&str>,
        job_key: Option<&str>,
        step_id: Option<&str>,
        kind: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<uuid::Uuid, StoreError> {
        let id = uuid::Uuid::new_v4();
        let subject = format!("{run_id}.{}", job_key.unwrap_or("run"));
        let row = sqlx::query(
            "INSERT INTO ci_event_outbox
               (id, run_id, repo_id, subject, event_type, job_id, job_key, step_id, status, error, payload)
             SELECT $1,$2,r.repo_id,$3,$4,$5,$6,$7,$8,$9,'{}'::jsonb FROM ci_run r WHERE r.id=$2
             RETURNING revision, transitioned_at, repo_id,
                       (SELECT sha FROM ci_run WHERE id=$2) AS sha,
                       (SELECT git_ref FROM ci_run WHERE id=$2) AS git_ref"
        ).bind(id).bind(run_id).bind(&subject).bind(kind).bind(job_id).bind(job_key)
          .bind(step_id).bind(status).bind(error).fetch_one(&mut **tx).await.map_err(StoreError::sql)?;
        let revision: i64 = row.get("revision");
        let transitioned_at: DateTime<Utc> = row.get("transitioned_at");
        let repo_id: Option<String> = row.get("repo_id");
        let sha: String = row.get("sha");
        let git_ref: String = row.get("git_ref");
        let payload = serde_json::json!({
            "version": 1,
            "id": id,
            "revision": revision,
            "type": kind,
            "run_id": run_id,
            "repo_id": repo_id,
            "sha": sha,
            "git_ref": git_ref,
            "job_id": job_id,
            "job_key": job_key,
            "step_id": step_id,
            // Kept at the top level for existing dashboard consumers.
            "status": status,
            "error": error,
            "transitioned_at": transitioned_at.to_rfc3339(),
        });
        sqlx::query("UPDATE ci_event_outbox SET payload=$2 WHERE id=$1")
            .bind(id).bind(payload)
            .execute(&mut **tx).await.map_err(StoreError::sql)?;
        Ok(id)
    }

    async fn add_step_event(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        step_id: &str,
        job_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let row = sqlx::query("SELECT run_id, job_key FROM ci_job WHERE id=$1")
            .bind(job_id).fetch_one(&mut **tx).await.map_err(StoreError::sql)?;
        let run: String = row.get("run_id");
        let key: String = row.get("job_key");
        Self::add_event(tx, &run, Some(job_id), Some(&key), Some(step_id), "ci.step.status.v1", status, error).await.map(|_| ())
    }

    pub async fn next_outbox_event(&self) -> Result<Option<OutboxEvent>, StoreError> {
        let row = sqlx::query(
            "SELECT id, subject, payload FROM ci_event_outbox
              WHERE published_at IS NULL ORDER BY revision LIMIT 1",
        ).fetch_optional(&self.pool).await.map_err(StoreError::sql)?;
        Ok(row.map(|r| OutboxEvent {
            id: r.get("id"), subject: r.get("subject"), payload: r.get("payload"),
        }))
    }

    pub async fn mark_outbox_published(&self, id: uuid::Uuid) -> Result<(), StoreError> {
        sqlx::query("UPDATE ci_event_outbox SET published_at=now(), attempts=attempts+1, last_error=NULL WHERE id=$1")
            .bind(id).execute(&self.pool).await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn mark_outbox_failed(&self, id: uuid::Uuid, error: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE ci_event_outbox SET attempts=attempts+1, last_error=$2 WHERE id=$1 AND published_at IS NULL")
            .bind(id).bind(error).execute(&self.pool).await.map_err(StoreError::sql)?;
        Ok(())
    }

    /// A bounded page in newest-first order. `before` is an exclusive revision
    /// cursor, stable even when multiple transitions share a timestamp.
    pub async fn run_events(&self, run_id: &str, before: Option<i64>, limit: i64) -> Result<Vec<RunEvent>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, revision, event_type, payload, job_id, job_key, step_id, status, error,
                    transitioned_at, published_at, attempts, last_error
               FROM ci_event_outbox WHERE run_id=$1 AND ($2::bigint IS NULL OR revision < $2)
              ORDER BY revision DESC LIMIT $3"
        ).bind(run_id).bind(before).bind(limit).fetch_all(&self.pool).await.map_err(StoreError::sql)?;
        Ok(rows.into_iter().map(|r| RunEvent {
            id: r.get("id"), revision: r.get("revision"), event_type: r.get("event_type"),
            payload: r.get("payload"),
            job_id: r.get("job_id"), job_key: r.get("job_key"), step_id: r.get("step_id"),
            status: r.get("status"), error: r.get("error"), transitioned_at: r.get("transitioned_at"),
            published_at: r.get("published_at"), attempts: r.get("attempts"), last_error: r.get("last_error"),
        }).collect())
    }
    pub async fn connect(
        database_url: &str,
        log_dir: PathBuf,
        statement_timeout: Duration,
    ) -> Result<Self, StoreError> {
        // Every connection, not the DSN: `options=-c statement_timeout=…` is
        // silently dropped by some poolers, and this has to hold on the
        // connection actually executing the query.
        let setting = format!("SET statement_timeout = {}", statement_timeout.as_millis());
        let pool = PgPoolOptions::new()
            .max_connections(10)
            // Fail fast at startup rather than after the default 30s: a wrong
            // `CI_DATABASE_URL` should look like a configuration error, not a
            // hang.
            .acquire_timeout(Duration::from_secs(10))
            // **`acquire_timeout` does not bound a query.** It bounds getting a
            // connection *out of the pool*; once one is checked out, a statement
            // the server never answers waits for ever. That is not hypothetical
            // here: a database behind a pool that suspends idle instances leaves
            // an established socket that accepts writes and returns nothing, the
            // same shape as a tunnel whose QUIC connection is up and whose data
            // path is dead.
            //
            // What made it expensive is where it lands. `run_job` reads the job
            // row and claims it *before* its first log statement, so a wedge
            // there is a consumer that has stopped working while saying nothing
            // at all: the job row stays `queued`, the message stays in flight
            // with the ack heartbeat renewing it, and the only visible symptom
            // is a reaper failing the job much later for a reason that is not
            // the reason.
            //
            // A bounded statement turns all of that into one error, logged,
            // retried by the delivery ladder.
            .after_connect(move |conn, _meta| {
                let setting = setting.clone();
                Box::pin(async move {
                    sqlx::query(&setting).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(|e| StoreError::Connect(e.to_string()))?;
        tokio::fs::create_dir_all(&log_dir)
            .await
            .map_err(|e| StoreError::LogDir {
                path: log_dir.clone(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            pool,
            log_dir,
            statement_timeout,
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Returns true only to the transaction that owns the single POST attempt.
    pub async fn begin_service_deployment(
        &self, id: &str, step: &str, service: &str, request_hash: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let inserted = sqlx::query(
            "INSERT INTO ci_service_deployment (id, step_id, run_id, job_id, service_id, request_hash, status, sha, git_ref)
             SELECT $1,s.id,r.id,j.id,$3,$4,'submitting',COALESCE(rel.candidate_sha,r.sha),COALESCE(rel.git_ref,r.git_ref)
             FROM ci_step s JOIN ci_job j ON j.id=s.job_id JOIN ci_run r ON r.id=j.run_id
             LEFT JOIN ci_release rel ON rel.run_id=r.id AND rel.status='published'
             WHERE s.id=$2 AND j.status='running' AND r.status <> 'cancelled'
             ON CONFLICT (step_id) DO NOTHING RETURNING run_id, job_id"
        ).bind(id).bind(step).bind(service).bind(request_hash)
            .fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
        if inserted.is_some() {
            Self::add_service_deployment_event(&mut tx, id).await?;
            tx.commit().await.map_err(StoreError::sql)?;
            Ok(true)
        } else {
            let matches: Option<bool> = sqlx::query_scalar(
                "SELECT id=$2 AND service_id=$3 AND request_hash=$4 FROM ci_service_deployment WHERE step_id=$1"
            ).bind(step).bind(id).bind(service).bind(request_hash)
                .fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
            if matches != Some(true) {
                return Err(StoreError::Sql("deployment request changed, or job is no longer running".into()));
            }
            tx.commit().await.map_err(StoreError::sql)?;
            Ok(false)
        }
    }

    pub async fn update_service_deployment(
        &self, id: &str, status: &str, phase: Option<&str>, message: Option<&str>, error: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_service_deployment SET status=$2,phase=$3,message=$4,error=$5,updated_at=now()
             WHERE id=$1 AND status NOT IN ('passed','failed')
               AND (status,phase,message,error) IS DISTINCT FROM ($2,$3,$4,$5)
             RETURNING run_id,job_id,step_id"
        ).bind(id).bind(status).bind(phase).bind(message).bind(error)
            .fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
        if row.is_some() {
            Self::add_service_deployment_event(&mut tx, id).await?;
        }
        tx.commit().await.map_err(StoreError::sql)
    }

    pub(crate) async fn add_service_deployment_event(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, id: &str,
    ) -> Result<(), StoreError> {
        let row = sqlx::query("SELECT d.*,j.job_key FROM ci_service_deployment d JOIN ci_job j ON j.id=d.job_id WHERE d.id=$1")
            .bind(id).fetch_one(&mut **tx).await.map_err(StoreError::sql)?;
        let event = Self::add_event(tx, &row.get::<String,_>("run_id"), Some(&row.get::<String,_>("job_id")),
            Some(&row.get::<String,_>("job_key")), Some(&row.get::<String,_>("step_id")),
            "ci.deployment.status.v1", &row.get::<String,_>("status"), row.get::<Option<String>,_>("error").as_deref()).await?;
        let detail = serde_json::json!({
            "deployment_id": id, "service_id": row.get::<String,_>("service_id"),
            "deployment_sha": row.get::<String,_>("sha"),
            "phase": row.get::<Option<String>,_>("phase"), "message": row.get::<Option<String>,_>("message"),
        });
        sqlx::query("UPDATE ci_event_outbox SET payload=payload || $2::jsonb WHERE id=$1")
            .bind(event).bind(detail).execute(&mut **tx).await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn service_deployments_of(&self, run: &str) -> Result<Vec<ServiceDeploymentRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM ci_service_deployment WHERE run_id=$1 ORDER BY created_at,id")
            .bind(run).fetch_all(&self.pool).await.map_err(StoreError::sql)?;
        Ok(rows.iter().map(|r| ServiceDeploymentRow {
            id: r.get("id"), step_id: r.get("step_id"), run_id: r.get("run_id"), job_id: r.get("job_id"),
            service_id: r.get("service_id"), status: r.get("status"), phase: r.get("phase"),
            message: r.get("message"), error: r.get("error"), sha: r.get("sha"), git_ref: r.get("git_ref"),
            created_at: r.get("created_at"), updated_at: r.get("updated_at"),
        }).collect())
    }

    /// Apply the migrations compiled into this binary, in filename order.
    ///
    /// Every file is re-executed on every startup, so each statement must be
    /// idempotent. There is no tracking table by design — see the module doc.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        self.apply(&embedded_migrations()).await
    }

    /// Apply `*.sql` from a directory, in addition to the embedded set.
    ///
    /// The `CI_MIGRATIONS_DIR` path, for an operator running SQL the binary
    /// does not carry. Reading a directory is the failure mode the embedded
    /// set exists to remove, so it is opt-in, runs second, and is named in the
    /// log.
    pub async fn migrate_from_dir(&self, dir: &Path) -> Result<(), StoreError> {
        let migrations = Self::read_migrations(dir).await?;
        self.apply(&migrations).await
    }

    async fn read_migrations(dir: &Path) -> Result<Vec<Migration>, StoreError> {
        let mut entries = Vec::new();
        let mut rd = tokio::fs::read_dir(dir)
            .await
            .map_err(|e| StoreError::Migrations {
                path: dir.to_path_buf(),
                reason: e.to_string(),
            })?;
        while let Some(entry) = rd.next_entry().await.map_err(|e| StoreError::Migrations {
            path: dir.to_path_buf(),
            reason: e.to_string(),
        })? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("sql") {
                entries.push(path);
            }
        }
        entries.sort();
        if entries.is_empty() {
            return Err(StoreError::Migrations {
                path: dir.to_path_buf(),
                reason: "no .sql files found".to_string(),
            });
        }
        let mut migrations = Vec::with_capacity(entries.len());
        for path in entries {
            let sql =
                tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| StoreError::Migrations {
                        path: path.clone(),
                        reason: e.to_string(),
                    })?;
            migrations.push(Migration {
                name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                sql,
            });
        }
        Ok(migrations)
    }

    /// Run a migration set, serialized and bounded as described below.
    ///
    /// **Serialized by a Postgres advisory lock**, and that is not belt and
    /// braces. `CREATE TABLE IF NOT EXISTS` is *not* concurrency-safe: two
    /// sessions both find the table absent, both proceed, and the loser fails
    /// with `duplicate key value violates unique constraint
    /// "pg_type_typname_nsp_index"` from the system catalogue. Since jobs are
    /// sharded per runner precisely so several orchestrators can run at once,
    /// two of them starting together is a normal event rather than a rare race.
    ///
    /// **And bounded by a lock timeout, with retries.** The advisory lock keeps
    /// migrators away from each other, but not away from *running* instances:
    /// `ALTER TABLE … ADD COLUMN` needs `ACCESS EXCLUSIVE` on a table that a
    /// live dispatcher is inserting into. Without a timeout that wait is
    /// unbounded — a rolling deploy would hang a starting instance behind a long
    /// build — and Postgres reports some of those cycles as `deadlock detected`
    /// rather than waiting at all. Failing fast and retrying turns both into a
    /// few seconds of startup delay.
    async fn apply(&self, migrations: &[Migration]) -> Result<(), StoreError> {
        let mut last: Option<StoreError> = None;
        for attempt in 1..=MIGRATION_ATTEMPTS {
            match self.migrate_once(migrations).await {
                Ok(()) => return Ok(()),
                Err(e) if is_lock_contention(&e) && attempt < MIGRATION_ATTEMPTS => {
                    tracing::warn!(
                        "migration attempt {attempt} hit lock contention with a running \
                         instance, retrying: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| StoreError::Sql("migration retries exhausted".into())))
    }

    async fn migrate_once(&self, migrations: &[Migration]) -> Result<(), StoreError> {
        let mut conn = self.pool.acquire().await.map_err(StoreError::sql)?;

        // Bounded so a migration never blocks indefinitely behind a live
        // dispatcher's inserts. Session-scoped, and the connection is returned
        // to the pool afterwards, so it is reset explicitly below.
        sqlx::query("SET lock_timeout = '5s'")
            .execute(&mut *conn)
            .await
            .map_err(StoreError::sql)?;

        // Migrations are exempt from the statement timeout. DDL is legitimately
        // slow — a `CREATE INDEX` over a grown table is the case — and it is not
        // the failure the timeout exists for: this session already holds the
        // advisory lock below, so exactly one process runs it and a wedge is
        // visible as a start that never completes rather than a consumer that
        // quietly stops. Restored explicitly at the end, not to `DEFAULT`, which
        // would return this connection to the pool with the server's setting
        // rather than ours.
        sqlx::query("SET statement_timeout = 0")
            .execute(&mut *conn)
            .await
            .map_err(StoreError::sql)?;

        // The lock is held on this one connection and released explicitly
        // below; a dropped connection also releases it, so a panicking migrator
        // cannot wedge every future start.
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_LOCK_KEY)
            .execute(&mut *conn)
            .await
            .map_err(StoreError::sql)?;

        let result = self.run_migrations(migrations, &mut conn).await;

        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_LOCK_KEY)
            .execute(&mut *conn)
            .await;
        // Undo the session setting; this connection goes back into the pool and
        // a 5s lock timeout on ordinary queries would be a surprising default.
        let _ = sqlx::query("SET lock_timeout = DEFAULT")
            .execute(&mut *conn)
            .await;
        // Ours, not `DEFAULT`: this connection goes back into the pool and must
        // carry the same bound `after_connect` gave every other one.
        let _ = sqlx::query(&format!(
            "SET statement_timeout = {}",
            self.statement_timeout.as_millis()
        ))
        .execute(&mut *conn)
        .await;
        result
    }

    async fn run_migrations(
        &self,
        migrations: &[Migration],
        conn: &mut sqlx::PgConnection,
    ) -> Result<(), StoreError> {
        for m in migrations {
            sqlx::raw_sql(&m.sql)
                .execute(&mut *conn)
                .await
                .map_err(|e| StoreError::Migrations {
                    path: PathBuf::from(&m.name),
                    reason: e.to_string(),
                })?;
            tracing::debug!("applied migration {}", m.name);
        }
        Ok(())
    }

    /// Insert a run and every job of its plan, in one transaction.
    ///
    /// All-or-nothing on purpose: a run whose jobs half-exist is worse than no
    /// run, because the dashboard shows a DAG that can never complete and
    /// nothing owns fixing it.
    pub async fn create_run(
        &self,
        run_id: &str,
        req: &RunRequest,
        plan: &Plan,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        Self::create_run_in(&mut tx, run_id, req, plan).await?;
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    /// Admission can persist a whole submission before any job is visible.
    pub(crate) async fn create_run_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        run_id: &str,
        req: &RunRequest,
        plan: &Plan,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO ci_run (id, workflow_id, workflow_path, workflow_name, repo_url,
                                 git_ref, sha, before_sha, actor_subject, actor_email,
                                 source, status, repo_id, changes, rerun_of, default_branch, release_base_sha,
                                 namespace)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12,$13,$14,$15,$16,$17)",
        )
        .bind(run_id)
        .bind(&req.workflow_id)
        .bind(&plan.workflow_path)
        .bind(&plan.workflow_name)
        .bind(&req.repo_url)
        .bind(&req.git_ref)
        .bind(&req.sha)
        .bind(&req.before_sha)
        .bind(&req.actor_subject)
        .bind(&req.actor_email)
        .bind(if req.source.is_empty() {
            "submit"
        } else {
            &req.source
        })
        .bind(&req.repo_id)
        // Serializing a `Changes` cannot fail — it is an enum of owned strings —
        // but the column is NOT NULL, so the fallback is the "no answer" shape
        // rather than a null that would break every read.
        .bind(serde_json::to_value(&req.changes).unwrap_or_else(|_| {
            serde_json::to_value(crate::paths::Changes::default()).unwrap_or_default()
        }))
        .bind(&req.rerun_of)
        .bind(&req.default_branch)
        .bind(&req.release_base_sha)
        .bind(&req.namespace)
        .execute(&mut **tx)
        .await
        .map_err(StoreError::sql)?;

        for job in &plan.jobs {
            let id = job_id(run_id, &job.key);
            let matrix = serde_json::to_value(&job.matrix).unwrap_or(serde_json::json!({}));
            let plan_json = serde_json::to_value(job).unwrap_or(serde_json::json!({}));
            sqlx::query(
                "INSERT INTO ci_job (id, run_id, job_key, base_id, display, network,
                                     fingerprint, status, matrix, plan)
                 VALUES ($1,$2,$3,$4,$5,$6,NULL,'pending',$7,$8)",
            )
            .bind(&id)
            .bind(run_id)
            .bind(&job.key)
            .bind(&job.base_id)
            .bind(&job.display)
            .bind(&job.target.network)
            .bind(&matrix)
            .bind(&plan_json)
            .execute(&mut **tx)
            .await
            .map_err(StoreError::sql)?;
            Self::add_event(tx, run_id, Some(&id), Some(&job.key), None, "ci.job.status.v1", "pending", None).await?;
        }

        Self::add_event(tx, run_id, None, None, None, "ci.run.status.v1", "queued", None).await?;

        Ok(())
    }

    /// Commit the immutable descriptor in the same transaction as admission.
    /// Exact replay is allowed; another descriptor cannot replace accepted work.
    pub(crate) async fn record_source_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        run_id: &str,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        crate::trigger::decode_descriptor(bytes).map_err(|e| StoreError::source(run_id, e))?;
        let written = sqlx::query(
            "INSERT INTO ci_run_source(run_id,descriptor) VALUES($1,$2)
             ON CONFLICT(run_id) DO UPDATE SET descriptor=ci_run_source.descriptor
             WHERE ci_run_source.descriptor=EXCLUDED.descriptor",
        ).bind(run_id).bind(bytes).execute(&mut **tx).await.map_err(StoreError::sql)?;
        if written.rows_affected() != 1 {
            return Err(StoreError::source(run_id, "accepted source cannot be replaced"));
        }
        Ok(())
    }

    pub async fn source_bytes(&self, run_id: &str) -> Result<Vec<u8>, StoreError> {
        sqlx::query_scalar("SELECT descriptor FROM ci_run_source WHERE run_id=$1")
            .bind(run_id).fetch_optional(&self.pool).await.map_err(StoreError::sql)?
            .ok_or_else(|| StoreError::source(run_id, "source is not in shared storage; import its retained descriptor before retrying"))
    }

    pub async fn source_descriptor(&self, run_id: &str) -> Result<crate::trigger::GitPatchSource, StoreError> {
        crate::trigger::decode_descriptor(&self.source_bytes(run_id).await?)
            .map_err(|e| StoreError::source(run_id, e))
    }

    /// Import retained descriptors before starting any executor or HTTP handler.
    /// Local files remain untouched. Once imported, every reader uses Postgres.
    pub async fn import_sources(&self, directory: &Path, max_bytes: usize) -> Result<u64, StoreError> {
        let mut entries = match tokio::fs::read_dir(directory).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StoreError::source("local import", e)),
        };
        let mut imported = 0;
        while let Some(entry) = entries.next_entry().await.map_err(|e| StoreError::source("local import", e))? {
            let name = entry.file_name();
            let Some(run_id) = name.to_str().and_then(|name| name.strip_suffix(".source.json")) else { continue };
            // Submission staging files without an admitted run are not history.
            if self.get_run(run_id).await?.is_none() { continue; }
            let metadata = entry.metadata().await.map_err(|e| StoreError::source(run_id, e))?;
            if !metadata.is_file() || metadata.len() > max_bytes as u64 {
                return Err(StoreError::source(run_id, "retained descriptor is not a bounded file"));
            }
            let bytes = tokio::fs::read(entry.path()).await.map_err(|e| StoreError::source(run_id, e))?;
            if bytes.len() > max_bytes { return Err(StoreError::source(run_id, "retained descriptor exceeds source limit")); }
            let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
            Self::record_source_in(&mut tx, run_id, &bytes).await?;
            tx.commit().await.map_err(StoreError::sql)?;
            imported += 1;
        }
        Ok(imported)
    }

    pub async fn get_run(&self, run_id: &str) -> Result<Option<Run>, StoreError> {
        let row = sqlx::query(
            "SELECT r.*, rp.name AS repo_name
               FROM ci_run r
               LEFT JOIN ci_repo rp ON rp.id = r.repo_id
              WHERE r.id = $1",
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(row.as_ref().map(Run::from_row))
    }

    /// [`Self::get_run`], answering only for a run in `namespace`.
    ///
    /// A run in another namespace is `None`, the same as one that never
    /// existed: a tenant is not entitled to learn which ids are real.
    pub async fn get_run_in(&self, namespace: &str, run_id: &str) -> Result<Option<Run>, StoreError> {
        Ok(self.get_run(run_id).await?.filter(|r| r.namespace == namespace))
    }

    /// Runs started from this one by the dashboard, oldest first — the other
    /// direction of `rerun_of`, so the original's page can point at what came
    /// after it.
    pub async fn reruns_of(&self, run_id: &str) -> Result<Vec<Run>, StoreError> {
        let rows = sqlx::query(
            "SELECT r.*, rp.name AS repo_name
               FROM ci_run r
               LEFT JOIN ci_repo rp ON rp.id = r.repo_id
              WHERE r.rerun_of = $1
              ORDER BY r.created_at",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(Run::from_row).collect())
    }

    /// Newest first. `repo_id` narrows to one registered repository; `None` is
    /// everything, so the unfiltered page and the filtered one are the same
    /// query rather than two that can drift.
    pub async fn recent_runs(
        &self,
        limit: i64,
        repo_id: Option<&str>,
    ) -> Result<Vec<Run>, StoreError> {
        self.recent_runs_where(limit, repo_id, None).await
    }

    /// [`Self::recent_runs`], narrowed to one namespace — `""` for the fleet's
    /// own. The namespace pages read only this, so a repository filter naming
    /// another namespace's registration matches nothing.
    pub async fn recent_runs_in(
        &self,
        namespace: &str,
        limit: i64,
        repo_id: Option<&str>,
    ) -> Result<Vec<Run>, StoreError> {
        self.recent_runs_where(limit, repo_id, Some(namespace)).await
    }

    async fn recent_runs_where(
        &self,
        limit: i64,
        repo_id: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<Vec<Run>, StoreError> {
        let rows = sqlx::query(
            "SELECT r.*, rp.name AS repo_name
               FROM ci_run r
               LEFT JOIN ci_repo rp ON rp.id = r.repo_id
              WHERE ($2::text IS NULL OR r.repo_id = $2)
                AND ($3::text IS NULL OR r.namespace = $3)
              ORDER BY r.created_at DESC
              LIMIT $1",
        )
        .bind(limit)
        .bind(repo_id)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(Run::from_row).collect())
    }

    /// Every tenant namespace that has a run, for the fleet runs page's filter.
    /// Empty on an installation no namespace has used, which is what keeps that
    /// page exactly as it was until one does.
    pub async fn run_namespaces(&self) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar(
            "SELECT DISTINCT namespace FROM ci_run WHERE namespace <> '' ORDER BY namespace",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)
    }

    pub async fn set_run_status(
        &self,
        run_id: &str,
        status: RunStatus,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        // The timestamps are set by the same statement that sets the status, so
        // a run can never be `running` with no `started_at` for a reader to trip
        // over.
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let result = sqlx::query(
            "UPDATE ci_run
                SET status = $2,
                    error = COALESCE($3, error),
                    started_at = CASE WHEN $2 = 'running' AND started_at IS NULL
                                      THEN now() ELSE started_at END,
                    finished_at = CASE WHEN $2 IN ('success','failure','cancelled')
                                       THEN now() ELSE finished_at END
              WHERE id = $1",
        )
        .bind(run_id)
        .bind(status.as_str())
        .bind(error)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if result.rows_affected() > 0 {
            Self::add_event(&mut tx, run_id, None, None, None, "ci.run.status.v1", status.as_str(), error).await?;
        }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    /// Recompute a run's status from its jobs, and return it.
    ///
    /// The run is the roll-up of its jobs rather than a separately maintained
    /// value, so the two cannot disagree — which is exactly what happens when
    /// a crash lands between "last job finished" and "mark the run done".
    pub async fn roll_up_run(&self, run_id: &str) -> Result<RunStatus, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let status = Self::roll_up_run_in(&mut tx, run_id).await?;
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(status)
    }

    pub(crate) async fn roll_up_run_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, run_id: &str,
    ) -> Result<RunStatus, StoreError> {
        let previous: String = sqlx::query_scalar("SELECT status FROM ci_run WHERE id=$1 FOR UPDATE")
            .bind(run_id).fetch_one(&mut **tx).await.map_err(StoreError::sql)?;
        let rows = sqlx::query("SELECT status FROM ci_job WHERE run_id = $1")
            .bind(run_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(StoreError::sql)?;

        let statuses: Vec<String> = rows.iter().map(|r| r.get::<String, _>("status")).collect();
        let mut status = if statuses.is_empty() {
            RunStatus::Success
        } else if statuses.iter().any(|s| s == "cancelled") {
            RunStatus::Cancelled
        } else if statuses.iter().any(|s| s == "failure") {
            // A failure is terminal for the run even while other jobs are still
            // going: the answer to "did this commit pass" is already no.
            RunStatus::Failure
        } else if statuses
            .iter()
            .all(|s| matches!(s.as_str(), "success" | "skipped"))
        {
            RunStatus::Success
        } else {
            RunStatus::Running
        };

        // The self-update job records intent and exits before its controller
        // is replaced. Its success is not deployment success. Cancellation
        // remains sticky even if an already-submitted update later succeeds.
        if previous == "cancelled" {
            status = RunStatus::Cancelled;
        } else if matches!(status, RunStatus::Success) {
            let deployments: Vec<String> = sqlx::query_scalar(
                "SELECT s.status FROM ci_service_deployment s WHERE s.run_id=$1 AND (EXISTS(SELECT 1 FROM ci_controller_rollout c WHERE COALESCE(c.deployment_record_id,c.id)=s.id) OR EXISTS(SELECT 1 FROM ci_regional_update u WHERE u.id=s.id)) UNION ALL SELECT COALESCE(result,'running') FROM ci_managed_update WHERE run_id=$1",
            ).bind(run_id).fetch_all(&mut **tx).await.map_err(StoreError::sql)?;
            if deployments.iter().any(|s| s == "failed") {
                status = RunStatus::Failure;
            } else if deployments.iter().any(|s| s != "passed") {
                status = RunStatus::Running;
            }
        }
        sqlx::query("UPDATE ci_run SET status=$2, started_at=CASE WHEN $2='running' THEN COALESCE(started_at,now()) ELSE started_at END, finished_at=CASE WHEN $2 IN ('success','failure','cancelled') THEN COALESCE(finished_at,now()) ELSE NULL END WHERE id=$1")
            .bind(run_id).bind(status.as_str()).execute(&mut **tx).await.map_err(StoreError::sql)?;
        if previous != status.as_str() {
            Self::add_event(tx, run_id, None, None, None, "ci.run.status.v1", status.as_str(), None).await?;
        }
        Ok(status)
    }

    /// Cancel a run and every job of it that has not finished.
    ///
    /// Returns how many jobs were stopped, and `None` if the run was already
    /// terminal — cancelling something that has finished is a no-op worth
    /// reporting rather than a silent success that looks like it did something.
    ///
    /// The jobs are marked first. A queued job is then dropped when JetStream
    /// delivers it, because [`Self::start_job`] refuses a job that is already
    /// terminal and `run_job` checks the same thing on entry; a running one
    /// notices at its next step boundary. So this one statement covers work in
    /// all three states without needing to reach any of them.
    pub async fn cancel_run(&self, run_id: &str) -> Result<Option<u64>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let run = sqlx::query(
            "UPDATE ci_run
                SET status='cancelled', finished_at=now(),
                    error=COALESCE(error, 'cancelled')
              WHERE id = $1 AND status NOT IN ('success','failure','cancelled')",
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if run.rows_affected() == 0 {
            tx.rollback().await.map_err(StoreError::sql)?;
            return Ok(None);
        }

        let jobs = sqlx::query(
            "UPDATE ci_job
                SET status='cancelled', finished_at=now(),
                    error=COALESCE(error, 'cancelled')
              WHERE run_id = $1
                AND status NOT IN ('success','failure','skipped','cancelled')
              RETURNING id, job_key",
        )
        .bind(run_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        Self::add_event(&mut tx, run_id, None, None, None, "ci.run.status.v1", "cancelled", Some("cancelled")).await?;
        for row in &jobs {
            let id: String = row.get("id"); let key: String = row.get("job_key");
            Self::add_event(&mut tx, run_id, Some(&id), Some(&key), None, "ci.job.status.v1", "cancelled", Some("cancelled")).await?;
        }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(Some(jobs.len() as u64))
    }

    /// Jobs that have sat on a queue longer than a runner was ever going to
    /// take to pick them up.
    ///
    /// A job is pinned to its host's subject even when that host is not online —
    /// deliberately, because the warm pool is host-local and silently migrating
    /// discards the cache the pin asked for. But consumers are only bound for
    /// hosts that *are* online, so a job pinned to one that is not goes to a
    /// subject nothing reads. Without this it waits for ever.
    pub async fn jobs_waiting_longer_than(
        &self,
        wait: Duration,
        limit: i64,
    ) -> Result<Vec<JobRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT j.* FROM ci_job j
               JOIN ci_run r ON r.id = j.run_id
              WHERE j.status = 'queued'
                AND j.queued_at IS NOT NULL
                AND j.queued_at < now() - make_interval(secs => $1)
                AND r.status NOT IN ('success','failure','cancelled')
              ORDER BY j.queued_at
              LIMIT $2",
        )
        .bind(wait.as_secs() as f64)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(JobRow::from_row).collect())
    }

    /// Whether a job has been cancelled out from under whoever is running it.
    ///
    /// Its own query rather than [`Self::get_job`]: this is asked between every
    /// step, and the plan JSONB is the largest column on the row.
    pub async fn is_job_cancelled(&self, job_id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT status FROM ci_job WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(row.map(|r| r.get::<String, _>("status")) == Some("cancelled".to_string()))
    }

    pub async fn jobs_of(&self, run_id: &str) -> Result<Vec<JobRow>, StoreError> {
        let rows =
            sqlx::query("SELECT * FROM ci_job WHERE run_id = $1 ORDER BY created_at, job_key")
                .bind(run_id)
                .fetch_all(&self.pool)
                .await
                .map_err(StoreError::sql)?;
        Ok(rows.iter().map(JobRow::from_row).collect())
    }

    pub async fn get_job(&self, job_id: &str) -> Result<Option<JobRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM ci_job WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(row.as_ref().map(JobRow::from_row))
    }

    /// Mark a job as picked up by a runner, before it has a VM.
    ///
    /// **The gap this closes is the whole of VM acquisition.** `start_job` runs
    /// only once a sandbox exists, and getting one means an iroh dial and a boot
    /// that together can take minutes — during which the row still said `queued`
    /// with no runner on it. Three things read that as "nobody took this job":
    /// the run page, which showed a build that was busy booting as not started;
    /// [`Self::jobs_waiting_longer_than`], which is a queue-for-an-offline-host
    /// reaper and would fail the job with a message blaming a host that was in
    /// fact online and working on it; and whoever was watching, for whom a
    /// failing-and-retrying create was indistinguishable from silence.
    ///
    /// So the transition to `running` happens when a consumer commits to the
    /// job, and `start_job` below is left to fill in *where* it ended up.
    /// `sandbox_id` and `fingerprint` stay null until then, which is the honest
    /// reading: running, no machine yet.
    ///
    /// Returns false for terminal or already-running work. Queue redelivery is
    /// not evidence that the previous executor stopped issuing remote commands.
    /// Reconciliation, not a delivery counter, must resolve an interrupted claim.
    pub async fn claim_job(
        &self,
        job_id: &str,
        runner_hd_id: &str,
        attempt: i32,
    ) -> Result<bool, StoreError> {
        Ok(self.claim_job_inner(job_id, runner_hd_id, attempt, None).await? == JobClaim::Claimed)
    }

    /// Claim executor work for one registered process boot. In addition to the
    /// job row race, this locks the boot row and rechecks admission in the same
    /// transaction, closing the outstanding-pull versus drain race.
    pub async fn claim_job_for_boot(
        &self,
        job_id: &str,
        runner_hd_id: &str,
        attempt: i32,
        boot_id: Uuid,
    ) -> Result<JobClaim, StoreError> {
        self.claim_job_inner(job_id, runner_hd_id, attempt, Some(boot_id)).await
    }

    // `None` is deliberately limited to the compatibility wrapper above. It
    // preserves unit-test and administrative callers without granting a NULL
    // historical claim authority over a boot-owned attempt.
    async fn claim_job_inner(
        &self,
        job_id: &str,
        runner_hd_id: &str,
        attempt: i32,
        boot_id: Option<Uuid>,
    ) -> Result<JobClaim, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        if let Some(boot_id) = boot_id {
            let admitted: Option<bool> = sqlx::query_scalar(
                "SELECT NOT draining AND NOT retired FROM ci_executor_boot WHERE boot_id=$1 FOR UPDATE",
            ).bind(boot_id).fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
            if admitted != Some(true) {
                tx.commit().await.map_err(StoreError::sql)?;
                return Ok(JobClaim::InstanceDraining);
            }
        }
        // Same transaction-scoped runner lock as maintenance intent. The
        // subsequent snapshot sees a committed fence, or maintenance sees
        // this running job and must drain it before submitting.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 222))")
            .bind(runner_hd_id).execute(&mut *tx).await.map_err(StoreError::sql)?;
        let cordoned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_runner_drain WHERE runner_hd_id=$1) OR EXISTS(SELECT 1 FROM ci_host_maintenance WHERE runner_hd_id=$1 AND phase<>'passed') OR EXISTS(SELECT 1 FROM ci_host_heyvm_bootstrap WHERE runner_hd_id=$1 AND phase NOT IN ('passed','superseded'))")
            .bind(runner_hd_id).fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
        if cordoned { return Ok(JobClaim::RunnerCordoned); }
        let row = sqlx::query(
            "UPDATE ci_job
                SET status = 'running', runner_hd_id = $2, attempt = $3,
                    executor_boot = $4,
                    started_at = COALESCE(started_at, now())
              WHERE id = $1
                AND status IN ('pending','queued')
                AND NOT EXISTS (SELECT 1 FROM ci_host_work w WHERE w.job_id=ci_job.id)
                AND NOT EXISTS (SELECT 1 FROM ci_service_deployment s JOIN ci_host_maintenance h ON h.id=s.id WHERE s.job_id=ci_job.id)
                AND NOT EXISTS (SELECT 1 FROM ci_service_deployment s JOIN ci_host_heyvm_bootstrap h ON h.id=s.id WHERE s.job_id=ci_job.id)
              RETURNING run_id, job_key",
        )
        .bind(job_id)
        .bind(runner_hd_id)
        .bind(attempt)
        .bind(boot_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row {
            let run: String = row.get("run_id"); let key: String = row.get("job_key");
            sqlx::query("INSERT INTO ci_host_work(job_id,runner_hd_id,attempt,phase,executor_boot) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(job_id).bind(runner_hd_id).bind(attempt)
                .bind(if boot_id.is_some() { "preparing" } else { "execution" }).bind(boot_id)
                .execute(&mut *tx).await.map_err(StoreError::sql)?;
            Self::add_event(&mut tx, &run, Some(job_id), Some(&key), None, "ci.job.status.v1", "running", None).await?;
            tx.commit().await.map_err(StoreError::sql)?;
            Ok(JobClaim::Claimed)
        } else { tx.commit().await.map_err(StoreError::sql)?; Ok(JobClaim::Unavailable) }
    }

    /// Commit before any VM acquisition/open/start effects. Serialize with
    /// preparation finalization and cancellation on the job row, not a global lock.
    pub async fn begin_job_execution(&self, job: &str, attempt: i32, boot: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let owned: Option<String> = sqlx::query_scalar("SELECT runner_hd_id FROM ci_job WHERE id=$1 AND attempt=$2 AND executor_boot=$3 AND status='running' FOR UPDATE")
            .bind(job).bind(attempt).bind(boot).fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
        let Some(runner) = owned else { return Ok(false) };
        let changed = sqlx::query("UPDATE ci_host_work SET phase='execution' WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3 AND executor_boot=$4 AND phase='preparing'")
            .bind(job).bind(runner).bind(attempt).bind(boot).execute(&mut *tx).await.map_err(StoreError::sql)?.rows_affected();
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(changed == 1)
    }

    /// The caller's preparation future has ended; it cannot issue VM effects.
    /// Unknown runner-side preparation survives as runner maintenance evidence,
    /// but no longer belongs to this CI app. Never infer this from missing VM rows.
    pub async fn finish_job_preparation(&self, job: &str, attempt: i32, boot: Uuid,
        error: &str, quiescent: bool) -> Result<Option<JobStatus>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query("SELECT run_id,job_key,status,runner_hd_id FROM ci_job WHERE id=$1 AND attempt=$2 AND executor_boot=$3 FOR UPDATE")
            .bind(job).bind(attempt).bind(boot).fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
        let Some(row) = row else { return Ok(None) };
        let runner: String = row.get("runner_hd_id");
        let changed = sqlx::query("UPDATE ci_host_work SET phase='detached_preparation' WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3 AND executor_boot=$4 AND phase='preparing'")
            .bind(job).bind(&runner).bind(attempt).bind(boot).execute(&mut *tx).await.map_err(StoreError::sql)?.rows_affected();
        if changed != 1 { return Ok(None) }
        let existing: String = row.get("status");
        let status = JobStatus::parse(&existing).filter(|s| s.is_terminal()).unwrap_or(JobStatus::Failure);
        sqlx::query("UPDATE ci_job SET status=$2,error=CASE WHEN status='cancelled' THEN COALESCE(error,$3) ELSE $3 END,finished_at=COALESCE(finished_at,now()),executor_boot=NULL WHERE id=$1")
            .bind(job).bind(status.as_str()).bind(error).execute(&mut *tx).await.map_err(StoreError::sql)?;
        if quiescent {
            sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3 AND executor_boot=$4 AND phase='detached_preparation'")
                .bind(job).bind(runner).bind(attempt).bind(boot).execute(&mut *tx).await.map_err(StoreError::sql)?;
        }
        Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job), Some(&row.get::<String,_>("job_key")),
            None, "ci.job.status.v1", status.as_str(), Some(error)).await?;
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(Some(status))
    }

    /// Only an executor with a verified VM release may clear drain evidence.
    /// Cancellation and terminal status updates intentionally do not clear it.
    pub async fn end_host_work(&self, job_id: &str, runner: &str, attempt: i32) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1 AND runner_hd_id=$2 AND attempt=$3")
            .bind(job_id).bind(runner).bind(attempt).execute(&self.pool).await.map_err(StoreError::sql)?;
        Ok(())
    }

    /// A recorded executor obligation survives cancellation, process death and
    /// lease expiry. Only verified release may remove it.
    pub async fn has_host_work(&self, job_id: &str) -> Result<bool, StoreError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_work WHERE job_id=$1)")
            .bind(job_id).fetch_one(&self.pool).await.map_err(StoreError::sql)
    }

    pub async fn has_unresolved_execution(&self, run_id: &str) -> Result<bool, StoreError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_host_work w JOIN ci_job j ON j.id=w.job_id WHERE j.run_id=$1) OR EXISTS(SELECT 1 FROM ci_native_job WHERE run_id=$1 AND state='leased')")
            .bind(run_id).fetch_one(&self.pool).await.map_err(StoreError::sql)
    }

    /// Count an actual pre-claim failure, independent of transport deliveries.
    ///
    /// A failed delivery is negative-acked and retried on the backoff ladder —
    /// 60s, then 5 minutes, then 15 — and until this existed the reason was
    /// written to the row only by the *last* attempt. So the first twenty
    /// minutes of a job that could never work (a VM image that is not on the
    /// host, a daemon refusing the driver) showed an empty error and a status of
    /// `queued`, and the log on the orchestrator was the only place the cause
    /// appeared at all.
    ///
    /// The UPDATE races atomically with a regional claim. Never annotate or
    /// fail another boot's work based on an earlier ownership observation.
    pub async fn record_unclaimed_job_error(&self, job_id: &str, error: &str) -> Result<Option<i32>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_job SET error = $2,
                    preclaim_failures = preclaim_failures + 1,
                    status = CASE WHEN preclaim_failures + 1 >= $3 THEN 'failure' ELSE status END,
                    finished_at = CASE WHEN preclaim_failures + 1 >= $3 THEN now() ELSE finished_at END
              WHERE id = $1 AND status IN ('pending','queued') AND executor_boot IS NULL
                AND NOT EXISTS (SELECT 1 FROM ci_host_work w WHERE w.job_id=ci_job.id)
              RETURNING run_id, job_key, status, preclaim_failures",
        )
        .bind(job_id)
        .bind(error)
        .bind(crate::bus::MAX_PRECLAIM_FAILURES)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = &row {
            Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job_id),
                Some(&row.get::<String,_>("job_key")), None, "ci.job.status.v1",
                &row.get::<String,_>("status"), Some(error)).await?;
        }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(row.map(|row| row.get("preclaim_failures")))
    }

    /// Record which machine a running job landed on.
    ///
    /// Returns false when the job was already terminal, which is how a
    /// redelivery of work that finished just before the ack is dropped instead
    /// of run twice.
    pub async fn start_job(
        &self,
        job_id: &str,
        runner_hd_id: &str,
        sandbox_id: &str,
        fingerprint: &str,
        attempt: i32,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE ci_job
                SET status = 'running', runner_hd_id = $2, sandbox_id = $3,
                    fingerprint = $4, attempt = $5,
                    started_at = COALESCE(started_at, now())
              WHERE id = $1
                AND status NOT IN ('success','failure','skipped','cancelled')",
        )
        .bind(job_id)
        .bind(runner_hd_id)
        .bind(sandbox_id)
        .bind(fingerprint)
        .bind(attempt)
        .execute(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// Fill in VM identity only for the boot and attempt that won the claim.
    pub async fn start_job_for_boot(&self, job_id: &str, runner_hd_id: &str,
        sandbox_id: &str, fingerprint: &str, attempt: i32, boot_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE ci_job SET sandbox_id=$3,fingerprint=$4
             WHERE id=$1 AND runner_hd_id=$2 AND attempt=$5 AND executor_boot=$6
               AND status='running'",
        ).bind(job_id).bind(runner_hd_id).bind(sandbox_id).bind(fingerprint)
            .bind(attempt).bind(boot_id).execute(&self.pool).await.map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn set_job_outputs_for_boot(&self, job_id: &str, outputs: &serde_json::Value,
        attempt: i32, boot_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE ci_job SET outputs=$2 WHERE id=$1 AND status='running' AND attempt=$3 AND executor_boot=$4")
            .bind(job_id).bind(outputs).bind(attempt).bind(boot_id).execute(&self.pool).await.map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn set_job_status_for_boot(&self, job_id: &str, status: JobStatus,
        error: Option<&str>, attempt: i32, boot_id: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query("UPDATE ci_job SET status=$2,error=CASE WHEN $2 IN ('success','skipped') THEN $3 ELSE COALESCE($3,error) END,finished_at=CASE WHEN $2 IN ('success','failure','skipped','cancelled') THEN now() ELSE finished_at END WHERE id=$1 AND status='running' AND attempt=$4 AND executor_boot=$5 RETURNING run_id,job_key")
            .bind(job_id).bind(status.as_str()).bind(error).bind(attempt).bind(boot_id)
            .fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
        if let Some(row) = &row { Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job_id), Some(&row.get::<String,_>("job_key")), None, "ci.job.status.v1", status.as_str(), error).await?; }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(row.is_some())
    }

    /// Move a job from `pending` to `queued`.
    ///
    /// Returns false when it was not pending, which is what stops a second
    /// scheduler pass from publishing the same job twice. The queue's own
    /// `Nats-Msg-Id` dedup is the belt; this is the braces, and it also keeps
    /// the row's status honest.
    pub async fn queue_job(&self, job_id: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_job SET status = 'queued', queued_at = now()
                  WHERE id = $1 AND status = 'pending' RETURNING run_id, job_key",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row {
            Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job_id), Some(&row.get::<String,_>("job_key")), None, "ci.job.status.v1", "queued", None).await?;
            tx.commit().await.map_err(StoreError::sql)?; Ok(true)
        } else { tx.commit().await.map_err(StoreError::sql)?; Ok(false) }
    }

    /// Put a job back on the runway after its message failed to publish.
    ///
    /// [`Self::queue_job`] commits `pending → queued` before anything reaches
    /// NATS, so a failed publish leaves a row claiming to be queued with nothing
    /// on the queue — and the two stores then disagree with nothing to notice.
    /// Returning it to `pending` makes the scheduler's own retry the repair.
    ///
    /// Guarded on `queued` so it can never take a job that has since started.
    pub async fn unqueue_job(&self, job_id: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_job SET status='pending', queued_at=NULL
              WHERE id = $1 AND status = 'queued' RETURNING run_id, job_key",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row {
            Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job_id), Some(&row.get::<String,_>("job_key")), None, "ci.job.status.v1", "pending", Some("queue publication failed; retrying")).await?;
            tx.commit().await.map_err(StoreError::sql)?; Ok(true)
        } else { tx.commit().await.map_err(StoreError::sql)?; Ok(false) }
    }

    /// Give a job of a re-run the result its counterpart earned in the run
    /// being re-run — status and outputs — so `needs:` resolves and the jobs
    /// downstream of it can run without it running again.
    ///
    /// Guarded on `pending`: it only ever fills a row the scheduler has not
    /// touched, which is every row of a run that has just been created. Returns
    /// whether it did, so a key the new plan no longer has is a count of zero
    /// rather than an error.
    pub async fn carry_over_job(&self, job_id: &str, from: &JobRow) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_job
                SET status = $2, outputs = $3, carried_from = $4,
                    started_at = now(), finished_at = now()
              WHERE id = $1 AND status = 'pending' RETURNING run_id, job_key",
        )
        .bind(job_id)
        .bind(&from.status)
        .bind(&from.outputs)
        .bind(&from.run_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row {
            Self::add_event(&mut tx, &row.get::<String,_>("run_id"), Some(job_id), Some(&row.get::<String,_>("job_key")), None, "ci.job.status.v1", &from.status, None).await?;
            tx.commit().await.map_err(StoreError::sql)?; Ok(true)
        } else { tx.commit().await.map_err(StoreError::sql)?; Ok(false) }
    }

    /// Active runs that still have a job waiting to be scheduled.
    ///
    /// The scheduler is otherwise only driven by a submit and by jobs finishing,
    /// so a run whose every job failed to publish has nothing left to nudge it.
    pub async fn runs_with_pending_jobs(&self, limit: i64) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT r.id FROM ci_run r
               JOIN ci_job j ON j.run_id = r.id
              WHERE r.status NOT IN ('success','failure','cancelled')
                AND j.status = 'pending'
                AND (NOT EXISTS (
                    SELECT 1 FROM ci_submission_validation m JOIN ci_run v ON v.id=m.validation_run_id
                    WHERE m.release_run_id=r.id AND v.status IN ('queued','running')
                ) OR EXISTS (
                    SELECT 1 FROM ci_submission_validation m JOIN ci_run v ON v.id=m.validation_run_id
                    WHERE m.release_run_id=r.id AND v.status IN ('failure','cancelled')
                ))
              ORDER BY r.id
              LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(|r| r.get::<String, _>("id")).collect())
    }

    pub async fn set_job_status(
        &self,
        job_id: &str,
        status: JobStatus,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_job
                SET status = $2,
                    error = CASE WHEN $2 IN ('success','skipped') THEN $3
                                 ELSE COALESCE($3, error) END,
                    finished_at = CASE WHEN $2 IN ('success','failure','skipped','cancelled')
                                       THEN now() ELSE finished_at END
              WHERE id = $1 RETURNING run_id, job_key",
        )
        .bind(job_id)
        .bind(status.as_str())
        .bind(error)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row {
            let run: String = row.get("run_id"); let key: String = row.get("job_key");
            Self::add_event(&mut tx, &run, Some(job_id), Some(&key), None, "ci.job.status.v1", status.as_str(), error).await?;
        }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn set_job_outputs(
        &self,
        job_id: &str,
        outputs: &serde_json::Value,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE ci_job SET outputs = $2 WHERE id = $1")
            .bind(job_id)
            .bind(outputs)
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(())
    }

    /// The `needs` context for a run: `{ "<base_id>": { "result": …, "outputs": … } }`.
    ///
    /// Keyed on `base_id`, and a base with several matrix cells collapses to the
    /// worst result among them — `needs.build.result` has to mean "did build
    /// pass", and it did not if any cell failed.
    pub async fn needs_context(&self, run_id: &str) -> Result<serde_json::Value, StoreError> {
        let jobs = self.jobs_of(run_id).await?;
        let mut map = serde_json::Map::new();
        for job in &jobs {
            let entry = map
                .entry(job.base_id.clone())
                .or_insert_with(|| serde_json::json!({"result": "success", "outputs": {}}));
            let current = entry
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or("success")
                .to_string();
            let worst = worse_of(&current, &job.status);
            entry["result"] = serde_json::Value::String(worst);
            if let (Some(dst), Some(src)) =
                (entry["outputs"].as_object_mut(), job.outputs.as_object())
            {
                for (k, v) in src {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
        Ok(serde_json::Value::Object(map))
    }

    // ---- steps ----------------------------------------------------------

    pub async fn create_step(
        &self,
        step_id: &str,
        job_id: &str,
        idx: i32,
        name: &str,
        uses: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let inserted = sqlx::query(
            "INSERT INTO ci_step (id, job_id, idx, name, uses, status)
             VALUES ($1,$2,$3,$4,$5,'pending')
             ON CONFLICT (job_id, idx) DO NOTHING",
        )
        .bind(step_id)
        .bind(job_id)
        .bind(idx)
        .bind(name)
        .bind(uses)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if inserted.rows_affected() > 0 {
            let row = sqlx::query("SELECT run_id, job_key FROM ci_job WHERE id=$1").bind(job_id).fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
            let run: String = row.get("run_id"); let key: String = row.get("job_key");
            Self::add_event(&mut tx, &run, Some(job_id), Some(&key), Some(step_id), "ci.step.status.v1", "pending", None).await?;
        }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn start_step(&self, step_id: &str, operation_id: &str) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_step
                SET status='running', operation_id=$2, started_at=COALESCE(started_at, now())
              WHERE id = $1 RETURNING job_id",
        )
        .bind(step_id)
        .bind(operation_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row { self.add_step_event(&mut tx, step_id, &row.get::<String,_>("job_id"), "running", None).await?; }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn finish_step(
        &self,
        step_id: &str,
        status: StepStatus,
        exit_code: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let row = sqlx::query(
            "UPDATE ci_step
                SET status=$2, exit_code=$3, error=$4, finished_at=now()
              WHERE id = $1 RETURNING job_id",
        )
        .bind(step_id)
        .bind(status.as_str())
        .bind(exit_code)
        .bind(error)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if let Some(row) = row { self.add_step_event(&mut tx, step_id, &row.get::<String,_>("job_id"), status.as_str(), error).await?; }
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(())
    }

    /// Commit a completed command once. A lost COMMIT response is safe to
    /// retry: the terminal row is the receipt, and its log is not appended twice.
    pub async fn finish_command(
        &self, step_id: &str, status: StepStatus, exit_code: i32, text: &str,
        attempt: i32, boot: uuid::Uuid,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let job = sqlx::query("SELECT j.id,j.attempt,j.executor_boot FROM ci_job j JOIN ci_step s ON s.job_id=j.id WHERE s.id=$1 FOR UPDATE OF j")
            .bind(step_id).fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
        if job.get::<i32,_>("attempt") != attempt || job.get::<Option<uuid::Uuid>,_>("executor_boot") != Some(boot) {
            return Err(StoreError::Sql("completed command no longer owns this job attempt".into()));
        }
        let row = sqlx::query("SELECT status,exit_code,finished_at IS NOT NULL AS finished FROM ci_step WHERE id=$1 FOR UPDATE")
            .bind(step_id).fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
        if row.get::<bool,_>("finished") {
            if row.get::<String,_>("status") != status.as_str() || row.get::<Option<i32>,_>("exit_code") != Some(exit_code) {
                return Err(StoreError::Sql("completed command conflicts with the recorded step result".into()));
            }
            return Ok(());
        }
        Self::append_log_in(&mut tx, step_id, text).await?;
        sqlx::query("UPDATE ci_step SET status=$2,exit_code=$3,error=NULL,finished_at=now() WHERE id=$1")
            .bind(step_id).bind(status.as_str()).bind(exit_code)
            .execute(&mut *tx).await.map_err(StoreError::sql)?;
        self.add_step_event(&mut tx, step_id, &job.get::<String,_>("id"), status.as_str(), None).await?;
        tx.commit().await.map_err(StoreError::sql)
    }

    pub async fn steps_of(&self, job_id: &str) -> Result<Vec<StepRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM ci_step WHERE job_id = $1 ORDER BY idx")
            .bind(job_id)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(rows.iter().map(StepRow::from_row).collect())
    }

    // ---- logs -----------------------------------------------------------

    /// Where a step's log lives: `<log_dir>/<run>/<job_key>/<idx>-<step>.log`.
    pub fn log_path(&self, run_id: &str, job_key: &str, idx: i32, step_id: &str) -> PathBuf {
        self.log_dir
            .join(sanitize_component(run_id))
            .join(sanitize_component(job_key))
            .join(format!("{idx:03}-{}.log", sanitize_component(step_id)))
    }

    /// Append in shared storage. The historical path argument is ignored;
    /// existing execution callers can retain their diagnostic path calculation.
    pub async fn append_log(
        &self,
        step_id: &str,
        _path: &Path,
        text: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        Self::append_log_in(&mut tx, step_id, text).await?;
        tx.commit().await.map_err(StoreError::sql)
    }

    /// Native completion commits logs and execution evidence together.
    pub async fn append_log_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        step_id: &str,
        text: &str,
    ) -> Result<(), StoreError> {
        let row = sqlx::query("SELECT log_path, log_bytes FROM ci_step WHERE id=$1 FOR UPDATE")
            .bind(step_id)
            .fetch_one(&mut **tx).await.map_err(StoreError::sql)?;
        let path: Option<String> = row.get("log_path");
        if path.as_deref().is_some_and(|p| p != "postgres:ci_step_log") {
            return Err(StoreError::Sql(format!("step {step_id} still has unimported local logs")));
        }
        if !text.is_empty() {
            sqlx::query("INSERT INTO ci_step_log(step_id,byte_offset,bytes) VALUES($1,$2,$3)")
                .bind(step_id).bind(row.get::<i64, _>("log_bytes")).bind(text.as_bytes())
                .execute(&mut **tx).await.map_err(StoreError::sql)?;
        }
        sqlx::query("UPDATE ci_step SET log_path='postgres:ci_step_log', log_bytes=log_bytes+$2 WHERE id=$1")
            .bind(step_id)
            .bind(text.len() as i64)
            .execute(&mut **tx).await.map_err(StoreError::sql)?;
        Ok(())
    }

    pub async fn read_log(&self, step: &StepRow) -> Result<Option<String>, StoreError> {
        // One statement snapshot keeps retention from producing partial reads.
        let rows = sqlx::query("SELECT s.log_path, l.bytes FROM ci_step s LEFT JOIN ci_step_log l ON l.step_id=s.id WHERE s.id=$1 ORDER BY l.byte_offset")
            .bind(&step.id).fetch_all(&self.pool).await.map_err(StoreError::sql)?;
        let Some(row) = rows.first() else { return Ok(None) };
        let path: Option<String> = row.get("log_path");
        let Some(path) = path else { return Ok(None) };
        if path != "postgres:ci_step_log" {
            return Err(StoreError::Sql(format!("step {} still has unimported local logs", step.id)));
        }
        let bytes: Vec<u8> = rows.into_iter().filter_map(|r| r.get::<Option<Vec<u8>>, _>("bytes")).flatten().collect();
        String::from_utf8(bytes).map(Some).map_err(|e| StoreError::Sql(format!("invalid log UTF-8: {e}")))
    }

    /// Upgrade only after the old controller has drained and stopped. Missing
    /// or unreadable retained logs block startup rather than silently losing history.
    pub async fn import_logs(&self) -> Result<u64, StoreError> {
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM ci_step WHERE log_path IS NOT NULL AND log_path <> 'postgres:ci_step_log' ORDER BY id")
            .fetch_all(&self.pool).await.map_err(StoreError::sql)?;
        let mut imported = 0;
        for id in ids {
            let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
            let row = sqlx::query("SELECT log_path,log_bytes FROM ci_step WHERE id=$1 FOR UPDATE")
                .bind(&id).fetch_optional(&mut *tx).await.map_err(StoreError::sql)?;
            let expected = row.as_ref().map(|r| r.get::<i64, _>("log_bytes")).unwrap_or(0);
            let path = row.and_then(|r| r.get::<Option<String>, _>("log_path"));
            if let Some(path) = path.filter(|p| p != "postgres:ci_step_log") {
                let text = tokio::fs::read_to_string(&path).await.map_err(|e| StoreError::LogDir {
                    path: PathBuf::from(&path), reason: e.to_string(),
                })?;
                if (text.len() as i64) < expected {
                    return Err(StoreError::LogDir { path: PathBuf::from(&path), reason: format!("retained log is shorter than its recorded {expected} bytes") });
                }
                sqlx::query("UPDATE ci_step SET log_path=NULL,log_bytes=0 WHERE id=$1")
                    .bind(&id).execute(&mut *tx).await.map_err(StoreError::sql)?;
                Self::append_log_in(&mut tx, &id, &text).await?;
                imported += 1;
            }
            tx.commit().await.map_err(StoreError::sql)?;
        }
        Ok(imported)
    }

    pub async fn record_artifact(
        &self,
        run_id: &str,
        job_id: &str,
        step_id: &str,
        name: &str,
        stored: &crate::artifacts::StoredArtifact,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        // Resolve all scope from a real step/job relationship, not independent
        // foreign keys that could associate another repository's artifact.
        let key: String = sqlx::query_scalar(
            "SELECT j.job_key FROM ci_job j JOIN ci_step s ON s.job_id=j.id
             WHERE j.id=$1 AND j.run_id=$2 AND s.id=$3",
        ).bind(job_id).bind(run_id).bind(step_id)
            .fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
        let artifact_id = crate::vm::new_id();
        let inserted = sqlx::query(
            "INSERT INTO ci_artifact (id, run_id, job_id, name, sink, digest, size_bytes, uri, public_url, step_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             ON CONFLICT (step_id) DO NOTHING",
        )
        .bind(&artifact_id)
        .bind(run_id)
        .bind(job_id)
        .bind(name)
        .bind(stored.sink)
        .bind(&stored.digest)
        .bind(stored.size_bytes as i64)
        .bind(&stored.uri)
        .bind(&stored.public_url)
        .bind(step_id)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        if inserted.rows_affected() == 0 {
            // An uncertain DB acknowledgement may retry the upload. Accept
            // the same publication, never silently replace its recorded bytes.
            let same: bool = sqlx::query_scalar(
                "SELECT name=$2 AND sink=$3 AND digest IS NOT DISTINCT FROM $4
                        AND size_bytes=$5 AND uri=$6 AND public_url IS NOT DISTINCT FROM $7
                   FROM ci_artifact WHERE step_id=$1",
            ).bind(step_id).bind(name).bind(stored.sink).bind(&stored.digest)
                .bind(stored.size_bytes as i64).bind(&stored.uri).bind(&stored.public_url)
                .fetch_one(&mut *tx).await.map_err(StoreError::sql)?;
            if !same {
                return Err(StoreError::Sql(format!("artifact publication changed for step {step_id}")));
            }
        } else {
            let event_id = Self::add_event(
                &mut tx, run_id, Some(job_id), Some(&key), Some(step_id),
                "ci.artifact.published.v1", "published", None,
            ).await?;
            let artifact = serde_json::json!({
                "id": artifact_id, "name": name, "sink": stored.sink,
                "digest": stored.digest, "size_bytes": stored.size_bytes,
                "uri": stored.uri, "public_url": stored.public_url,
            });
            sqlx::query("UPDATE ci_event_outbox SET payload=payload || jsonb_build_object('artifact', $2::jsonb) WHERE id=$1")
                .bind(event_id).bind(artifact).execute(&mut *tx).await.map_err(StoreError::sql)?;
        }
        tx.commit().await.map_err(StoreError::sql)
    }

    pub async fn artifacts_of(&self, run_id: &str) -> Result<Vec<ArtifactRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM ci_artifact WHERE run_id = $1 ORDER BY created_at")
            .bind(run_id)
            .fetch_all(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(rows
            .iter()
            .map(|r| ArtifactRow {
                name: r.get("name"),
                sink: r.get("sink"),
                digest: r.get("digest"),
                size_bytes: r.get("size_bytes"),
                uri: r.get("uri"),
                public_url: r.get("public_url"),
            })
            .collect())
    }

    /// Runs old enough to sweep that still have a log recorded.
    ///
    /// Driven by the rows rather than by walking the log directory: a directory
    /// whose run was deleted has nothing to update, and a run whose files were
    /// removed by hand should stop being offered every hour. The `EXISTS`
    /// clause is what makes the sweep converge — once the paths are nulled the
    /// run is not returned again.
    pub async fn runs_with_logs_before(
        &self,
        cutoff: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(
            "SELECT r.id FROM ci_run r
              WHERE r.created_at < $1
                AND EXISTS (
                      SELECT 1 FROM ci_job j
                        JOIN ci_step s ON s.job_id = j.id
                       WHERE j.run_id = r.id AND s.log_path IS NOT NULL)
              ORDER BY r.created_at
              LIMIT $2",
        )
        .bind(cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(|r| r.get::<String, _>("id")).collect())
    }

    /// Atomically expire shared log bytes and their metadata.
    ///
    /// The rows survive — a step that ran and its exit code are the run's
    /// history, and losing that because the log aged out would make an old run
    /// look like it never happened. Only the pointer and the byte count go.
    pub async fn forget_logs_of(&self, run_id: &str) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await.map_err(StoreError::sql)?;
        let ids: Vec<String> = sqlx::query_scalar(
            "UPDATE ci_step SET log_path = NULL, log_bytes = 0
              WHERE log_path IS NOT NULL
                AND job_id IN (SELECT id FROM ci_job WHERE run_id = $1)
              RETURNING id",
        )
        .bind(run_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(StoreError::sql)?;
        sqlx::query("DELETE FROM ci_step_log WHERE step_id=ANY($1)")
            .bind(&ids).execute(&mut *tx).await.map_err(StoreError::sql)?;
        tx.commit().await.map_err(StoreError::sql)?;
        Ok(ids.len() as u64)
    }

    /// The directory holding every log of one run.
    pub fn run_log_dir(&self, run_id: &str) -> PathBuf {
        self.log_dir.join(sanitize_component(run_id))
    }

    // ---- registered repositories ----------------------------------------

    /// Register a repository, or update the one already registered at that URL.
    ///
    /// Upsert rather than insert, keyed on the normalized URL: someone
    /// registering `git@github.com:me/app.git` when
    /// `https://github.com/me/app` is already registered means to edit that
    /// registration, not to create a second one that competes with it for the
    /// same submits. Existing tokens keep working, which is the point — the
    /// alternative is that fixing a typo in a display name invalidates
    /// everyone's credential.
    pub async fn register_repo(
        &self,
        url: &str,
        name: &str,
        workflow_path: Option<&str>,
        network: Option<&str>,
        actor: Option<(&str, &str)>,
    ) -> Result<Repo, StoreError> {
        self.register_repo_in("", url, name, workflow_path, network, actor).await
    }

    /// [`Self::register_repo`] in a namespace — `""` is the fleet.
    ///
    /// The upsert is keyed on `(namespace, normalized)`: re-registering a URL
    /// edits *this namespace's* registration of it and never another's. A
    /// tenant naming a fleet repository's URL gets a registration of its own,
    /// with its own tokens, rather than the fleet's row.
    pub async fn register_repo_in(
        &self,
        namespace: &str,
        url: &str,
        name: &str,
        workflow_path: Option<&str>,
        network: Option<&str>,
        actor: Option<(&str, &str)>,
    ) -> Result<Repo, StoreError> {
        let row = sqlx::query(
            "INSERT INTO ci_repo (id, url, normalized, name, workflow_path, network,
                                  created_by, created_email, namespace)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (namespace, normalized) DO UPDATE
                SET url = EXCLUDED.url,
                    name = EXCLUDED.name,
                    workflow_path = EXCLUDED.workflow_path,
                    network = EXCLUDED.network
             RETURNING *",
        )
        .bind(crate::vm::new_id())
        .bind(url)
        .bind(crate::repos::normalize(url))
        .bind(name)
        .bind(workflow_path)
        .bind(network)
        .bind(actor.map(|a| a.0))
        .bind(actor.map(|a| a.1))
        .bind(namespace)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(Repo::from_row(&row))
    }

    /// Point a repository at a heyvm network, or back at the default.
    ///
    /// Its own route rather than a re-registration, because reassigning a
    /// network is the thing an operator does most often here — moving a
    /// repository onto new hardware — and making that go through a form that
    /// also rewrites the name and the workflow path invites clobbering both.
    ///
    /// Takes effect on the next submit. Jobs already scheduled keep the network
    /// stamped into their stored plan, so a build in flight is not rerouted onto
    /// hardware it did not warm a VM on.
    pub async fn set_repo_network(
        &self,
        repo_id: &str,
        network: Option<&str>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE ci_repo SET network = $2 WHERE id = $1")
            .bind(repo_id)
            .bind(network.map(str::trim).filter(|n| !n.is_empty()))
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// The fleet's registrations. Tenant namespaces manage their own on their
    /// own pages; listing them here would offer the operator's network picker
    /// for repositories whose network the tenant policy decides.
    pub async fn repos(&self) -> Result<Vec<Repo>, StoreError> {
        self.repos_in("").await
    }

    pub async fn repos_in(&self, namespace: &str) -> Result<Vec<Repo>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM ci_repo WHERE namespace = $1 ORDER BY name, normalized",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(Repo::from_row).collect())
    }

    /// [`Self::get_repo`], answering only for a registration in `namespace`.
    pub async fn get_repo_in(&self, namespace: &str, id: &str) -> Result<Option<Repo>, StoreError> {
        Ok(self.get_repo(id).await?.filter(|r| r.namespace == namespace))
    }

    pub async fn get_repo(&self, id: &str) -> Result<Option<Repo>, StoreError> {
        let row = sqlx::query("SELECT * FROM ci_repo WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(row.as_ref().map(Repo::from_row))
    }

    /// The fleet registration for a clone URL, in any of its spellings.
    ///
    /// **Fleet only.** This is how a shared-secret submit finds a registration,
    /// and the shared secret is the operator's credential: it must never land
    /// a run in a tenant namespace, where the tenant's secrets and network
    /// would apply to a submit the tenant did not make.
    pub async fn repo_by_url(&self, url: &str) -> Result<Option<Repo>, StoreError> {
        let row = sqlx::query("SELECT * FROM ci_repo WHERE normalized = $1 AND namespace = ''")
            .bind(crate::repos::normalize(url))
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(row.as_ref().map(Repo::from_row))
    }

    /// Stop, or resume, a repository submitting.
    ///
    /// Separate from revoking tokens because it answers a different question. A
    /// repository that should not be building right now — a migration, an
    /// incident, a repository that was archived — is not a repository whose
    /// tokens are compromised, and making the operator revoke and re-mint every
    /// one to pause it teaches them to leave it running instead.
    pub async fn set_repo_enabled(&self, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE ci_repo SET enabled = $2 WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// [`Self::set_repo_enabled`], only for a registration in `namespace`.
    pub async fn set_repo_enabled_in(&self, namespace: &str, id: &str, enabled: bool) -> Result<bool, StoreError> {
        let result = sqlx::query("UPDATE ci_repo SET enabled = $3 WHERE id = $1 AND namespace = $2")
            .bind(id)
            .bind(namespace)
            .bind(enabled)
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// [`Self::delete_repo`], only for a registration in `namespace`.
    pub async fn delete_repo_in(&self, namespace: &str, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM ci_repo WHERE id = $1 AND namespace = $2")
            .bind(id)
            .bind(namespace)
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// Remove a registration and every token it issued.
    ///
    /// Its runs survive with a null `repo_id` — deleting the registration must
    /// not delete the history of what it built.
    pub async fn delete_repo(&self, id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM ci_repo WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// Mint a token for a repository and return it in plaintext — once.
    ///
    /// The plaintext is returned and not stored. There is no route that can
    /// show it again, because there is nothing left to show it from.
    pub async fn create_repo_token(
        &self,
        repo_id: &str,
        name: &str,
        actor: Option<(&str, &str)>,
    ) -> Result<(RepoToken, String), StoreError> {
        let minted = crate::repos::mint(&crate::vm::new_id());
        let row = sqlx::query(
            "INSERT INTO ci_repo_token (id, repo_id, name, secret_hash, created_by, created_email)
             VALUES ($1,$2,$3,$4,$5,$6)
             RETURNING *",
        )
        .bind(&minted.key_id)
        .bind(repo_id)
        .bind(name)
        .bind(&minted.secret_hash)
        .bind(actor.map(|a| a.0))
        .bind(actor.map(|a| a.1))
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok((RepoToken::from_row(&row), minted.plaintext))
    }

    pub async fn repo_tokens(&self, repo_id: &str) -> Result<Vec<RepoToken>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM ci_repo_token WHERE repo_id = $1
              ORDER BY revoked_at IS NOT NULL, created_at DESC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(rows.iter().map(RepoToken::from_row).collect())
    }

    /// Stop a token working, without forgetting it existed.
    ///
    /// Idempotent, and `revoked_at` is only ever set once: revoking twice must
    /// not rewrite when access actually ended.
    pub async fn revoke_repo_token(&self, token_id: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE ci_repo_token SET revoked_at = now()
              WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(token_id)
        .execute(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// [`Self::revoke_repo_token`], only for a token of `repo_id`, and only when
    /// that registration is in `namespace`. A token id from anywhere else is
    /// `false`, the same as one already revoked.
    pub async fn revoke_repo_token_in(
        &self,
        namespace: &str,
        repo_id: &str,
        token_id: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE ci_repo_token t SET revoked_at = now()
               FROM ci_repo r
              WHERE t.id = $1 AND t.repo_id = $2 AND r.id = t.repo_id
                AND r.namespace = $3 AND t.revoked_at IS NULL",
        )
        .bind(token_id)
        .bind(repo_id)
        .bind(namespace)
        .execute(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(result.rows_affected() > 0)
    }

    /// Resolve a presented submit token to the repository it may submit for.
    ///
    /// `Ok(None)` covers every way of not being a valid credential —
    /// malformed, unknown key id, wrong secret, revoked, or a registration that
    /// has been disabled. The caller reports one message for all of them, for
    /// the same reason [`crate::trigger::TriggerError`] gives: telling a caller
    /// *which* part of their credential was wrong tells an attacker how far
    /// they got.
    ///
    /// A malformed presentation never reaches the database — this route is
    /// unauthenticated and on the open internet.
    pub async fn authenticate_repo_token(
        &self,
        presented: &str,
    ) -> Result<Option<Repo>, StoreError> {
        let Some((key_id, secret)) = crate::repos::parse(presented) else {
            return Ok(None);
        };

        let row = sqlx::query(
            "SELECT t.secret_hash AS secret_hash, r.*
               FROM ci_repo_token t
               JOIN ci_repo r ON r.id = t.repo_id
              WHERE t.id = $1 AND t.revoked_at IS NULL AND r.enabled",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::sql)?;

        let Some(row) = row else { return Ok(None) };
        let stored: String = row.get("secret_hash");
        if !crate::repos::secret_matches(secret, &stored) {
            return Ok(None);
        }

        // Best-effort: a submit that ran is not undone by failing to record
        // that its token was used.
        if let Err(e) = sqlx::query("UPDATE ci_repo_token SET last_used_at = now() WHERE id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await
        {
            tracing::warn!("could not record use of submit token {key_id}: {e}");
        }

        Ok(Some(Repo::from_row(&row)))
    }

    /// The most recent run of a registered repository, for the dashboard.
    pub async fn last_run_of_repo(&self, repo_id: &str) -> Result<Option<Run>, StoreError> {
        let row = sqlx::query(
            "SELECT r.*, rp.name AS repo_name
               FROM ci_run r
               LEFT JOIN ci_repo rp ON rp.id = r.repo_id
              WHERE r.repo_id = $1
              ORDER BY r.created_at DESC
              LIMIT 1",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(row.as_ref().map(Run::from_row))
    }

    // ---- users ----------------------------------------------------------

    /// Record a person and return their role, seeding admins from config.
    ///
    /// Keyed on the stable subject, so an email change updates the row rather
    /// than creating a second account for the same person.
    pub async fn upsert_user(
        &self,
        subject: &str,
        email: &str,
        name: Option<&str>,
        admin_emails: &[String],
    ) -> Result<String, StoreError> {
        let seed_role = if admin_emails
            .iter()
            .any(|a| a == &email.to_ascii_lowercase())
        {
            "admin"
        } else {
            "viewer"
        };
        let row = sqlx::query(
            "INSERT INTO ci_user (subject, email, name, role)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (subject) DO UPDATE
                SET email = EXCLUDED.email,
                    name = EXCLUDED.name,
                    last_seen_at = now(),
                    -- Promote on the config list, but never demote: a role
                    -- granted in the UI must survive the list changing.
                    role = CASE WHEN EXCLUDED.role = 'admin' THEN 'admin'
                                ELSE ci_user.role END
             RETURNING role",
        )
        .bind(subject)
        .bind(email)
        .bind(name)
        .bind(seed_role)
        .fetch_one(&self.pool)
        .await
        .map_err(StoreError::sql)?;
        Ok(row.get("role"))
    }
}

/// A job's row id, derived from the run and the job key so it is stable across
/// a redelivery — the same job always resolves to the same row.
pub fn job_id(run_id: &str, job_key: &str) -> String {
    format!("{run_id}.{job_key}")
}

/// A step's row id, likewise derived and therefore reusable as the daemon's
/// `operationId`: re-running the same step of the same job reattaches.
pub fn step_id(job_id: &str, idx: usize) -> String {
    format!("{job_id}.{idx}")
}

/// Rank two job statuses and return the worse, for rolling matrix cells up into
/// one `needs.<base>.result`.
fn worse_of(a: &str, b: &str) -> String {
    fn rank(s: &str) -> u8 {
        match s {
            "success" => 0,
            "skipped" => 1,
            "pending" | "queued" | "running" => 2,
            "cancelled" => 3,
            _ => 4, // failure
        }
    }
    if rank(b) > rank(a) {
        b.to_string()
    } else {
        a.to_string()
    }
}

/// Keep a path component inside the log directory.
///
/// Ids are already charset-restricted, but a log path is assembled from values
/// that reach us over HTTP, and one `..` would write outside `CI_LOG_DIR`.
fn sanitize_component(s: &str) -> String {
    // `.` is folded away too, not just `/`. Keeping dots would be safe — a
    // component with no separator cannot traverse — but it produces names like
    // `..-..-etc-passwd` that read as an attempted escape to anyone auditing
    // the directory, and hidden files that `ls` does not show.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let c = if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '-'
        };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        return "-".to_string();
    }
    trimmed.to_string()
}

/// Steps to create for a job, in order.
pub fn step_rows_for(plan: &JobPlan, job_id: &str) -> Vec<(String, i32, String, Option<String>)> {
    plan.steps
        .iter()
        .enumerate()
        .map(|(i, s)| (step_id(job_id, i), i as i32, s.label(i), s.uses.clone()))
        .collect()
}

#[derive(Debug)]
pub enum StoreError {
    Connect(String),
    Migrations { path: PathBuf, reason: String },
    LogDir { path: PathBuf, reason: String },
    Source { run_id: String, reason: String },
    Sql(String),
}

impl StoreError {
    fn sql(e: sqlx::Error) -> Self {
        Self::Sql(e.to_string())
    }

    fn source(run_id: &str, reason: impl fmt::Display) -> Self {
        Self::Source { run_id: run_id.into(), reason: reason.to_string() }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(
                f,
                "could not connect to Postgres: {e}. Check CI_DATABASE_URL."
            ),
            Self::Migrations { path, reason } => {
                write!(f, "migration {} failed: {reason}", path.display())
            }
            Self::LogDir { path, reason } => {
                write!(f, "could not write logs under {}: {reason}", path.display())
            }
            Self::Source { run_id, reason } => write!(f, "source of run {run_id}: {reason}"),
            Self::Sql(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    /// The binary carries every migration in the directory, in order. A
    /// file that exists on disk and not here is exactly the drift `build.rs`
    /// exists to prevent, so this reads the directory independently.
    #[test]
    fn every_migration_on_disk_is_compiled_in_and_in_order() {
        let mut on_disk: Vec<String> = std::fs::read_dir("migrations")
            .expect("migrations/ beside Cargo.toml")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sql"))
            .collect();
        on_disk.sort();
        let embedded: Vec<&str> = EMBEDDED_MIGRATIONS.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            embedded, on_disk,
            "rebuild: build.rs did not see the directory"
        );
        assert!(embedded.windows(2).all(|w| w[0] < w[1]), "{embedded:?}");
        assert!(
            EMBEDDED_MIGRATIONS
                .iter()
                .all(|(_, sql)| !sql.trim().is_empty()),
            "an empty migration is a file that was written and forgotten"
        );
    }

    use super::*;

    #[test]
    fn statuses_round_trip_through_their_wire_names() {
        assert_eq!(RunStatus::Success.as_str(), "success");
        assert!(RunStatus::Failure.is_terminal());
        assert!(!RunStatus::Running.is_terminal());
        assert!(JobStatus::Skipped.is_terminal());
        assert!(!JobStatus::Queued.is_terminal());
        assert_eq!(StepStatus::Running.as_str(), "running");
    }

    /// A skipped dependency is not a failure — a downstream `if:` may want to
    /// run anyway, and GitHub reports it as `skipped`.
    #[test]
    fn a_skipped_job_reports_skipped_not_failure() {
        assert_eq!(JobStatus::Skipped.result_name(), "skipped");
        assert_eq!(JobStatus::Failure.result_name(), "failure");
        assert_eq!(JobStatus::Running.result_name(), "pending");
    }

    /// `needs.build.result` must mean "did build pass", so one failed matrix
    /// cell has to poison the whole base id.
    #[test]
    fn rolling_matrix_cells_up_takes_the_worst_result() {
        assert_eq!(worse_of("success", "failure"), "failure");
        assert_eq!(worse_of("failure", "success"), "failure");
        assert_eq!(worse_of("success", "skipped"), "skipped");
        assert_eq!(worse_of("skipped", "success"), "skipped");
        assert_eq!(worse_of("success", "running"), "running");
        assert_eq!(worse_of("cancelled", "failure"), "failure");
        assert_eq!(worse_of("success", "success"), "success");
    }

    /// Ids are derived rather than minted so a redelivery addresses the same
    /// rows, and a step id doubles as the daemon's idempotent `operationId`.
    #[test]
    fn ids_are_derived_and_therefore_stable() {
        let run = "019f7c7ef325-00000000";
        let j = job_id(run, "build-x86_64");
        assert_eq!(j, "019f7c7ef325-00000000.build-x86_64");
        assert_eq!(job_id(run, "build-x86_64"), j, "deriving twice agrees");

        let s = step_id(&j, 2);
        assert_eq!(s, "019f7c7ef325-00000000.build-x86_64.2");
        assert!(
            crate::vm::valid_operation_id(&s),
            "a step id must be usable as an operationId: {s}"
        );
    }

    // ---- integration ----------------------------------------------------
    //
    // Need a Postgres. Run with:
    //   CI_TEST_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/ci_test \
    //     cargo test -- --ignored store::
    //
    // Each test uses its own run id, so they are safe to run against a database
    // that already has rows in it and safe to run concurrently.

    async fn test_store() -> Store {
        let url = std::env::var("CI_TEST_DATABASE_URL").expect("CI_TEST_DATABASE_URL");
        let dir = std::env::temp_dir().join(format!("ci-test-logs-{}", crate::vm::new_id()));
        let store = Store::connect(&url, dir, std::time::Duration::from_secs(30))
            .await
            .expect("connects");
        store.migrate().await.expect("migrations apply");
        store
    }

    #[tokio::test]
    #[ignore = "needs Postgres"]
    async fn shared_source_is_atomic_immutable_and_independent_of_local_files() {
        let store = test_store().await;
        let peer = test_store().await;
        let source = serde_json::to_vec(&serde_json::json!({
            "baseRevision": "a".repeat(40), "targetTree": "b".repeat(40),
            "patchBase64": "AAEC", "workflows": {"build.yml": "# héllo\njobs: {}\n"}
        })).unwrap();
        let run = crate::vm::new_id();
        let mut tx = store.pool.begin().await.unwrap();
        Store::create_run_in(&mut tx, &run, &RunRequest::default(), &test_plan()).await.unwrap();
        Store::record_source_in(&mut tx, &run, &source).await.unwrap();
        assert!(peer.get_run(&run).await.unwrap().is_none());
        assert!(peer.source_bytes(&run).await.is_err(), "source is not visible before admission commits");
        tx.commit().await.unwrap();
        assert_eq!(peer.source_bytes(&run).await.unwrap(), source);
        assert_eq!(peer.source_descriptor(&run).await.unwrap().patch().unwrap(), vec![0, 1, 2]);

        let mut changed: serde_json::Value = serde_json::from_slice(&source).unwrap();
        changed["targetTree"] = serde_json::json!("c".repeat(40));
        let changed = serde_json::to_vec(&changed).unwrap();
        let mut tx = peer.pool.begin().await.unwrap();
        Store::record_source_in(&mut tx, &run, &source).await.unwrap();
        tx.commit().await.unwrap();
        let mut tx = peer.pool.begin().await.unwrap();
        assert!(Store::record_source_in(&mut tx, &run, &changed).await.is_err());
        tx.rollback().await.unwrap();
        assert_eq!(store.source_bytes(&run).await.unwrap(), source);

        let rejected = crate::vm::new_id();
        let mut tx = store.pool.begin().await.unwrap();
        Store::create_run_in(&mut tx, &rejected, &RunRequest::default(), &test_plan()).await.unwrap();
        assert!(Store::record_source_in(&mut tx, &rejected, b"{}").await.is_err());
        tx.rollback().await.unwrap();
        assert!(peer.get_run(&rejected).await.unwrap().is_none());
        assert!(peer.jobs_of(&rejected).await.unwrap().is_empty());
        assert!(peer.run_events(&rejected, None, 100).await.unwrap().is_empty());

        // Existing admitted history is imported without deleting its files.
        let old = crate::vm::new_id();
        store.create_run(&old, &RunRequest::default(), &test_plan()).await.unwrap();
        let local = tempfile::tempdir().unwrap();
        let file = local.path().join(format!("{old}.source.json"));
        std::fs::write(&file, &source).unwrap();
        assert!(store.import_sources(local.path(), source.len() - 1).await.is_err());
        assert!(peer.source_bytes(&old).await.is_err());
        assert_eq!(store.import_sources(local.path(), source.len()).await.unwrap(), 1);
        assert_eq!(store.import_sources(local.path(), source.len()).await.unwrap(), 1);
        assert_eq!(std::fs::read(&file).unwrap(), source);
        std::fs::write(&file, &changed).unwrap();
        assert!(store.import_sources(local.path(), changed.len()).await.is_err());
        assert_eq!(peer.source_bytes(&old).await.unwrap(), source);
        drop(local);
        assert_eq!(peer.source_bytes(&old).await.unwrap(), source, "removing the old disk cannot remove admitted source");
    }

    #[tokio::test]
    #[ignore = "needs Postgres"]
    async fn outbox_insert_rolls_back_with_its_state_transaction() {
        let store = test_store().await;
        let run_id = crate::vm::new_id();
        store.create_run(&run_id, &RunRequest::default(), &test_plan()).await.unwrap();
        let before = store.run_events(&run_id, None, 100).await.unwrap().len();
        // Force only this run's event insert to fail, through the production
        // status API. An update accidentally outside its transaction would
        // leave the run running even though publication cannot be recorded.
        let constraint = format!("reject_outbox_{run_id}");
        sqlx::query(&format!(
            "ALTER TABLE ci_event_outbox ADD CONSTRAINT \"{constraint}\" CHECK (run_id <> '{run_id}' OR status <> 'running')"
        )).execute(&store.pool).await.unwrap();
        let result = store.set_run_status(&run_id, RunStatus::Running, None).await;
        sqlx::query(&format!("ALTER TABLE ci_event_outbox DROP CONSTRAINT \"{constraint}\""))
            .execute(&store.pool).await.unwrap();
        assert!(result.is_err(), "outbox failure must reject the transition");
        assert_eq!(store.run_events(&run_id, None, 100).await.unwrap().len(), before);
        assert_eq!(store.get_run(&run_id).await.unwrap().unwrap().status, "queued", "the actual transition rolls back too");
    }

    #[tokio::test]
    #[ignore = "needs Postgres"]
    async fn retry_and_restart_keep_event_identity() {
        let store = test_store().await;
        let run_id = crate::vm::new_id();
        let request = RunRequest {
            sha: "aabbcc00112233445566778899aabbcc00112233".into(),
            git_ref: "refs/heads/release".into(),
            ..RunRequest::default()
        };
        store.create_run(&run_id, &request, &test_plan()).await.unwrap();
        let row = sqlx::query("SELECT id, subject, payload FROM ci_event_outbox WHERE run_id=$1 ORDER BY revision DESC LIMIT 1")
            .bind(&run_id)
            .fetch_one(&store.pool).await.unwrap();
        let first = OutboxEvent { id: row.get("id"), subject: row.get("subject"), payload: row.get("payload") };
        assert_eq!(first.payload["sha"], request.sha);
        assert_eq!(first.payload["git_ref"], request.git_ref);
        let page = store.run_events(&run_id, None, 2).await.unwrap();
        assert_eq!(page.len(), 2);
        let older = store.run_events(&run_id, Some(page[1].revision), 2).await.unwrap();
        assert!(!older.is_empty());
        assert!(older.iter().all(|e| e.revision < page[1].revision));
        assert!(store.run_events("not-this-run", None, 2).await.unwrap().is_empty());
        store.mark_outbox_failed(first.id, "nats unavailable").await.unwrap();
        // Drop the original pool and reconnect: this exercises durable state,
        // not merely another handle to the same Store.
        let url = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        drop(store);
        let restarted = Store::connect(&url, std::env::temp_dir().join(crate::vm::new_id()), Duration::from_secs(30)).await.unwrap();
        let row = sqlx::query("SELECT id, subject, payload FROM ci_event_outbox WHERE id=$1 AND published_at IS NULL")
            .bind(first.id).fetch_one(&restarted.pool).await.unwrap();
        let again = OutboxEvent { id: row.get("id"), subject: row.get("subject"), payload: row.get("payload") };
        assert_eq!(again.id, first.id);
        assert_eq!(again.payload, first.payload);
        restarted.mark_outbox_published(again.id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs Postgres"]
    async fn successful_retry_clears_the_previous_attempt_error() {
        let store = test_store().await;
        let run_id = crate::vm::new_id();
        store.create_run(&run_id, &RunRequest::default(), &test_plan()).await.unwrap();
        let job = store.jobs_of(&run_id).await.unwrap().remove(0);

        assert_eq!(store.record_unclaimed_job_error(&job.id, "attempt 1 failed; retrying").await.unwrap(), Some(1));
        assert_eq!(store.get_job(&job.id).await.unwrap().unwrap().error.as_deref(), Some("attempt 1 failed; retrying"));
        store.set_job_status(&job.id, JobStatus::Success, None).await.unwrap();
        let finished = store.get_job(&job.id).await.unwrap().unwrap();
        assert_eq!(finished.status, "success");
        assert_eq!(finished.error, None, "a successful retry must not display an earlier attempt as its final error");
    }

    #[tokio::test]
    #[ignore = "needs Postgres"]
    async fn artifact_publication_is_atomic_scoped_and_retry_safe() {
        let store = test_store().await;
        let run = crate::vm::new_id();
        let request = RunRequest {
            sha: "11223344556677889900aabbccddeeff00112233".into(),
            git_ref: "refs/heads/release".into(),
            ..RunRequest::default()
        };
        store.create_run(&run, &request, &test_plan()).await.unwrap();
        let job = store.jobs_of(&run).await.unwrap().remove(0);
        let sid = step_id(&job.id, 0);
        store.create_step(&sid, &job.id, 0, "Upload", Some("ci/upload-artifact")).await.unwrap();
        let artifact = crate::artifacts::StoredArtifact {
            sink: "artifacts", digest: Some("ab".repeat(32)), size_bytes: 37,
            uri: "ci-release-test".into(), public_url: None,
        };
        // Fail the real outbox write, not a simulated transaction. Neither
        // the artifact nor its event can become visible alone.
        let constraint = format!("reject_artifact_{run}");
        sqlx::query(&format!(
            "ALTER TABLE ci_event_outbox ADD CONSTRAINT \"{constraint}\" CHECK (run_id <> '{run}' OR event_type <> 'ci.artifact.published.v1')"
        )).execute(&store.pool).await.unwrap();
        let failed = store.record_artifact(&run, &job.id, &sid, "binary", &artifact).await;
        sqlx::query(&format!("ALTER TABLE ci_event_outbox DROP CONSTRAINT \"{constraint}\""))
            .execute(&store.pool).await.unwrap();
        assert!(failed.is_err());
        assert!(store.artifacts_of(&run).await.unwrap().is_empty());

        let (a, b) = tokio::join!(
            store.record_artifact(&run, &job.id, &sid, "binary", &artifact),
            store.record_artifact(&run, &job.id, &sid, "binary", &artifact),
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(store.artifacts_of(&run).await.unwrap().len(), 1);
        let events = store.run_events(&run, None, 100).await.unwrap();
        let publications: Vec<_> = events.iter().filter(|e| e.event_type == "ci.artifact.published.v1").collect();
        assert_eq!(publications.len(), 1);
        let event = publications[0];
        assert_eq!(event.payload["sha"], request.sha);
        assert_eq!(event.payload["git_ref"], request.git_ref);
        assert_eq!(event.payload["step_id"], sid);
        assert_eq!(event.payload["artifact"]["digest"], "ab".repeat(32));
        assert_eq!(event.payload["artifact"]["size_bytes"], 37);
        assert_eq!(event.payload["artifact"]["uri"], "ci-release-test");
        assert!(event.published_at.is_none(), "recorded without any NATS connection");
        let artifact_id: String = sqlx::query_scalar("SELECT id FROM ci_artifact WHERE step_id=$1")
            .bind(&sid).fetch_one(&store.pool).await.unwrap();
        assert_eq!(event.payload["artifact"]["id"], artifact_id);

        let changed = crate::artifacts::StoredArtifact { digest: Some("cd".repeat(32)), ..artifact.clone() };
        assert!(store.record_artifact(&run, &job.id, &sid, "binary", &changed).await.is_err());
        let other = crate::vm::new_id();
        store.create_run(&other, &RunRequest::default(), &test_plan()).await.unwrap();
        assert!(store.record_artifact(&other, &job.id, &sid, "binary", &artifact).await.is_err());
        assert!(store.artifacts_of(&other).await.unwrap().is_empty());
        assert_eq!(store.artifacts_of(&run).await.unwrap()[0].digest, artifact.digest);
        let replay = store.run_events(&run, None, 100).await.unwrap();
        let replay: Vec<_> = replay.iter().filter(|e| e.event_type == "ci.artifact.published.v1").collect();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].id, event.id);
        assert_eq!(replay[0].payload, event.payload);
    }

    fn test_plan() -> Plan {
        let wf = crate::workflow::Workflow::parse(
            "wf.yml",
            r#"
name: test
jobs:
  build:
    vm: { driver: firecracker }
    strategy:
      matrix:
        target: [x86_64, aarch64]
    steps:
      - name: Compile
        run: "true"
      - name: Test
        run: "true"
  deploy:
    needs: [build]
    vm: { driver: firecracker }
    steps: [{ name: Ship, run: "true" }]
"#,
        )
        .expect("workflow parses");
        Plan::build(&wf).expect("plan builds")
    }

    /// A failed-only re-run copies the succeeded jobs' results across so
    /// `needs:` reads them, leaves the rest for the scheduler, and the two
    /// runs point at each other.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_rerun_carries_succeeded_jobs_over_and_links_both_ways() {
        let store = test_store().await;
        let plan = test_plan();
        let first = crate::vm::new_id();
        store
            .create_run(&first, &RunRequest::default(), &plan)
            .await
            .expect("run created");
        // Both build cells succeeded with an output; deploy failed.
        for j in store.jobs_of(&first).await.unwrap() {
            if j.base_id == "build" {
                store
                    .set_job_outputs(&j.id, &serde_json::json!({"version": "1.2.3"}))
                    .await
                    .unwrap();
                store
                    .set_job_status(&j.id, JobStatus::Success, None)
                    .await
                    .unwrap();
            } else {
                store
                    .set_job_status(&j.id, JobStatus::Failure, Some("ship broke"))
                    .await
                    .unwrap();
            }
        }

        let again = crate::vm::new_id();
        store
            .create_run(
                &again,
                &RunRequest {
                    rerun_of: Some(first.clone()),
                    source: "rerun".into(),
                    ..Default::default()
                },
                &plan,
            )
            .await
            .expect("re-run created");
        let previous = store.jobs_of(&first).await.unwrap();
        let mut carried = 0;
        for j in previous.iter().filter(|j| j.status == "success") {
            if store
                .carry_over_job(&job_id(&again, &j.job_key), j)
                .await
                .unwrap()
            {
                carried += 1;
            }
        }
        assert_eq!(carried, 2, "both build cells, and not deploy");
        // A second pass finds nothing pending to fill.
        for j in previous.iter().filter(|j| j.status == "success") {
            assert!(
                !store
                    .carry_over_job(&job_id(&again, &j.job_key), j)
                    .await
                    .unwrap()
            );
        }

        for j in store.jobs_of(&again).await.unwrap() {
            if j.base_id == "build" {
                assert_eq!(j.status, "success");
                assert_eq!(j.carried_from.as_deref(), Some(first.as_str()));
                assert_eq!(j.outputs["version"], "1.2.3");
                assert!(j.finished_at.is_some(), "a carried job is terminal");
            } else {
                assert_eq!(j.status, "pending", "the failed job is the scheduler's");
                assert!(j.carried_from.is_none());
                assert!(j.error.is_none(), "the failure stayed with the first run");
            }
        }
        // What the scheduler's `if:` guard and `${{ needs.build.outputs }}` see.
        let needs = store.needs_context(&again).await.unwrap();
        assert_eq!(needs["build"]["result"], "success");
        assert_eq!(needs["build"]["outputs"]["version"], "1.2.3");

        let run = store.get_run(&again).await.unwrap().expect("re-run exists");
        assert_eq!(run.rerun_of.as_deref(), Some(first.as_str()));
        let original = store.get_run(&first).await.unwrap().expect("first exists");
        assert!(original.rerun_of.is_none());
        let reruns = store.reruns_of(&first).await.unwrap();
        assert_eq!(
            reruns.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec![again.as_str()]
        );
        assert!(store.reruns_of(&again).await.unwrap().is_empty());
    }

    /// Re-running every migration on every startup is the whole scheme, so it
    /// has to actually be idempotent rather than merely intended to be.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn migrations_are_idempotent() {
        let store = test_store().await;
        for _ in 0..3 {
            store
                .migrate()
                .await
                .expect("re-applying migrations is a no-op");
        }
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_run_and_its_jobs_are_created_together() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();

        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .expect("run created");

        let run = store.get_run(&run_id).await.unwrap().expect("run exists");
        assert_eq!(run.status, "queued");
        assert_eq!(run.workflow_name.as_deref(), Some("test"));

        let jobs = store.jobs_of(&run_id).await.unwrap();
        assert_eq!(jobs.len(), 3, "two matrix cells plus deploy");
        assert!(jobs.iter().all(|j| j.status == "pending"));
        let keys: Vec<&str> = jobs.iter().map(|j| j.job_key.as_str()).collect();
        assert!(keys.contains(&"build-x86_64"), "{keys:?}");
        assert!(keys.contains(&"deploy"), "{keys:?}");
    }

    /// The guard that makes a JetStream redelivery safe: work that already
    /// finished must not be restarted by a second delivery.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn starting_a_finished_job_is_refused() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();
        let jid = job_id(&run_id, "deploy");

        assert!(
            store
                .start_job(&jid, "hd-1", "sb-1", "fp", 1)
                .await
                .unwrap(),
            "a pending job starts"
        );
        store
            .set_job_status(&jid, JobStatus::Success, None)
            .await
            .unwrap();
        assert!(
            !store
                .start_job(&jid, "hd-1", "sb-2", "fp", 2)
                .await
                .unwrap(),
            "a finished job must not be restarted by a redelivery"
        );

        let job = store.get_job(&jid).await.unwrap().unwrap();
        assert_eq!(job.status, "success");
        assert_eq!(job.sandbox_id.as_deref(), Some("sb-1"), "not overwritten");
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_run_rolls_up_from_its_jobs() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();

        // Nothing finished yet.
        assert_eq!(
            store.roll_up_run(&run_id).await.unwrap(),
            RunStatus::Running
        );

        for key in ["build-x86_64", "build-aarch64", "deploy"] {
            store
                .set_job_status(&job_id(&run_id, key), JobStatus::Success, None)
                .await
                .unwrap();
        }
        assert_eq!(
            store.roll_up_run(&run_id).await.unwrap(),
            RunStatus::Success
        );
        let run = store.get_run(&run_id).await.unwrap().unwrap();
        assert!(
            run.finished_at.is_some(),
            "a terminal run gets a finish time"
        );

        // One failure poisons the run even though the rest passed.
        store
            .set_job_status(&job_id(&run_id, "deploy"), JobStatus::Failure, Some("boom"))
            .await
            .unwrap();
        assert_eq!(
            store.roll_up_run(&run_id).await.unwrap(),
            RunStatus::Failure
        );
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL; no VM execution"]
    async fn managed_update_completion_controls_run_result_and_preserves_cancellation() {
        let store = test_store().await;
        for outcome in ["passed", "failed", "cancelled"] {
            let run = crate::vm::new_id();
            store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
            for key in ["build-x86_64", "build-aarch64", "deploy"] {
                store.set_job_status(&job_id(&run,key), JobStatus::Success, None).await.unwrap();
            }
            let job = job_id(&run,"deploy");
            let step = format!("{job}:managed-update");
            sqlx::query("INSERT INTO ci_step(id,job_id,idx,name,status) VALUES($1,$2,99,'managed-update','success')")
                .bind(&step).bind(&job).execute(store.pool()).await.unwrap();
            sqlx::query("INSERT INTO ci_managed_update(operation_id,step_id,run_id,job_id,service_id,request) VALUES($1,$2,$1,$3,$1,'{}')")
                .bind(&run).bind(&step).bind(&job).execute(store.pool()).await.unwrap();
            assert_eq!(store.roll_up_run(&run).await.unwrap(),RunStatus::Running);
            assert!(store.get_run(&run).await.unwrap().unwrap().finished_at.is_none());
            if outcome=="cancelled" {store.cancel_run(&run).await.unwrap();}
            sqlx::query("UPDATE ci_managed_update SET result=$2 WHERE operation_id=$1")
                .bind(&run).bind(if outcome=="failed" {"failed"} else {"passed"}).execute(store.pool()).await.unwrap();
            assert_eq!(store.roll_up_run(&run).await.unwrap(),match outcome {
                "passed"=>RunStatus::Success,"failed"=>RunStatus::Failure,_=>RunStatus::Cancelled});
        }
    }

    /// A skipped job must not make the run fail — that is how a conditional
    /// deploy job behaves on a branch that does not deploy.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_skipped_job_still_lets_a_run_succeed() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();
        for key in ["build-x86_64", "build-aarch64"] {
            store
                .set_job_status(&job_id(&run_id, key), JobStatus::Success, None)
                .await
                .unwrap();
        }
        store
            .set_job_status(&job_id(&run_id, "deploy"), JobStatus::Skipped, None)
            .await
            .unwrap();
        assert_eq!(
            store.roll_up_run(&run_id).await.unwrap(),
            RunStatus::Success
        );
    }

    /// `needs.build.result` means "did build pass". One failed cell has to make
    /// it `failure`, or a deploy job runs off a broken build.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn needs_context_collapses_matrix_cells_to_the_worst_result() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();

        store
            .set_job_status(&job_id(&run_id, "build-x86_64"), JobStatus::Success, None)
            .await
            .unwrap();
        store
            .set_job_outputs(
                &job_id(&run_id, "build-x86_64"),
                &serde_json::json!({"sha": "abc123"}),
            )
            .await
            .unwrap();
        store
            .set_job_status(&job_id(&run_id, "build-aarch64"), JobStatus::Failure, None)
            .await
            .unwrap();

        let needs = store.needs_context(&run_id).await.unwrap();
        assert_eq!(needs["build"]["result"], "failure", "{needs}");
        assert_eq!(needs["build"]["outputs"]["sha"], "abc123");

        // And that context makes the guard on a dependent job evaluate false.
        let mut ctx = crate::expr::Context::new();
        ctx.set("needs", needs);
        assert!(
            !ctx.eval_condition("needs.build.result == 'success'")
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn steps_record_their_outcome_and_share_logs_without_local_files() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();

        let jid = job_id(&run_id, "build-x86_64");
        let cell = plan.jobs.iter().find(|j| j.key == "build-x86_64").unwrap();
        for (sid, idx, name, uses) in step_rows_for(cell, &jid) {
            store
                .create_step(&sid, &jid, idx, &name, uses.as_deref())
                .await
                .unwrap();
        }

        let steps = store.steps_of(&jid).await.unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].name, "Compile");
        assert_eq!(steps[1].name, "Test");

        let sid = &steps[0].id;
        store.start_step(sid, sid).await.unwrap();
        let path = store.log_path(&run_id, "build-x86_64", 0, sid);
        store.append_log(sid, &path, "compiling\n").await.unwrap();
        store.append_log(sid, &path, "done\n").await.unwrap();
        store
            .finish_step(sid, StepStatus::Success, Some(0), None)
            .await
            .unwrap();

        let steps = store.steps_of(&jid).await.unwrap();
        assert_eq!(steps[0].status, "success");
        assert_eq!(steps[0].exit_code, Some(0));
        assert_eq!(steps[0].log_bytes, 15, "both appends counted");
        assert_eq!(
            store.read_log(&steps[0]).await.unwrap().as_deref(),
            Some("compiling\ndone\n")
        );
        assert!(!path.exists());
        let other = test_store().await;
        let (a, b) = tokio::join!(
            store.append_log(sid, &path, "α\0\n"),
            other.append_log(sid, &path, "second\n"),
        );
        a.unwrap();
        b.unwrap();
        let text = other.read_log(&steps[0]).await.unwrap().unwrap();
        assert!(text == "compiling\ndone\nα\0\nsecond\n" || text == "compiling\ndone\nsecond\nα\0\n");
        assert_eq!(other.steps_of(&jid).await.unwrap()[0].log_bytes, 26);
        let mut tx = store.pool.begin().await.unwrap();
        Store::append_log_in(&mut tx, sid, "must roll back").await.unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(other.read_log(&steps[0]).await.unwrap().unwrap(), text);
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn command_completion_retries_do_not_duplicate_logs_or_change_outcome() {
        let store = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let jid = job_id(&run, "deploy");
        let sid = step_id(&jid, 0);
        let boot = uuid::Uuid::new_v4();
        sqlx::query("UPDATE ci_job SET status='running',attempt=3,executor_boot=$2 WHERE id=$1")
            .bind(&jid).bind(boot).execute(store.pool()).await.unwrap();
        store.create_step(&sid, &jid, 0, "deploy", None).await.unwrap();
        store.start_step(&sid, &sid).await.unwrap();
        assert!(store.finish_command(&sid, StepStatus::Failure, 7, "failed once\n", 2, boot).await.is_err());
        assert!(store.finish_command(&sid, StepStatus::Failure, 7, "failed once\n", 3, uuid::Uuid::new_v4()).await.is_err());
        assert_eq!(store.steps_of(&jid).await.unwrap()[0].log_bytes, 0);
        store.finish_command(&sid, StepStatus::Failure, 7, "failed once\n", 3, boot).await.unwrap();
        // Models replay after the server committed but its reply was lost.
        store.finish_command(&sid, StepStatus::Failure, 7, "failed once\n", 3, boot).await.unwrap();
        assert!(store.finish_command(&sid, StepStatus::Success, 0, "wrong\n", 3, boot).await.is_err());
        let steps = store.steps_of(&jid).await.unwrap();
        assert_eq!(steps[0].status, "failure");
        assert_eq!(steps[0].exit_code, Some(7));
        assert_eq!(steps[0].log_bytes, 12);
        assert_eq!(store.read_log(&steps[0]).await.unwrap().as_deref(), Some("failed once\n"));
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn retained_logs_import_once_preserve_files_and_fail_on_missing_history() {
        let store = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let jid = job_id(&run, "deploy");
        let sid = step_id(&jid, 0);
        store.create_step(&sid, &jid, 0, "old log", None).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retained.log");
        sqlx::query("UPDATE ci_step SET log_path=$2,log_bytes=8 WHERE id=$1")
            .bind(&sid).bind(path.to_str().unwrap()).execute(&store.pool).await.unwrap();
        assert!(store.import_logs().await.is_err());
        let steps = store.steps_of(&jid).await.unwrap();
        assert_eq!(steps[0].log_bytes, 8);
        assert!(store.read_log(&steps[0]).await.is_err());
        assert!(store.append_log(&sid, &path, "do not overwrite").await.is_err());
        tokio::fs::write(&path, "short").await.unwrap();
        assert!(store.import_logs().await.is_err());
        tokio::fs::write(&path, "old\0雪\n").await.unwrap();
        assert!(store.import_logs().await.unwrap() >= 1);
        assert_eq!(store.import_logs().await.unwrap(), 0);
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), "old\0雪\n");
        drop(dir);
        let other = test_store().await;
        assert_eq!(other.read_log(&steps[0]).await.unwrap().as_deref(), Some("old\0雪\n"));
    }

    /// Creating steps must be safe to repeat — a redelivered job re-creates its
    /// step rows before running anything.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn creating_the_same_step_twice_is_a_no_op() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();
        let jid = job_id(&run_id, "deploy");
        for _ in 0..3 {
            store
                .create_step(&step_id(&jid, 0), &jid, 0, "Ship", None)
                .await
                .expect("repeatable");
        }
        assert_eq!(store.steps_of(&jid).await.unwrap().len(), 1);
    }

    // ---- registered repositories ----------------------------------------

    /// A URL unique to this test run, so the tests are safe to run against a
    /// database that already has registrations and safe to run concurrently.
    fn test_repo_url() -> String {
        format!("git@github.com:test/{}.git", crate::vm::new_id())
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_token_authenticates_for_its_own_repository_and_nothing_else() {
        let store = test_store().await;
        let a = store
            .register_repo(&test_repo_url(), "a", None, None, None)
            .await
            .expect("registers");
        let b = store
            .register_repo(&test_repo_url(), "b", None, None, None)
            .await
            .expect("registers");

        let (token_row, plaintext) = store
            .create_repo_token(&a.id, "laptop", Some(("sub-1", "sam@sarocu.com")))
            .await
            .expect("mints");

        let resolved = store
            .authenticate_repo_token(&plaintext)
            .await
            .unwrap()
            .expect("the token resolves");
        assert_eq!(resolved.id, a.id);
        assert_ne!(resolved.id, b.id);

        // The plaintext is not recoverable from anything that is stored.
        let listed = store.repo_tokens(&a.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, token_row.id);
        assert!(listed[0].last_used_at.is_some(), "use is recorded");
        assert!(!format!("{listed:?}").contains(&plaintext));

        store.delete_repo(&a.id).await.unwrap();
        store.delete_repo(&b.id).await.unwrap();
    }

    /// The one thing revocation has to actually do.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_revoked_token_stops_authenticating_but_stays_listed() {
        let store = test_store().await;
        let repo = store
            .register_repo(&test_repo_url(), "app", None, None, None)
            .await
            .unwrap();
        let (token, plaintext) = store.create_repo_token(&repo.id, "ci", None).await.unwrap();

        assert!(
            store
                .authenticate_repo_token(&plaintext)
                .await
                .unwrap()
                .is_some()
        );
        assert!(store.revoke_repo_token(&token.id).await.unwrap());
        assert!(
            store
                .authenticate_repo_token(&plaintext)
                .await
                .unwrap()
                .is_none(),
            "a revoked token must not submit"
        );
        assert!(
            !store.revoke_repo_token(&token.id).await.unwrap(),
            "revoking twice must not rewrite when access ended"
        );

        let listed = store.repo_tokens(&repo.id).await.unwrap();
        assert_eq!(listed.len(), 1, "still nameable after it stopped working");
        assert!(!listed[0].is_active());

        store.delete_repo(&repo.id).await.unwrap();
    }

    /// Pausing a repository has to stop its existing tokens, or it is not a
    /// pause — it is a label.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_paused_repository_refuses_a_valid_token() {
        let store = test_store().await;
        let repo = store
            .register_repo(&test_repo_url(), "app", None, None, None)
            .await
            .unwrap();
        let (_, plaintext) = store.create_repo_token(&repo.id, "ci", None).await.unwrap();

        assert!(store.set_repo_enabled(&repo.id, false).await.unwrap());
        assert!(
            store
                .authenticate_repo_token(&plaintext)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.set_repo_enabled(&repo.id, true).await.unwrap());
        assert!(
            store
                .authenticate_repo_token(&plaintext)
                .await
                .unwrap()
                .is_some()
        );

        store.delete_repo(&repo.id).await.unwrap();
    }

    /// A wrong or forged token must be refused, and a malformed one must not
    /// even reach a query — this is checked on a public route.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_forged_or_malformed_token_resolves_to_nothing() {
        let store = test_store().await;
        let repo = store
            .register_repo(&test_repo_url(), "app", None, None, None)
            .await
            .unwrap();
        let (token, plaintext) = store.create_repo_token(&repo.id, "ci", None).await.unwrap();

        // The right key id with the wrong secret is the interesting forgery:
        // the lookup succeeds and only the digest comparison stops it.
        let forged = format!("{}{}.{}", crate::repos::TOKEN_PREFIX, token.id, "not-it");
        assert!(
            store
                .authenticate_repo_token(&forged)
                .await
                .unwrap()
                .is_none()
        );

        for bad in ["", "garbage", "cis_nosuchkey.secret", &plaintext[..20]] {
            assert!(
                store.authenticate_repo_token(bad).await.unwrap().is_none(),
                "{bad:?} must not authenticate"
            );
        }

        store.delete_repo(&repo.id).await.unwrap();
    }

    /// Registering a URL that is already registered in another spelling must
    /// edit that registration rather than making a second one — and must not
    /// invalidate the tokens already issued for it.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn re_registering_the_other_spelling_updates_and_keeps_tokens() {
        let store = test_store().await;
        let name = crate::vm::new_id();
        let ssh = format!("git@github.com:test/{name}.git");
        let https = format!("https://github.com/test/{name}");

        let first = store
            .register_repo(&ssh, "app", None, None, None)
            .await
            .unwrap();
        let (_, plaintext) = store
            .create_repo_token(&first.id, "ci", None)
            .await
            .unwrap();

        let second = store
            .register_repo(&https, "app (renamed)", Some("ci/*.yml"), None, None)
            .await
            .unwrap();
        assert_eq!(second.id, first.id, "one repository, not two");
        assert_eq!(second.name, "app (renamed)");
        assert_eq!(second.workflow_path.as_deref(), Some("ci/*.yml"));
        assert_eq!(second.url, https, "the newer spelling is what is shown");

        assert!(
            store
                .authenticate_repo_token(&plaintext)
                .await
                .unwrap()
                .is_some(),
            "fixing a name must not invalidate everyone's credential"
        );

        // And either spelling finds it.
        assert_eq!(
            store.repo_by_url(&ssh).await.unwrap().map(|r| r.id),
            Some(first.id.clone())
        );

        store.delete_repo(&first.id).await.unwrap();
    }

    /// The assignment this whole column exists for: a repository points at a
    /// network, and reassigning it is one write rather than a re-registration
    /// that also rewrites the name and the workflow path.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_repository_can_be_pointed_at_a_network_and_back_at_the_default() {
        let store = test_store().await;
        let repo = store
            .register_repo(&test_repo_url(), "app", None, Some("prod-runners"), None)
            .await
            .unwrap();
        assert_eq!(repo.network.as_deref(), Some("prod-runners"));

        assert!(store.set_repo_network(&repo.id, Some("lab")).await.unwrap());
        assert_eq!(
            store.get_repo(&repo.id).await.unwrap().unwrap().network,
            Some("lab".to_string())
        );

        // Back to the installation default, and a blank is that rather than a
        // network named "  ".
        assert!(store.set_repo_network(&repo.id, Some("  ")).await.unwrap());
        assert_eq!(
            store.get_repo(&repo.id).await.unwrap().unwrap().network,
            None
        );

        assert!(
            !store
                .set_repo_network("no-such-repo", Some("lab"))
                .await
                .unwrap(),
            "assigning a network to nothing must report that it did nothing"
        );

        store.delete_repo(&repo.id).await.unwrap();
    }

    /// Removing a registration must not delete the history of what it built.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn deleting_a_repository_keeps_its_runs() {
        let store = test_store().await;
        let repo = store
            .register_repo(&test_repo_url(), "app", None, None, None)
            .await
            .unwrap();
        let run_id = crate::vm::new_id();
        store
            .create_run(
                &run_id,
                &RunRequest {
                    repo_id: Some(repo.id.clone()),
                    repo_url: repo.url.clone(),
                    ..RunRequest::default()
                },
                &test_plan(),
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .last_run_of_repo(&repo.id)
                .await
                .unwrap()
                .map(|r| r.id),
            Some(run_id.clone())
        );

        assert!(store.delete_repo(&repo.id).await.unwrap());
        assert!(
            store.get_run(&run_id).await.unwrap().is_some(),
            "the run survives its registration"
        );
    }

    /// The repair for a publish that failed after the status was committed:
    /// the job goes back on the runway, and the scheduler finds the run again.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_failed_publish_returns_the_job_to_pending_and_the_run_is_found() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();
        let job = job_id(&run_id, "build-x86_64");

        assert!(store.queue_job(&job).await.unwrap());
        assert!(store.unqueue_job(&job).await.unwrap(), "rolled back");

        // Back to pending, with the queue clock cleared — otherwise the
        // runner-wait watchdog would count time it never spent queued.
        let row = store.get_job(&job).await.unwrap().unwrap();
        assert_eq!(row.status, "pending");
        assert!(
            store
                .jobs_waiting_longer_than(Duration::from_secs(0), 50)
                .await
                .unwrap()
                .iter()
                .all(|j| j.id != job),
            "a rolled-back job is not waiting on a runner"
        );

        // And the run is offered to the scheduler again, which is what stops it
        // sitting pending for ever.
        assert!(
            store
                .runs_with_pending_jobs(500)
                .await
                .unwrap()
                .contains(&run_id)
        );

        // Re-queueing works, and rolling back a job that has since started does
        // not: it would take a running job off a runner.
        assert!(store.queue_job(&job).await.unwrap());
        store
            .start_job(&job, "hd-1", "sb-1", "fp", 1)
            .await
            .unwrap();
        assert!(
            !store.unqueue_job(&job).await.unwrap(),
            "a started job must never be rolled back"
        );
        assert_eq!(
            store.get_job(&job).await.unwrap().unwrap().status,
            "running"
        );
    }

    /// A job pinned to a host that never comes online must become findable, or
    /// it waits for ever with no steps and no error — which is what
    /// `CI_RUNNER_WAIT_SECS` was always documented to prevent and never did.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_job_waiting_on_a_runner_becomes_visible_after_the_wait() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();
        let job = job_id(&run_id, "build-x86_64");

        // Pending, not queued: a job waiting on `needs:` is not waiting on a
        // runner, and failing it would kill work that has not been offered yet.
        assert!(
            store
                .jobs_waiting_longer_than(Duration::from_secs(0), 50)
                .await
                .unwrap()
                .iter()
                .all(|j| j.id != job),
            "a pending job is not waiting on a runner"
        );

        assert!(store.queue_job(&job).await.unwrap());
        // Long enough that nothing legitimately queued qualifies.
        assert!(
            store
                .jobs_waiting_longer_than(Duration::from_secs(3600), 50)
                .await
                .unwrap()
                .iter()
                .all(|j| j.id != job),
            "a job queued a moment ago is not stuck"
        );

        let stuck = store
            .jobs_waiting_longer_than(Duration::from_secs(0), 50)
            .await
            .unwrap();
        assert!(stuck.iter().any(|j| j.id == job), "queued past the wait");

        // Once it starts, or the run ends, it stops being offered.
        store
            .start_job(&job, "hd-1", "sb-1", "fp", 1)
            .await
            .unwrap();
        assert!(
            store
                .jobs_waiting_longer_than(Duration::from_secs(0), 50)
                .await
                .unwrap()
                .iter()
                .all(|j| j.id != job),
            "a running job is not waiting"
        );
    }

    /// Cancelling has to stop work in all three states a job might be in, and
    /// leave finished work alone.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn cancelling_stops_unfinished_jobs_and_keeps_the_rest() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();

        // One already finished, one running, one still pending.
        let done = job_id(&run_id, "build-x86_64");
        let running = job_id(&run_id, "build-aarch64");
        store
            .set_job_status(&done, JobStatus::Success, None)
            .await
            .unwrap();
        store
            .start_job(&running, "hd-1", "sb-1", "fp", 1)
            .await
            .unwrap();

        let cancelled = store.cancel_run(&run_id).await.unwrap();
        assert_eq!(cancelled, Some(2), "the running and the pending one");

        let by_key: std::collections::HashMap<_, _> = store
            .jobs_of(&run_id)
            .await
            .unwrap()
            .into_iter()
            .map(|j| (j.job_key.clone(), j))
            .collect();
        assert_eq!(
            by_key["build-x86_64"].status, "success",
            "work that finished is not rewritten"
        );
        assert_eq!(by_key["build-aarch64"].status, "cancelled");
        assert_eq!(by_key["deploy"].status, "cancelled");
        assert_eq!(
            store.get_run(&run_id).await.unwrap().unwrap().status,
            "cancelled"
        );

        // What the executor polls between steps.
        assert!(store.is_job_cancelled(&running).await.unwrap());
        assert!(!store.is_job_cancelled(&done).await.unwrap());

        // A redelivery of a cancelled job must not restart it.
        assert!(
            !store
                .start_job(&running, "hd-1", "sb-2", "fp", 2)
                .await
                .unwrap(),
            "a cancelled job must refuse to start"
        );

        // And cancelling twice reports that there was nothing left to stop.
        let before: i64 = sqlx::query("SELECT count(*) n FROM ci_event_outbox WHERE run_id=$1")
            .bind(&run_id).fetch_one(&store.pool).await.unwrap().get("n");
        assert_eq!(store.cancel_run(&run_id).await.unwrap(), None);
        assert!(!store.claim_job(&running, "hd-2", 3).await.unwrap());
        let after: i64 = sqlx::query("SELECT count(*) n FROM ci_event_outbox WHERE run_id=$1")
            .bind(&run_id).fetch_one(&store.pool).await.unwrap().get("n");
        assert_eq!(after, before, "terminal cancel and claim no-ops emit no false transition");
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn regional_claims_and_expiry_cannot_reassign_unresolved_execution() {
        let store = test_store().await;
        let other = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let job = job_id(&run, "build-x86_64");
        let us = format!("hd-us-{run}");
        let eu = format!("hd-eu-{run}");
        // Different runner locks must still serialize on the one job row.
        let (a, b) = tokio::join!(store.claim_job(&job, &us, 1), other.claim_job(&job, &eu, 2));
        assert_ne!(a.as_ref().unwrap(), b.as_ref().unwrap(), "exactly one regional claim wins");
        let (runner, attempt) = if a.unwrap() { (&us, 1) } else { (&eu, 2) };
        let first = store.get_job(&job).await.unwrap().unwrap();
        assert_eq!(first.runner_hd_id.as_deref(), Some(runner.as_str()));
        assert_eq!(first.attempt, attempt);
        assert!(!other.claim_job(&job, &eu, 9).await.unwrap(), "redelivery cannot steal running work");
        assert_eq!(other.get_job(&job).await.unwrap().unwrap().attempt, attempt);

        let pool = crate::pool::Pool::new(store.pool().clone());
        let sandbox = format!("sb-{run}");
        let expired = crate::pool::Lease { instance: "partitioned-controller", ttl: Duration::ZERO };
        pool.register(&sandbox, runner, "fp", "wf", None, &job, expired).await.unwrap();
        let building = pool.begin_build(&job, runner, "fp-build", "wf", None,
            crate::pool::Lease { instance: "partitioned-controller", ttl: Duration::ZERO }).await.unwrap();
        let runners = vec![runner.clone()];
        assert_eq!(pool.release_orphans(&runners, "new-controller").await.unwrap(), 0);
        assert_eq!(pool.sweep_stale_builds(&runners, "new-controller").await.unwrap(), 0);
        assert_eq!(pool.get(&sandbox).await.unwrap().unwrap().status, "claimed");
        assert!(pool.get(&building).await.unwrap().is_some(), "lost create response retains its evidence");

        store.cancel_run(&run).await.unwrap();
        assert!(other.has_host_work(&job).await.unwrap(), "cancellation is not executor quiescence");
        assert_eq!(pool.release_orphans(&runners, "new-controller").await.unwrap(), 0);
        assert_eq!(pool.sweep_stale_builds(&runners, "new-controller").await.unwrap(), 0);
        assert!(!other.claim_job(&job, &us, 10).await.unwrap());
        // A verified release is an explicit action, not an expired timer.
        store.end_host_work(&job, runner, attempt).await.unwrap();
        assert!(!other.has_host_work(&job).await.unwrap());
        assert_eq!(pool.release_orphans(&runners, "new-controller").await.unwrap(), 1);
        assert_eq!(pool.sweep_stale_builds(&runners, "new-controller").await.unwrap(), 1);
        assert_eq!(pool.get(&sandbox).await.unwrap().unwrap().status, "idle");
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn boot_claim_is_atomic_with_drain_and_cannot_be_completed_by_another_boot() {
        let store = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let job = job_id(&run, "build-x86_64");
        let admitted = Uuid::new_v4();
        let other = Uuid::new_v4();
        for boot in [admitted, other] {
            sqlx::query("INSERT INTO ci_executor_boot(boot_id,deployment_id,draining) VALUES($1,$2,FALSE)")
                .bind(boot).bind(format!("test-{boot}")).execute(store.pool()).await.unwrap();
        }

        assert_eq!(store.claim_job_for_boot(&job, "hd-1", 1, admitted).await.unwrap(), JobClaim::Claimed);
        assert_eq!(store.claim_job_for_boot(&job, "hd-2", 2, other).await.unwrap(), JobClaim::Unavailable,
            "a regional redelivery cannot steal a running attempt");
        assert!(!store.set_job_status_for_boot(&job, JobStatus::Success, None, 1, other).await.unwrap(),
            "another boot cannot complete the winner's attempt");

        let waiting = job_id(&run, "build-aarch64");
        let mut draining = store.pool().begin().await.unwrap();
        sqlx::query("UPDATE ci_executor_boot SET draining=TRUE WHERE boot_id=$1")
            .bind(admitted).execute(&mut *draining).await.unwrap();
        let late_claim = store.claim_job_for_boot(&waiting, "hd-1", 1, admitted);
        tokio::pin!(late_claim);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut late_claim).await.is_err(),
            "claim must serialize with the in-flight drain transaction");
        draining.commit().await.unwrap();
        let rejected = late_claim.await.unwrap();
        // Resuming after the rejected transaction cannot turn its result into
        // a terminal/duplicate verdict and authorize an ACK of queued work.
        sqlx::query("UPDATE ci_executor_boot SET draining=FALSE WHERE boot_id=$1")
            .bind(admitted).execute(store.pool()).await.unwrap();
        assert_eq!(rejected, JobClaim::InstanceDraining,
            "a draining boot cannot turn an outstanding delivery into new work");
        assert_eq!(store.claim_job_for_boot(&waiting, "hd-2", 1, other).await.unwrap(), JobClaim::Claimed,
            "the peer remains able to claim the exact rejected job");
        assert!(store.set_job_status_for_boot(&job, JobStatus::Success, None, 1, admitted).await.unwrap(),
            "drain does not prevent already-owned work from finishing");
        assert_eq!(store.get_job(&job).await.unwrap().unwrap().status, "success");
        assert_eq!(store.get_job(&waiting).await.unwrap().unwrap().executor_boot, Some(other));
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn preparation_failure_releases_instance_without_erasing_runner_work() {
        use crate::executor::ExecutorInstance;
        let store = test_store().await;
        for (quiescent, cancelled) in [(true, false), (false, false), (false, true)] {
            let run = crate::vm::new_id();
            store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
            let job = job_id(&run, "build-x86_64");
            let runner = format!("runner-{run}");
            let owner = ExecutorInstance::register(store.pool().clone(), &run).await.unwrap();
            let boot = owner.boot_id();
            assert_eq!(store.claim_job_for_boot(&job, &runner, 1, boot).await.unwrap(), JobClaim::Claimed);
            assert!(owner.has_work().await.unwrap());
            assert!(store.finish_job_preparation(&job, 2, boot, "stale attempt", true).await.unwrap().is_none());
            assert!(store.finish_job_preparation(&job, 1, Uuid::new_v4(), "wrong boot", true).await.unwrap().is_none());
            if cancelled { store.cancel_run(&run).await.unwrap(); }
            let expected = if cancelled { JobStatus::Cancelled } else { JobStatus::Failure };
            assert_eq!(store.finish_job_preparation(&job, 1, boot, "preparation failed", quiescent).await.unwrap(), Some(expected));
            let result = store.get_job(&job).await.unwrap().unwrap();
            assert_eq!(result.status, expected.as_str());
            assert_eq!(result.executor_boot, None);
            assert!(!owner.has_work().await.unwrap(), "terminal preparation must release CI-app drain");
            assert_eq!(store.has_host_work(&job).await.unwrap(), !quiescent,
                "uncertain daemon work must still block runner maintenance");
            if !quiescent {
                let evidence: (String, Option<Uuid>) = sqlx::query_as("SELECT phase,executor_boot FROM ci_host_work WHERE job_id=$1")
                    .bind(&job).fetch_one(store.pool()).await.unwrap();
                assert_eq!(evidence, ("detached_preparation".into(), Some(boot)));
            }
            assert!(!store.begin_job_execution(&job, 1, boot).await.unwrap());
            assert!(!store.claim_job(&job, "another-region", 2).await.unwrap());
            let operation = Uuid::new_v4();
            owner.pause(operation).await.unwrap();
            owner.quiesce(operation).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn preparation_boundary_cannot_release_execution_or_legacy_claims() {
        let store = test_store().await;
        for legacy in [false, true] {
            let run = crate::vm::new_id();
            store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
            let job = job_id(&run, "build-x86_64");
            let owner = crate::executor::ExecutorInstance::register(store.pool().clone(), &run).await.unwrap();
            let boot = owner.boot_id();
            assert_eq!(store.claim_job_for_boot(&job, "runner", 1, boot).await.unwrap(), JobClaim::Claimed);
            if legacy {
                // Old writer omits the new columns; absence of a VM is not proof.
                sqlx::query("DELETE FROM ci_host_work WHERE job_id=$1").bind(&job).execute(store.pool()).await.unwrap();
                sqlx::query("INSERT INTO ci_host_work(job_id,runner_hd_id,attempt) VALUES($1,'runner',1)")
                    .bind(&job).execute(store.pool()).await.unwrap();
            } else {
                let operation = Uuid::new_v4();
                owner.pause(operation).await.unwrap();
                assert!(store.begin_job_execution(&job, 1, boot).await.unwrap(), "already-owned jobs finish during drain");
            }
            assert!(store.get_job(&job).await.unwrap().unwrap().sandbox_id.is_none());
            assert!(store.finish_job_preparation(&job, 1, boot, "timeout", true).await.unwrap().is_none());
            assert!(owner.has_work().await.unwrap());
        }
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let job = job_id(&run, "build-x86_64");
        let owner = crate::executor::ExecutorInstance::register(store.pool().clone(), &run).await.unwrap();
        let boot = owner.boot_id();
        assert_eq!(store.claim_job_for_boot(&job, "runner", 1, boot).await.unwrap(), JobClaim::Claimed);
        let (began, finished) = tokio::join!(store.begin_job_execution(&job, 1, boot),
            store.finish_job_preparation(&job, 1, boot, "preparation ended", false));
        assert_ne!(began.unwrap(), finished.unwrap().is_some(), "only one side of the VM boundary may win");
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn runner_drain_moves_waiting_work_without_interrupting_running_jobs() {
        use crate::host_maintenance::{runner_drain, runner_drain_status};
        let store = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let us = format!("us-{run}");
        let eu = format!("eu-{run}");
        let first = job_id(&run, "build-x86_64");
        let waiting = job_id(&run, "build-aarch64");
        assert!(store.claim_job(&first, &us, 1).await.unwrap());
        let operation = Uuid::new_v4();
        // Force a late claim to wait for the same lock as drain admission.
        let mut drain = store.pool().begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,222))")
            .bind(&us).execute(&mut *drain).await.unwrap();
        sqlx::query("INSERT INTO ci_runner_drain(runner_hd_id,operation_id) VALUES($1,$2)")
            .bind(&us).bind(operation).execute(&mut *drain).await.unwrap();
        let late = store.claim_job(&waiting, &us, 1);
        tokio::pin!(late);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut late).await.is_err());
        drain.commit().await.unwrap();
        assert!(!late.await.unwrap(), "drain must exclude a racing claim");
        runner_drain(&store, &us, operation, true).await.unwrap();
        assert!(runner_drain(&store, &us, Uuid::new_v4(), false).await.is_err());
        assert_eq!(runner_drain_status(&store, &us).await.unwrap()["drained"], false);
        assert!(store.claim_job(&waiting, &eu, 1).await.unwrap(), "same run continues on EU");
        store.set_job_status(&first, JobStatus::Success, None).await.unwrap();
        assert_eq!(runner_drain_status(&store, &us).await.unwrap()["drained"], false,
            "terminal status alone must not erase cleanup obligations");
        store.end_host_work(&first, &us, 1).await.unwrap();
        assert_eq!(runner_drain_status(&store, &us).await.unwrap()["drained"], true);
        assert_eq!(store.get_job(&waiting).await.unwrap().unwrap().runner_hd_id.as_deref(), Some(eu.as_str()));
        let next_run = crate::vm::new_id();
        store.create_run(&next_run, &RunRequest::default(), &test_plan()).await.unwrap();
        let next_job = job_id(&next_run, "build-x86_64");
        assert!(!store.claim_job(&next_job, &us, 1).await.unwrap(), "new runs also avoid US");
        runner_drain(&store, &us, operation, false).await.unwrap();
        assert!(store.claim_job(&next_job, &us, 1).await.unwrap(), "recovered US accepts new jobs");
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn delivery_failure_cannot_overwrite_a_regional_claim() {
        let store = test_store().await;
        let run = crate::vm::new_id();
        store.create_run(&run, &RunRequest::default(), &test_plan()).await.unwrap();
        let job = job_id(&run, "build-x86_64");
        let boot = Uuid::new_v4();
        // Hold a winning claim uncommitted so the losing delivery's UPDATE
        // takes its snapshot before the winner commits and must recheck it.
        let mut winner = store.pool().begin().await.unwrap();
        sqlx::query("UPDATE ci_job SET status='running',executor_boot=$2,attempt=7,error='winner diagnostic' WHERE id=$1")
            .bind(&job).bind(boot).execute(&mut *winner).await.unwrap();
        let losing_error = store.record_unclaimed_job_error(&job, "loser exhausted retries");
        tokio::pin!(losing_error);
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut losing_error).await.is_err());
        winner.commit().await.unwrap();
        assert_eq!(losing_error.await.unwrap(), None);
        assert_eq!(store.record_unclaimed_job_error(&job, "loser retry diagnostic").await.unwrap(), None);
        assert!(!store.set_job_status_for_boot(&job, JobStatus::Running, Some("loser owned error"), 7, Uuid::new_v4()).await.unwrap());
        let claimed = store.get_job(&job).await.unwrap().unwrap();
        assert_eq!(claimed.status, "running");
        assert_eq!(claimed.attempt, 7);
        assert_eq!(claimed.executor_boot, Some(boot));
        assert_eq!(claimed.error.as_deref(), Some("winner diagnostic"));

        // Genuine pre-claim failures still record retry diagnostics and reach
        // a terminal failure, rather than silently leaving pending jobs behind.
        let unclaimed = job_id(&run, "build-aarch64");
        assert_eq!(store.record_unclaimed_job_error(&unclaimed, "retry").await.unwrap(), Some(1));
        let pending = store.get_job(&unclaimed).await.unwrap().unwrap();
        assert_eq!(pending.status, "pending");
        assert_eq!(pending.error.as_deref(), Some("retry"));
        // Independent dispatchers share one persisted failure budget. Neither
        // can lose the other's increment, and three failures remain retryable.
        let (a, b) = tokio::join!(
            store.record_unclaimed_job_error(&unclaimed, "retry a"),
            store.record_unclaimed_job_error(&unclaimed, "retry b"),
        );
        let mut counts = [a.unwrap().unwrap(), b.unwrap().unwrap()];
        counts.sort();
        assert_eq!(counts, [2, 3]);
        assert_eq!(store.get_job(&unclaimed).await.unwrap().unwrap().status, "pending");
        assert_eq!(store.record_unclaimed_job_error(&unclaimed, "exhausted").await.unwrap(), Some(4));
        let failed = store.get_job(&unclaimed).await.unwrap().unwrap();
        assert_eq!(failed.status, "failure");
        assert_eq!(failed.error.as_deref(), Some("exhausted"));
        assert_eq!(store.record_unclaimed_job_error(&unclaimed, "late retry").await.unwrap(), None);
        assert_eq!(store.get_job(&unclaimed).await.unwrap().unwrap().error.as_deref(), Some("exhausted"));
    }

    // ---- log retention ---------------------------------------------------

    /// The sweep has to be driven by rows, converge, and leave the run's
    /// history behind — losing the fact that a step ran, along with its bytes,
    /// would make an old run look as though it never happened.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn sweeping_discards_log_bytes_and_keeps_the_history() {
        let store = test_store().await;
        let plan = test_plan();
        let run_id = crate::vm::new_id();
        store
            .create_run(&run_id, &RunRequest::default(), &plan)
            .await
            .unwrap();

        let jid = job_id(&run_id, "deploy");
        let sid = step_id(&jid, 0);
        store
            .create_step(&sid, &jid, 0, "Ship", None)
            .await
            .unwrap();
        let path = store.log_path(&run_id, "deploy", 0, &sid);
        store.append_log(&sid, &path, "output\n").await.unwrap();
        store
            .finish_step(&sid, StepStatus::Success, Some(0), None)
            .await
            .unwrap();
        assert!(!path.exists());

        // Not yet old enough: a sweep must not take a run that is still inside
        // the retention window.
        let recent = store
            .runs_with_logs_before(Utc::now() - chrono::Duration::days(1), 100)
            .await
            .unwrap();
        assert!(
            !recent.contains(&run_id),
            "swept a run inside its retention"
        );

        // Old enough now.
        let due = store
            .runs_with_logs_before(Utc::now() + chrono::Duration::days(1), 500)
            .await
            .unwrap();
        assert!(
            due.contains(&run_id),
            "a run past retention must be offered"
        );

        tokio::fs::remove_dir_all(store.run_log_dir(&run_id))
            .await
            .ok();
        assert_eq!(store.forget_logs_of(&run_id).await.unwrap(), 1);

        // The row survives with its result; only the pointer and size go.
        let steps = store.steps_of(&jid).await.unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].status, "success");
        assert_eq!(steps[0].exit_code, Some(0));
        assert_eq!(steps[0].log_path, None);
        assert_eq!(steps[0].log_bytes, 0);
        assert_eq!(store.read_log(&steps[0]).await.unwrap(), None);
        let chunks: i64 = sqlx::query_scalar("SELECT count(*) FROM ci_step_log WHERE step_id=$1")
            .bind(&sid).fetch_one(&store.pool).await.unwrap();
        assert_eq!(chunks, 0);
        assert!(store.get_run(&run_id).await.unwrap().is_some());

        // And it converges: a swept run is not offered again, or the sweeper
        // would rescan the same rows every hour forever.
        let again = store
            .runs_with_logs_before(Utc::now() + chrono::Duration::days(1), 500)
            .await
            .unwrap();
        assert!(!again.contains(&run_id), "the sweep must converge");
    }

    /// Being on the admin list promotes, but dropping off it must not demote —
    /// a role granted in the UI has to survive the env var changing.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn admin_seeding_promotes_but_never_demotes() {
        let store = test_store().await;
        let subject = format!("sub-{}", crate::vm::new_id());
        let admins = vec!["boss@example.com".to_string()];

        let role = store
            .upsert_user(&subject, "nobody@example.com", None, &admins)
            .await
            .unwrap();
        assert_eq!(role, "viewer");

        let role = store
            .upsert_user(&subject, "boss@example.com", Some("Boss"), &admins)
            .await
            .unwrap();
        assert_eq!(role, "admin", "the config list promotes");

        let role = store
            .upsert_user(&subject, "boss@example.com", Some("Boss"), &[])
            .await
            .unwrap();
        assert_eq!(role, "admin", "an empty list must not demote");
    }

    /// A log path is assembled from values that arrive over HTTP; one `..`
    /// would write outside CI_LOG_DIR.
    #[test]
    fn log_path_components_cannot_escape_the_log_directory() {
        assert_eq!(sanitize_component("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitize_component(".."), "-");
        assert_eq!(sanitize_component("."), "-");
        assert_eq!(sanitize_component(""), "-");
        assert_eq!(sanitize_component("/"), "-");
        // Ids and job keys survive intact — they are already in the alphabet.
        assert_eq!(sanitize_component("build-x86_64"), "build-x86_64");
        assert_eq!(
            sanitize_component("019f7c7ef325-00000000"),
            "019f7c7ef325-00000000"
        );

        let store_dir = PathBuf::from("/var/lib/ci-logs");
        let joined = store_dir
            .join(sanitize_component("../.."))
            .join(sanitize_component("x"));
        assert!(
            joined.starts_with("/var/lib/ci-logs"),
            "escaped: {}",
            joined.display()
        );
    }
}
