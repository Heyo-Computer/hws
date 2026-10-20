//! Preparing verified source and building VM images on the selected runner.
//!
//! The build itself runs **on the runner, by its daemon**. The daemon checks out
//! and verifies the descriptor, then builds directly from its local context; CI
//! never reads or uploads Dockerfile/context/repository bytes. Heyvmd runs
//! the same `docker build → docker export → mke2fs` pipeline `heyvm mvm build`
//! runs locally, writing `~/.heyo/images/firecracker/{name}.ext4` into the
//! host's own catalog. `ci` never parses the Dockerfile and never boots a
//! builder VM — docker's semantics apply in full (multi-stage, `COPY --from`,
//! `ADD`, everything), and the host's docker layer cache makes a rebuild of a
//! mostly-unchanged Dockerfile incremental.
//!
//! Two consequences of `docker export` are inherited from the pipeline and are
//! the image author's to handle, exactly as they are for a hand-built image:
//!
//! - **OCI metadata is discarded** — `ENV`, `CMD`, `ENTRYPOINT` do not survive
//!   into the rootfs. An environment variable that steps need must be written
//!   to `/etc/profile.d` by a `RUN` (steps run under `sh -lc`, which reads it).
//! - **The VM boots `init=/init.sh`** and must print `HEYVM_READY`. An image
//!   without an init script builds fine and then fails every boot; see
//!   `.ci/image/ci/init.sh` for the contract.
//!
//! ## The name is the cache key
//!
//! An image is named `ci-img-<12 hex>`, hashed over the Dockerfile bytes,
//! every file in the build context, and the size override. Identical inputs
//! name an image the host already has; any change names one it does not.
//! There is no invalidation step and nothing to remember to bump — "reused
//! until cache busted" is what content addressing does on its own. The daemon
//! returning `ready` for a name that already exists is what makes two jobs
//! racing to build the same image safe: the loser is told it is done, which
//! is the outcome it wanted.
//!
//! ## What is left in the catalog
//!
//! CI selects old, unused catalog rows; the daemon owns reference checks and
//! serialization with builds and VM creation. A failed or unsupported eviction
//! retains the row for retry. Never unlink base images directly on a live host.

use heyo_sdk::{HeyoClient, HeyoClientOptions, RequestOptions};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

/// How long a build may hold its catalog claim without renewal.
///
/// Longer than the VM lease because it bounds something slower: a whole image
/// build, not a boot. A claim that lapses under a live build only costs a
/// duplicate build request, which the daemon's own idempotency then collapses.
pub const BUILD_LEASE: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareRequest {
    pub repository_url: String,
    pub base_revision: String,
    pub target_tree: String,
    pub patch_base64: String,
    pub workflow_hashes: BTreeMap<String, String>,
    pub cache_key_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_build: Option<PrepareImageBuild>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareImageBuild {
    pub dockerfile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_mb: Option<u64>,
    pub driver: &'static str,
}

#[derive(Debug, Clone)]
pub struct PreparedSource {
    pub source_id: String,
    pub cache_keys: BTreeMap<String, crate::pool::VerifiedContent>,
    pub image: Option<PreparedImage>,
}

#[derive(Debug, Clone)]
pub struct PreparedImage { pub name: String, pub input_digest: String }

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CacheKey { Present { sha256: String }, Absent { absent: bool } }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareStatus {
    source_id: String,
    status: String,
    #[serde(default)] cache_keys: Option<BTreeMap<String, CacheKey>>,
    #[serde(default)] image: Option<PreparedImageWire>,
    #[serde(default)] error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedImageWire { name: String, input_digest: String }

pub async fn prepare_remote(options: impl Into<crate::runners::Connection>, request: &PrepareRequest, deadline: Duration) -> Result<PreparedSource, ImageError> {
    let poll = poll_interval();
    let connection = options.into();
    let client = HeyoClient::new(connection.options.clone()).map_err(|source| ImageError::Daemon { what: "building a client for source preparation", source })?;
    let started = std::time::Instant::now();
    let mut status: PrepareStatus = client.request(Method::POST, "/sources/prepare", Some(request), RequestOptions { timeout: Some(Duration::from_secs(120)), query: vec![] })
        .await.map_err(|source| match source {
            heyo_sdk::HeyoError::NotFound(_) => ImageError::Capability,
            source => ImageError::Daemon { what: "preparing verified source on the runner", source },
        })?;
    validate_source_id(&status.source_id)?;
    let source_id = status.source_id.clone();
    loop {
        if status.source_id != source_id {
            return Err(ImageError::Protocol(format!("runner changed sourceId from {source_id:?} to {:?} while polling", status.source_id)));
        }
        match status.status.as_str() {
            "ready" => return validate_prepared(status, request),
            "failed" => return Err(ImageError::Source(status.error.unwrap_or_else(|| "runner reported no reason".into()))),
            "preparing" => {}
            other => return Err(ImageError::Protocol(format!("unknown source preparation status {other:?}"))),
        }
        if started.elapsed() >= deadline { return Err(ImageError::SourceTimeout(deadline)); }
        tokio::time::sleep(poll).await;
        status = client.request(Method::GET, &format!("/sources/{source_id}"), None::<&()>, RequestOptions { timeout: Some(Duration::from_secs(30)), query: vec![] }).await
            .map_err(|source| match source {
                heyo_sdk::HeyoError::NotFound(_) => ImageError::SourceExpired,
                source => ImageError::Daemon { what: "polling verified source preparation", source },
            })?;
    }
}

fn validate_source_id(value: &str) -> Result<(), ImageError> {
    if (1..=128).contains(&value.len())
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(ImageError::Protocol(format!("runner returned malformed sourceId {value:?}")))
    }
}

fn poll_interval() -> Duration {
    if cfg!(test) { Duration::from_millis(10) } else { Duration::from_secs(3) }
}

fn validate_prepared(status: PrepareStatus, request: &PrepareRequest) -> Result<PreparedSource, ImageError> {
    validate_source_id(&status.source_id)?;
    let expected: BTreeSet<_> = request.cache_key_files.iter().cloned().collect();
    let keys = status.cache_keys.unwrap_or_default();
    let actual: BTreeSet<_> = keys.keys().cloned().collect();
    if actual != expected { return Err(ImageError::Protocol(format!("runner returned cache key set {actual:?}, requested {expected:?}"))); }
    let mut cache_keys = BTreeMap::new();
    for (path, value) in keys {
        let value = match value {
            CacheKey::Present { sha256 } => {
                let bytes = hex::decode(&sha256).map_err(|_| ImageError::Protocol(format!("invalid SHA-256 for cache key {path:?}")))?;
                let digest: [u8; 32] = bytes.try_into().map_err(|_| ImageError::Protocol(format!("invalid SHA-256 length for cache key {path:?}")))?;
                crate::pool::VerifiedContent::Sha256(digest)
            }
            CacheKey::Absent { absent: true } => crate::pool::VerifiedContent::Absent,
            CacheKey::Absent { absent: false } => return Err(ImageError::Protocol(format!("invalid absent marker for cache key {path:?}"))),
        };
        cache_keys.insert(path, value);
    }
    let image = match (request.image_build.is_some(), status.image) {
        (true, Some(i)) if !i.name.is_empty() && !i.input_digest.is_empty() && hex::decode(&i.input_digest).is_ok_and(|d| d.len() == 32) => Some(PreparedImage { name: i.name, input_digest: i.input_digest }),
        (true, _) => return Err(ImageError::Protocol("runner omitted or returned invalid prepared image metadata".into())),
        (false, None) => None,
        (false, Some(_)) => return Err(ImageError::Protocol("runner returned unrequested image metadata".into())),
    };
    Ok(PreparedSource { source_id: status.source_id, cache_keys, image })
}

// ---- driving the daemon ------------------------------------------------

/// `POST /images/build` / `GET /images/build/status` response body. One shape
/// for both: the daemon answers `{status, name}` plus `error` on failure and
/// `size_bytes` when a ready image's size is known.
#[derive(Debug, Deserialize)]
struct BuildStatus {
    status: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
}

/// What a finished remote build reports back.
pub struct Built {
    pub size_bytes: u64,
    /// A short transcript of what happened, for the log attached to the job.
    pub log: String,
}

pub struct Submission<'a> {
    pub store: &'a crate::store::Store,
    pub job: &'a str,
    pub runner: &'a str,
    pub attempt: i32,
    pub boot: uuid::Uuid,
}

impl Submission<'_> {
    pub async fn record(&self, source: &str, image: &str, state: crate::store::ImageSubmission) -> Result<(), ImageError> {
        self.store.image_submission(self.job, self.runner, self.attempt, self.boot, source, image, state)
            .await.map_err(|e| ImageError::Protocol(format!("persisting image submission: {e}")))
    }
}

/// Read only: never restart work while reconciling detached evidence.
pub async fn terminal_image(options: crate::runners::Connection, source: &str, image: &str) -> Result<bool, ImageError> {
    validate_source_id(source)?;
    let client = HeyoClient::new(options.options).map_err(|source| ImageError::Daemon { what: "building reconciliation client", source })?;
    let status: BuildStatus = client.request(Method::GET, &format!("/sources/{source}/image"), None::<&()>, RequestOptions {
        timeout: Some(Duration::from_secs(30)), query: vec![],
    }).await.map_err(|source| ImageError::Daemon { what: "reconciling image build", source })?;
    validate_build_name(&status, image)?;
    Ok(matches!(status.status.as_str(), "ready" | "failed"))
}

/// Ask `runner`'s daemon to build `plan` and wait for the result.
///
/// `options` point at the runner's tunnel, exactly as VM operations do. The
/// call is fire-and-poll: the POST returns immediately and status is polled
/// until `ready` or `failed`, bounded by `deadline`. `renew` is called on each
/// poll so the catalog claim in Postgres outlives a long build — a claim that
/// lapsed mid-build would invite a second job to start a duplicate.
///
/// An `unknown` status after a POST means the daemon restarted or the failure
/// state aged out; the POST is simply re-sent — it is idempotent, and if the
/// image landed before the restart the re-POST answers `ready`.
pub async fn build_remote<F, Fut>(
    options: impl Into<crate::runners::Connection>,
    source_id: &str,
    name: &str,
    deadline: Duration,
    renew: F,
) -> Result<Built, ImageError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // One budget includes acceptance, polling, claim renewal and restart POSTs.
    // Timing out drops only our waiter, not the remote build; callers must
    // retain uncertain preparation ownership.
    build_remote_tracked(options, source_id, name, deadline, renew, None).await
}

pub async fn build_remote_tracked<F, Fut>(
    options: impl Into<crate::runners::Connection>, source_id: &str, name: &str,
    deadline: Duration, renew: F, submission: Option<&Submission<'_>>,
) -> Result<Built, ImageError>
where F: FnMut() -> Fut, Fut: std::future::Future<Output = ()>,
{
    tokio::time::timeout(deadline, build_remote_inner(options, source_id, name, deadline, renew, submission))
        .await
        .unwrap_or_else(|_| Err(ImageError::BuildTimeout { name: name.into(), after: deadline }))
}

async fn build_remote_inner<F, Fut>(
    options: impl Into<crate::runners::Connection>,
    source_id: &str,
    name: &str,
    deadline: Duration,
    mut renew: F,
    submission: Option<&Submission<'_>>,
) -> Result<Built, ImageError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use std::fmt::Write as _;

    let poll = poll_interval();

    let connection = options.into();
    let client = HeyoClient::new(connection.options.clone()).map_err(|e| ImageError::Daemon {
        what: "building a client for the runner",
        source: e,
    })?;

    let mut log = String::new();
    let _ = writeln!(log, "[ci] building verified image {name} from prepared source {source_id}");
    let path = format!("/sources/{source_id}/image");

    let post = |client: &HeyoClient| {
        let client = client.clone();
        let path = path.clone();
        async move {
            client
                .request::<BuildStatus>(
                    Method::POST,
                    &path,
                    None::<&()>,
                    RequestOptions {
                        // The build itself is not waited on here — the route
                        // returns after accepting the prepared source.
                        timeout: Some(Duration::from_secs(120)),
                        query: Vec::new(),
                    },
                )
                .await
        }
    };

    let map_build_error = |what, e| match e {
        heyo_sdk::HeyoError::NotFound(_) => ImageError::SourceExpired,
        source => ImageError::Daemon { what, source },
    };
    if let Some(s) = submission { s.record(source_id, name, crate::store::ImageSubmission::Uncertain).await?; }
    let first = post(&client).await.map_err(|e| map_build_error("starting the image build", e))?;
    validate_build_name(&first, name)?;
    if matches!(first.status.as_str(), "ready" | "building" | "failed") {
        if let Some(s) = submission { s.record(source_id, name, crate::store::ImageSubmission::Acknowledged).await?; }
    }
    if first.status == "ready" {
        // The daemon already had it — the whole point of content-hashed names.
        let _ = writeln!(log, "[ci] the runner already has this image");
        return Ok(Built {
            size_bytes: first.size_bytes.unwrap_or(0),
            log,
        });
    }

    let started = std::time::Instant::now();
    loop {
        tokio::time::sleep(poll).await;
        renew().await;

        let result = client
            .request(
                Method::GET,
                &path,
                None::<&()>,
                RequestOptions {
                    timeout: Some(Duration::from_secs(30)),
                    query: vec![],
                },
            )
            .await;
        let status: BuildStatus = match result {
            Ok(status) => status,
            // Reads are safe to retry. Never turn an uncertain read into a
            // POST, source replay, or VM acquisition. Auth/protocol errors and
            // explicit source expiry still fail closed.
            Err(source) if transient_build_read(&source) => {
                let _ = writeln!(log, "[ci] retrying image status read: {source}");
                continue;
            }
            Err(source) => return Err(map_build_error("polling the image build", source)),
        };

        validate_build_name(&status, name)?;
        match status.status.as_str() {
            "ready" => {
                let _ = writeln!(
                    log,
                    "[ci] image {} is ready after {:?}",
                    name,
                    started.elapsed()
                );
                return Ok(Built {
                    size_bytes: status.size_bytes.unwrap_or(0),
                    log,
                });
            }
            "failed" => {
                let detail = status
                    .error
                    .unwrap_or_else(|| "the daemon reported no reason".to_string());
                let _ = writeln!(log, "[ci] build failed: {detail}");
                return Err(ImageError::Build {
                    name: name.to_string(),
                    detail,
                });
            }
            "building" => {}
            "unknown" => {
                if let Some(s) = submission { s.record(source_id, name, crate::store::ImageSubmission::Uncertain).await?; }
                let restarted = post(&client).await
                    .map_err(|e| map_build_error("restarting the interrupted image build", e))?;
                validate_build_name(&restarted, name)?;
                if matches!(restarted.status.as_str(), "ready" | "building" | "failed") {
                    if let Some(s) = submission { s.record(source_id, name, crate::store::ImageSubmission::Acknowledged).await?; }
                }
                match restarted.status.as_str() {
                    "ready" => return Ok(Built { size_bytes: restarted.size_bytes.unwrap_or(0), log }),
                    "building" => {}
                    "failed" => return Err(ImageError::Build { name: name.to_string(), detail: restarted.error.unwrap_or_else(|| "the daemon reported no reason".into()) }),
                    other => return Err(ImageError::Protocol(format!("unknown image build status {other:?} after restart"))),
                }
            }
            other => return Err(ImageError::Protocol(format!("unknown image build status {other:?}"))),
        }

        if started.elapsed() >= deadline {
            return Err(ImageError::BuildTimeout {
                name: name.to_string(),
                after: deadline,
            });
        }
    }
}

fn validate_build_name(status: &BuildStatus, expected: &str) -> Result<(), ImageError> {
    if status.name.as_deref() == Some(expected) { Ok(()) } else {
        Err(ImageError::Protocol(format!("runner image response named {:?}, expected {expected:?}", status.name)))
    }
}

fn transient_build_read(error: &heyo_sdk::HeyoError) -> bool {
    matches!(error,
        heyo_sdk::HeyoError::Api { status: 0 | 408 | 429 | 500..=599, .. }
        | heyo_sdk::HeyoError::Timeout(..)
        | heyo_sdk::HeyoError::Connection(_))
}

// ---- the catalog -------------------------------------------------------

/// One image this orchestrator has built, or is building, on one runner.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub name: String,
    pub runner_hd_id: String,
    pub status: String,
    pub workflow_id: String,
    pub built_by_job: Option<String>,
    pub size_bytes: i64,
    pub error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub ready_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl CatalogEntry {
    fn from_row(r: &sqlx::postgres::PgRow) -> Self {
        Self {
            name: r.get("name"),
            runner_hd_id: r.get("runner_hd_id"),
            status: r.get("status"),
            workflow_id: r.get("workflow_id"),
            built_by_job: r.get("built_by_job"),
            size_bytes: r.get("size_bytes"),
            error: r.get("error"),
            created_at: r.get("created_at"),
            ready_at: r.get("ready_at"),
        }
    }
}

/// What this orchestrator has put in each runner's image catalog.
///
/// The daemon has no route to list its images — `heyvm mvm images` reads the
/// directory locally — so "does this host already have it" cannot be asked over
/// the tunnel. This table answers it instead, on the same reasoning
/// `ci_vm_pool` is the source of truth for VMs: a record kept here is one query,
/// and drift is self-healing because a create against a missing image fails and
/// forgets the row.
#[derive(Clone)]
pub struct Catalog {
    db: PgPool,
}

/// What [`Catalog::claim`] found.
pub enum Claim {
    /// The runner has it. Use it.
    Ready,
    /// Nobody is building it and this caller now owns doing so.
    Build,
    /// Somebody else is building it; wait rather than build a second copy.
    InProgress,
}

impl Catalog {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Decide, in one statement, whether to use, build, or wait.
    ///
    /// The insert is what makes it a decision rather than a read: two jobs
    /// racing arrive at the same primary key, and exactly one of them inserts.
    /// The other is told `InProgress` and waits — which is the difference
    /// between one image build on a host and one per concurrent job.
    ///
    /// A claim whose lease has lapsed is taken over rather than waited on, so a
    /// dispatcher that died mid-build does not block the image for ever.
    pub async fn claim(
        &self,
        name: &str,
        runner: &str,
        workflow_id: &str,
        job_id: &str,
        lease: Duration,
    ) -> Result<Claim, ImageError> {
        let mut tx = self.db.begin().await.map_err(ImageError::sql)?;
        let row = sqlx::query(
            "INSERT INTO ci_vm_image
                (name, runner_hd_id, workflow_id, status, built_by_job, leased_until)
             VALUES ($1,$2,$3,'building',$4, now() + make_interval(secs => $5))
             ON CONFLICT (name, runner_hd_id) DO UPDATE
                SET status='building', built_by_job=$4, error=NULL,
                    leased_until=now() + make_interval(secs => $5)
              WHERE ci_vm_image.status <> 'ready'
                AND (ci_vm_image.leased_until IS NULL OR ci_vm_image.leased_until < now())
             RETURNING status",
        )
        .bind(name)
        .bind(runner)
        .bind(workflow_id)
        .bind(job_id)
        .bind(lease.as_secs() as f64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ImageError::sql)?;

        // The upsert holds the row lock even when its WHERE rejects takeover.
        // Touch ready hits too, before a sweeper may select this image.
        let status: String = sqlx::query_scalar("UPDATE ci_vm_image SET last_used_at=now() WHERE name=$1 AND runner_hd_id=$2 RETURNING status")
            .bind(name).bind(runner).fetch_one(&mut *tx).await.map_err(ImageError::sql)?;
        tx.commit().await.map_err(ImageError::sql)?;
        Ok(if row.is_some() { Claim::Build } else if status == "ready" { Claim::Ready } else { Claim::InProgress })
    }

    /// One candidate per host/pass, with durable backoff for refusals. The row
    /// lock serializes claims and competing sweepers until the explicit daemon
    /// receipt is committed. Lost responses leave a retryable catalog entry.
    pub async fn evict_one(&self, runner: &str, idle: Duration,
        connection: impl Into<crate::runners::Connection>) -> Result<(), ImageError> {
        let mut tx = self.db.begin().await.map_err(ImageError::sql)?;
        // Same runner admission lock as Store::claim_job and maintenance.
        // New host work cannot appear between the idle check and deletion.
        let admitted: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 222))")
            .bind(runner).fetch_one(&mut *tx).await.map_err(ImageError::sql)?;
        if !admitted { return Ok(()) }
        let name: Option<String> = sqlx::query_scalar(
            "SELECT name FROM ci_vm_image i WHERE runner_hd_id=$1 AND status='ready'
             AND name ~ '^ci-img-[a-f0-9]{12}$'
             AND last_used_at < now()-make_interval(secs => $2) AND cleanup_after<=now()
             AND NOT EXISTS (SELECT 1 FROM ci_vm_pool p WHERE p.runner_hd_id=$1 AND p.status IN ('building','claimed'))
             AND NOT EXISTS (SELECT 1 FROM ci_host_work w WHERE w.runner_hd_id=$1)
             AND NOT EXISTS (SELECT 1 FROM ci_host_maintenance h WHERE h.runner_hd_id=$1 AND h.phase<>'passed')
             AND NOT EXISTS (SELECT 1 FROM ci_host_heyvm_bootstrap h WHERE h.runner_hd_id=$1 AND h.phase NOT IN ('passed','superseded'))
             ORDER BY cleanup_after,last_used_at LIMIT 1 FOR UPDATE OF i SKIP LOCKED")
            .bind(runner).bind(idle.as_secs() as f64).fetch_optional(&mut *tx).await.map_err(ImageError::sql)?;
        let Some(name) = name else { return Ok(()) };
        let connection = connection.into();
        let result = async {
            let client = HeyoClient::new(connection.options.clone())
                .map_err(|source| ImageError::Daemon { what: "opening image cleanup client", source })?;
            #[derive(Deserialize)]
            struct Receipt { name: String, status: String }
            let receipt: Receipt = client.request(Method::POST, &format!("/images/{name}/evict"), None::<&()>,
                RequestOptions { timeout: Some(Duration::from_secs(20)), query: vec![] }).await
                .map_err(|source| ImageError::Daemon { what: "evicting CI base image", source })?;
            if receipt.name != name || !matches!(receipt.status.as_str(), "deleted" | "missing") {
                return Err(ImageError::Protocol(format!("image eviction not confirmed: {} {}", receipt.name, receipt.status)));
            }
            Ok(())
        }.await;
        match &result {
            Ok(()) => {
                sqlx::query("DELETE FROM ci_vm_image WHERE name=$1 AND runner_hd_id=$2")
                    .bind(&name).bind(runner).execute(&mut *tx).await.map_err(ImageError::sql)?;
            }
            Err(e) => {
                sqlx::query("UPDATE ci_vm_image SET cleanup_after=now()+interval '5 minutes',error=$3 WHERE name=$1 AND runner_hd_id=$2")
                    .bind(&name).bind(runner).bind(e.to_string()).execute(&mut *tx).await.map_err(ImageError::sql)?;
            }
        }
        tx.commit().await.map_err(ImageError::sql)?;
        if result.is_ok() { tracing::info!(runner, image=%name, "CI base image eviction confirmed"); }
        result
    }

    pub async fn status_of(&self, name: &str, runner: &str) -> Result<Option<String>, ImageError> {
        let row =
            sqlx::query("SELECT status FROM ci_vm_image WHERE name = $1 AND runner_hd_id = $2")
                .bind(name)
                .bind(runner)
                .fetch_optional(&self.db)
                .await
                .map_err(ImageError::sql)?;
        Ok(row.map(|r| r.get("status")))
    }

    /// Hold a claim while a long build runs.
    pub async fn renew(&self, name: &str, runner: &str, lease: Duration) -> Result<(), ImageError> {
        sqlx::query(
            "UPDATE ci_vm_image SET leased_until = now() + make_interval(secs => $3)
              WHERE name = $1 AND runner_hd_id = $2 AND status = 'building'",
        )
        .bind(name)
        .bind(runner)
        .bind(lease.as_secs() as f64)
        .execute(&self.db)
        .await
        .map_err(ImageError::sql)?;
        Ok(())
    }

    pub async fn mark_ready(
        &self,
        name: &str,
        runner: &str,
        size_bytes: u64,
    ) -> Result<(), ImageError> {
        sqlx::query(
            "UPDATE ci_vm_image
                SET status='ready', ready_at=now(), leased_until=NULL, error=NULL,
                    size_bytes=CASE WHEN $3>0 THEN $3 ELSE size_bytes END
              WHERE name = $1 AND runner_hd_id = $2",
        )
        .bind(name)
        .bind(runner)
        .bind(size_bytes as i64)
        .execute(&self.db)
        .await
        .map_err(ImageError::sql)?;
        Ok(())
    }

    /// Record a failed build, keeping the row so the page can say what happened.
    ///
    /// `failed` rather than deleted, and unleased: the next job to want this
    /// image takes the claim and tries again, which is right for a build that
    /// failed on a transient apt mirror — while the row still carries the
    /// reason the last attempt gave.
    pub async fn mark_failed(
        &self,
        name: &str,
        runner: &str,
        error: &str,
    ) -> Result<(), ImageError> {
        sqlx::query(
            "UPDATE ci_vm_image
                SET status='failed', leased_until=NULL, error=$3
              WHERE name = $1 AND runner_hd_id = $2 AND status <> 'ready'",
        )
        .bind(name)
        .bind(runner)
        .bind(error)
        .execute(&self.db)
        .await
        .map_err(ImageError::sql)?;
        Ok(())
    }

    /// Drop the record of an image the runner turns out not to have.
    pub async fn forget(&self, name: &str, runner: &str) -> Result<(), ImageError> {
        sqlx::query("DELETE FROM ci_vm_image WHERE name = $1 AND runner_hd_id = $2")
            .bind(name)
            .bind(runner)
            .execute(&self.db)
            .await
            .map_err(ImageError::sql)?;
        Ok(())
    }

    /// Every image on the runners this instance serves.
    pub async fn inventory(&self, runners: &[String]) -> Result<Vec<CatalogEntry>, ImageError> {
        if runners.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT * FROM ci_vm_image
              WHERE runner_hd_id = ANY($1)
              ORDER BY runner_hd_id, created_at DESC",
        )
        .bind(runners)
        .fetch_all(&self.db)
        .await
        .map_err(ImageError::sql)?;
        Ok(rows.iter().map(CatalogEntry::from_row).collect())
    }
}

#[derive(Debug)]
pub enum ImageError {
    Capability,
    SourceExpired,
    Source(String),
    SourceTimeout(Duration),
    Protocol(String),
    /// The daemon could not be asked, or stopped answering. The source is kept
    /// typed so a transport-level failure — the tunnel, not the build — can be
    /// told from the daemon actually refusing.
    Daemon {
        what: &'static str,
        source: heyo_sdk::HeyoError,
    },
    /// The daemon ran the build and it failed — a Dockerfile problem, named.
    Build {
        name: String,
        detail: String,
    },
    BuildTimeout {
        name: String,
        after: Duration,
    },
    Sql(String),
    /// Somebody else's build did not finish inside the window this job could
    /// wait for it.
    WaitTimeout {
        name: String,
        waited: Duration,
    },
}

impl ImageError {
    fn sql(e: sqlx::Error) -> Self {
        Self::Sql(e.to_string())
    }
}

impl ImageError {
    /// True when the failure was reaching the daemon at all — see
    /// [`crate::vm::is_transport`]. A build the daemon refused or failed is
    /// never this; those answers arrived.
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Daemon { source, .. } if crate::vm::is_transport(source))
    }
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability => write!(f, "runner backend does not support verified source preparation; upgrade heyvmd (the CI service will not upload repository or image-context bytes)"),
            Self::SourceExpired => write!(f, "prepared source expired on the runner"),
            Self::Source(e) => write!(f, "runner failed to prepare verified source: {e}"),
            Self::SourceTimeout(after) => write!(f, "runner did not prepare verified source within {after:?}"),
            Self::Protocol(e) => write!(f, "runner returned an invalid verified-source response: {e}"),
            Self::Daemon { what, source } => write!(f, "{what}: {source}"),
            Self::Build { name, detail } => {
                write!(f, "the runner could not build image {name}: {detail}")
            }
            Self::BuildTimeout { name, after } => write!(
                f,
                "the runner did not finish building image {name} within {after:?}"
            ),
            Self::Sql(e) => write!(f, "database error: {e}"),
            Self::WaitTimeout { name, waited } => write!(
                f,
                "another job has been building image {name} on this runner for {waited:?} and \
                 has not finished. This job gave up waiting rather than building a second copy; \
                 it will be retried."
            ),
        }
    }
}

impl std::error::Error for ImageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{ImageBuild, VmSpec};
    use heyo_sdk::{SandboxDriver, SandboxSize};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const FINGERPRINT_LEN: usize = 12;
    #[derive(Debug)]
    struct LocalPlan { name: String, context_tar_gz: Option<Vec<u8>> }
    fn plan_for(build: &ImageBuild, spec: &VmSpec, workspace: &std::path::Path) -> Result<LocalPlan, std::io::Error> {
        fn collect(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), std::io::Error> {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.is_dir() { collect(&path, root, out)?; }
                else if path.is_file() { out.push((path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(path)?)); }
            }
            Ok(())
        }
        let dockerfile = std::fs::read(workspace.join(&build.dockerfile))?;
        let root = workspace.join(build.context_dir());
        let mut files = vec![];
        collect(&root, &root, &mut files)?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut h = Sha256::new();
        h.update(b"ci-image-v2\0"); h.update(&dockerfile); h.update([0]);
        h.update(format!("{:?}\0{}\0", spec.driver, build.size_mb.unwrap_or(0)).as_bytes());
        for (path, bytes) in &files { h.update(path.as_bytes()); h.update([0]); h.update(Sha256::digest(bytes)); }
        let name = format!("ci-img-{}", &hex::encode(h.finalize())[..FINGERPRINT_LEN]);
        let context_tar_gz = if files.is_empty() { None } else {
            use std::io::Write;
            let mut tar = tar::Builder::new(Vec::new());
            for (path, bytes) in files { let mut header = tar::Header::new_gnu(); header.set_size(bytes.len() as u64); header.set_mode(0o644); header.set_cksum(); tar.append_data(&mut header, path, bytes.as_slice())?; }
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(&tar.into_inner()?)?; Some(gz.finish()?)
        };
        Ok(LocalPlan { name, context_tar_gz })
    }

    fn spec() -> VmSpec {
        VmSpec {
            driver: SandboxDriver::Firecracker,
            image: None,
            build: None,
            size_class: Some(SandboxSize::Medium),
            disk_size_gb: Some(20),
            working_directory: None,
            env_vars: BTreeMap::new(),
            setup_hooks: vec![],
            cache_key_files: vec![],
            reuse: true,
            ttl_seconds: None,
        }
    }

    fn build(dockerfile: &str) -> ImageBuild {
        ImageBuild {
            dockerfile: dockerfile.into(),
            context: None,
            size_mb: None,
        }
    }

    fn ws(files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ci-img-{}", crate::vm::new_id()));
        for (rel, body) in files {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The whole cache story in one test: the name is the content, so an
    /// unchanged Dockerfile reuses and any change rebuilds.
    #[test]
    fn the_image_name_is_the_hash_of_the_dockerfile_and_its_context() {
        let files = [
            (
                "img/Dockerfile",
                "FROM debian\nCOPY marker.txt /etc/marker\n",
            ),
            ("img/marker.txt", "one\n"),
        ];
        let w = ws(&files);
        let b = build("img/Dockerfile");

        let first = plan_for(&b, &spec(), &w).unwrap();
        assert!(first.name.starts_with("ci-img-"), "{}", first.name);
        assert_eq!(first.name.len(), "ci-img-".len() + FINGERPRINT_LEN);
        assert_eq!(
            first.name,
            plan_for(&b, &spec(), &w).unwrap().name,
            "the same inputs must name the same image, or nothing is ever reused"
        );
        // The Dockerfile itself is part of the context dir here, and the
        // context rides along for the daemon to build from.
        assert!(first.context_tar_gz.is_some());

        // A context file changing is a different image.
        std::fs::write(w.join("img/marker.txt"), "two\n").unwrap();
        let after_file = plan_for(&b, &spec(), &w).unwrap();
        assert_ne!(
            first.name, after_file.name,
            "a changed context file must bust the cache"
        );

        // So is the Dockerfile changing — including only a comment, because
        // the hash is over raw bytes now that docker owns the semantics.
        std::fs::write(
            w.join("img/Dockerfile"),
            "# c\nFROM debian\nCOPY marker.txt /etc/marker\n",
        )
        .unwrap();
        assert_ne!(after_file.name, plan_for(&b, &spec(), &w).unwrap().name);

        // And so is the size override: a different ext4 is a different image.
        let mut sized = build("img/Dockerfile");
        sized.size_mb = Some(6144);
        assert_ne!(
            plan_for(&sized, &spec(), &w).unwrap().name,
            plan_for(&build("img/Dockerfile"), &spec(), &w)
                .unwrap()
                .name
        );

        std::fs::remove_dir_all(&w).ok();
    }

    #[test]
    fn a_dockerfile_with_no_context_files_ships_none() {
        let w = ws(&[]);
        std::fs::write(w.join("Dockerfile"), "FROM debian\nRUN true\n").unwrap();
        // Context defaults to the Dockerfile's directory — which here contains
        // only the Dockerfile itself, so it *is* shipped (docker would too).
        let plan = plan_for(&build("Dockerfile"), &spec(), &w).unwrap();
        assert!(plan.context_tar_gz.is_some());
        std::fs::remove_dir_all(&w).ok();
    }

    #[test]
    fn a_directory_deep_in_the_context_still_busts_the_cache() {
        let w = ws(&[
            ("img/Dockerfile", "FROM debian\nCOPY . /app\n"),
            ("img/nested/deep/b.txt", "two"),
        ]);
        let b = build("img/Dockerfile");
        let before = plan_for(&b, &spec(), &w).unwrap();
        std::fs::write(w.join("img/nested/deep/b.txt"), "changed").unwrap();
        assert_ne!(before.name, plan_for(&b, &spec(), &w).unwrap().name);
        std::fs::remove_dir_all(&w).ok();
    }

    #[test]
    fn a_missing_dockerfile_names_the_path() {
        let w = ws(&[]);
        assert!(plan_for(&build("absent/Dockerfile"), &spec(), &w).is_err());
        std::fs::remove_dir_all(&w).ok();
    }

    /// `heyvm mvm build -f x/Dockerfile` defaults its context to `x`, and a
    /// workflow that says only `dockerfile:` should mean the same thing.
    #[test]
    fn the_context_defaults_to_the_dockerfiles_directory() {
        let b = build("deploy/image/Dockerfile");
        assert_eq!(b.context_dir(), "deploy/image");
        assert_eq!(build("Dockerfile").context_dir(), ".");
        let mut b = build("deploy/image/Dockerfile");
        b.context = Some("deploy".into());
        assert_eq!(b.context_dir(), "deploy");
    }

    /// The packed context round-trips through tar+gzip, which is what the
    /// daemon unpacks on the other side.
    #[test]
    fn the_context_archive_round_trips() {
        let w = ws(&[
            ("img/Dockerfile", "FROM debian\n"),
            ("img/a.txt", "alpha"),
            ("img/sub/b.txt", "beta"),
        ]);
        let plan = plan_for(&build("img/Dockerfile"), &spec(), &w).unwrap();
        let gz = plan.context_tar_gz.expect("context");

        let mut seen = std::collections::BTreeMap::new();
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(gz)));
        for entry in ar.entries().unwrap() {
            use std::io::Read;
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            let mut body = String::new();
            entry.read_to_string(&mut body).unwrap();
            seen.insert(path, body);
        }
        assert_eq!(seen.get("a.txt").map(String::as_str), Some("alpha"));
        assert_eq!(seen.get("sub/b.txt").map(String::as_str), Some("beta"));
        assert!(seen.contains_key("Dockerfile"));
        std::fs::remove_dir_all(&w).ok();
    }

    fn prepare_request() -> PrepareRequest {
        PrepareRequest {
            repository_url: "https://github.com/acme/repo.git".into(),
            base_revision: "a".repeat(40), target_tree: "b".repeat(40),
            patch_base64: "cGF0Y2g=".into(),
            workflow_hashes: BTreeMap::from([(".ci/workflows/a.yml".into(), "c".repeat(64))]),
            cache_key_files: vec!["Cargo.lock".into()],
            image_build: Some(PrepareImageBuild { dockerfile: "Dockerfile".into(), context: None, size_mb: None, driver: "firecracker" }),
            git_auth_token: Some("fresh-secret".into()),
        }
    }

    async fn http_options(app: axum::Router) -> HeyoClientOptions {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        HeyoClientOptions { api_key: None, base_url: Some(format!("http://{addr}")), timeout: None }
    }

    #[tokio::test]
    async fn detached_image_evidence_requires_exact_terminal_response() {
        use axum::{Json, Router, routing::get};
        for (status, name, expected) in [
            ("ready", "image", Some(true)), ("failed", "image", Some(true)),
            ("unknown", "image", Some(false)), ("building", "image", Some(false)),
            ("ready", "wrong", None),
        ] {
            let app = Router::new().route("/sources/source_1/image", get(move || async move {
                Json(serde_json::json!({"status":status,"name":name}))
            }));
            let result = terminal_image(http_options(app).await.into(), "source_1", "image").await;
            assert_eq!(result.ok(), expected);
        }
        for code in [axum::http::StatusCode::NOT_FOUND, axum::http::StatusCode::UNAUTHORIZED, axum::http::StatusCode::SERVICE_UNAVAILABLE] {
            let app = Router::new().route("/sources/source_1/image", get(move || async move { code }));
            assert!(terminal_image(http_options(app).await.into(), "source_1", "image").await.is_err());
        }
    }

    fn ready_source(id: &str) -> serde_json::Value {
        serde_json::json!({
            "sourceId": id, "status": "ready",
            "cacheKeys": {"Cargo.lock": {"sha256": "11".repeat(32)}},
            "image": {"name": "ci-img-aabbccddee11", "inputDigest": "22".repeat(32)}
        })
    }

    #[tokio::test]
    async fn prepare_http_contract_posts_metadata_and_polls_same_source() {
        use axum::{Json, Router, extract::State, routing::{get, post}};
        use std::sync::{Arc, Weak};
        let owner = Arc::new(HeyoClient::new(HeyoClientOptions::default()).unwrap());
        let weak = Arc::downgrade(&owner);
        let app = Router::new()
            .route("/sources/prepare", post(|State(owner): State<Weak<HeyoClient>>, Json(body): Json<serde_json::Value>| async move {
                assert!(owner.upgrade().is_some(), "source POST lost its connection owner");
                assert_eq!(body["repositoryUrl"], "https://github.com/acme/repo.git");
                assert_eq!(body["gitAuthToken"], "fresh-secret");
                assert!(body.get("context_tar_gz").is_none());
                Json(serde_json::json!({"sourceId":"source_1", "status":"preparing"}))
            }))
            .route("/sources/source_1", get(|State(owner): State<Weak<HeyoClient>>| async move {
                assert!(owner.upgrade().is_some(), "source polling lost its connection owner");
                Json(ready_source("source_1"))
            }))
            .with_state(weak.clone());
        let connection = crate::runners::Connection { options: http_options(app).await, _tunnel: Some(owner) };
        let prepared = prepare_remote(connection, &prepare_request(), Duration::from_secs(1)).await.unwrap();
        assert_eq!(prepared.source_id, "source_1");
        assert_eq!(prepared.image.unwrap().name, "ci-img-aabbccddee11");
        assert!(weak.upgrade().is_none(), "completed preparation leaked its connection");
    }

    #[tokio::test]
    async fn prepare_rejects_malformed_and_changed_source_ids_and_reports_expiry() {
        use axum::{Json, Router, routing::{get, post}};
        let malformed = Router::new().route("/sources/prepare", post(|| async {
            Json(serde_json::json!({"sourceId":"../bad", "status":"preparing"}))
        }));
        assert!(matches!(prepare_remote(http_options(malformed).await, &prepare_request(), Duration::from_secs(1)).await, Err(ImageError::Protocol(_))));

        let changed = Router::new()
            .route("/sources/prepare", post(|| async { Json(serde_json::json!({"sourceId":"one", "status":"preparing"})) }))
            .route("/sources/one", get(|| async { Json(ready_source("two")) }));
        assert!(matches!(prepare_remote(http_options(changed).await, &prepare_request(), Duration::from_secs(1)).await, Err(ImageError::Protocol(_))));

        let expired = Router::new()
            .route("/sources/prepare", post(|| async { Json(serde_json::json!({"sourceId":"gone", "status":"preparing"})) }))
            .route("/sources/gone", get(|| async { axum::http::StatusCode::NOT_FOUND }));
        assert!(matches!(prepare_remote(http_options(expired).await, &prepare_request(), Duration::from_secs(1)).await, Err(ImageError::SourceExpired)));
    }

    #[tokio::test]
    async fn interrupted_build_unknown_is_reposted_and_wrong_metadata_is_rejected() {
        use axum::{Json, Router, extract::State, routing::post};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let posts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/sources/source_1/image", post(|State(n): State<Arc<AtomicUsize>>| async move {
                let call = n.fetch_add(1, Ordering::SeqCst);
                Json(if call == 0 { serde_json::json!({"status":"building","name":"image"}) } else { serde_json::json!({"status":"ready","name":"image","size_bytes":9}) })
            }).get(|| async { Json(serde_json::json!({"status":"unknown","name":"image"})) }))
            .with_state(posts.clone());
        let built = build_remote(http_options(app).await, "source_1", "image", Duration::from_secs(1), || async {}).await.unwrap();
        assert_eq!(built.size_bytes, 9);
        assert_eq!(posts.load(Ordering::SeqCst), 2);

        let wrong = Router::new().route("/sources/source_1/image", post(|| async {
            Json(serde_json::json!({"status":"ready","name":"another"}))
        }));
        assert!(matches!(build_remote(http_options(wrong).await, "source_1", "image", Duration::from_secs(1), || async {}).await, Err(ImageError::Protocol(_))));
    }

    #[tokio::test]
    async fn build_poll_retries_transient_reads_without_reposting() {
        use axum::{Json, Router, body::Body, extract::State, response::IntoResponse, routing::post};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let counts = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let app = Router::new().route("/sources/source_1/image", post(
            |State(n): State<Arc<(AtomicUsize, AtomicUsize)>>| async move {
                n.0.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({"status":"building","name":"image"}))
            }
        ).get(|State(n): State<Arc<(AtomicUsize, AtomicUsize)>>| async move {
            match n.1.fetch_add(1, Ordering::SeqCst) {
                // A broken response body exercises SDK transport status 0,
                // the same classification used for network timeouts.
                0 => axum::response::Response::new(Body::from_stream(futures::stream::once(async {
                    Err::<String, _>(std::io::Error::other("connection reset"))
                }))),
                1 => axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
                _ => Json(serde_json::json!({"status":"ready","name":"image","size_bytes":9})).into_response(),
            }
        })).with_state(counts.clone());
        let renewals = AtomicUsize::new(0);
        let built = build_remote(http_options(app).await, "source_1", "image", Duration::from_secs(2), || async {
            renewals.fetch_add(1, Ordering::SeqCst);
        }).await.unwrap();
        assert_eq!(built.size_bytes, 9);
        assert_eq!(counts.0.load(Ordering::SeqCst), 1);
        assert_eq!(counts.1.load(Ordering::SeqCst), 3);
        assert_eq!(renewals.load(Ordering::SeqCst), 3);
        assert_eq!(built.log.matches("retrying image status read").count(), 2);
    }

    #[tokio::test]
    async fn build_budget_bounds_acceptance_reads_and_renewal() {
        use axum::{Json, Router, routing::post};
        for stage in ["post", "get", "renew", "transient"] {
            let app = Router::new().route("/sources/source_1/image", post(move || async move {
                if stage == "post" { std::future::pending::<()>().await; }
                Json(serde_json::json!({"status":"building","name":"image"}))
            }).get(move || async move {
                if stage == "get" { std::future::pending::<()>().await; }
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            }));
            let result = tokio::time::timeout(Duration::from_secs(2), build_remote(
                http_options(app).await, "source_1", "image", Duration::from_millis(80), || async {
                    if stage == "renew" { std::future::pending::<()>().await; }
                },
            )).await.expect("overall build budget was not enforced");
            assert!(matches!(result, Err(ImageError::BuildTimeout { .. })), "stage {stage}");
        }
    }

    #[tokio::test]
    async fn build_post_404_requests_source_replay() {
        use axum::{Router, routing::post};
        let app = Router::new().route("/sources/source_1/image", post(|| async { axum::http::StatusCode::NOT_FOUND }));
        assert!(matches!(build_remote(http_options(app).await, "source_1", "image", Duration::from_secs(1), || async {}).await, Err(ImageError::SourceExpired)));
    }

    // ---- the catalog ----------------------------------------------------
    //
    //   CI_TEST_DATABASE_URL=... cargo test -- --ignored image::

    async fn test_catalog() -> Catalog {
        let url = std::env::var("CI_TEST_DATABASE_URL").expect("CI_TEST_DATABASE_URL");
        let dir = std::env::temp_dir().join(format!("ci-img-logs-{}", crate::vm::new_id()));
        let store = crate::store::Store::connect(&url, dir, std::time::Duration::from_secs(30))
            .await
            .unwrap();
        store.migrate().await.expect("migrations");
        Catalog::new(store.pool().clone())
    }

    /// A distinct runner per test so concurrent runs never contend.
    fn runner_id() -> String {
        format!("hd-{}", crate::vm::new_id().replace('-', ""))
    }

    const LEASE: Duration = Duration::from_secs(600);
    const LAPSED: Duration = Duration::from_secs(0);

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL; fake daemon HTTP"]
    async fn image_eviction_is_scoped_retryable_and_serialized_with_claims() {
        use axum::{Json, Router, extract::{Path, State}, http::StatusCode, response::IntoResponse, routing::post};
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct Remote { mode: String, removed: bool, calls: usize, deletes: usize }
        let remote = Arc::new(Mutex::new(Remote::default()));
        let app = Router::new().route("/images/{name}/evict", post(
            |State(remote): State<Arc<Mutex<Remote>>>, Path(name): Path<String>| async move {
                let mut r = remote.lock().unwrap(); r.calls += 1;
                match r.mode.as_str() {
                    "unsupported" => return StatusCode::NOT_FOUND.into_response(),
                    "busy" => return Json(serde_json::json!({"name":name,"status":"busy"})).into_response(),
                    "wrong" => return Json(serde_json::json!({"name":"another-image","status":"deleted"})).into_response(),
                    _ => {}
                }
                let status = if r.removed { "missing" } else { r.removed=true; r.deletes+=1; "deleted" };
                if r.mode == "lost" { return StatusCode::BAD_GATEWAY.into_response(); }
                Json(serde_json::json!({"name":name,"status":status})).into_response()
            })).with_state(remote.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let options = HeyoClientOptions { base_url: Some(format!("http://{}", listener.local_addr().unwrap())), ..Default::default() };
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let c = test_catalog().await;
        let name = "ci-img-012345abcdef";
        let idle = Duration::from_secs(3600);
        for mode in ["unsupported", "busy", "wrong", "lost"] {
            *remote.lock().unwrap() = Remote { mode: mode.into(), ..Default::default() };
            let runner = runner_id();
            let foreign = runner_id();
            for host in [&runner, &foreign] {
                c.claim(name, host, "wf", "job", LEASE).await.unwrap();
                c.mark_ready(name, host, 1024).await.unwrap();
            }
            c.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().calls, 0, "new images get a grace period");
            sqlx::query("UPDATE ci_vm_image SET last_used_at=now()-interval '2 hours' WHERE runner_hd_id IN ($1,$2)")
                .bind(&runner).bind(&foreign).execute(&c.db).await.unwrap();
            // A ready cache hit refreshes usage, not just builds.
            assert!(matches!(c.claim(name, &runner, "wf", "new-job", LEASE).await.unwrap(), Claim::Ready));
            c.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().calls, 0);
            sqlx::query("UPDATE ci_vm_image SET last_used_at=now()-interval '2 hours' WHERE runner_hd_id=$1")
                .bind(&runner).execute(&c.db).await.unwrap();
            // A competing claimant owns the row: sweep must skip it rather
            // than deciding from an unlocked/stale candidate list.
            let mut tx = c.db.begin().await.unwrap();
            sqlx::query("SELECT name FROM ci_vm_image WHERE runner_hd_id=$1 FOR UPDATE")
                .bind(&runner).fetch_one(&mut *tx).await.unwrap();
            c.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().calls, 0);
            tx.rollback().await.unwrap();
            assert!(c.evict_one(&runner, idle, options.clone()).await.is_err());
            assert_eq!(c.status_of(name, &runner).await.unwrap().as_deref(), Some("ready"));
            let error: Option<String> = sqlx::query_scalar("SELECT error FROM ci_vm_image WHERE name=$1 AND runner_hd_id=$2")
                .bind(name).bind(&runner).fetch_one(&c.db).await.unwrap();
            assert!(error.is_some());
            let calls = remote.lock().unwrap().calls;
            c.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().calls, calls, "retry backoff is durable");
            sqlx::query("UPDATE ci_vm_image SET cleanup_after=now() WHERE runner_hd_id=$1")
                .bind(&runner).execute(&c.db).await.unwrap();
            remote.lock().unwrap().mode.clear();
            let restarted = test_catalog().await;
            restarted.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().deletes, 1, "lost response must not delete twice");
            assert!(c.status_of(name, &runner).await.unwrap().is_none());
            assert_eq!(c.status_of(name, &foreign).await.unwrap().as_deref(), Some("ready"));
            assert!(matches!(c.claim(name, &runner, "wf", "next-job", LEASE).await.unwrap(), Claim::Build));
            // Even an old building row must not be swept.
            sqlx::query("UPDATE ci_vm_image SET last_used_at=now()-interval '2 hours' WHERE runner_hd_id=$1")
                .bind(&runner).execute(&c.db).await.unwrap();
            let calls = remote.lock().unwrap().calls;
            c.evict_one(&runner, idle, options.clone()).await.unwrap();
            assert_eq!(remote.lock().unwrap().calls, calls);
            c.forget(name, &runner).await.unwrap();
            c.forget(name, &foreign).await.unwrap();
        }
        server.abort();
    }

    /// The whole point of the table: one build per host, and every later job
    /// finds it ready instead of rebuilding a multi-gigabyte rootfs.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn one_job_builds_an_image_and_the_rest_wait_then_reuse_it() {
        let c = test_catalog().await;
        let runner = runner_id();
        let name = "ci-img-aaaaaaaaaaaa";

        assert!(matches!(
            c.claim(name, &runner, "wf", "job-1", LEASE).await.unwrap(),
            Claim::Build
        ));
        // A second job arriving mid-build must not start its own.
        assert!(matches!(
            c.claim(name, &runner, "wf", "job-2", LEASE).await.unwrap(),
            Claim::InProgress
        ));

        c.mark_ready(name, &runner, 4096).await.unwrap();
        for job in ["job-2", "job-3"] {
            assert!(
                matches!(
                    c.claim(name, &runner, "wf", job, LEASE).await.unwrap(),
                    Claim::Ready
                ),
                "{job} must reuse the image rather than rebuild it"
            );
        }

        // A ready image is never taken over, however old its row.
        assert!(matches!(
            c.claim(name, &runner, "wf", "job-4", LAPSED).await.unwrap(),
            Claim::Ready
        ));

        let seen = c.inventory(std::slice::from_ref(&runner)).await.unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].status, "ready");
        assert_eq!(seen[0].size_bytes, 4096);
        c.forget(name, &runner).await.unwrap();
    }

    /// An image is a file on one host's disk, so one runner having it says
    /// nothing about another.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn an_image_on_one_runner_is_not_an_image_on_another() {
        let c = test_catalog().await;
        let (a, b) = (runner_id(), runner_id());
        let name = "ci-img-bbbbbbbbbbbb";

        c.claim(name, &a, "wf", "job-1", LEASE).await.unwrap();
        c.mark_ready(name, &a, 1).await.unwrap();

        assert!(matches!(
            c.claim(name, &b, "wf", "job-2", LEASE).await.unwrap(),
            Claim::Build,
        ));
        assert_eq!(c.inventory(&[a.clone()]).await.unwrap().len(), 1);
        c.forget(name, &a).await.unwrap();
        c.forget(name, &b).await.unwrap();
    }

    /// A dispatcher that died mid-build must not block the image for ever, and
    /// a failed build must be retried by the next job that wants it — with the
    /// last reason still on the row for whoever looks.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_lapsed_or_failed_build_is_taken_over_by_the_next_job() {
        let c = test_catalog().await;
        let runner = runner_id();
        let name = "ci-img-cccccccccccc";

        // A holder that stopped renewing.
        c.claim(name, &runner, "wf", "dead-job", LAPSED)
            .await
            .unwrap();
        assert!(matches!(
            c.claim(name, &runner, "wf", "job-2", LEASE).await.unwrap(),
            Claim::Build,
        ));
        // And renewing keeps it held against a third.
        c.renew(name, &runner, LEASE).await.unwrap();
        assert!(matches!(
            c.claim(name, &runner, "wf", "job-3", LEASE).await.unwrap(),
            Claim::InProgress
        ));

        c.mark_failed(name, &runner, "apt-get exited 100")
            .await
            .unwrap();
        let seen = c.inventory(std::slice::from_ref(&runner)).await.unwrap();
        assert_eq!(seen[0].status, "failed");
        assert_eq!(seen[0].error.as_deref(), Some("apt-get exited 100"));

        // Retried rather than stuck: a mirror that was down is worth another go.
        assert!(matches!(
            c.claim(name, &runner, "wf", "job-4", LEASE).await.unwrap(),
            Claim::Build
        ));
        c.forget(name, &runner).await.unwrap();
        assert!(c.inventory(&[runner]).await.unwrap().is_empty());
    }
}
