//! Deploy jobs: the two ways a deployment's code gets updated.
//!
//! Both kinds run as an async task on the app-lb host, one at a time per
//! deployment, and are polled through the same records:
//!
//! * **`image-build`** (managed deployments) — get a Dockerfile onto this host,
//!   hand it to `heyvm mvm build`, then rewrite `vm.image` to the image that
//!   produced, which recycles the pool onto it. heyvm has no build API, so this
//!   is app-lb driving child processes.
//!
//!   Two ways in, and only the first few steps differ: `git fetch` a repo and
//!   find a Dockerfile inside it, or fetch a Dockerfile manifest from an
//!   artifact store and unpack its context. Both converge on one `Prepared` —
//!   a Dockerfile, a context directory, and a version string to name the image
//!   after — which is why there is one job kind and not two.
//! * **`artifact-pull`** (managed deployments) — resolve a reference in an
//!   artifact store to a rootfs blob, materialize it as an `.ext4` heyvmd can
//!   boot, and rewrite `vm.image` the same way. The difference from a build is
//!   that nothing is produced: the digest names bytes that already exist, so the
//!   same reference gives the same rootfs on every host that can reach the
//!   store. See [`crate::artifact`].
//!
//!   Worth being precise about, now that a build can also name a store: what
//!   separates the two is not *where the bytes live* but *whether an image is
//!   made*. A `build.store` holds a recipe and every host that uses it runs its
//!   own `docker build`; an `artifact.store` holds the finished rootfs and no
//!   host builds anything.
//! * **`host-update`** (static/`proxy_pass` deployments) — run a list of
//!   commands in a working directory on this host, then re-probe the upstreams
//!   to prove the service came back. A static deployment's backend is a process
//!   somebody else runs; this is the "somebody else" being app-lb.
//!
//! Each is rejected on the wrong kind of deployment: there is no image to build
//! or pull for a `proxy_pass` upstream, and a working directory on the host has
//! nothing to do with a microVM's rootfs. The two managed kinds are exclusive
//! per deployment too — `DeploymentSpec::validate` refuses a spec holding both
//! `build` and `artifact`, because both rewrite `vm.image` and a deployment with
//! two sources for it cannot say where the running image came from.
//!
//! Things this module is careful about, all because both specs arrive over the
//! admin API rather than from a config file:
//!
//! * **Credentials never reach argv.** A URL with a token in it lands in
//!   `.git/config` and in every `ps`, so values go through `GIT_ASKPASS` and the
//!   child's environment instead.
//! * **Paths cannot leave the checkout.** Validated in the spec, then re-checked
//!   after canonicalization so a symlink committed to a repo can't redirect a
//!   build at `/etc`.
//! * **One job per deployment.** A second request while one is running is a
//!   conflict, not a queue — two `heyvm mvm build`s writing the same
//!   `<image>.ext4`, or two `cargo build`s in one directory, would race.

use crate::artifact::{Puller, human as human_bytes};
use crate::autoscale::Autoscaler;
use crate::config::{ArtifactSpec, Backend, BuildSource, BuildSpec, MountSpec, UpdateSpec};
use crate::deployment::{Deployment, now_secs};
use crate::health;
use crate::registry::Registry;
use crate::secrets::SecretStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How many jobs are remembered **per deployment**. Records are in memory only:
/// a job is a transient event, and the durable outcome of a successful one is
/// either the `image` in the persisted spec or the state of the host itself.
///
/// Per-deployment rather than global, because a global cap is not a retention
/// policy at fleet scale — it is a race. One deployment pulling images in a loop
/// would evict every other deployment's history, so the one job you came to
/// investigate is the one already gone.
const HISTORY_PER_DEPLOYMENT: usize = 20;

/// Ceiling across all deployments, so the fleet as a whole cannot pin unbounded
/// memory in job records. Reached only when thousands of deployments each have
/// recent jobs; the per-deployment cap does the real work.
const HISTORY_LIMIT: usize = 2_000;
/// Log lines kept per record. Enough to hold a compiler error or a failing
/// `RUN` step, not enough for a full `docker build` transcript.
const LOG_LIMIT: usize = 400;
/// How deep to look for a Dockerfile when the spec doesn't name one.
const SEARCH_DEPTH: usize = 3;
/// Directories that never contain the Dockerfile you meant.
const SKIP_DIRS: [&str; 6] = [".git", "node_modules", "target", "vendor", "dist", ".venv"];
/// Grace before the first post-update health probe. A service that was just
/// restarted may still have its predecessor's listener up for a moment, and a
/// probe that lands there would verify the process being replaced.
const VERIFY_SETTLE: Duration = Duration::from_secs(2);
/// Gap between verification probes.
const VERIFY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobKind {
    /// Build a guest image from git + a Dockerfile (managed deployments).
    ImageBuild,
    /// Materialize content from an artifact store: a guest rootfs for a managed
    /// deployment, an unpacked bundle for a site.
    ArtifactPull,
    /// Run commands in a working directory on this host (static deployments and
    /// sites).
    HostUpdate,
    /// Materialize a managed deployment's guest mounts from an artifact store,
    /// and roll the pool onto the trees that came out.
    ///
    /// Its own kind rather than part of [`Self::ArtifactPull`] because the two
    /// answer different questions and a deployment can want both: a pull decides
    /// which *rootfs* the guests boot, this decides which *data* they boot with,
    /// and neither implies the other.
    MountPull,
}

impl JobKind {
    fn label(self) -> &'static str {
        match self {
            Self::ImageBuild => "build",
            Self::ArtifactPull => "pull",
            Self::HostUpdate => "update",
            Self::MountPull => "mounts",
        }
    }

    /// Whether this kind of job means anything for that kind of backend.
    ///
    /// Deliberately a table rather than a pair of `is_managed()` comparisons,
    /// because the mapping stopped being one-to-one when sites learned to pull:
    /// two kinds apply to a site, and `ArtifactPull` applies to two backends. A
    /// predicate that answers "managed?" cannot express either.
    fn applies_to(self, backend: Backend) -> bool {
        match self {
            // A guest image from a Dockerfile for a VM; a git checkout copied
            // into the root for a site.
            Self::ImageBuild => matches!(backend, Backend::Vm | Backend::Site),
            // A rootfs for a VM, a directory tree for a site. What a static
            // deployment proxies to is somebody else's process, with neither.
            Self::ArtifactPull => matches!(backend, Backend::Vm | Backend::Site),
            // Commands in a directory on this host. A VM's backend is not here.
            Self::HostUpdate => matches!(backend, Backend::Upstreams | Backend::Site),
            // Trees mounted inside a guest. Only a VM has a guest.
            Self::MountPull => backend == Backend::Vm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Running,
    Succeeded,
    Failed,
}

/// One job, as the admin API reports it.
///
/// The kind-specific fields are omitted rather than nulled, so a `host-update`
/// record doesn't carry six empty image fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JobRecord {
    pub id: String,
    pub deployment: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    /// Caller correlation for durable, idempotent pulls. Absent for legacy jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_namespace: Option<String>,
    /// SHA-256 of the immutable requested artifact and deployment template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_fingerprint: Option<String>,
    /// Template fingerprint captured before any artifact or VM effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_fingerprint: Option<String>,
    /// Exact source spec, including the image, checked under the mutation lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_spec_fingerprint: Option<String>,
    /// True only after a healthy replacement from this rollout is observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_verified: Option<bool>,
    /// A restart found this operation in flight and cannot prove its outcome.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reconciliation_required: bool,

    // -- image-build ------------------------------------------------------
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// What was asked for (`main`, a tag, a sha), or `None` for the remote's
    /// default branch.
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// What it resolved to. The answer to "which commit is live?".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Dockerfile path relative to the checkout, once located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Whether `vm.image` was updated and the pool told to roll. Set by both
    /// image sources — it describes the roll-out, not how the image was made.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rolled_out: bool,

    // -- artifact-pull ----------------------------------------------------
    /// The store this pulled from, URL or path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// What was asked for: a tag or a digest.
    #[serde(rename = "artifact", skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// What it resolved to. The artifact counterpart of `commit`, and the answer
    /// to "which bytes are live?" — a tag can move, a digest cannot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Bytes transferred or copied. `0` with `reused` set means the
    /// content-addressed image was already on disk and nothing moved; `0`
    /// without it means a local store hardlinked the blob instead of copying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Whether the fetch was skipped because the content was already present.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
    /// The directory a site's bundle was unpacked into. Only a site pull sets
    /// it — for a managed deployment the pull's destination is `image`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_root: Option<String>,
    /// Regular files unpacked. The site pull's answer to "did this deploy what
    /// I think it did?", which `bytes` cannot give when the blob was hardlinked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,

    // -- mount-pull -------------------------------------------------------
    /// One entry per guest mount, in spec order. A mount pull covers all of a
    /// deployment's mounts in one job, and the single `digest`/`store` fields
    /// above cannot describe eight of them — so this is the record, and those
    /// stay empty on a mount pull.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountOutcome>,

    // -- host-update ------------------------------------------------------
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands_total: Option<usize>,
    /// How many commands finished successfully — which command failed, without
    /// reading the log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands_run: Option<usize>,
    /// Whether the upstreams answered a health probe afterwards. `None` when
    /// verification was switched off or the job never got that far.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,

    pub error: Option<String>,
    /// Tail of the combined output of every step.
    pub log: Vec<String>,
}

/// What one guest mount's pull did, as the admin API reports it.
///
/// Deliberately the whole story per mount rather than a total across them: with
/// several mounts on one deployment, "3 GB transferred" answers nothing, and
/// which of them moved is the entire question when a pull takes longer than
/// expected.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MountOutcome {
    /// The guest path, which is the mount's identity within the deployment.
    pub path: String,
    pub store: String,
    #[serde(rename = "ref")]
    pub artifact_ref: String,
    /// What the ref resolved to, and what was written back into the spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The tree on this host the guests will mount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tree: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,
    /// Bytes transferred from the store. `0` with `reused` set means the tree
    /// was already here; `0` without it means a local store hardlinked the
    /// bundle rather than copying it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Uncompressed bytes in the tree — how much disk this mount costs the host,
    /// which `bytes` cannot answer for a gzipped bundle or a hardlinked one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpacked: Option<u64>,
    /// Whether the tree was already on this host and nothing was fetched.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
    /// Whether this mount's digest changed — the reason, or not, that the pool
    /// was recycled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub changed: bool,
}

impl JobRecord {
    fn new(id: String, deployment: String, kind: JobKind) -> Self {
        Self {
            id,
            deployment,
            kind,
            status: JobStatus::Running,
            started_at: now_secs(),
            finished_at: None,
            operation_id: None,
            target_namespace: None,
            intent_fingerprint: None,
            config_fingerprint: None,
            source_spec_fingerprint: None,
            readiness_verified: None,
            reconciliation_required: false,
            repo: None,
            git_ref: None,
            commit: None,
            dockerfile: None,
            image: None,
            rolled_out: false,
            store: None,
            artifact_ref: None,
            digest: None,
            bytes: None,
            reused: false,
            site_root: None,
            files: None,
            mounts: Vec::new(),
            working_dir: None,
            commands_total: None,
            commands_run: None,
            verified: None,
            error: None,
            log: Vec::new(),
        }
    }

    fn push_log(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > LOG_LIMIT {
            let overflow = self.log.len() - LOG_LIMIT;
            self.log.drain(0..overflow);
        }
    }
}

/// Why a job could not be *started*. A job that starts and then fails is a
/// record with `status: failed`, not one of these.
#[derive(Debug)]
pub enum StartError {
    NoDeployment(String),
    /// The deployment is the wrong kind for this job. Carries the backend it
    /// actually has, because "wrong kind" is only useful with what it is
    /// instead — and with three backends and three job kinds, the message
    /// cannot be inferred from the job kind alone.
    WrongKind {
        id: String,
        kind: JobKind,
        backend: Backend,
    },
    NoSpec {
        id: String,
        kind: JobKind,
    },
    AlreadyRunning(String),
    BadRef(String),
    ConflictingOperation(String),
    Persistence(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDeployment(id) => write!(f, "no deployment {id:?}"),
            Self::WrongKind {
                id,
                kind: JobKind::ImageBuild,
                backend,
            } => write!(
                f,
                "deployment {id:?} {}, so it has no guest image to build. {}",
                describe_backend(*backend),
                match backend {
                    Backend::Site => "Use `pull` to unpack a bundle from an artifact store, \
                                      or `update` to build on this host",
                    _ => "Use `update` to run commands on the host instead",
                }
            ),
            Self::WrongKind {
                id,
                kind: JobKind::ArtifactPull,
                backend,
            } => write!(
                f,
                "deployment {id:?} {}, so there is nothing for a pull to land in — it \
                 forwards to upstreams somebody else runs. Use `update` to run commands on \
                 the host instead",
                describe_backend(*backend),
            ),
            Self::WrongKind {
                id,
                kind: JobKind::HostUpdate,
                backend,
            } => write!(
                f,
                "deployment {id:?} {}; its backends are microVMs, not processes on this \
                 host. Use `build` or `pull` to change its image",
                describe_backend(*backend),
            ),
            Self::WrongKind {
                id,
                kind: JobKind::MountPull,
                backend,
            } => write!(
                f,
                "deployment {id:?} {}, so it has no guest to mount anything inside. Mounts \
                 are a `vm` deployment's; a site serves its own files, and what a static \
                 deployment forwards to is somebody else's process",
                describe_backend(*backend),
            ),
            Self::NoSpec {
                id,
                kind: JobKind::MountPull,
            } => write!(
                f,
                "deployment {id:?} declares no `vm.mounts` — add one with a `path` inside \
                 the guest, a `store` and a `ref` naming a tarball, and this will unpack it"
            ),
            Self::NoSpec {
                id,
                kind: JobKind::ImageBuild,
            } => write!(
                f,
                "deployment {id:?} has no `build` block — set `build.repo` (and optionally \
                 `build.dockerfile`) to build from a git checkout, or `build.store` and \
                 `build.ref` to build a Dockerfile manifest out of an artifact store"
            ),
            Self::NoSpec {
                id,
                kind: JobKind::ArtifactPull,
            } => write!(
                f,
                "deployment {id:?} has no `artifact` block — set `artifact.store` (an \
                 `art serve` URL or a store root on this host) and `artifact.ref` on the \
                 spec first"
            ),
            Self::NoSpec {
                id,
                kind: JobKind::HostUpdate,
            } => write!(
                f,
                "deployment {id:?} has no `update` block — set `update.working_dir` and \
                 `update.commands` on the spec first"
            ),
            Self::AlreadyRunning(id) => write!(
                f,
                "a job for deployment {id:?} is already running; wait for it to finish"
            ),
            Self::BadRef(r) => write!(f, "{r}"),
            Self::ConflictingOperation(id) => write!(f, "operation_id {id:?} was already used with different artifact or deployment configuration"),
            Self::Persistence(e) => write!(f, "could not durably record deployment operation: {e}"),
        }
    }
}

/// A digest, short enough for a one-line job outcome.
fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fingerprint(value: &impl Serialize) -> String {
    // Feature unification can enable serde_json's preserve_order. Sort nested
    // objects explicitly so retry identity never depends on map insertion order.
    let mut value = serde_json::to_value(value).expect("job intent serializes");
    value.sort_all_objects();
    let bytes = serde_json::to_vec(&value).expect("job intent serializes");
    format!("{:x}", Sha256::digest(bytes))
}

/// Configuration a rollout must preserve. `vm.image` is the field the rollout
/// itself changes and `artifact.ref` is overridden by the pinned request.
fn deployment_config_fingerprint(spec: &crate::config::DeploymentSpec) -> String {
    let mut normalized = spec.clone();
    if let Some(vm) = normalized.vm.as_mut() {
        vm.image = None;
    }
    if let Some(artifact) = normalized.artifact.as_mut() {
        artifact.artifact_ref.clear();
    }
    fingerprint(&normalized)
}

fn persist_job(dir: &Path, record: &JobRecord) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.json", record.id));
    let temporary = dir.join(format!("{}.json.tmp", record.id));
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    use std::io::Write;
    let mut file = std::fs::File::create(&temporary).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
    std::fs::File::open(dir).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())
}

fn load_durable_jobs(dir: &Path) -> Result<Vec<JobRecord>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
        records.push(serde_json::from_slice(&bytes).map_err(|e| format!("unreadable durable job {}: {e}", entry.path().display()))?);
    }
    records.sort_by_key(|r: &JobRecord| r.started_at);
    Ok(records)
}

/// What a build source produced, which is all `heyvm mvm build` needs.
///
/// The narrow waist between the two sources: whatever a git checkout and an
/// artifact store had to do to get here, from this point on a build is the same
/// build. Adding a field is the test of whether a difference between the sources
/// is real — `size_mb` is, because only a manifest can carry a default; a
/// `commit` field would not be, because the image name is all it was ever for.
struct Prepared {
    dockerfile: PathBuf,
    context: PathBuf,
    /// What the image is named after: a commit, or a manifest digest.
    version: String,
    /// A `--size-mb` default carried by the source itself. Overridden by
    /// `build.image_size_mb` when the spec sets one.
    size_mb: Option<u64>,
}

/// A backend as it appears mid-sentence in a "wrong kind of deployment" error.
fn describe_backend(backend: Backend) -> &'static str {
    match backend {
        Backend::Vm => "is a managed VM pool",
        Backend::Upstreams => "is static (proxy_pass)",
        Backend::Site => "is a site: it serves files off disk",
    }
}

impl std::error::Error for StartError {}

pub struct JobConfig {
    /// Parent of the per-deployment checkouts.
    pub work_dir: PathBuf,
    pub heyvm_bin: String,
    /// The `art` CLI, for pulling from a store on this host.
    pub art_bin: String,
    /// app-lb's own scratch for images on their way to the daemon: a pull
    /// fetches here and a build (`heyvm mvm build` with `MVM_DATA_DIR` set
    /// to it) writes here, then the result is uploaded into the daemon's
    /// catalog (`PUT /images/:name`) and removed. Nothing the daemon reads.
    pub images_dir: PathBuf,
    pub git_bin: String,
    /// Where guest mount trees are unpacked. Unlike `images_dir` this is not a
    /// `Result`: it is app-lb's own directory and it was created at startup, so
    /// there is nothing left to resolve here.
    pub mounts: crate::mounts::MountStore,
    /// Shell that host-update commands are run through.
    pub shell: String,
    pub timeout: Duration,
    /// `HOME` for child processes, when app-lb and heyvmd run as different users.
    pub home: Option<String>,
    /// app-lb's own directory for site roots (`APP_LB_SITES_DIR`). A site
    /// `build` whose root is inside it gets its parent directories created;
    /// anywhere else they must already exist, as for an artifact pull.
    pub sites_dir: Option<PathBuf>,
}

pub struct Jobs {
    cfg: JobConfig,
    /// Built once and shared: it holds an HTTP client whose connection pool is
    /// worth keeping between pulls of the same store.
    puller: Puller,
    registry: Arc<Registry>,
    autoscaler: Arc<Autoscaler>,
    secrets: Arc<SecretStore>,
    history: Mutex<VecDeque<JobRecord>>,
    durable_dir: PathBuf,
    durable_error: Option<String>,
    /// Deployment ids with a job in flight.
    running: Mutex<HashSet<String>>,
    /// Mirrors step output into app-obs, so a transcript outlives this process's
    /// bounded in-memory history. `None` when log shipping is off.
    obs: Option<crate::obs::LogSink>,
}

impl Jobs {
    pub fn new(
        cfg: JobConfig,
        registry: Arc<Registry>,
        autoscaler: Arc<Autoscaler>,
        secrets: Arc<SecretStore>,
        obs: Option<crate::obs::LogSink>,
    ) -> Self {
        let durable_dir = registry.state_dir().join("jobs");
        let (mut history, mut durable_error) = match load_durable_jobs(&durable_dir) {
            Ok(history) => (history, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        for record in &mut history {
            if record.status == JobStatus::Running {
                record.status = JobStatus::Failed;
                record.finished_at = Some(now_secs());
                record.reconciliation_required = true;
                record.readiness_verified = Some(false);
                record.error = Some("app-lb restarted while this rollout was running; outcome is uncertain and reconciliation is required; destructive work was not replayed".into());
                if let Err(error) = persist_job(&durable_dir, record) {
                    durable_error = Some(error);
                }
            }
        }
        if let Some(error) = &durable_error {
            tracing::error!(%error, "correlated pulls disabled: durable job history needs repair");
        }
        Self {
            puller: Puller::new(
                cfg.art_bin.clone(),
                cfg.images_dir.clone(),
                cfg.home.clone(),
                autoscaler.vms().clone(),
            ),
            cfg,
            registry,
            autoscaler,
            secrets,
            history: Mutex::new(history.into()),
            durable_dir,
            durable_error,
            running: Mutex::new(HashSet::new()),
            obs,
        }
    }

    /// Jobs newest-first, optionally for one deployment.
    /// Return the newest record first.
    pub fn records(&self, deployment: Option<&str>) -> Vec<JobRecord> {
        self.history
            .lock()
            .expect("job history mutex poisoned")
            .iter()
            .rev()
            .filter(|r| deployment.is_none_or(|d| r.deployment == d))
            .cloned()
            .collect()
    }

    pub fn record(&self, job_id: &str) -> Option<JobRecord> {
        self.history
            .lock()
            .expect("job history mutex poisoned")
            .iter()
            .find(|r| r.id == job_id)
            .cloned()
    }

    /// Build a managed deployment's guest image, then roll the pool onto it.
    ///
    /// Asynchronous by necessity: a `docker build` takes minutes, and an admin
    /// API that blocks that long would time out in every client. Progress is
    /// polled through `GET /jobs/:id`.
    pub fn start_build(
        self: &Arc<Self>,
        deployment_id: &str,
        ref_override: Option<String>,
    ) -> Result<JobRecord, StartError> {
        let deployment = self.claimable(deployment_id, JobKind::ImageBuild)?;
        let Some(mut spec) = deployment.spec.build.clone() else {
            return Err(StartError::NoSpec {
                id: deployment_id.to_string(),
                kind: JobKind::ImageBuild,
            });
        };
        if let Some(r) = ref_override {
            // A one-off ref does not touch the stored spec — `POST …/build
            // {"ref": "v2.1"}` builds that tag without making it the default.
            spec.source_ref = Some(r);
            // The stored spec was validated on registration; an override was not.
            // This is also what refuses a git ref on a store source and vice
            // versa: the two have different rules and the same field.
            let probe = crate::config::DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                build: Some(spec.clone()),
                ..deployment.spec.clone()
            };
            probe.validate().map_err(|e| StartError::BadRef(e.to_string()))?;
        }

        // The record says up front which source this build is using, so a job
        // list distinguishes the two without waiting for the first log line.
        let source_ref = spec.source_ref.clone();
        let repo = spec.repo.clone();
        let store = spec.store.clone();
        self.spawn(deployment_id, JobKind::ImageBuild, move |r| {
            match (repo, store) {
                (Some(repo), _) => {
                    r.repo = Some(repo);
                    r.git_ref = source_ref;
                }
                (None, store) => {
                    r.store = store;
                    r.artifact_ref = source_ref;
                }
            }
        }, move |jobs, job_id, deployment_id| async move {
            jobs.run_build(&job_id, &deployment_id, &spec).await
        })
    }

    /// Pull a managed deployment's guest rootfs from an artifact store, then
    /// roll the pool onto it.
    ///
    /// The same shape as [`start_build`](Self::start_build), including the
    /// one-off reference override: `POST …/pull {"ref": "web-v2"}` pulls that
    /// tag without making it the deployment's default, which is what a rollback
    /// to a known digest looks like.
    ///
    /// `force` re-fetches even when the content-addressed image is already on
    /// disk. There is normally no reason to — the filename *is* the digest — so
    /// it exists for the one case the name cannot describe: a file that was
    /// damaged after it was written.
    pub fn start_pull(
        self: &Arc<Self>,
        deployment_id: &str,
        ref_override: Option<String>,
        force: bool,
    ) -> Result<JobRecord, StartError> {
        let deployment = self.claimable(deployment_id, JobKind::ArtifactPull)?;
        let Some(mut spec) = deployment.spec.artifact.clone() else {
            return Err(StartError::NoSpec {
                id: deployment_id.to_string(),
                kind: JobKind::ArtifactPull,
            });
        };
        if let Some(r) = ref_override {
            spec.artifact_ref = r;
            // The stored spec was validated on registration; an override was not.
            let probe = crate::config::DeploymentSpec {
                ingress: None,
                account_id: None,
                user_id: None,
                artifact: Some(spec.clone()),
                ..deployment.spec.clone()
            };
            probe.validate().map_err(|e| StartError::BadRef(e.to_string()))?;
        }

        let store = spec.store.clone();
        let reference = spec.artifact_ref.clone();
        self.spawn(
            deployment_id,
            JobKind::ArtifactPull,
            move |r| {
                r.store = Some(store);
                r.artifact_ref = Some(reference);
            },
            move |jobs, job_id, deployment_id| async move {
                jobs.run_pull(&job_id, &deployment_id, &spec, force).await
            },
        )
    }

    /// Durable, caller-correlated pull. Unlike the legacy form this requires a
    /// digest and does not consider installation alone a successful rollout.
    pub fn start_correlated_pull(
        self: &Arc<Self>,
        deployment_id: &str,
        operation_id: String,
        digest: String,
        force: bool,
    ) -> Result<JobRecord, StartError> {
        if let Some(error) = &self.durable_error {
            return Err(StartError::Persistence(error.clone()));
        }
        if operation_id.trim().is_empty() || operation_id.len() > 200 {
            return Err(StartError::BadRef("operation_id must be 1..=200 characters".into()));
        }
        if !is_sha256_digest(&digest) {
            return Err(StartError::BadRef("correlated pulls require `ref` to be a pinned 64-character lowercase SHA-256 digest".into()));
        }
        let deployment = self.claimable(deployment_id, JobKind::ArtifactPull)?;
        if deployment.spec.vm.is_none() {
            return Err(StartError::BadRef("correlated pulls require a managed VM deployment".into()));
        }
        if deployment.desired_replicas() == 0 {
            return Err(StartError::BadRef("correlated pulls require a non-zero desired replica target; app-lb will not invent scaling demand".into()));
        }
        let Some(mut artifact) = deployment.spec.artifact.clone() else {
            return Err(StartError::NoSpec { id: deployment_id.into(), kind: JobKind::ArtifactPull });
        };
        artifact.artifact_ref = digest.clone();
        let config_fingerprint = deployment_config_fingerprint(&deployment.spec);
        let intent_fingerprint = fingerprint(&(digest.clone(), force, &config_fingerprint));

        let mut running = self.running.lock().expect("job slot mutex poisoned");
        if self.registry.get(deployment_id).is_some_and(|d| crate::rollout::reserved(&d)) {
            return Err(StartError::AlreadyRunning(deployment_id.into()));
        }
        let mut history = self.history.lock().expect("job history mutex poisoned");
        if let Some(existing) = history.iter().find(|r| {
            r.deployment == deployment_id
                && r.target_namespace.as_deref() == Some(&deployment.spec.namespace)
                && r.operation_id.as_deref() == Some(&operation_id)
        }) {
            return if existing.intent_fingerprint.as_deref() == Some(&intent_fingerprint) {
                Ok(existing.clone())
            } else {
                Err(StartError::ConflictingOperation(operation_id))
            };
        }
        if !running.insert(deployment_id.to_string()) {
            return Err(StartError::AlreadyRunning(deployment_id.to_string()));
        }
        let mut record = JobRecord::new(new_job_id(), deployment_id.into(), JobKind::ArtifactPull);
        record.operation_id = Some(operation_id);
        record.target_namespace = Some(deployment.spec.namespace.clone());
        record.intent_fingerprint = Some(intent_fingerprint);
        record.config_fingerprint = Some(config_fingerprint.clone());
        record.source_spec_fingerprint = Some(fingerprint(&deployment.spec));
        record.store = Some(artifact.store.clone());
        record.artifact_ref = Some(digest.clone());
        history.push_back(record.clone());
        trim_history(&mut history, deployment_id);
        if let Err(e) = persist_job(&self.durable_dir, &record) {
            // Rename may have succeeded before directory sync failed. Keep
            // the identity reserved even though no worker will be started.
            let failed = history.iter_mut().find(|r| r.id == record.id).expect("record just inserted");
            failed.status = JobStatus::Failed;
            failed.finished_at = Some(now_secs());
            failed.reconciliation_required = true;
            failed.readiness_verified = Some(false);
            failed.error = Some(format!("submission persistence failed; no worker started: {e}"));
            running.remove(deployment_id);
            return Err(StartError::Persistence(e));
        }
        drop(history);
        drop(running);

        let jobs = self.clone();
        let job_id = record.id.clone();
        let deployment_id = deployment_id.to_string();
        tokio::spawn(async move {
            let _slot = JobSlot { jobs: jobs.clone(), deployment: deployment_id.clone() };
            let result = jobs.run_pull(&job_id, &deployment_id, &artifact, force).await;
            match result {
                Ok(_) => jobs.finish(&job_id, JobStatus::Succeeded, None),
                Err(e) => jobs.finish(&job_id, JobStatus::Failed, Some(e)),
            }
        });
        Ok(record)
    }

    /// Materialize every guest mount a managed deployment declares, then roll the
    /// pool onto the trees.
    ///
    /// One job for all of them rather than one per mount, because they are one
    /// question: a deployment either has the data it says it has or it does not,
    /// and half a set of mounts is not a state to leave a pool in. The record
    /// carries a per-mount outcome so a slow pull is still attributable.
    ///
    /// Unlike a build or a rootfs pull there is **no one-off reference
    /// override**. Those rewrite `vm.image`, a single field, and "pull this tag
    /// just once" is a coherent thing to ask of it. With several mounts an
    /// override would have to say which one it meant, and a rollback is already
    /// expressible in the place it belongs: pin `digest`, or move `ref`.
    ///
    /// `force` re-fetches trees already on this host; see
    /// [`crate::artifact::Puller::pull_mount`].
    pub fn start_mount_pull(
        self: &Arc<Self>,
        deployment_id: &str,
        force: bool,
    ) -> Result<JobRecord, StartError> {
        let deployment = self.claimable(deployment_id, JobKind::MountPull)?;
        let mounts: Vec<MountSpec> = deployment
            .spec
            .vm
            .as_ref()
            .map(|vm| vm.mounts.clone())
            .unwrap_or_default();
        if mounts.is_empty() {
            return Err(StartError::NoSpec {
                id: deployment_id.to_string(),
                kind: JobKind::MountPull,
            });
        }

        // The record lists every mount before the first byte moves, so a job
        // that is still running says what it is working through rather than
        // growing a list as it goes.
        let planned: Vec<MountOutcome> = mounts
            .iter()
            .map(|m| MountOutcome {
                path: m.guest_path().to_string(),
                store: m.store.clone(),
                artifact_ref: m.artifact_ref.clone(),
                digest: None,
                tree: None,
                files: None,
                bytes: None,
                unpacked: None,
                reused: false,
                changed: false,
            })
            .collect();

        self.spawn(
            deployment_id,
            JobKind::MountPull,
            move |r| {
                r.mounts = planned;
            },
            move |jobs, job_id, deployment_id| async move {
                jobs.run_mount_pull(&job_id, &deployment_id, mounts, force).await
            },
        )
    }

    /// Whether this deployment has a mount with no tree on this host — the
    /// condition under which its pool cannot be created at all.
    ///
    /// The admin API asks this on register and on edit so the pull that fixes it
    /// starts by itself, rather than leaving an operator to discover the reason
    /// their pool is empty in the autoscaler's error line.
    pub fn mounts_need_pulling(&self, spec: &crate::config::DeploymentSpec) -> bool {
        spec.vm
            .as_ref()
            .is_some_and(|vm| vm.mounts.iter().any(|m| self.cfg.mounts.resolve(m).is_none()))
    }

    pub fn with_rollout_slot<T>(&self, id: &str, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let running = self.running.lock().expect("job slot mutex poisoned");
        if running.contains(id) { return Err("legacy deployment job is running".into()); }
        f()
    }

    /// Materialize privately: never install a spec or recycle its serving pool.
    /// Force verification rather than trusting catalog name/size reuse.
    pub async fn prepare_candidate(&self, spec: &crate::config::DeploymentSpec, generation: &str, progress: tokio::sync::watch::Sender<String>) -> Result<crate::config::DeploymentSpec, String> {
        let mut puller = self.puller.for_candidate()?;
        puller.preparation_progress = Some(progress.clone());
        let mut prepared = spec.clone();
        let mut artifact = spec.artifact.clone().ok_or("pinned rootfs artifact required")?;
        artifact.image_name = Some(format!("rollout-{}", generation));
        progress.send_replace("rootfs_credentials".into());
        let key = self.store_key(artifact.auth.as_ref())?;
        progress.send_replace("rootfs_manifest".into());
        artifact.artifact_ref = puller.pinned_rootfs(&artifact, key.as_deref()).await?;
        let mut log = |_: String| {};
        let pulled = puller.pull(&spec.id, &artifact, key.as_deref(), true, &mut log).await?;
        if pulled.digest != artifact.artifact_ref { return Err("rootfs blob differs from pinned manifest".into()); }
        let vm = prepared.vm.as_mut().ok_or("managed VM required")?;
        vm.image = Some(pulled.image);
        vm.image_download_url = None;
        vm.image_sha256 = None;
        vm.image_size_bytes = None;
        for mount in &spec.vm_spec().mounts {
            progress.send_replace("mount_credentials".into());
            let key = self.store_key(mount.auth.as_ref())?;
            progress.send_replace("mount_materialization".into());
            let pulled = puller.pull_mount(mount, &self.cfg.mounts, key.as_deref(), true, &mut log).await?;
            if Some(&pulled.digest) != mount.digest.as_ref() { return Err("mount digest differs from requested artifact".into()); }
        }
        Ok(prepared)
    }

    /// Run a static deployment's update commands on this host.
    pub fn start_update(
        self: &Arc<Self>,
        deployment_id: &str,
    ) -> Result<JobRecord, StartError> {
        let deployment = self.claimable(deployment_id, JobKind::HostUpdate)?;
        let Some(spec) = deployment.spec.update.clone() else {
            return Err(StartError::NoSpec {
                id: deployment_id.to_string(),
                kind: JobKind::HostUpdate,
            });
        };

        let working_dir = spec.working_dir.clone();
        let total = spec.commands.len();
        self.spawn(deployment_id, JobKind::HostUpdate, move |r| {
            r.working_dir = Some(working_dir);
            r.commands_total = Some(total);
            r.commands_run = Some(0);
        }, move |jobs, job_id, deployment_id| async move {
            jobs.run_update(&job_id, &deployment_id, &spec).await
        })
    }

    /// The shared checks every job start makes: the deployment exists and is the
    /// right kind for this job.
    fn claimable(
        &self,
        deployment_id: &str,
        kind: JobKind,
    ) -> Result<Arc<Deployment>, StartError> {
        let Some(deployment) = self.registry.get(deployment_id) else {
            return Err(StartError::NoDeployment(deployment_id.to_string()));
        };
        if crate::rollout::reserved(&deployment) { return Err(StartError::AlreadyRunning(deployment_id.into())); }
        let backend = deployment.spec.backend();
        if !kind.applies_to(backend) {
            return Err(StartError::WrongKind {
                id: deployment_id.to_string(),
                kind,
                backend,
            });
        }
        Ok(deployment)
    }

    /// Claim the deployment's job slot, record the job, and spawn it.
    ///
    /// The slot is taken before spawning, so two concurrent requests cannot both
    /// see "not running", and released by `JobSlot`'s drop however the task
    /// ends — panic included.
    fn spawn<F, Fut>(
        self: &Arc<Self>,
        deployment_id: &str,
        kind: JobKind,
        describe: impl FnOnce(&mut JobRecord),
        run: F,
    ) -> Result<JobRecord, StartError>
    where
        F: FnOnce(Arc<Self>, String, String) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        {
            let mut running = self.running.lock().expect("job slot mutex poisoned");
            if self.registry.get(deployment_id).is_some_and(|d| crate::rollout::reserved(&d)) {
                return Err(StartError::AlreadyRunning(deployment_id.into()));
            }
            if !running.insert(deployment_id.to_string()) {
                return Err(StartError::AlreadyRunning(deployment_id.to_string()));
            }
        }

        let mut record = JobRecord::new(new_job_id(), deployment_id.to_string(), kind);
        describe(&mut record);
        {
            let mut history = self.history.lock().expect("job history mutex poisoned");
            history.push_back(record.clone());
            trim_history(&mut history, deployment_id);
        }

        let jobs = self.clone();
        let job_id = record.id.clone();
        let deployment_id = deployment_id.to_string();
        tokio::spawn(async move {
            let _retirement=jobs.registry.retirement_gate.read().await;
            let _slot = JobSlot {
                jobs: jobs.clone(),
                deployment: deployment_id.clone(),
            };
            if jobs.registry.retirement_frozen(&deployment_id) {
                jobs.finish(&job_id,JobStatus::Failed,Some("deployment permanently frozen for retirement".into()));
                return;
            }
            // Arbitrary host jobs are not a complete allocation/effect ledger.
            // Remember this across restart, not only in the bounded job history.
            if let Some(d)=jobs.registry.get(&deployment_id) {
                d.mutate_state(|s|s.allocation_history_complete=false);
                if jobs.registry.persist_one(&deployment_id).is_err() {
                    jobs.finish(&job_id,JobStatus::Failed,Some("cannot persist worker effect intent".into()));
                    return;
                }
            }
            let started = std::time::Instant::now();
            match run(jobs.clone(), job_id.clone(), deployment_id.clone()).await {
                Ok(outcome) => {
                    tracing::info!(
                        deployment = %deployment_id,
                        job = %job_id,
                        kind = kind.label(),
                        outcome = %outcome,
                        elapsed_s = started.elapsed().as_secs(),
                        "job succeeded",
                    );
                    jobs.finish(&job_id, JobStatus::Succeeded, None);
                }
                Err(e) => {
                    tracing::error!(
                        deployment = %deployment_id,
                        job = %job_id,
                        kind = kind.label(),
                        error = %e,
                        elapsed_s = started.elapsed().as_secs(),
                        "job failed",
                    );
                    jobs.finish(&job_id, JobStatus::Failed, Some(e));
                }
            }
        });

        Ok(record)
    }

    fn update_record(&self, job_id: &str, f: impl FnOnce(&mut JobRecord)) {
        let mut history = self.history.lock().expect("job history mutex poisoned");
        if let Some(r) = history.iter_mut().find(|r| r.id == job_id) {
            if r.reconciliation_required {
                return;
            }
            f(r);
            if r.operation_id.is_some() && let Err(e) = persist_job(&self.durable_dir, r) {
                tracing::error!(job = %job_id, error = %e, "failed to persist correlated job update");
                r.status = JobStatus::Failed;
                r.reconciliation_required = true;
                r.readiness_verified = Some(false);
                r.error = Some(format!("could not persist rollout status; reconciliation required: {e}"));
            }
        }
    }

    /// Record one line of a job's output — in the record, and in app-obs.
    ///
    /// The deployment id is read off the record rather than passed in, so a line
    /// can only be attributed to a job that is still in the history; one whose
    /// record has aged out has nowhere honest to go and is dropped with it.
    fn log(&self, job_id: &str, line: impl Into<String>) {
        let line = line.into();
        // Only pay for the copy when there is somewhere to send it.
        let shipped = self.obs.is_some().then(|| line.clone());
        let mut deployment = None;
        self.update_record(job_id, |r| {
            deployment = Some(r.deployment.clone());
            r.push_log(line);
        });

        if let (Some(sink), Some(line), Some(deployment)) = (&self.obs, shipped, deployment) {
            sink.send(crate::obs::job_line(&deployment, job_id, line));
        }
    }

    fn finish(&self, job_id: &str, status: JobStatus, error: Option<String>) {
        self.update_record(job_id, |r| {
            r.status = status;
            r.finished_at = Some(now_secs());
            r.error = error;
        });
    }

    // -- image builds ------------------------------------------------------

    /// The build itself. Every error is a string because it goes straight into
    /// the record for a human to read.
    ///
    /// Two sources produce the same three things — a Dockerfile path, a context
    /// directory, and a version string to name the image after — and everything
    /// downstream of that is identical. So the sources diverge only for as long
    /// as they must, and `heyvm mvm build` is driven from one place: a second
    /// copy of the invocation is a second place for `--local-only` to be
    /// forgotten.
    async fn run_build(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &BuildSpec,
    ) -> Result<String, String> {
        if let Some(site) = self.registry.get(deployment_id).and_then(|d| d.spec.site.clone()) {
            return self.run_site_build(job_id, deployment_id, spec, &site).await;
        }
        let prepared = match spec.source().ok_or_else(|| {
            // Unreachable through the admin API, which validates on registration
            // and on a ref override. Reachable by hand-editing the state file.
            format!(
                "deployment {deployment_id:?} has a `build` block with neither `repo` nor \
                 `store` set, so there is no Dockerfile to build"
            )
        })? {
            BuildSource::Git { .. } => self.prepare_git_build(job_id, deployment_id, spec).await?,
            BuildSource::Dockerfile { store, reference } => {
                self.prepare_store_build(job_id, deployment_id, spec, store, reference)
                    .await?
            }
        };

        let image = spec.image_for(deployment_id, &prepared.version);
        self.update_record(job_id, |r| r.image = Some(image.clone()));

        // An application image rarely brings the PID 1 a Firecracker guest
        // boots (`init=/init.sh`); without one every VM panics and the pool
        // never fills. Supply the standard one when the Dockerfile has none.
        let mut prepared = prepared;
        match guest_init::supply(&prepared.dockerfile, &prepared.context) {
            Ok(Some(derived)) => {
                self.log(
                    job_id,
                    "the Dockerfile never mentions /init.sh, so app-lb adds its standard guest init \
                     (it starts nothing; the deployment's start_command starts the app)"
                        .to_string(),
                );
                prepared.dockerfile = derived;
            }
            Ok(None) => {}
            Err(e) => return Err(format!("cannot add the standard guest init: {e}")),
        }

        let mut cmd = tokio::process::Command::new(&self.cfg.heyvm_bin);
        cmd.arg("mvm")
            .arg("build")
            .arg("-f")
            .arg(&prepared.dockerfile)
            .arg("-c")
            .arg(&prepared.context)
            .arg("-n")
            .arg(&image)
            // Never upload: the image is consumed by the daemon on this host,
            // and a cloud push would need credentials app-lb does not have.
            .arg("--local-only")
            .current_dir(&prepared.context);
        // The spec wins over the manifest's annotation, which is only a default
        // recorded by whoever pushed the recipe; `build.image_size_mb` is the
        // operator of *this* deployment saying what its guest needs.
        if let Some(mb) = spec.image_size_mb.or(prepared.size_mb) {
            cmd.arg("--size-mb").arg(mb.to_string());
        }
        if let Some(home) = &self.cfg.home {
            cmd.env("HOME", home);
        }
        // The CLI installs its result under `$MVM_DATA_DIR/images/firecracker`.
        // Pointed at app-lb's own scratch, not the daemon's data directory:
        // the image reaches the daemon by upload, not by sharing a filesystem.
        cmd.env("MVM_DATA_DIR", &self.cfg.images_dir);
        self.step(job_id, "heyvm", cmd, self.cfg.timeout).await?;

        // -- upload ----------------------------------------------------------
        let built = self
            .cfg
            .images_dir
            .join("images")
            .join("firecracker")
            .join(format!("{image}.ext4"));
        let size = tokio::fs::metadata(&built)
            .await
            .map_err(|e| {
                format!(
                    "heyvm mvm build reported success but left no image at {}: {e}",
                    built.display()
                )
            })?
            .len();
        self.log(job_id, format!("uploading {} ({size} bytes) to the daemon", built.display()));
        let installed = self
            .autoscaler
            .vms()
            .upload_image(&image, &built, &heyo_sdk::ImageUploadOptions::default())
            .await
            .map_err(|e| format!("could not upload {image} to the daemon: {e}"))?;
        let _ = tokio::fs::remove_file(&built).await;
        self.log(job_id, format!("installed as {} on the daemon", installed.path));

        // -- roll out --------------------------------------------------------
        self.roll_out(job_id, deployment_id, &image).await?;
        Ok(image)
    }

    /// Where app-lb keeps the site roots it manages, if anywhere.
    pub fn sites_dir(&self) -> Option<&Path> {
        self.cfg.sites_dir.as_deref()
    }

    /// A site's build: check the repo out and copy `build.context` (default:
    /// the whole checkout) into `site.root` with the staged swap an artifact
    /// pull uses. Nothing in the checkout is run, so a repo cannot execute
    /// anything on this host by being deployed.
    async fn run_site_build(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &BuildSpec,
        site: &crate::config::SiteSpec,
    ) -> Result<String, String> {
        let checkout = self.cfg.work_dir.join(sanitize_dir(deployment_id));
        crate::tls::create_dir_private(&checkout)
            .map_err(|e| format!("could not create {}: {e}", checkout.display()))?;
        let token = self.git_token(spec.auth.as_ref())?;
        let commit = self.checkout(job_id, &checkout, spec, token.as_ref()).await?;
        self.update_record(job_id, |r| r.commit = Some(commit.clone()));

        let src = match spec.context.as_deref().map(str::trim).filter(|c| !c.is_empty() && *c != ".") {
            Some(c) => checkout.join(c),
            None => checkout.clone(),
        };
        let root = PathBuf::from(site.root.trim());
        if let (Some(managed), Some(parent)) = (&self.cfg.sites_dir, root.parent())
            && root.starts_with(managed)
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
        }
        let index = site.index.trim().to_string();
        let context_shown = spec.context.clone().unwrap_or_else(|| ".".into());
        self.log(job_id, format!("copying {context_shown} at {} into {}", short(&commit), root.display()));
        let staged_root = root.clone();
        let unpacked = tokio::task::spawn_blocking(move || {
            let (staged, unpacked) = crate::unpack::stage_tree(&staged_root, &src)?;
            // Checked before the swap, as a pull does, so a checkout missing
            // its index is refused while the old tree is still serving.
            if !index.is_empty() && !staged.dir().join(&index).is_file() {
                return Err(format!(
                    "{context_shown} has no {index} at its top level; set build.context to the \
                     directory holding the built site (for example `dist`), or site.index to \
                     the file to serve for a directory"
                ));
            }
            staged.commit()?;
            // An artifact pull's digest marker would otherwise claim this tree.
            crate::unpack::forget_digest(&staged_root);
            Ok::<_, String>(unpacked)
        })
        .await
        .map_err(|e| format!("the copy task failed: {e}"))??;

        let shown = root.display().to_string();
        self.update_record(job_id, |r| {
            r.site_root = Some(shown.clone());
            r.files = Some(unpacked.files);
            r.bytes = Some(unpacked.bytes);
            r.verified = Some(true);
        });
        Ok(format!(
            "{} file{} from {} in {shown}",
            unpacked.files,
            if unpacked.files == 1 { "" } else { "s" },
            short(&commit)
        ))
    }

    /// Fetch a git checkout and find the Dockerfile in it.
    async fn prepare_git_build(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &BuildSpec,
    ) -> Result<Prepared, String> {
        let repo = spec.repo.as_deref().expect("a git source has a repo");
        let checkout = self.cfg.work_dir.join(sanitize_dir(deployment_id));
        crate::tls::create_dir_private(&checkout)
            .map_err(|e| format!("could not create {}: {e}", checkout.display()))?;

        let token = self.git_token(spec.auth.as_ref())?;
        // Said once per build rather than once per git command: an ssh remote
        // authenticates with the host's key material, so a secret here is a
        // credential somebody thinks is in use and isn't.
        if token.is_some() && is_ssh_remote(repo) {
            let note = "build.auth is set on an ssh remote; git authenticates with the host's \
                        key material and the secret is ignored";
            tracing::warn!(repo = %repo, "{note}");
            self.log(job_id, note);
        }

        let commit = self.checkout(job_id, &checkout, spec, token.as_ref()).await?;
        self.update_record(job_id, |r| r.commit = Some(commit.clone()));

        let (dockerfile, context) = locate_dockerfile(&checkout, spec)?;
        let shown = dockerfile
            .strip_prefix(&checkout)
            .unwrap_or(&dockerfile)
            .display()
            .to_string();
        self.update_record(job_id, |r| r.dockerfile = Some(shown.clone()));
        self.log(job_id, format!("using {shown} (context {})", context.display()));

        Ok(Prepared {
            dockerfile,
            context,
            version: commit,
            size_mb: None,
        })
    }

    /// Fetch a Dockerfile manifest from an artifact store and lay it out on disk.
    ///
    /// The image is named after the *manifest* digest rather than the recipe's,
    /// because the manifest is what covers the whole build input — the recipe,
    /// the context and the annotations together. Naming it after the Dockerfile
    /// alone would give two builds with different contexts the same image name.
    async fn prepare_store_build(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &BuildSpec,
        store: &str,
        reference: &str,
    ) -> Result<Prepared, String> {
        // Inside the deployment's own work directory, not beside it: a sibling
        // called `<id>-recipe` would collide with a deployment actually named
        // that, and nesting cannot, because the parent is already unique per
        // deployment.
        //
        // A subdirectory of the checkout rather than the checkout itself, so a
        // deployment that switches sources never unpacks a context over a git
        // tree — a `COPY` satisfied by a file the current recipe never shipped
        // is exactly what `git clean -xffdq` exists to prevent on the other
        // path. Switching the other way needs nothing: `git clean` removes this
        // directory along with everything else it did not put there.
        let deployment_dir = self.cfg.work_dir.join(sanitize_dir(deployment_id));
        // `0700` here rather than in the puller: a build context holds whatever
        // the person who pushed it put in it, and the mode is a property of
        // where app-lb stages work, not of how the bytes were fetched.
        crate::tls::create_dir_private(&deployment_dir)
            .map_err(|e| format!("could not create {}: {e}", deployment_dir.display()))?;
        let dir = deployment_dir.join(".recipe");

        let api_key = self.store_key(spec.auth.as_ref())?;
        if api_key.is_some() && !spec.store_is_remote() {
            let note = "build.auth is set on a local store; a store root is protected by file \
                        permissions, not by an API key, and the secret is unused";
            tracing::warn!(store = %store, "{note}");
            self.log(job_id, note);
        }

        let mut log = |line: String| self.log(job_id, line);
        let fetched = self
            .puller
            .fetch_dockerfile(store, reference, api_key.as_deref(), &dir, &mut log)
            .await?;

        self.update_record(job_id, |r| {
            r.digest = Some(fetched.manifest.clone());
            r.dockerfile = Some(crate::artifact::DOCKERFILE_ENTRY.to_string());
            r.bytes = Some(fetched.bytes_written);
            // The same question a site pull's `files` answers — "did this deploy
            // what I think it did?" — asked of the build's inputs. `bytes` cannot
            // answer it, because a local store hardlinks and transfers nothing.
            r.files = fetched.context_files;
        });

        Ok(Prepared {
            dockerfile: fetched.dockerfile,
            context: fetched.context,
            version: fetched.manifest,
            size_mb: fetched.size_mb,
        })
    }

    /// Fetch and check out, returning the resolved commit.
    async fn checkout(
        &self,
        job_id: &str,
        dir: &Path,
        spec: &BuildSpec,
        token: Option<&(String, String)>,
    ) -> Result<String, String> {
        let repo = spec
            .repo
            .as_deref()
            .ok_or("this build has no `repo`; a git checkout was asked for anyway")?;

        // `git init` on an existing repo just reinitializes it, so the checkout
        // directory survives between builds and a rebuild is a shallow fetch
        // rather than a fresh clone.
        let mut init = self.git(token);
        init.arg("init").arg("-q").arg(dir);
        self.step(job_id, "git", init, self.cfg.timeout).await?;

        let refspec = spec.source_ref.clone().unwrap_or_else(|| "HEAD".into());
        let fetch = |depth: Option<&str>| {
            let mut cmd = self.git(token);
            cmd.arg("-C").arg(dir).arg("fetch").arg("--no-tags").arg("--force");
            if let Some(d) = depth {
                cmd.arg("--depth").arg(d);
            }
            cmd.arg(repo).arg(&refspec);
            cmd
        };

        if let Err(shallow_err) = self.step(job_id, "git", fetch(Some("1")), self.cfg.timeout).await
        {
            // A raw commit sha can only be fetched directly if the server allows
            // it (`uploadpack.allowReachableSHA1InWant`); plenty don't. Falling
            // back to a full fetch turns "cannot deploy this commit" into
            // "deploying this commit is slower".
            if !looks_like_sha(&refspec) {
                return Err(shallow_err);
            }
            self.log(
                job_id,
                format!("shallow fetch of {refspec} was refused; retrying with full history"),
            );
            let mut full = self.git(token);
            full.arg("-C").arg(dir).arg("fetch").arg("--no-tags").arg("--force").arg(repo);
            self.step(job_id, "git", full, self.cfg.timeout).await?;
        }

        let mut checkout = self.git(token);
        checkout
            .arg("-C")
            .arg(dir)
            .arg("checkout")
            .arg("-q")
            .arg("--detach")
            .arg("--force")
            .arg(if spec.source_ref.is_some() && looks_like_sha(&refspec) {
                refspec.clone()
            } else {
                "FETCH_HEAD".into()
            });
        self.step(job_id, "git", checkout, self.cfg.timeout).await?;

        // Artefacts from a previous build of this checkout would otherwise land
        // in the docker context and, worse, could satisfy a `COPY` that the
        // current commit no longer produces.
        let mut clean = self.git(token);
        clean.arg("-C").arg(dir).arg("clean").arg("-xffdq");
        self.step(job_id, "git", clean, self.cfg.timeout).await?;

        let mut rev = self.git(token);
        rev.arg("-C").arg(dir).arg("rev-parse").arg("HEAD");
        let out = self.step(job_id, "git", rev, self.cfg.timeout).await?;
        let commit = out.trim().to_string();
        if commit.is_empty() {
            return Err("git rev-parse HEAD produced nothing".into());
        }
        Ok(commit)
    }

    /// Point the deployment at the new image and recycle its pool.
    ///
    /// Deliberately unconditional: rebuilding the same commit overwrites the same
    /// `<image>.ext4`, and running VMs hold a copy of the *old* rootfs, so
    /// "nothing changed in the spec" is not the same as "nothing changed". Same
    /// swap-then-teardown order as the admin API's update path — while the old
    /// deployment is still live the autoscaler would boot VMs into it.
    async fn roll_out(
        &self,
        job_id: &str,
        deployment_id: &str,
        image: &str,
    ) -> Result<Arc<Deployment>, String> {
        let change = self.registry.change_guard().await;
        let Some(old) = self.registry.get(deployment_id) else {
            return Err(format!(
                "deployment {deployment_id:?} was removed while its image was building; \
                 the image {image:?} was built but nothing is using it"
            ));
        };
        if crate::rollout::reserved(&old) { return Err("candidate rollout reserves this deployment".into()); }
        if self.autoscaler.workspaces().recovery_active(deployment_id) {
            return Err("workspace recovery reserves this deployment".into());
        }
        {
            let history = self.history.lock().expect("job history mutex poisoned");
            if let Some(record) = history.iter().find(|r| r.id == job_id && r.operation_id.is_some()) {
                if record.reconciliation_required {
                    return Err("rollout persistence failed; no VM replacement attempted".into());
                }
                if record.source_spec_fingerprint.as_deref() != Some(&fingerprint(&old.spec)) {
                    return Err("deployment changed since pull acceptance; no VM replacement attempted".into());
                }
            }
        }
        let mut spec = old.spec.clone();
        let Some(vm) = spec.vm.as_mut() else {
            return Err(format!(
                "deployment {deployment_id:?} is no longer a managed VM deployment"
            ));
        };
        let previous = vm.image.clone();
        vm.image = Some(image.to_string());

        let deployment = self.registry.upsert(spec);
        let persistence_error = self.registry.persist_one(&deployment.spec.id).err();
        if let Some(e) = &persistence_error {
            tracing::error!(error = %e, "failed to persist state after a build");
        }
        drop(change);
        self.autoscaler.teardown(&old).await;
        deployment.scale_signal.notify_one();

        self.update_record(job_id, |r| {
            r.rolled_out = true;
            r.push_log(format!(
                "vm.image {} -> {image}; pool recycling",
                previous.as_deref().unwrap_or("(daemon default)")
            ));
        });
        if let Some(error) = persistence_error {
            let correlated = self.history.lock().expect("job history mutex poisoned")
                .iter().any(|r| r.id == job_id && r.operation_id.is_some());
            if correlated {
                let error = format!("replacement started but deployment state could not be persisted; reconciliation required: {error}");
                self.update_record(job_id, |r| {
                    r.status = JobStatus::Failed;
                    r.finished_at = Some(now_secs());
                    r.reconciliation_required = true;
                    r.readiness_verified = Some(false);
                    r.error = Some(error.clone());
                });
                return Err(error);
            }
        }
        tracing::info!(
            deployment = %deployment_id,
            image = %image,
            previous = previous.as_deref().unwrap_or("(none)"),
            "rolled deployment onto its new image",
        );
        Ok(deployment)
    }

    // -- artifact pulls ----------------------------------------------------

    /// Resolve the reference, materialize the rootfs, roll the pool onto it.
    ///
    /// Shorter than a build because there is no source to fetch and nothing to
    /// compile — the work is entirely in [`crate::artifact`], and what is left
    /// here is the same "rewrite `vm.image` and recycle" ending a build has.
    async fn run_pull(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &ArtifactSpec,
        force: bool,
    ) -> Result<String, String> {
        // Resolved here rather than inside the puller, so the one place that
        // reads secrets is the one place that already does for a build.
        let api_key = self.store_key(spec.auth.as_ref())?;

        // A site's artifact is a directory tree rather than a guest rootfs, and
        // everything after the resolve differs: where the bytes land, what
        // proves they landed, and whether there is a pool to roll afterwards.
        if let Some(site) = self.registry.get(deployment_id).and_then(|d| d.spec.site.clone()) {
            return self.run_site_pull(job_id, spec, &site, api_key.as_deref(), force).await;
        }

        let mut log = |line: String| self.log(job_id, line);
        let pulled = self
            .puller
            .pull(deployment_id, spec, api_key.as_deref(), force, &mut log)
            .await?;

        self.update_record(job_id, |r| {
            r.digest = Some(pulled.digest.clone());
            r.image = Some(pulled.image.clone());
            r.bytes = Some(pulled.bytes_written);
            r.reused = pulled.reused;
        });
        self.log(
            job_id,
            format!(
                "{} is {} ({})",
                pulled.path.display(),
                pulled.digest,
                human_bytes(pulled.size)
            ),
        );

        // Unconditional, exactly as a build's is. A pull that reused an image
        // already on disk still has to roll: the running VMs hold a copy of
        // whatever rootfs they booted from, which is not necessarily this one.
        let replacement = self.roll_out(job_id, deployment_id, &pulled.image).await?;
        let correlated = self.history.lock().expect("job history mutex poisoned")
            .iter().any(|r| r.id == job_id && r.operation_id.is_some());
        if correlated {
            self.verify_correlated_readiness(job_id, deployment_id, &replacement).await?;
        }
        Ok(pulled.image)
    }

    async fn verify_correlated_readiness(
        &self,
        job_id: &str,
        deployment_id: &str,
        replacement: &Arc<Deployment>,
    ) -> Result<(), String> {
        let image = replacement.spec.vm.as_ref().and_then(|vm| vm.image.as_deref()).unwrap_or("");
        let deadline = tokio::time::Instant::now() + self.cfg.timeout;
        loop {
            let Some(deployment) = self.registry.get(deployment_id) else {
                return Err("deployment was removed while waiting for replacement readiness".into());
            };
            if !Arc::ptr_eq(&deployment, replacement) {
                self.update_record(job_id, |r| r.readiness_verified = Some(false));
                return Err("deployment was replaced again during rollout; readiness cannot be attributed to this operation".into());
            }
            if deployment.spec.vm.as_ref().and_then(|vm| vm.image.as_deref()) != Some(image) {
                self.update_record(job_id, |r| r.readiness_verified = Some(false));
                return Err("deployment image changed before replacement readiness was proven".into());
            }
            let backends = deployment.backends();
            let desired = deployment.desired_replicas() as usize;
            if desired > 0 && backends.len() >= desired && backends.iter().all(|b| b.is_healthy() && !b.is_draining()) {
                self.update_record(job_id, |r| {
                    r.readiness_verified = Some(true);
                    r.push_log(format!("{} replacement replica(s) healthy on requested image {image}", backends.len()));
                });
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                self.update_record(job_id, |r| r.readiness_verified = Some(false));
                return Err(format!("replacement on requested image {image} did not become healthy within {}s", self.cfg.timeout.as_secs()));
            }
            tokio::select! {
                _ = deployment.ready_signal.notified() => {},
                _ = tokio::time::sleep(VERIFY_INTERVAL) => {},
            }
        }
    }

    /// The site reading of a pull: a bundle unpacked into `site.root`.
    ///
    /// Where the managed path ends in a pool roll, this ends in nothing at all —
    /// and that is the whole appeal. There is no image to name, no VM to
    /// recycle, and no window in which capacity is short: the files are simply
    /// the files, and the next request reads the new ones.
    ///
    /// It also ends without the verification step the *other* two deploy paths
    /// need, because that step has already happened. `pull_tree` checks the
    /// unpacked tree for the site's index before it swaps anything in, so by
    /// the time this returns there is nothing left to confirm — unlike an
    /// update, which can only look at the wreckage afterwards.
    async fn run_site_pull(
        &self,
        job_id: &str,
        spec: &ArtifactSpec,
        site: &crate::config::SiteSpec,
        api_key: Option<&str>,
        force: bool,
    ) -> Result<String, String> {
        let mut log = |line: String| self.log(job_id, line);
        let pulled = self
            .puller
            .pull_tree(spec, site, api_key, force, &mut log)
            .await?;

        let root = pulled.root.display().to_string();
        self.update_record(job_id, |r| {
            r.digest = Some(pulled.digest.clone());
            r.bytes = Some(pulled.bytes_written);
            r.reused = pulled.reused;
            r.site_root = Some(root.clone());
            // Both are about the tree that is now live, so a reused pull reports
            // what is serving rather than the zero it did not write.
            if !pulled.reused {
                r.files = Some(pulled.files);
            }
            // The index was checked before the swap; saying so is what makes a
            // succeeded site pull mean the same thing as a succeeded update.
            r.verified = Some(true);
        });

        if pulled.reused {
            return Ok(format!("{} already serving {}", root, short(&pulled.digest)));
        }
        Ok(format!(
            "{} file{} ({}) in {root}",
            pulled.files,
            if pulled.files == 1 { "" } else { "s" },
            crate::artifact::human(pulled.unpacked),
        ))
    }

    // -- guest mounts ------------------------------------------------------

    /// Pull every mount, then move the pool onto whatever changed.
    ///
    /// Sequential rather than concurrent, and that is a choice rather than an
    /// oversight: these are multi-gigabyte transfers landing on one host's disk,
    /// and running eight of them at once makes all eight slower while making the
    /// first one — which might have been the only one that had to move — late.
    ///
    /// A mount that fails ends the job with the mounts before it already
    /// unpacked. That is safe because nothing has been rolled out yet: the trees
    /// are content-addressed and unreferenced until the spec names them, so the
    /// deployment goes on running whatever it was running, and the retry starts
    /// from the first mount that has not landed.
    async fn run_mount_pull(
        &self,
        job_id: &str,
        deployment_id: &str,
        mounts: Vec<MountSpec>,
        force: bool,
    ) -> Result<String, String> {
        let mut resolved: Vec<(String, String)> = Vec::with_capacity(mounts.len());
        let mut moved = 0u64;
        let mut reused = 0usize;

        for (index, mount) in mounts.iter().enumerate() {
            // Resolved per mount rather than once: each names its own store, and
            // eight mounts can hold eight credentials.
            let api_key = self.store_key(mount.auth.as_ref())?;
            let pulled = {
                let mut log = |line: String| self.log(job_id, line);
                self.puller
                    .pull_mount(mount, &self.cfg.mounts, api_key.as_deref(), force, &mut log)
                    .await
                    .map_err(|e| format!("mount {}: {e}", mount.guest_path()))?
            };

            moved += pulled.bytes_written;
            if pulled.reused {
                reused += 1;
            }
            let tree = pulled.tree.display().to_string();
            let (digest, files, unpacked, bytes, was_reused) = (
                pulled.digest.clone(),
                pulled.files,
                pulled.unpacked,
                pulled.bytes_written,
                pulled.reused,
            );
            self.update_record(job_id, |r| {
                if let Some(outcome) = r.mounts.get_mut(index) {
                    outcome.digest = Some(digest);
                    outcome.tree = Some(tree);
                    outcome.bytes = Some(bytes);
                    outcome.reused = was_reused;
                    // Both describe an unpack that happened. On a reuse there
                    // was none, and zero would read as "this bundle is empty"
                    // rather than "nothing was written".
                    if !was_reused {
                        outcome.files = Some(files);
                        outcome.unpacked = Some(unpacked);
                    }
                }
            });
            resolved.push((pulled.path, pulled.digest));
        }

        let rolled = self.roll_out_mounts(job_id, deployment_id, &resolved).await?;

        let n = mounts.len();
        Ok(format!(
            "{n} mount{} ({reused} already on this host, {}){}",
            if n == 1 { "" } else { "s" },
            human_bytes(moved),
            if rolled {
                "; pool recycling"
            } else {
                "; the pool already has them"
            },
        ))
    }

    /// Write the resolved digests into the spec and recycle the pool, if
    /// anything actually moved.
    ///
    /// Returns whether the pool was rolled. **Not** unconditional, unlike the
    /// roll-out a build or a rootfs pull ends with, and the asymmetry is the
    /// point: those recycle because the running VMs hold a *copy* of a rootfs
    /// that may not be the one just materialized, and no name can prove
    /// otherwise. A mount's tree is content-addressed and a running VM's copy of
    /// it was built from the same digest, so an unchanged digest means the pool
    /// already has exactly these bytes. Recycling anyway would make the pull
    /// that runs on every registration — see [`Self::mounts_need_pulling`] —
    /// into a fleet-wide restart.
    ///
    /// Mounts are matched by guest path rather than by index, because the spec
    /// can be edited while the job runs and an index would then write a digest
    /// onto a different mount than the one it was fetched for.
    async fn roll_out_mounts(
        &self,
        job_id: &str,
        deployment_id: &str,
        resolved: &[(String, String)],
    ) -> Result<bool, String> {
        let change = self.registry.change_guard().await;
        let Some(old) = self.registry.get(deployment_id) else {
            return Err(format!(
                "deployment {deployment_id:?} was removed while its mounts were being pulled; \
                 the trees are on this host but nothing is using them"
            ));
        };
        if crate::rollout::reserved(&old) { return Err("candidate rollout reserves this deployment".into()); }
        if self.autoscaler.workspaces().recovery_active(deployment_id) {
            return Err("workspace recovery reserves this deployment".into());
        }
        let mut spec = old.spec.clone();
        let Some(vm) = spec.vm.as_mut() else {
            return Err(format!(
                "deployment {deployment_id:?} is no longer a managed VM deployment"
            ));
        };

        let mut changed: Vec<String> = Vec::new();
        let mut dropped: Vec<String> = Vec::new();
        for (path, digest) in resolved {
            match vm.mounts.iter_mut().find(|m| m.guest_path() == path) {
                Some(mount) if mount.digest.as_deref() != Some(digest.as_str()) => {
                    mount.digest = Some(digest.clone());
                    changed.push(path.clone());
                }
                Some(_) => {}
                None => dropped.push(path.clone()),
            }
        }

        for path in &dropped {
            self.log(
                job_id,
                format!("mount {path} was removed from the spec while it was being pulled; its \
                         tree is on this host but nothing names it"),
            );
        }

        if changed.is_empty() {
            drop(change);
            self.update_record(job_id, |r| {
                r.push_log(
                    "every mount is already pinned to the digest that was pulled; the pool is \
                     left alone",
                );
            });
            return Ok(false);
        }

        let deployment = self.registry.upsert(spec);
        if let Err(e) = self.registry.persist_one(&deployment.spec.id) {
            tracing::error!(error = %e, "failed to persist state after a mount pull");
        }
        drop(change);
        self.autoscaler.teardown(&old).await;
        deployment.scale_signal.notify_one();

        let rolled = changed.clone();
        self.update_record(job_id, |r| {
            r.rolled_out = true;
            for outcome in r.mounts.iter_mut() {
                outcome.changed = rolled.contains(&outcome.path);
            }
            r.push_log(format!(
                "{} moved to a new digest; pool recycling",
                rolled.join(", ")
            ));
        });
        tracing::info!(
            deployment = %deployment_id,
            mounts = %changed.join(","),
            "rolled deployment onto new mount trees",
        );
        Ok(true)
    }

    // -- host updates ------------------------------------------------------

    /// Run the update commands, then prove the upstreams came back.
    ///
    /// Nothing in the spec changes: a static deployment's backends are fixed
    /// addresses, and what moved is the code behind them. That is exactly why
    /// the verification step exists — without it a successful job would only
    /// mean "the commands exited 0", which is not the same as "the service is
    /// serving".
    async fn run_update(
        &self,
        job_id: &str,
        deployment_id: &str,
        spec: &UpdateSpec,
    ) -> Result<String, String> {
        let dir = Path::new(&spec.working_dir);
        if !dir.is_dir() {
            return Err(format!(
                "update.working_dir {} does not exist on this host (app-lb runs as {}), \
                 so there is nothing to update",
                spec.working_dir,
                whoami()
            ));
        }

        // Resolve every secret before running anything: discovering a missing
        // credential after `git pull` has already moved the working directory is
        // strictly worse than discovering it now.
        let env = self.update_env(spec)?;
        let token = self.git_token(spec.auth.as_ref())?;
        let timeout = spec
            .timeout_secs
            .map_or(self.cfg.timeout, Duration::from_secs);

        for (i, command) in spec.commands.iter().enumerate() {
            let mut cmd = tokio::process::Command::new(&self.cfg.shell);
            // Through a shell because that is what the spec's strings are:
            // `git pull --ff-only && cargo build --release` is one command to
            // whoever wrote it. The string is never interpolated into a larger
            // shell line, so it means exactly what it says.
            cmd.arg("-c").arg(command).current_dir(dir);
            for (k, v) in &env {
                cmd.env(k, v);
            }
            self.apply_git_auth(&mut cmd, token.as_ref());
            if let Some(home) = &self.cfg.home {
                cmd.env("HOME", home);
            }

            self.step(job_id, &format!("command {}", i + 1), cmd, timeout)
                .await
                .map_err(|e| format!("{e} (command {} of {})", i + 1, spec.commands.len()))?;
            self.update_record(job_id, |r| r.commands_run = Some(i + 1));
        }

        // -- verify ----------------------------------------------------------
        let wait = spec.verify_timeout();
        if wait.is_zero() {
            self.log(job_id, "verification is disabled (verify_timeout_secs: 0)");
            return Ok(format!("{} command(s)", spec.commands.len()));
        }

        // A site has no upstreams to probe, so "did it come back" is a different
        // question: did the build leave something servable in the root. Without
        // this the job would report failure after a perfectly good build, purely
        // because there was nothing to send a request to.
        if let Some(site) = self.registry.get(deployment_id).and_then(|d| d.spec.site.clone()) {
            return match verify_site(&site) {
                Ok(what) => {
                    self.update_record(job_id, |r| {
                        r.verified = Some(true);
                        r.push_log(what.clone());
                    });
                    Ok(format!("{} command(s), {what}", spec.commands.len()))
                }
                Err(e) => {
                    self.update_record(job_id, |r| r.verified = Some(false));
                    Err(format!(
                        "the commands succeeded but the site is not servable: {e}"
                    ))
                }
            };
        }

        self.log(
            job_id,
            format!(
                "commands finished; waiting up to {}s for the upstreams to answer",
                wait.as_secs()
            ),
        );
        match self.verify(deployment_id, wait).await {
            Ok(peers) => {
                self.update_record(job_id, |r| {
                    r.verified = Some(true);
                    r.push_log(format!("{peers} upstream(s) healthy"));
                });
                Ok(format!("{} command(s), upstreams healthy", spec.commands.len()))
            }
            Err(e) => {
                self.update_record(job_id, |r| r.verified = Some(false));
                // The commands succeeded, so this is not "the update failed to
                // run" — it is "the update ran and the service is not back".
                // Both are failures; only the message can tell them apart.
                Err(format!(
                    "every command succeeded, but {e}. The host has already been changed — \
                     check the service and its logs"
                ))
            }
        }
    }

    /// Poll the deployment's upstreams until they all answer, or give up.
    ///
    /// Probes directly rather than reading the autoscaler's `healthy` flags: a
    /// flag set two seconds ago describes the process that was just replaced.
    async fn verify(&self, deployment_id: &str, wait: Duration) -> Result<usize, String> {
        tokio::time::sleep(VERIFY_SETTLE.min(wait)).await;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let Some(d) = self.registry.get(deployment_id) else {
                return Err(format!("deployment {deployment_id:?} was removed mid-update"));
            };
            let backends = d.backends();
            if backends.is_empty() {
                return Err("the deployment has no upstreams to probe".to_string());
            }

            let mut unhealthy = Vec::new();
            for b in backends.iter() {
                if !probe_peer(b, &d.spec.health).await {
                    unhealthy.push(b.peer.clone());
                }
            }
            if unhealthy.is_empty() {
                return Ok(backends.len());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "{} of {} upstream(s) did not answer within {}s ({})",
                    unhealthy.len(),
                    backends.len(),
                    wait.as_secs(),
                    unhealthy.join(", ")
                ));
            }
            tokio::time::sleep(VERIFY_INTERVAL).await;
        }
    }

    /// Literal env plus values pulled from the secret store.
    ///
    /// Ordered, so the log line naming which variables were set reads the same
    /// way twice — and so a secret always wins over a literal of the same name
    /// rather than winning at random.
    fn update_env(&self, spec: &UpdateSpec) -> Result<BTreeMap<String, String>, String> {
        let mut env: BTreeMap<String, String> =
            spec.env.clone().unwrap_or_default().into_iter().collect();
        for from in &spec.env_from {
            let value = self.secrets.resolve(&from.secret_ref()).map_err(|e| {
                format!("{e} — `heyctl get secrets` lists what this LB holds")
            })?;
            env.insert(from.env_name(), value);
        }
        Ok(env)
    }

    // -- shared child-process plumbing -------------------------------------

    /// Resolve a git credential reference into `(value, username)`.
    /// An artifact store's API key, out of the secret store.
    ///
    /// The counterpart of [`git_token`](Self::git_token), and the only other
    /// thing `build.auth` / `artifact.auth` can mean. Kept beside it so the
    /// places that read secrets stay countable.
    fn store_key(
        &self,
        auth: Option<&crate::secrets::SecretRef>,
    ) -> Result<Option<String>, String> {
        match auth {
            None => Ok(None),
            Some(r) => Ok(Some(self.secrets.resolve(r).map_err(|e| {
                format!("{e} — `heyctl get secrets` lists what this LB holds")
            })?)),
        }
    }

    fn git_token(
        &self,
        auth: Option<&crate::secrets::SecretRef>,
    ) -> Result<Option<(String, String)>, String> {
        match auth {
            None => Ok(None),
            Some(r) => Ok(Some((
                self.secrets.resolve(r).map_err(|e| {
                    format!("{e} — `heyctl get secrets` lists what this LB holds")
                })?,
                r.username.clone().unwrap_or_else(|| "x-access-token".into()),
            ))),
        }
    }

    /// A `git` invocation with the environment set so it can never block on a
    /// prompt, and so a token (when there is one) travels out of band.
    fn git(&self, token: Option<&(String, String)>) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.cfg.git_bin);
        if let Some(home) = &self.cfg.home {
            cmd.env("HOME", home);
        }
        self.apply_git_auth(&mut cmd, token);
        cmd
    }

    /// Make a child able to authenticate to git without the token appearing in
    /// its arguments. Applied to `git` itself for a build, and to the shell for
    /// a host update — whose first command is very often `git pull`.
    fn apply_git_auth(
        &self,
        cmd: &mut tokio::process::Command,
        token: Option<&(String, String)>,
    ) {
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        let Some((value, username)) = token else {
            return;
        };
        match self.askpass_script() {
            Ok(script) => {
                cmd.env("GIT_ASKPASS", script)
                    .env("APP_LB_GIT_TOKEN", value)
                    .env("APP_LB_GIT_USERNAME", username)
                    // Clear any credential helper the host has configured, so the
                    // answer comes from our askpass and not from a cached
                    // credential for a different account. `-c` for git itself;
                    // the env form also reaches a `git` run inside a shell command.
                    .env("GIT_CONFIG_COUNT", "1")
                    .env("GIT_CONFIG_KEY_0", "credential.helper")
                    .env("GIT_CONFIG_VALUE_0", "");
            }
            Err(e) => {
                tracing::error!(error = %e, "could not write the git askpass helper");
            }
        }
    }

    /// Write (once) the helper that answers git's credential prompts from the
    /// environment. On disk because `GIT_ASKPASS` takes a program, not a value;
    /// `0700` because it is executable, and it holds no secret itself.
    fn askpass_script(&self) -> std::io::Result<PathBuf> {
        let path = self.cfg.work_dir.join("git-askpass.sh");
        if path.exists() {
            return Ok(path);
        }
        crate::tls::create_dir_private(&self.cfg.work_dir)?;
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             # Written by app-lb: answers git's credential prompts from the environment,\n\
             # so a token is never visible in argv.\n\
             case \"$1\" in\n\
             \x20 Username*) printf %s \"${APP_LB_GIT_USERNAME:-x-access-token}\" ;;\n\
             \x20 *)         printf %s \"${APP_LB_GIT_TOKEN}\" ;;\n\
             esac\n",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(path)
    }

    /// Run one child to completion, logging its output and failing on a non-zero
    /// exit or a timeout.
    async fn step(
        &self,
        job_id: &str,
        label: &str,
        mut cmd: tokio::process::Command,
        timeout: Duration,
    ) -> Result<String, String> {
        let shown = describe(&cmd);
        self.log(job_id, format!("$ {shown}"));

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Without this a timed-out `docker build` keeps running after the
            // future is dropped, holding the daemon and the disk.
            .kill_on_drop(true);

        let output = match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "{label} is not installed or not on app-lb's PATH ({shown}): {e}"
                ));
            }
            Ok(Err(e)) => return Err(format!("could not run {label}: {e}")),
            Err(_) => {
                return Err(format!(
                    "{label} timed out after {}s",
                    timeout.as_secs()
                ));
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        for line in stdout.lines().chain(String::from_utf8_lossy(&output.stderr).lines()) {
            self.log(job_id, line.to_string());
        }

        if output.status.success() {
            Ok(stdout)
        } else {
            // The tail of stderr is what actually says why, so put it in the
            // error rather than making the caller go read the log.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<&str> = stderr.lines().rev().take(5).collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            Err(format!(
                "{label} exited with {}: {}",
                output.status.code().map_or("a signal".into(), |c| c.to_string()),
                if tail.is_empty() {
                    "no output".to_string()
                } else {
                    tail.join(" / ")
                }
            ))
        }
    }
}

/// Frees a deployment's job slot however the task ends, panic included.
struct JobSlot {
    jobs: Arc<Jobs>,
    deployment: String,
}

impl Drop for JobSlot {
    fn drop(&mut self) {
        if let Ok(mut running) = self.jobs.running.lock() {
            running.remove(&self.deployment);
        }
    }
}

/// Resolve an upstream and probe it with the deployment's health check — the
/// same two steps the autoscaler's static re-probe takes each tick.
async fn probe_peer(
    peer: &crate::deployment::VmBackend,
    check: &crate::config::HealthCheck,
) -> bool {
    if peer.tls {
        return health::probe_https(&peer.address, &peer.sni, check).await;
    }
    match tokio::net::lookup_host(&peer.address).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => health::probe(addr, check).await,
            None => false,
        },
        Err(_) => false,
    }
}

/// Who app-lb is running as, for the "that directory isn't there" message —
/// which is very often a permissions or wrong-user problem, not a typo.
/// Enforce the retention caps after pushing a record for `deployment`.
///
/// Two passes, in this order and not the other: the deployment that just gained
/// a record is trimmed to [`HISTORY_PER_DEPLOYMENT`] first, so a busy deployment
/// evicts *its own* oldest job rather than somebody else's. Only then does the
/// global [`HISTORY_LIMIT`] apply, and by construction it almost never bites.
///
/// Oldest-first order is preserved, so `records` still reads newest-first.
fn trim_history(history: &mut VecDeque<JobRecord>, deployment: &str) {
    // Correlation records are the retry ledger, not expendable log history.
    // Keep them until an explicit operation-retention policy exists.
    let mut mine = history.iter().filter(|r| r.deployment == deployment && r.operation_id.is_none()).count();
    if mine > HISTORY_PER_DEPLOYMENT {
        history.retain(|r| {
            if r.operation_id.is_some() || r.deployment != deployment || mine <= HISTORY_PER_DEPLOYMENT {
                return true;
            }
            mine -= 1;
            false
        });
    }
    let mut excess = history.iter().filter(|r| r.operation_id.is_none()).count().saturating_sub(HISTORY_LIMIT);
    history.retain(|r| {
        if r.operation_id.is_none() && excess > 0 {
            excess -= 1;
            false
        } else {
            true
        }
    });
}

/// Whether a site's root still holds something worth serving.
///
/// The counterpart to probing a static deployment's upstreams: a build that
/// exits 0 but writes its output somewhere else leaves a directory that answers
/// every request with a 404, and "the commands succeeded" would call that a
/// successful deploy.
fn verify_site(spec: &crate::config::SiteSpec) -> Result<String, String> {
    let root = Path::new(&spec.root);
    if !root.is_dir() {
        return Err(format!(
            "site.root {} is not a directory on this host (app-lb runs as {})",
            spec.root,
            whoami()
        ));
    }
    let index = spec.index.trim();
    if index.is_empty() {
        // No index configured, so the site is a bag of files; the directory
        // existing is all there is to check.
        return Ok(format!("{} exists", spec.root));
    }
    if !root.join(index).is_file() {
        return Err(format!(
            "{index} is missing from {} — did the build write its output somewhere else?",
            spec.root
        ));
    }
    Ok(format!("{index} is in place"))
}

/// The user app-lb is running as, for the errors that are almost always a
/// permission problem wearing a different hat.
pub fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid {}", unsafe { libc_getuid() }))
}

#[cfg(unix)]
unsafe fn libc_getuid() -> u32 {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

#[cfg(not(unix))]
unsafe fn libc_getuid() -> u32 {
    0
}

fn is_ssh_remote(repo: &str) -> bool {
    repo.starts_with("git@") || repo.starts_with("ssh://")
}

/// Find the Dockerfile and the context, as absolute paths inside `root`.
///
/// The canonicalized result is re-checked against the checkout: everything here
/// came from a repo, and a committed symlink is the one way a validated relative
/// path can still end up pointing at `/etc`.
fn locate_dockerfile(root: &Path, spec: &BuildSpec) -> Result<(PathBuf, PathBuf), String> {
    let root_real = root
        .canonicalize()
        .map_err(|e| format!("checkout {} is unreadable: {e}", root.display()))?;

    let context_root = match &spec.context {
        Some(c) => contained(&root_real, &root_real.join(c), "build.context")?,
        None => root_real.clone(),
    };

    let dockerfile = match &spec.dockerfile {
        Some(f) => {
            let candidate = root_real.join(f);
            // Existence first: a dangling or absent path should say what is
            // missing, not that it escaped the checkout.
            if !candidate.is_file() {
                return Err(format!(
                    "no Dockerfile at {f:?} in this checkout — the repo may have moved it, \
                     or `build.dockerfile` may be stale"
                ));
            }
            contained(&root_real, &candidate, "build.dockerfile")?
        }
        // The search matches on filename and `is_file()`, both of which follow
        // symlinks, so its result needs the same containment check as a path the
        // spec named.
        None => contained(
            &root_real,
            &find_dockerfile(&context_root)?,
            "the Dockerfile found in the checkout",
        )?,
    };

    // heyvm's own default, made explicit: the context is the Dockerfile's
    // directory unless the spec says otherwise.
    let context = match &spec.context {
        Some(_) => context_root,
        None => dockerfile
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root_real.clone()),
    };
    Ok((dockerfile, context))
}

/// Canonicalize and refuse anything that escaped `root`.
fn contained(root: &Path, path: &Path, what: &str) -> Result<PathBuf, String> {
    let real = path
        .canonicalize()
        .map_err(|e| format!("{what} {} is not in the checkout: {e}", path.display()))?;
    if real.starts_with(root) {
        Ok(real)
    } else {
        Err(format!(
            "{what} resolves to {} which is outside the checkout; a symlink in the repo \
             cannot be used to reach the host filesystem",
            real.display()
        ))
    }
}

/// Look for a Dockerfile: the context root first, then a bounded walk. Several
/// candidates is an error — picking one would make the deployed image depend on
/// directory iteration order.
fn find_dockerfile(context_root: &Path) -> Result<PathBuf, String> {
    let obvious = context_root.join("Dockerfile");
    if obvious.is_file() {
        return Ok(obvious);
    }

    let mut found = Vec::new();
    let mut frontier = vec![(context_root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = frontier.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if depth < SEARCH_DEPTH && !SKIP_DIRS.contains(&name.as_ref()) {
                    frontier.push((path, depth + 1));
                }
            } else if name == "Dockerfile" {
                found.push(path);
            }
        }
    }
    found.sort();

    match found.len() {
        0 => Err(format!(
            "no Dockerfile found within {SEARCH_DEPTH} directories of {}; set \
             `build.dockerfile` to its path in the repo",
            context_root.display()
        )),
        1 => Ok(found.into_iter().next().expect("len == 1")),
        _ => {
            let names: Vec<String> = found
                .iter()
                .map(|p| {
                    p.strip_prefix(context_root)
                        .unwrap_or(p)
                        .display()
                        .to_string()
                })
                .take(8)
                .collect();
            Err(format!(
                "found {} Dockerfiles ({}); set `build.dockerfile` to say which one builds \
                 this deployment",
                found.len(),
                names.join(", ")
            ))
        }
    }
}

/// A ref that is a full or abbreviated commit sha. Such a ref may need a full
/// fetch, and can be checked out by name once fetched.
fn looks_like_sha(r: &str) -> bool {
    r.len() >= 7 && r.len() <= 40 && r.chars().all(|c| c.is_ascii_hexdigit())
}

/// `<work_dir>/<deployment>` — the id is only constrained by the route table, so
/// it cannot be trusted as a path component.
fn sanitize_dir(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "_".into()
    } else {
        cleaned
    }
}

/// A command as a log line. Safe to print in full: credentials travel in the
/// environment precisely so that this never has to be redacted.
fn describe(cmd: &tokio::process::Command) -> String {
    let std_cmd = cmd.as_std();
    let mut out = std_cmd.get_program().to_string_lossy().into_owned();
    for arg in std_cmd.get_args() {
        out.push(' ');
        out.push_str(&arg.to_string_lossy());
    }
    out
}

fn new_job_id() -> String {
    let mut bytes = [0u8; 6];
    if openssl::rand::rand_bytes(&mut bytes).is_err() {
        // Only used for uniqueness within a 50-entry history.
        let n = now_secs();
        bytes.copy_from_slice(&n.to_le_bytes()[..6]);
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("job-{hex}")
}

#[cfg(test)]
mod retention {
    use super::*;

    fn push(history: &mut VecDeque<JobRecord>, deployment: &str, n: usize) {
        for i in 0..n {
            history.push_back(JobRecord::new(
                format!("{deployment}-{i}"),
                deployment.to_string(),
                JobKind::ImageBuild,
            ));
            trim_history(history, deployment);
        }
    }

    fn ids_for(history: &VecDeque<JobRecord>, deployment: &str) -> Vec<String> {
        history
            .iter()
            .filter(|r| r.deployment == deployment)
            .map(|r| r.id.clone())
            .collect()
    }

    #[test]
    fn a_deployment_keeps_its_most_recent_jobs_and_no_more() {
        let mut history = VecDeque::new();
        push(&mut history, "a", HISTORY_PER_DEPLOYMENT + 5);

        let ids = ids_for(&history, "a");
        assert_eq!(ids.len(), HISTORY_PER_DEPLOYMENT);
        assert_eq!(ids.last().unwrap(), &format!("a-{}", HISTORY_PER_DEPLOYMENT + 4));
        assert_eq!(ids.first().unwrap(), &"a-5".to_string(), "the oldest go first");
    }

    /// The reason the cap is per-deployment. Under a global cap, one deployment
    /// churning jobs would evict every other deployment's history — so the job
    /// you came to investigate is the one already gone.
    #[test]
    fn a_busy_deployment_evicts_only_its_own_history() {
        let mut history = VecDeque::new();
        push(&mut history, "quiet", 1);
        push(&mut history, "busy", HISTORY_PER_DEPLOYMENT * 3);

        assert_eq!(ids_for(&history, "quiet"), vec!["quiet-0"]);
        assert_eq!(ids_for(&history, "busy").len(), HISTORY_PER_DEPLOYMENT);
    }

    /// The fleet-wide ceiling still applies once enough deployments each hold
    /// recent jobs, and it evicts oldest-first across the whole history.
    #[test]
    fn the_global_ceiling_bounds_the_whole_fleet() {
        let mut history = VecDeque::new();
        // One job each from more deployments than the ceiling allows.
        for i in 0..HISTORY_LIMIT + 10 {
            let id = format!("d{i}");
            history.push_back(JobRecord::new(format!("{id}-0"), id.clone(), JobKind::ImageBuild));
            trim_history(&mut history, &id);
        }
        assert_eq!(history.len(), HISTORY_LIMIT);
        assert_eq!(history.front().unwrap().deployment, "d10", "oldest evicted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment_spec() -> crate::config::DeploymentSpec {
        serde_json::from_value(serde_json::json!({
            "id": "web", "namespace": "ci", "routes": [],
            "vm": {"driver": "firecracker", "image": "old", "port": 8080},
            "scaling": {"min_replicas": 1, "max_replicas": 1},
            "artifact": {"store": "/artifacts", "ref": "old-tag"}
        })).unwrap()
    }

    fn build_spec() -> BuildSpec {
        BuildSpec {
            repo: Some("https://example.com/acme/web.git".into()),
            store: None,
            source_ref: None,
            dockerfile: None,
            context: None,
            image_name: None,
            image_size_mb: None,
            auth: None,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-lb-jobs-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn jobs_at(dir: &Path) -> Arc<Jobs> {
        jobs_with_timeout(dir, Duration::ZERO)
    }

    fn jobs_with_timeout(dir: &Path, timeout: Duration) -> Arc<Jobs> {
        let registry = Arc::new(Registry::new(dir.join("state.json")));
        let secrets = Arc::new(SecretStore::new(dir.join("secrets.json"), None));
        let mounts = crate::mounts::MountStore::new(dir.join("mounts"), 0);
        let vms = crate::vm::VmManager::new(Some("http://127.0.0.1:1".into()), None, mounts.clone()).unwrap();
        let workspaces = Arc::new(crate::workspace::Workspaces::new(
            crate::workspace::WorkspaceConfig {
                root: dir.join("workspaces"), tar_bin: "tar".into(), aws_bin: "aws".into(),
                art_bin: "art".into(), s3_endpoint: None, home: None, timeout: Duration::from_secs(1),
            }, vms.clone(), registry.clone(), secrets.clone(),
        ));
        let autoscaler = Arc::new(Autoscaler::new(
            registry.clone(),
            crate::runtime::Runtime::new(vms, crate::config::LxcConfig { enabled: false, ..Default::default() }),
            Arc::new(crate::metrics::Metrics::new()), Arc::new(crate::feed::Feed::new()),
            workspaces, secrets.clone(),
        ));
        Arc::new(Jobs::new(JobConfig {
            work_dir: dir.join("work"), heyvm_bin: "heyvm".into(), art_bin: "art".into(),
            images_dir: dir.join("images"), git_bin: "git".into(), mounts, shell: "sh".into(),
            timeout, home: None, sites_dir: Some(dir.join("sites")),
        }, registry, autoscaler, secrets, None))
    }

    /// A site built from a repo: the checkout's `context` lands in the root
    /// (created, because it is under the managed sites dir), `.git` does not,
    /// a rebuild replaces it, and a checkout without the index is refused while
    /// the old tree keeps serving.
    #[tokio::test]
    async fn a_site_build_copies_the_checkout_into_the_root() {
        let dir = scratch("site-build");
        let jobs = jobs_with_timeout(&dir, Duration::from_secs(30));
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("dist/css")).unwrap();
        std::fs::write(src.join("dist/index.html"), "v1").unwrap();
        std::fs::write(src.join("dist/css/app.css"), "body{}").unwrap();
        std::fs::write(src.join("README.md"), "not served").unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C").arg(&src).args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@t")
                .status().unwrap().success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "v1"]);

        let root = dir.join("sites/team-a/docs");
        let spec: crate::config::DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "docs", "namespace": "team-a", "routes": [{"host": "docs.local"}],
            "site": {"root": root},
            "build": {"repo": src, "ref": "main", "context": "dist"}
        }))
        .unwrap();
        spec.validate().unwrap();
        jobs.registry.upsert(spec.clone());
        let build = spec.build.clone().unwrap();

        let out = jobs.run_build("job", "docs", &build).await.unwrap();
        assert!(out.starts_with("2 files"), "{out}");
        assert_eq!(std::fs::read_to_string(root.join("index.html")).unwrap(), "v1");
        assert!(root.join("css/app.css").is_file());
        assert!(!root.join("README.md").exists() && !root.join(".git").exists());

        std::fs::write(src.join("dist/index.html"), "v2").unwrap();
        git(&["commit", "-qam", "v2"]);
        jobs.run_build("job", "docs", &build).await.unwrap();
        assert_eq!(std::fs::read_to_string(root.join("index.html")).unwrap(), "v2");

        std::fs::remove_file(src.join("dist/index.html")).unwrap();
        git(&["commit", "-qam", "drop index"]);
        let err = jobs.run_build("job", "docs", &build).await.unwrap_err();
        assert!(err.contains("build.context"), "{err}");
        assert_eq!(std::fs::read_to_string(root.join("index.html")).unwrap(), "v2", "old tree still serving");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn readiness_requires_full_healthy_pool_and_exact_generation() {
        let dir = scratch("pool-readiness");
        let jobs = jobs_at(&dir);
        let mut spec = deployment_spec();
        spec.scaling.min_replicas = 2;
        spec.scaling.max_replicas = 2;
        let replacement = jobs.registry.upsert(spec.clone());
        let first = Arc::new(crate::deployment::VmBackend::for_upstream("10.0.0.1:8080".into()));
        let second = Arc::new(crate::deployment::VmBackend::for_upstream("10.0.0.2:8080".into()));
        replacement.set_backends(vec![first.clone()]);
        assert!(jobs.verify_correlated_readiness("job", "web", &replacement).await.is_err());
        replacement.set_backends(vec![first.clone(), second.clone()]);
        second.set_healthy(false);
        assert!(jobs.verify_correlated_readiness("job", "web", &replacement).await.is_err());
        second.set_healthy(true);
        second.set_draining(true);
        assert!(jobs.verify_correlated_readiness("job", "web", &replacement).await.is_err());
        second.set_draining(false);
        assert!(jobs.verify_correlated_readiness("job", "web", &replacement).await.is_ok());
        let later = jobs.registry.upsert(spec);
        later.set_backends(vec![first, second]);
        let error = jobs.verify_correlated_readiness("job", "web", &replacement).await.unwrap_err();
        assert!(error.contains("replaced again"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stale_pull_cannot_overwrite_concurrent_image_change() {
        let dir = scratch("stale-pull");
        let jobs = jobs_at(&dir);
        let mut spec = deployment_spec();
        jobs.registry.upsert(spec.clone());
        let mut record = JobRecord::new("job".into(), "web".into(), JobKind::ArtifactPull);
        record.operation_id = Some("run".into());
        record.source_spec_fingerprint = Some(fingerprint(&spec));
        jobs.history.lock().unwrap().push_back(record);
        spec.vm.as_mut().unwrap().image = Some("concurrent-image".into());
        let concurrent = jobs.registry.upsert(spec);
        assert!(jobs.roll_out("job", "web", "stale-image").await.err().unwrap().contains("changed since"));
        assert!(Arc::ptr_eq(&jobs.registry.get("web").unwrap(), &concurrent));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn failed_status_persistence_cannot_later_report_success() {
        let dir = scratch("status-persistence");
        let jobs = jobs_at(&dir);
        let mut record = JobRecord::new("job".into(), "web".into(), JobKind::ArtifactPull);
        record.operation_id = Some("run".into());
        jobs.history.lock().unwrap().push_back(record);
        std::fs::create_dir_all(jobs.durable_dir.parent().unwrap()).unwrap();
        std::fs::write(&jobs.durable_dir, "not a directory").unwrap();
        jobs.update_record("job", |r| r.readiness_verified = Some(true));
        std::fs::remove_file(&jobs.durable_dir).unwrap();
        jobs.finish("job", JobStatus::Succeeded, None);
        let record = jobs.records(None).remove(0);
        assert_eq!(record.status, JobStatus::Failed);
        assert_eq!(record.readiness_verified, Some(false));
        assert!(record.reconciliation_required);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fingerprints_ignore_map_insertion_order() {
        use std::collections::HashMap;
        let first: HashMap<_, _> = [("z", "last"), ("a", "first")].into_iter().collect();
        let second: HashMap<_, _> = [("a", "first"), ("z", "last")].into_iter().collect();
        assert_eq!(fingerprint(&first), fingerprint(&second));
        assert_eq!(fingerprint(&first), fingerprint(&serde_json::json!({"a":"first", "z":"last"})));
        let first: serde_json::Value = serde_json::from_str(r#"{"z":[{"b":2,"a":1}],"a":0}"#).unwrap();
        let second: serde_json::Value = serde_json::from_str(r#"{"a":0,"z":[{"a":1,"b":2}]}"#).unwrap();
        assert_eq!(fingerprint(&first), fingerprint(&second));
        assert_ne!(fingerprint(&first), fingerprint(&serde_json::json!({"a":0,"z":[{"a":2,"b":1}]})));
        assert_ne!(fingerprint(&serde_json::json!([1,2])), fingerprint(&serde_json::json!([2,1])));
    }

    #[test]
    fn correlation_identity_survives_both_history_limits() {
        let mut history = VecDeque::new();
        let mut durable = JobRecord::new("durable".into(), "web".into(), JobKind::ArtifactPull);
        durable.operation_id = Some("run-1".into());
        history.push_back(durable);
        for i in 0..HISTORY_PER_DEPLOYMENT + 10 {
            history.push_back(JobRecord::new(format!("web-{i}"), "web".into(), JobKind::ArtifactPull));
            trim_history(&mut history, "web");
        }
        for i in 0..HISTORY_LIMIT + 10 {
            let id = format!("other-{i}");
            history.push_back(JobRecord::new(id.clone(), id.clone(), JobKind::ArtifactPull));
            trim_history(&mut history, &id);
        }
        assert_eq!(history.front().unwrap().id, "durable");
        assert_eq!(history.len(), HISTORY_LIMIT + 1);
    }

    #[test]
    fn correlated_job_is_persisted_before_execution_and_loadable() {
        let dir = scratch("durable-submission");
        let mut record = JobRecord::new("job-durable".into(), "web".into(), JobKind::ArtifactPull);
        record.operation_id = Some("ci-run-42".into());
        record.target_namespace = Some("ci".into());
        persist_job(&dir, &record).unwrap();
        let loaded = load_durable_jobs(&dir).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, JobStatus::Running);
        assert_eq!(loaded[0].operation_id.as_deref(), Some("ci-run-42"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn intent_distinguishes_artifact_and_template_but_not_rollout_image_swap() {
        let mut spec = deployment_spec();
        let authorized = deployment_config_fingerprint(&spec);
        spec.vm.as_mut().unwrap().image = Some("new-digest-image".into());
        assert_eq!(deployment_config_fingerprint(&spec), authorized);
        spec.vm.as_mut().unwrap().port = 9090;
        assert_ne!(deployment_config_fingerprint(&spec), authorized);
        assert_ne!(fingerprint(&("a", false, &authorized)), fingerprint(&("b", false, &authorized)));
    }

    #[tokio::test]
    async fn restart_recovers_running_identity_without_replaying_it() {
        let dir = scratch("interrupted");
        let spec = deployment_spec();
        let digest = "a".repeat(64);
        let mut record = JobRecord::new("job-interrupted".into(), "web".into(), JobKind::ArtifactPull);
        record.operation_id = Some("ci-run-43".into());
        record.target_namespace = Some(spec.namespace.clone());
        record.intent_fingerprint = Some(fingerprint(&(digest.clone(), false, deployment_config_fingerprint(&spec))));
        persist_job(&dir.join("state.d/jobs"), &record).unwrap();
        let jobs = jobs_at(&dir);
        jobs.registry.upsert(spec);
        let replay = jobs.start_correlated_pull("web", "ci-run-43".into(), digest, false).unwrap();
        assert_eq!(replay.id, "job-interrupted");
        assert_eq!(replay.status, JobStatus::Failed);
        assert!(replay.reconciliation_required);
        assert!(jobs.running.lock().unwrap().is_empty());
        assert!(matches!(jobs.start_correlated_pull("web", "ci-run-43".into(), "b".repeat(64), false), Err(StartError::ConflictingOperation(_))));
        let again = load_durable_jobs(&jobs.durable_dir).unwrap();
        assert_eq!(again[0].status, JobStatus::Failed);
        assert!(again[0].reconciliation_required);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn corrupt_ledger_blocks_new_correlated_work() {
        let dir = scratch("corrupt-ledger");
        std::fs::create_dir_all(dir.join("state.d/jobs")).unwrap();
        std::fs::write(dir.join("state.d/jobs/job.json"), "broken").unwrap();
        let jobs = jobs_at(&dir);
        jobs.registry.upsert(deployment_spec());
        assert!(matches!(jobs.start_correlated_pull("web", "run".into(), "a".repeat(64), false), Err(StartError::Persistence(_))));
        assert!(jobs.running.lock().unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "FROM scratch\n").unwrap();
    }

    #[test]
    fn the_obvious_dockerfile_wins_over_a_search() {
        let dir = scratch("obvious");
        touch(&dir.join("Dockerfile"));
        touch(&dir.join("deploy/Dockerfile"));

        let (df, ctx) = locate_dockerfile(&dir, &build_spec()).unwrap();
        assert!(df.ends_with("Dockerfile"));
        assert_eq!(df.parent().unwrap(), ctx, "context defaults to its directory");
        assert_eq!(df, dir.canonicalize().unwrap().join("Dockerfile"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_single_nested_dockerfile_is_found() {
        let dir = scratch("nested");
        touch(&dir.join("docker/app/Dockerfile"));

        let (df, ctx) = locate_dockerfile(&dir, &build_spec()).unwrap();
        assert!(df.ends_with("docker/app/Dockerfile"), "{}", df.display());
        assert!(ctx.ends_with("docker/app"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ambiguity_is_reported_rather_than_guessed() {
        let dir = scratch("ambiguous");
        touch(&dir.join("api/Dockerfile"));
        touch(&dir.join("web/Dockerfile"));

        let err = locate_dockerfile(&dir, &build_spec()).unwrap_err();
        assert!(err.contains("found 2 Dockerfiles"), "{err}");
        assert!(err.contains("build.dockerfile"), "{err}");

        // Naming one resolves it.
        let spec = BuildSpec {
            dockerfile: Some("web/Dockerfile".into()),
            ..build_spec()
        };
        let (df, _) = locate_dockerfile(&dir, &spec).unwrap();
        assert!(df.ends_with("web/Dockerfile"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vendored_trees_are_not_searched() {
        let dir = scratch("skips");
        touch(&dir.join("node_modules/pkg/Dockerfile"));
        touch(&dir.join(".git/Dockerfile"));
        touch(&dir.join("svc/Dockerfile"));

        let (df, _) = locate_dockerfile(&dir, &build_spec()).unwrap();
        assert!(df.ends_with("svc/Dockerfile"), "{}", df.display());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_dockerfile_says_which_knob_to_set() {
        let dir = scratch("missing");
        let err = locate_dockerfile(&dir, &build_spec()).unwrap_err();
        assert!(err.contains("no Dockerfile found"), "{err}");

        let named = BuildSpec {
            dockerfile: Some("deploy/Dockerfile".into()),
            ..build_spec()
        };
        let err = locate_dockerfile(&dir, &named).unwrap_err();
        assert!(err.contains("no Dockerfile at"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Regression: `build.dockerfile` is validated as a relative path, but a
    /// symlink committed to the repo can still resolve outside the checkout.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_checkout_is_refused() {
        let dir = scratch("symlink");
        let outside = scratch("symlink-target");
        touch(&outside.join("Dockerfile"));
        std::os::unix::fs::symlink(outside.join("Dockerfile"), dir.join("Dockerfile")).unwrap();

        match locate_dockerfile(&dir, &build_spec()) {
            Err(e) => assert!(
                e.contains("outside the checkout") || e.contains("not in the checkout"),
                "{e}"
            ),
            Ok((df, _)) => panic!("accepted a symlink to {}", df.display()),
        }

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn a_context_scopes_the_search() {
        let dir = scratch("context");
        touch(&dir.join("services/api/Dockerfile"));
        touch(&dir.join("services/web/Dockerfile"));

        // Two candidates at the root...
        assert!(locate_dockerfile(&dir, &build_spec()).is_err());
        // ...one within the context.
        let spec = BuildSpec {
            context: Some("services/api".into()),
            ..build_spec()
        };
        let (df, ctx) = locate_dockerfile(&dir, &spec).unwrap();
        assert!(df.ends_with("services/api/Dockerfile"));
        assert!(ctx.ends_with("services/api"), "an explicit context is kept");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shas_are_told_apart_from_branch_names() {
        assert!(looks_like_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(looks_like_sha("0123456"));
        assert!(!looks_like_sha("main"), "a branch, even if short");
        assert!(!looks_like_sha("012345"), "too short to be a useful sha");
        assert!(!looks_like_sha("release-1"));
    }

    #[test]
    fn a_deployment_id_cannot_pick_the_checkout_directory() {
        assert_eq!(sanitize_dir("web"), "web");
        assert_eq!(sanitize_dir("../../etc"), "_.._etc");
        assert_eq!(sanitize_dir("a/b"), "a_b");
        assert_eq!(sanitize_dir(".."), "_");
    }

    #[test]
    fn a_log_keeps_the_tail_not_the_head() {
        let mut r = JobRecord::new("job-1".into(), "web".into(), JobKind::ImageBuild);
        for i in 0..(LOG_LIMIT + 10) {
            r.push_log(format!("line {i}"));
        }
        assert_eq!(r.log.len(), LOG_LIMIT);
        assert_eq!(r.log.last().unwrap(), &format!("line {}", LOG_LIMIT + 9));
        assert_eq!(r.log.first().unwrap(), "line 10");
    }

    #[test]
    fn job_ids_are_distinct() {
        let a = new_job_id();
        assert!(a.starts_with("job-"), "{a}");
        assert_ne!(a, new_job_id());
    }

    #[test]
    fn a_record_only_serializes_the_fields_its_kind_uses() {
        let build = JobRecord::new("job-1".into(), "web".into(), JobKind::ImageBuild);
        let json = serde_json::to_string(&build).unwrap();
        assert!(json.contains(r#""kind":"image-build""#), "{json}");
        assert!(!json.contains("working_dir"), "no host-update fields: {json}");
        assert!(!json.contains("commands_total"), "{json}");

        let mut update = JobRecord::new("job-2".into(), "obs".into(), JobKind::HostUpdate);
        update.working_dir = Some("/srv/app".into());
        update.commands_total = Some(3);
        update.commands_run = Some(1);
        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains(r#""kind":"host-update""#), "{json}");
        assert!(json.contains(r#""working_dir":"/srv/app""#), "{json}");
        assert!(!json.contains("dockerfile"), "no image fields: {json}");
        assert!(!json.contains("rolled_out"), "{json}");

        let mut pull = JobRecord::new("job-3".into(), "web".into(), JobKind::ArtifactPull);
        pull.store = Some("http://127.0.0.1:8080".into());
        pull.artifact_ref = Some("debian-hermes".into());
        pull.digest = Some("c74abee2ce84".into());
        pull.bytes = Some(609_222_656);
        let json = serde_json::to_string(&pull).unwrap();
        assert!(json.contains(r#""kind":"artifact-pull""#), "{json}");
        assert!(json.contains(r#""artifact":"debian-hermes""#), "{json}");
        assert!(json.contains(r#""digest":"c74abee2ce84""#), "{json}");
        // A pull has no repo and no commit; those belong to the other source.
        assert!(!json.contains("commit"), "no build fields: {json}");
        assert!(!json.contains("working_dir"), "no host-update fields: {json}");
        // And a pull that fetched nothing does not claim to have reused
        // anything until it did.
        assert!(!json.contains("reused"), "{json}");
    }

    #[test]
    fn a_reused_image_is_reported_as_zero_bytes_rather_than_omitted() {
        // `bytes: 0` and `reused: true` together are the difference between
        // "the fetch was skipped" and "the fetch never ran", which is exactly
        // what somebody looking at a suspiciously fast pull wants to know.
        let mut pull = JobRecord::new("job-4".into(), "web".into(), JobKind::ArtifactPull);
        pull.bytes = Some(0);
        pull.reused = true;
        let json = serde_json::to_string(&pull).unwrap();
        assert!(json.contains(r#""bytes":0"#), "{json}");
        assert!(json.contains(r#""reused":true"#), "{json}");
    }

    #[test]
    fn each_job_kind_is_refused_on_the_backends_it_does_not_describe() {
        // The message has to say what to use instead: somebody who ran `build`
        // on a static deployment wants `update`, and vice versa.
        let build_on_static = StartError::WrongKind {
            id: "obs".into(),
            kind: JobKind::ImageBuild,
            backend: Backend::Upstreams,
        }
        .to_string();
        assert!(build_on_static.contains("static"), "{build_on_static}");
        assert!(build_on_static.contains("update"), "{build_on_static}");

        let pull_on_static = StartError::WrongKind {
            id: "obs".into(),
            kind: JobKind::ArtifactPull,
            backend: Backend::Upstreams,
        }
        .to_string();
        assert!(pull_on_static.contains("static"), "{pull_on_static}");
        assert!(pull_on_static.contains("update"), "{pull_on_static}");

        let update_on_managed = StartError::WrongKind {
            id: "web".into(),
            kind: JobKind::HostUpdate,
            backend: Backend::Vm,
        }
        .to_string();
        assert!(update_on_managed.contains("managed"), "{update_on_managed}");
        assert!(update_on_managed.contains("build"), "{update_on_managed}");

        // A site is neither of the other two, and the message that used to be
        // reached here called it "static (proxy_pass)" — which is wrong, and
        // sends somebody looking for upstreams they do not have.
        let build_on_site = StartError::WrongKind {
            id: "docs".into(),
            kind: JobKind::ImageBuild,
            backend: Backend::Site,
        }
        .to_string();
        assert!(build_on_site.contains("serves files off disk"), "{build_on_site}");
        assert!(!build_on_site.contains("proxy_pass"), "{build_on_site}");
        // Both of a site's deploy paths, since either could be what was meant.
        assert!(build_on_site.contains("pull"), "{build_on_site}");
        assert!(build_on_site.contains("update"), "{build_on_site}");
    }

    /// The table that replaced "is this deployment managed?", which could not
    /// express a job kind applying to two backends or a backend accepting two
    /// job kinds — and both are now true.
    #[test]
    fn a_pull_applies_to_a_vm_and_a_site_but_never_to_upstreams() {
        for (kind, expected) in [
            (JobKind::ImageBuild, [true, false, true]),
            (JobKind::ArtifactPull, [true, false, true]),
            (JobKind::HostUpdate, [false, true, true]),
        ] {
            for (backend, want) in
                [Backend::Vm, Backend::Upstreams, Backend::Site].into_iter().zip(expected)
            {
                assert_eq!(
                    kind.applies_to(backend),
                    want,
                    "{kind:?} on {backend:?}",
                );
            }
        }
    }

    /// A site pull records what it unpacked; a rootfs pull has no such thing and
    /// must not carry the fields as nulls.
    #[test]
    fn a_site_pull_reports_its_root_and_file_count() {
        let mut pull = JobRecord::new("job-5".into(), "docs".into(), JobKind::ArtifactPull);
        pull.site_root = Some("/srv/docs/public".into());
        pull.files = Some(412);
        let json = serde_json::to_string(&pull).unwrap();
        assert!(json.contains(r#""site_root":"/srv/docs/public""#), "{json}");
        assert!(json.contains(r#""files":412"#), "{json}");

        let rootfs = JobRecord::new("job-6".into(), "web".into(), JobKind::ArtifactPull);
        let json = serde_json::to_string(&rootfs).unwrap();
        assert!(!json.contains("site_root"), "no site fields on a rootfs pull: {json}");
        assert!(!json.contains("files"), "{json}");
    }
}

/// The standard PID 1 for a guest image that brings none.
///
/// heyvm boots every Firecracker guest with `init=/init.sh` and adds nothing of
/// its own, so a Dockerfile written for Docker (an app, a `CMD`) produces an
/// image whose kernel panics on boot: the deployment registers, builds, and
/// then cold-starts forever with `ready: 0`. Images that bring an init (every
/// one in this repository) mention `/init.sh` in their Dockerfile and are left
/// alone; the rest get `src/guest_init.sh` copied in as the final step.
///
/// A `COPY` rather than a `RUN`, so it needs no shell or base64 in the image:
/// the script is written into the build context and the derived Dockerfile is
/// written beside the original, both under the job's own checkout.
pub(crate) mod guest_init {
    use std::path::{Path, PathBuf};

    pub const SCRIPT: &str = include_str!("guest_init.sh");
    pub const CONTEXT_NAME: &str = "heyo-guest-init.sh";

    /// Whether a Dockerfile already provides its own init.
    pub fn provides_init(dockerfile: &str) -> bool {
        dockerfile.lines().any(|l| {
            let l = l.trim_start();
            !l.starts_with('#') && l.contains("/init.sh")
        })
    }

    /// The Dockerfile to build: `None` to use `dockerfile` as it is, or a
    /// derived one that also installs the standard init.
    pub fn supply(dockerfile: &Path, context: &Path) -> std::io::Result<Option<PathBuf>> {
        let text = std::fs::read_to_string(dockerfile)?;
        if provides_init(&text) {
            return Ok(None);
        }
        let script = context.join(CONTEXT_NAME);
        std::fs::write(&script, SCRIPT)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        }
        let mut derived = text;
        if !derived.ends_with('\n') {
            derived.push('\n');
        }
        derived.push_str(&format!(
            "\n# Added by app-lb: this image brings no PID 1 for the Firecracker guest.\nCOPY {CONTEXT_NAME} /init.sh\n"
        ));
        let mut name = dockerfile.as_os_str().to_owned();
        name.push(".app-lb");
        let out = PathBuf::from(name);
        std::fs::write(&out, derived)?;
        Ok(Some(out))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn an_app_dockerfile_gets_the_standard_init_and_one_with_its_own_does_not() {
            let dir = tempfile::tempdir().unwrap();
            let df = dir.path().join("Dockerfile");
            std::fs::write(&df, "FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD [\"node\", \"server.js\"]").unwrap();
            let derived = supply(&df, dir.path()).unwrap().expect("an app image gets an init");
            let text = std::fs::read_to_string(&derived).unwrap();
            assert!(text.starts_with("FROM node:20-slim"), "the original is kept: {text}");
            assert!(text.trim_end().ends_with("COPY heyo-guest-init.sh /init.sh"), "{text}");
            let script = dir.path().join(CONTEXT_NAME);
            assert_eq!(std::fs::read_to_string(&script).unwrap(), SCRIPT);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&script).unwrap().permissions().mode() & 0o777, 0o755);
            }

            std::fs::write(&df, "FROM ubuntu:24.04\nCOPY remote/init.sh /init.sh\nCMD [\"/init.sh\"]\n").unwrap();
            assert!(supply(&df, dir.path()).unwrap().is_none(), "an image with its own init is left alone");
            // A commented mention is not an init.
            assert!(!provides_init("FROM x\n# TODO: /init.sh\n"));
        }

        #[test]
        fn the_script_is_a_pid_1_that_signals_ready_and_never_exits() {
            assert!(SCRIPT.starts_with("#!/bin/sh"));
            assert!(SCRIPT.contains("echo \"HEYVM_READY\""));
            assert!(SCRIPT.contains("while :; do"));
            assert!(!SCRIPT.contains("bash"), "base images may have no bash");
        }
    }
}
