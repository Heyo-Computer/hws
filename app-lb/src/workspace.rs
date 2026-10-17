//! Deployment-owned workspaces: a writable directory that outlives the VM.
//!
//! The spec side is [`WorkspaceSpec`]; this module is the host side — where the
//! tree lives, how a retiring VM's disk becomes the next VM's seed, and how a
//! snapshot gets to and from the durable store. The autoscaler calls in at
//! three points, and everything else is the worker behind them:
//!
//! * [`Workspaces::seed_for_create`] — before a replica is created: the tree to
//!   hand heyvmd, or the reason there is not one yet (a capture in flight, a
//!   restore pending). The autoscaler skips the create in that case and asks
//!   again next tick; a workspace deployment is never booted from a stale tree.
//! * [`Workspaces::retire`] — when a replica leaves the pool for any reason:
//!   the guest is synced, the VM is stopped, and a capture is queued. What
//!   happens to the VM afterwards (destroyed, or kept suspended for
//!   `idle_action: retain`) is decided now and carried out by the worker once
//!   the capture has landed, so a VM is never destroyed with state that has not
//!   been copied out of it.
//! * [`Workspaces::blocked`] — the one-line reason, for logs and for the
//!   deployment status, that a pool is sitting at zero.
//!
//! ## Layout
//!
//! ```text
//! /var/lib/app-lb/workspaces/<deployment>/
//!   state.json                 what is current, what was pushed, who was seeded from what
//!   snapshots/<digest>/        extracted trees; `current` is the one the next VM gets
//!   empty/                     the tree a workspace starts from when the store has nothing
//!   bundles/<digest>.tar.gz    the snapshot as sent to (or fetched from) the store
//!   staging-<token>[.tar.gz]   a capture or restore in progress
//! ```
//!
//! Snapshots are named by the sha256 of their bundle, which makes "is the
//! store's copy the one we have?" a string comparison and makes a partially
//! written tree impossible to mistake for a finished one — it is never under
//! its final name until it is complete.
//!
//! ## Lineage
//!
//! Every VM is seeded from exactly one snapshot, and that is recorded
//! (`seeds`) when it is created. A capture is accepted only from a VM whose seed
//! is the **current** snapshot. That rule is what keeps the history linear: a
//! replica that was seeded from an older snapshot — an orphan the autoscaler
//! found late, a resume of a VM from before a rollout — cannot overwrite the
//! work of the one that replaced it. Such a VM is kept, stopped, for an
//! operator to look at (`/disks` lists it), rather than captured or destroyed.
//!
//! The same rule applies on the store side: a push refuses to move the tag if
//! the store holds a snapshot this host has never seen, which is what a
//! deployment moving between hosts looks like from here.
//!
//! ## What runs as what
//!
//! None of this needs root. `debugfs` reads the ext4 image directly (`rdump`),
//! `mke2fs -d` builds the next one from a directory, and both are part of
//! e2fsprogs, which heyvmd already requires. The cost is that ownership is
//! flattened to app-lb's own uid; modes, symlinks and mtimes survive. The image
//! is `e2fsck`'d before it is read, because heyvmd stops a Firecracker VM by
//! killing it and the journal is therefore always dirty.

use crate::config::{DeploymentSpec, WorkspaceSpec, WorkspaceStore};
use crate::deployment::{Deployment, now_secs};
use crate::registry::Registry;
use crate::secrets::SecretStore;
use crate::vm::VmManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod recovery;
pub use recovery::{Recovery, RecoveryRequest};

/// How long the worker sleeps between looks at its queues when nothing has
/// nudged it. Every enqueue nudges it, so this is only the retry cadence for
/// work that failed.
const TICK: Duration = Duration::from_secs(15);

/// How long a failed push or restore waits before it is tried again. Long
/// enough that a store that is down does not produce a log line every tick.
const RETRY_AFTER: Duration = Duration::from_secs(120);

/// Read size when hashing a bundle as it is written.
const CHUNK: usize = 1024 * 1024;

/// `exec sync` in the guest before stopping it. Best-effort and bounded: a
/// guest that cannot answer gets stopped anyway, with a warning, because the
/// alternative is a pool that never rolls.
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// The snapshots kept on this host besides the current one. One is enough to
/// go back a step by hand; the store holds the rest.
const KEEP_PREVIOUS: usize = 1;

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    /// Root of the layout above. `APP_LB_WORKSPACES_DIR`.
    pub root: PathBuf,
    pub tar_bin: String,
    pub aws_bin: String,
    pub art_bin: String,
    /// `--endpoint-url` for an S3-compatible store.
    pub s3_endpoint: Option<String>,
    /// `HOME` for `art`, when app-lb and heyvmd run as different users.
    pub home: Option<String>,
    /// Ceiling on one capture, one push or one restore.
    pub timeout: Duration,
}

impl WorkspaceConfig {
    pub fn from_env(cfg: &crate::config::LbConfig) -> Self {
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        for gone in ["APP_LB_DEBUGFS_BIN", "APP_LB_E2FSCK_BIN"] {
            if env(gone).is_some() {
                tracing::warn!(
                    "{gone} is set but no longer read: the daemon replays and extracts a \
                     workspace image itself (GET /sandboxes/:id/mounts/export)"
                );
            }
        }
        Self {
            root: env("APP_LB_WORKSPACES_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/app-lb/workspaces")),
            tar_bin: env("APP_LB_TAR_BIN").unwrap_or_else(|| "tar".into()),
            aws_bin: cfg.aws_bin.clone(),
            art_bin: cfg.art_bin.clone(),
            s3_endpoint: env("APP_LB_DISK_ARCHIVE_ENDPOINT"),
            home: cfg.heyvm_home.clone(),
            timeout: Duration::from_secs(
                env("APP_LB_WORKSPACE_TIMEOUT_SECS")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3600),
            ),
        }
    }
}


// ---------------------------------------------------------------------------
// persisted state
// ---------------------------------------------------------------------------

/// What to do with a VM once its workspace has been captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Then {
    /// Destroy it.
    Kill,
    /// Leave it stopped and put it on the deployment's suspended list, so the
    /// next scale-up resumes it (`idle_action: retain`).
    Suspend,
}

/// The snapshot a VM was built from, and whether it may have written since.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed {
    /// `None` is the empty workspace.
    pub digest: Option<String>,
    /// Set when the VM is created or resumed, cleared by a capture. A clean VM
    /// is stopped and destroyed without another extraction.
    pub dirty: bool,
    /// Which `mount<n>.ext4` the workspace is on the daemon: the number of
    /// declared mounts in the spec that created the VM. Recorded at create
    /// time because the spec can have changed by the time the VM retires.
    #[serde(default)]
    pub mount_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCapture {
    pub sandbox_id: String,
    pub then: Then,
    pub queued_at: u64,
    /// Failures so far. The capture is retried — the VM is still there — but a
    /// count in the status says so.
    #[serde(default)]
    pub attempts: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recoveries: Vec<Recovery>,
    /// The snapshot the next VM is seeded from. `None` is the empty tree.
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub captured_at: Option<u64>,
    #[serde(default)]
    pub captured_from: Option<String>,
    /// Size of the current snapshot, for the status page.
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub bytes: u64,
    /// The snapshot the store is known to hold — the last one pushed, or the
    /// one restored from it.
    #[serde(default)]
    pub pushed: Option<String>,
    #[serde(default)]
    pub pushed_at: Option<u64>,
    /// `digest` has not reached the store yet.
    #[serde(default)]
    pub push_pending: bool,
    /// The store has been consulted at least once, so `digest: None` means
    /// "empty" rather than "unknown".
    #[serde(default)]
    pub initialized: bool,
    #[serde(default)]
    pub seeds: BTreeMap<String, Seed>,
    #[serde(default)]
    pub pending: Vec<PendingCapture>,
    /// A deployment replacement has withdrawn the old pool but has not yet
    /// queued (or completed) every workspace capture. Persisted because a
    /// restart in this interval must not boot from the previous snapshot.
    #[serde(default)]
    pub replacement_captures_remaining: usize,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_error_at: Option<u64>,
}

/// What the admin API shows. A projection of the record plus the runtime
/// phase.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkspaceStatus {
    pub path: String,
    pub store: String,
    pub digest: Option<String>,
    pub captured_at: Option<u64>,
    pub captured_from: Option<String>,
    pub files: u64,
    pub bytes: u64,
    pub pushed: Option<String>,
    pub pushed_at: Option<u64>,
    pub push_pending: bool,
    /// `idle`, `restoring`, `capturing`, `pushing`, or `blocked`.
    pub phase: String,
    /// Why the pool cannot create a replica right now, if it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<PendingCapture>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

/// Runtime-only state per deployment.
#[derive(Debug, Default)]
struct Runtime {
    /// A capture, push or restore is running right now.
    phase: Option<&'static str>,
    /// A restore has been asked for and not yet done.
    restore_wanted: bool,
    /// The last record mutation could not be written to state.json; the
    /// in-memory record is ahead of the disk and must be persisted again.
    persist_failed: bool,
    /// Do not retry the store before this instant.
    backoff_until: Option<u64>,
}

/// The tree a VM is created from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seeded {
    pub tree: PathBuf,
    pub digest: Option<String>,
}

impl Seeded {
    /// What the create body carries: the tree, under the id the daemon holds
    /// it by. A snapshot is named by its digest, so every replica of the
    /// same snapshot shares one upload; the empty seed is one shared tree
    /// too, because empty is empty.
    pub fn seed(&self) -> crate::vm::WorkspaceSeed {
        crate::vm::WorkspaceSeed {
            tree_id: match &self.digest {
                Some(digest) => format!("ws-{digest}"),
                None => "ws-empty".to_string(),
            },
            tree: self.tree.clone(),
        }
    }
}

pub struct Workspaces {
    /// Serializes capture/recovery and destructive disk decisions.
    lifecycle: tokio::sync::Mutex<()>,
    disk_store: Mutex<std::sync::Weak<crate::disks::DiskStore>>,
    #[cfg(test)]
    fail_after_rename: std::sync::atomic::AtomicBool,
    cfg: WorkspaceConfig,
    vms: VmManager,
    registry: Arc<Registry>,
    secrets: Arc<SecretStore>,
    records: Mutex<HashMap<String, WorkspaceRecord>>,
    runtime: Mutex<HashMap<String, Runtime>>,
    /// The deployment object that retired each pending sandbox, so a `Suspend`
    /// lands on the right suspended list — or on none, if that object has been
    /// replaced since (a rollout), in which case the VM is destroyed instead.
    owners: Mutex<HashMap<String, Arc<Deployment>>>,
    wake: tokio::sync::Notify,
    http: reqwest::Client,
}

impl Workspaces {
    pub fn new(
        cfg: WorkspaceConfig,
        vms: VmManager,
        registry: Arc<Registry>,
        secrets: Arc<SecretStore>,
    ) -> Self {
        Self {
            lifecycle: tokio::sync::Mutex::new(()),
            disk_store: Mutex::new(std::sync::Weak::new()),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
            cfg,
            vms,
            registry,
            secrets,
            records: Mutex::new(HashMap::new()),
            runtime: Mutex::new(HashMap::new()),
            owners: Mutex::new(HashMap::new()),
            wake: tokio::sync::Notify::new(),
            http: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Create the root, or say why it cannot be. Called at startup so a
    /// directory app-lb cannot write is a startup error.
    pub fn ensure_root(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.cfg.root)
            .map_err(|e| format!("cannot create {}: {e}", self.cfg.root.display()))?;
        // heyvmd reads the trees, so the directory chain has to be traversable
        // by its user. 0755 matches the mount root.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&self.cfg.root, std::fs::Permissions::from_mode(0o755));
        }
        Ok(())
    }

    /// Load every `state.json` under the root. Pending captures are resumed by
    /// the worker; the deployment objects that queued them are gone, so a
    /// `Suspend` lands on whatever is live for that id now.
    pub fn load(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.cfg.root) else {
            return 0;
        };
        let mut n = 0;
        for entry in entries.flatten() {
            let id = entry.file_name().to_string_lossy().to_string();
            let path = entry.path().join("state.json");
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            match serde_json::from_str::<WorkspaceRecord>(&text) {
                Ok(record) => {
                    if !record.pending.is_empty() {
                        tracing::info!(
                            deployment = %id,
                            pending = record.pending.len(),
                            "resuming workspace captures queued before restart",
                        );
                    }
                    self.records.lock().unwrap().insert(id, record);
                    n += 1;
                }
                Err(e) => tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "unreadable workspace state; this deployment's workspace is ignored until it is fixed",
                ),
            }
        }
        self.wake.notify_one();
        n
    }

    // -- paths ---------------------------------------------------------------

    fn dir(&self, deployment_id: &str) -> PathBuf {
        self.cfg.root.join(deployment_id)
    }

    fn state_path(&self, deployment_id: &str) -> PathBuf {
        self.dir(deployment_id).join("state.json")
    }

    fn tree_path(&self, deployment_id: &str, digest: Option<&str>) -> PathBuf {
        match digest {
            Some(d) => self.dir(deployment_id).join("snapshots").join(d),
            None => self.dir(deployment_id).join("empty"),
        }
    }

    fn bundle_path(&self, deployment_id: &str, digest: &str) -> PathBuf {
        self.dir(deployment_id)
            .join("bundles")
            .join(format!("{digest}.tar.gz"))
    }

    fn staging_path(&self, deployment_id: &str) -> PathBuf {
        let token = format!("{}-{}", now_secs(), std::process::id());
        self.dir(deployment_id).join(format!("staging-{token}"))
    }


    // -- records -------------------------------------------------------------

    fn with_record<T>(&self, deployment_id: &str, f: impl FnOnce(&mut WorkspaceRecord) -> T) -> T {
        let mut records = self.records.lock().unwrap();
        let record = records.entry(deployment_id.to_string()).or_default();
        let out = f(record);
        let snapshot = record.clone();
        if let Err(e) = self.persist(deployment_id, &snapshot) {
            tracing::error!(deployment = %deployment_id, error = %e, "failed to persist workspace state");
            self.runtime
                .lock()
                .unwrap()
                .entry(deployment_id.to_string())
                .or_default()
                .persist_failed = true;
        }
        out
    }

    fn record(&self, deployment_id: &str) -> WorkspaceRecord {
        self.records
            .lock()
            .unwrap()
            .get(deployment_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Whether deleting the deployment record would detach workspace history
    /// or an operation which must remain addressable by deployment id.
    pub fn has_retained_state(&self, deployment_id: &str) -> bool {
        self.record(deployment_id) != WorkspaceRecord::default()
            || self.runtime.lock().unwrap().contains_key(deployment_id)
    }

    /// Try again to write the in-memory record to state.json after a persist
    /// failure. Returns true once the disk has caught up. The worker calls
    /// this each pass so a transient failure (a full disk, a permissions
    /// hiccup) self-heals without silently stranding the record ahead of the
    /// disk, which is what a restart would otherwise surface as a leftover or
    /// a "snapshot this host has never seen" mismatch.
    fn re_persist(&self, deployment_id: &str) -> bool {
        let records = self.records.lock().unwrap();
        let snapshot = records.get(deployment_id).cloned().unwrap_or_default();
        match self.persist(deployment_id, &snapshot) {
            Ok(()) => {
                self.runtime
                    .lock()
                    .unwrap()
                    .entry(deployment_id.to_string())
                    .or_default()
                    .persist_failed = false;
                true
            }
            Err(e) => {
                tracing::error!(deployment = %deployment_id, error = %e, "retry failed to persist workspace state");
                false
            }
        }
    }

    fn persist(&self, deployment_id: &str, record: &WorkspaceRecord) -> Result<(), String> {
        let path = self.state_path(deployment_id);
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = dir.join(".state.json.tmp");
        let text = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
        #[cfg(test)]
        if self.fail_after_rename.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err("injected uncertainty after rename".into());
        }
        std::fs::File::open(dir).and_then(|f| f.sync_all()).map_err(|e| e.to_string())?;
        std::fs::File::open(&self.cfg.root).and_then(|f| f.sync_all()).map_err(|e| e.to_string())
    }

    fn set_phase(&self, deployment_id: &str, phase: Option<&'static str>) {
        self.runtime
            .lock()
            .unwrap()
            .entry(deployment_id.to_string())
            .or_default()
            .phase = phase;
    }

    fn runtime(&self, deployment_id: &str) -> (Option<&'static str>, bool, Option<u64>) {
        let rt = self.runtime.lock().unwrap();
        match rt.get(deployment_id) {
            Some(r) => (r.phase, r.restore_wanted, r.backoff_until),
            None => (None, false, None),
        }
    }

    /// Whether the last record mutation failed to reach state.json and still
    /// needs writing.
    fn persist_failed(&self, deployment_id: &str) -> bool {
        self.runtime
            .lock()
            .unwrap()
            .get(deployment_id)
            .map(|r| r.persist_failed)
            .unwrap_or(false)
    }

    fn note_error(&self, deployment_id: &str, error: String) {
        tracing::warn!(deployment = %deployment_id, "{error}");
        self.with_record(deployment_id, |r| {
            r.last_error = Some(error);
            r.last_error_at = Some(now_secs());
        });
        self.runtime
            .lock()
            .unwrap()
            .entry(deployment_id.to_string())
            .or_default()
            .backoff_until = Some(now_secs() + RETRY_AFTER.as_secs());
    }

    // -- the autoscaler's entry points ---------------------------------------

    /// Why this deployment cannot create a replica right now, if it cannot.
    pub fn blocked(&self, d: &Deployment) -> Option<String> {
        d.spec.vm.as_ref()?.workspace.as_ref()?;
        let id = &d.spec.id;
        let record = self.record(id);
        let (phase, restore_wanted, _) = self.runtime(id);
        if self.recovery_active(id) {
            return Some("explicit workspace recovery is pending".into());
        }
        if record.replacement_captures_remaining > 0 {
            return Some("workspace capture for deployment replacement is pending".into());
        }
        if let Some(phase) = phase {
            return Some(format!("workspace {phase}"));
        }
        if let Some(p) = record.pending.first() {
            return Some(format!(
                "workspace capture of {} is queued{}",
                p.sandbox_id,
                if p.attempts > 0 {
                    format!(
                        " ({} failed attempt{}: {})",
                        p.attempts,
                        if p.attempts == 1 { "" } else { "s" },
                        record.last_error.as_deref().unwrap_or("see the log")
                    )
                } else {
                    String::new()
                }
            ));
        }
        if self.persist_failed(id) {
            return Some("workspace state could not be written to disk; check the workspace store".into());
        }
        if restore_wanted || !record.initialized {
            return Some(match &record.last_error {
                Some(e) => format!("workspace restore pending: {e}"),
                None => "workspace restore pending".into(),
            });
        }
        if record.digest.is_some() && !self.tree_path(id, record.digest.as_deref()).is_dir() {
            return Some("workspace tree missing on this host; restore pending".into());
        }
        None
    }

    /// The tree to seed a new replica from, or why there is none yet.
    ///
    /// A `None` tree is a create without a workspace (the spec has none). An
    /// `Err` is *not* a failure: it is "not now", and the autoscaler treats it
    /// as such — no backoff, no issue, a debug line and another look next tick.
    pub fn seed_for_create(&self, d: &Deployment) -> Result<Option<Seeded>, String> {
        let Some(_ws) = d.spec.vm.as_ref().and_then(|vm| vm.workspace.as_ref()) else {
            return Ok(None);
        };
        if let Some(why) = self.blocked(d) {
            self.request_restore_if_needed(&d.spec.id);
            return Err(why);
        }
        let id = &d.spec.id;
        let record = self.record(id);
        let tree = self.tree_path(id, record.digest.as_deref());
        if record.digest.is_none() {
            std::fs::create_dir_all(&tree)
                .map_err(|e| format!("cannot create {}: {e}", tree.display()))?;
        }
        Ok(Some(Seeded {
            tree,
            digest: record.digest.clone(),
        }))
    }

    fn request_restore_if_needed(&self, deployment_id: &str) {
        let record = self.record(deployment_id);
        let needs = !record.initialized
            || (record.digest.is_some()
                && !self
                    .tree_path(deployment_id, record.digest.as_deref())
                    .is_dir());
        if needs {
            let mut rt = self.runtime.lock().unwrap();
            let r = rt.entry(deployment_id.to_string()).or_default();
            if !r.restore_wanted {
                r.restore_wanted = true;
                drop(rt);
                self.wake.notify_one();
            }
        }
    }

    /// Record which snapshot a just-created replica was built from, and where
    /// its image sits on the daemon.
    pub fn note_seeded(
        &self,
        deployment_id: &str,
        sandbox_id: &str,
        digest: Option<String>,
        mount_index: usize,
    ) {
        self.with_record(deployment_id, |r| {
            r.seeds.insert(
                sandbox_id.to_string(),
                Seed {
                    digest,
                    dirty: true,
                    mount_index: Some(mount_index),
                },
            );
        });
    }

    /// A suspended replica was resumed: it may write again.
    pub fn note_resumed(&self, deployment_id: &str, sandbox_id: &str) {
        self.with_record(deployment_id, |r| {
            match r.seeds.get_mut(sandbox_id) {
                Some(seed) => seed.dirty = true,
                None => {
                    // Adopted from before this record existed. Assume the
                    // current lineage; the alternative is refusing to ever
                    // capture it.
                    let digest = r.digest.clone();
                    r.seeds.insert(
                        sandbox_id.to_string(),
                        Seed {
                            digest,
                            dirty: true,
                            mount_index: None,
                        },
                    );
                }
            }
        });
    }

    /// Forget a sandbox that is gone.
    pub fn forget(&self, deployment_id: &str, sandbox_id: &str) {
        if self.source_retained(sandbox_id) { return; }
        self.with_record(deployment_id, |r| {
            r.seeds.remove(sandbox_id);
            r.pending.retain(|p| p.sandbox_id != sandbox_id);
        });
        self.owners.lock().unwrap().remove(sandbox_id);
    }

    /// Whether a sandbox is waiting for, or undergoing, a capture.
    pub fn is_pending(&self, deployment_id: &str, sandbox_id: &str) -> bool {
        self.record(deployment_id)
            .pending
            .iter()
            .any(|p| p.sandbox_id == sandbox_id)
    }

    pub fn retirement_protects(&self, sandbox: &str) -> bool {
        self.records.lock().unwrap().iter().any(|(id,r)|self.registry.retirement_frozen(id)
            && (r.seeds.contains_key(sandbox) || r.captured_from.as_deref()==Some(sandbox)
                || r.pending.iter().any(|p|p.sandbox_id==sandbox)
                || r.recoveries.iter().any(|o|o.request.source_sandbox_id==sandbox)))
    }

    pub fn retirement_blocker(&self, id: &str) -> Option<String> {
        let r=self.record(id);
        (!r.pending.is_empty() || r.replacement_captures_remaining>0 || self.persist_failed(id)
            || self.recovery_active(id))
            .then(||"workspace effects require explicit reconciliation; storage remains pinned".into())
    }

    /// Close the stale-seed window before a replacement is installed in the
    /// registry. The autoscaler holds its create permits while setting this,
    /// so an old-template create cannot slip between the fence and the swap.
    pub(crate) fn begin_replacement(&self, deployment_id: &str, expected: usize) -> Result<(), String> {
        if self.recovery_active(deployment_id) { return Err("workspace recovery reserves this deployment".into()); }
        self.with_record(deployment_id, |r| {
            // A second edit may see an empty replacement pool while the first
            // edit is still capturing its predecessor. It cannot clear that
            // predecessor's fence merely because its own pool has no VMs.
            if r.replacement_captures_remaining == 0 {
                r.replacement_captures_remaining = expected;
            }
        });
        if self.persist_failed(deployment_id) {
            return Err("could not persist workspace replacement fence; deployment remains unchanged".into());
        }
        Ok(())
    }

    fn complete_replacement_capture(&self, deployment_id: &str) {
        self.with_record(deployment_id, |r| {
            r.replacement_captures_remaining = r.replacement_captures_remaining.saturating_sub(1);
        });
    }

    /// Take a replica out of service: sync, stop, and queue its capture.
    ///
    /// Returns once the VM is stopped and the capture is queued. The VM is not
    /// destroyed here even for `Then::Kill` — that happens after the capture,
    /// in the worker. If the VM cannot be stopped the error is returned and
    /// nothing is queued; the caller decides whether to kill it anyway.
    pub async fn retire(
        &self,
        d: &Arc<Deployment>,
        sandbox_id: &str,
        then: Then,
    ) -> Result<(), String> {
        let id = d.spec.id.clone();
        if self.is_pending(&id, sandbox_id) {
            return Ok(());
        }
        self.vms.sync_guest(&id, sandbox_id, SYNC_TIMEOUT).await;
        self.vms
            .suspend(sandbox_id)
            .await
            .map_err(|e| format!("could not stop {sandbox_id} for capture: {e}"))?;

        self.owners
            .lock()
            .unwrap()
            .insert(sandbox_id.to_string(), d.clone());
        self.with_record(&id, |r| {
            r.pending.push(PendingCapture {
                sandbox_id: sandbox_id.to_string(),
                then,
                queued_at: now_secs(),
                attempts: 0,
            });
        });
        tracing::info!(deployment = %id, sandbox = %sandbox_id, ?then, "workspace capture queued");
        self.wake.notify_one();
        Ok(())
    }

    /// [`retire`](Self::retire) for a VM that is already stopped: no sync, no
    /// stop, straight onto the queue.
    pub fn retire_stopped(
        &self,
        d: &Arc<Deployment>,
        sandbox_id: &str,
        then: Then,
    ) -> Result<(), String> {
        let id = d.spec.id.clone();
        if self.is_pending(&id, sandbox_id) {
            return Ok(());
        }
        self.owners
            .lock()
            .unwrap()
            .insert(sandbox_id.to_string(), d.clone());
        self.with_record(&id, |r| {
            r.pending.push(PendingCapture {
                sandbox_id: sandbox_id.to_string(),
                then,
                queued_at: now_secs(),
                attempts: 0,
            });
        });
        self.wake.notify_one();
        Ok(())
    }

    /// Whether a stopped sandbox is this module's to decide about: queued for
    /// capture, of unknown or older lineage, or possibly holding writes that
    /// were never captured. The suspended-VM sweep leaves such a sandbox alone;
    /// only one whose last capture is the current snapshot is free for it.
    pub fn holds(&self, deployment_id: &str, sandbox_id: &str) -> bool {
        if self.source_retained(sandbox_id) { return true; }
        let record = self.record(deployment_id);
        if record.pending.iter().any(|p| p.sandbox_id == sandbox_id) {
            return true;
        }
        match record.seeds.get(sandbox_id) {
            Some(seed) => seed.dirty || seed.digest != record.digest,
            None => true,
        }
    }

    pub fn status(&self, d: &Deployment) -> Option<WorkspaceStatus> {
        let ws = d.spec.vm.as_ref()?.workspace.as_ref()?;
        let record = self.record(&d.spec.id);
        let (phase, restore_wanted, _) = self.runtime(&d.spec.id);
        let blocked = self.blocked(d);
        Some(WorkspaceStatus {
            path: ws.guest_path().to_string(),
            store: ws.store.trim().to_string(),
            digest: record.digest.clone(),
            captured_at: record.captured_at,
            captured_from: record.captured_from.clone(),
            files: record.files,
            bytes: record.bytes,
            pushed: record.pushed.clone(),
            pushed_at: record.pushed_at,
            push_pending: record.push_pending,
            phase: phase.map(str::to_string).unwrap_or_else(|| {
                if restore_wanted {
                    "restoring".into()
                } else if blocked.is_some() {
                    "blocked".into()
                } else {
                    "idle".into()
                }
            }),
            blocked,
            pending: record.pending.clone(),
            last_error: record.last_error.clone(),
        })
    }

    // -- the worker ----------------------------------------------------------

    /// One pass over every deployment's queues. Sequential on purpose: each
    /// item is gigabytes of disk or network I/O.
    async fn pass(&self) {
        let _retirement=self.registry.retirement_gate.read().await;
        let _lifecycle = self.lifecycle_guard().await;
        let ids: Vec<String> = {
            let records = self.records.lock().unwrap();
            let rt = self.runtime.lock().unwrap();
            let mut ids: Vec<String> = records
                .iter()
                .filter(|(_, r)| !r.pending.is_empty() || r.push_pending || r.recoveries.iter().any(|o| o.status == "running"))
                .map(|(id, _)| id.clone())
                .chain(
                    rt.iter()
                        .filter(|(_, r)| r.restore_wanted || r.persist_failed)
                        .map(|(id, _)| id.clone()),
                )
                .collect();
            ids.sort();
            ids.dedup();
            ids
        };
        for id in ids {
            if self.registry.retirement_frozen(&id) {continue;}
            let Some(d) = self.registry.get(&id) else {
                // Deregistered. Captures still run — a deployment that is gone
                // should still have its last state in the store — but there is
                // nothing to restore for.
                self.runtime.lock().unwrap().remove(&id);
                if let Some(spec) = self.spec_for_orphan(&id) {
                    self.drain_captures(&id, &spec).await;
                }
                continue;
            };
            if d.spec
                .vm
                .as_ref()
                .and_then(|vm| vm.workspace.as_ref())
                .is_none()
            {
                continue;
            }
            let (_, _, backoff) = self.runtime(&id);
            let in_backoff = backoff.is_some_and(|until| now_secs() < until);

            // If the last mutation could not reach state.json, get the disk
            // back in sync with the in-memory record before deciding anything
            // else, so a restart can never re-discover a stale record as a
            // "snapshot this host has never seen" mismatch.
            if self.persist_failed(&id) {
                if !self.re_persist(&id) { continue; }
            }

            if self.recovery_active(&id) {
                if !in_backoff { self.run_recovery(&d).await; }
                continue;
            }
            self.drain_captures(&id, &d.spec).await;

            let record = self.record(&id);
            let (_, restore_wanted, _) = self.runtime(&id);
            if restore_wanted && record.pending.is_empty() && !in_backoff {
                self.run_restore(&d).await;
            }
            let record = self.record(&id);
            if record.push_pending && !in_backoff {
                self.run_push(&d.spec).await;
            }
        }
    }

    /// A deregistered deployment has no spec in the registry; the capture
    /// needs one for the image index and the store. The last one is kept
    /// beside the state for exactly this.
    fn spec_for_orphan(&self, deployment_id: &str) -> Option<DeploymentSpec> {
        let path = self.dir(deployment_id).join("spec.json");
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn remember_spec(&self, spec: &DeploymentSpec) {
        let path = self.dir(&spec.id).join("spec.json");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string(spec) {
            let _ = std::fs::write(path, text);
        }
    }

    async fn drain_captures(&self, id: &str, spec: &DeploymentSpec) {
        loop {
            let Some(next) = self.record(id).pending.first().cloned() else {
                return;
            };
            let outcome = self.run_capture(spec, &next).await;
            match outcome {
                Ok(()) => {
                    self.with_record(id, |r| {
                        r.pending.retain(|p| p.sandbox_id != next.sandbox_id)
                    });
                    self.after_capture(id, &next).await;
                }
                Err(CaptureError::Stale(why)) => {
                    // Not retried: the VM is left stopped for a person.
                    self.note_error(
                        id,
                        format!(
                            "workspace of {} not captured: {why}. The VM is kept stopped; its disk \
                         is listed at /disks. An authorized workspace recovery can select this retained source",
                            next.sandbox_id
                        ),
                    );
                    self.with_record(id, |r| {
                        r.pending.retain(|p| p.sandbox_id != next.sandbox_id)
                    });
                    self.owners.lock().unwrap().remove(&next.sandbox_id);
                }
                Err(CaptureError::Gone(why)) => {
                    // No image: nothing to capture and nothing to keep.
                    tracing::warn!(deployment = %id, sandbox = %next.sandbox_id, "{why}; destroying the VM");
                    self.with_record(id, |r| {
                        r.pending.retain(|p| p.sandbox_id != next.sandbox_id)
                    });
                    self.complete_replacement_capture(id);
                    self.kill(id, &next.sandbox_id).await;
                }
                Err(CaptureError::Retry(why)) => {
                    self.note_error(
                        id,
                        format!("workspace capture of {} failed: {why}", next.sandbox_id),
                    );
                    self.with_record(id, |r| {
                        if let Some(p) = r
                            .pending
                            .iter_mut()
                            .find(|p| p.sandbox_id == next.sandbox_id)
                        {
                            p.attempts += 1;
                        }
                    });
                    return; // back off; the VM stays stopped and queued
                }
            }
        }
    }

    async fn after_capture(&self, id: &str, done: &PendingCapture) {
        if self.recovery_pinned(&done.sandbox_id) { return; }
        self.complete_replacement_capture(id);
        let owner = self.owners.lock().unwrap().remove(&done.sandbox_id);
        if self.persist_failed(id) || done.then == Then::Kill && self.source_retained(&done.sandbox_id) { return; }
        match done.then {
            Then::Kill => self.kill(id, &done.sandbox_id).await,
            Then::Suspend => {
                let live = self.registry.get(id);
                let same = match (&owner, &live) {
                    (Some(o), Some(l)) => Arc::ptr_eq(o, l),
                    // After a restart the owner is unknown; the live object is
                    // the one that loaded this deployment's suspended list.
                    (None, Some(_)) => true,
                    _ => false,
                };
                match live {
                    Some(d) if same => {
                        let changed = d.mutate_state(|s| {
                            if !s.suspended.contains(&done.sandbox_id) {
                                s.suspended.push(done.sandbox_id.clone());
                            }
                        });
                        if changed && let Err(e) = self.registry.persist_one(id) {
                            tracing::error!(deployment = %id, error = %e, "failed to persist suspended sandboxes");
                        }
                        d.scale_signal.notify_one();
                    }
                    _ => {
                        tracing::info!(
                            deployment = %id,
                            sandbox = %done.sandbox_id,
                            "captured; the deployment was replaced meanwhile, so the VM is destroyed rather than kept",
                        );
                        self.kill(id, &done.sandbox_id).await;
                    }
                }
            }
        }
        if let Some(d) = self.registry.get(id) {
            d.scale_signal.notify_one();
        }
    }

    async fn kill(&self, deployment_id: &str, sandbox_id: &str) {
        if self.source_retained(sandbox_id) { return; }
        if let Err(e) = self.vms.kill(sandbox_id).await {
            tracing::warn!(deployment = %deployment_id, sandbox = %sandbox_id, error = %e, "failed to kill VM after capture");
        }
        self.with_record(deployment_id, |r| {
            r.seeds.remove(sandbox_id);
        });
    }

    // -- capture -------------------------------------------------------------

    async fn run_capture(
        &self,
        spec: &DeploymentSpec,
        p: &PendingCapture,
    ) -> Result<(), CaptureError> {
        let id = spec.id.clone();
        let sandbox_id = p.sandbox_id.clone();
        if self.recovery_pinned(&sandbox_id) {
            return Err(CaptureError::Stale("explicit recovery source remains pinned".into()));
        }
        self.remember_spec(spec);

        let record = self.record(&id);
        let seed = record.seeds.get(&sandbox_id).cloned();
        match &seed {
            Some(seed) if seed.digest != record.digest => {
                return Err(CaptureError::Stale(format!(
                    "it was seeded from {} but the current snapshot is {}",
                    short(seed.digest.as_deref()),
                    short(record.digest.as_deref())
                )));
            }
            Some(seed) if !seed.dirty => {
                tracing::info!(deployment = %id, sandbox = %sandbox_id, "workspace unchanged since its last capture; nothing to extract");
                return Ok(());
            }
            Some(_) => {}
            None => tracing::warn!(
                deployment = %id, sandbox = %sandbox_id,
                "no record of which snapshot this VM was seeded from; assuming the current one",
            ),
        }

        if !crate::disks::valid_sandbox_id(&sandbox_id) {
            return Err(CaptureError::Gone(format!("{sandbox_id} is not a sandbox id")));
        }
        let guest_path = spec
            .vm
            .as_ref()
            .and_then(|vm| vm.workspace.as_ref())
            .map(|ws| ws.guest_path().to_string())
            .unwrap_or_else(|| crate::config::DEFAULT_WORKSPACE_PATH.to_string());

        // The one check that matters: the image must not be in use. The
        // daemon refuses an export of a live sandbox too, but stopping it
        // here is what makes the retry succeed.
        match self.vms.list().await {
            Ok(fleet) => {
                if fleet
                    .iter()
                    .any(|s| s.id == sandbox_id && s.status == heyo_sdk::SandboxStatus::Running)
                {
                    // Stop it again; whatever resumed it did not know.
                    if let Err(e) = self.vms.suspend(&sandbox_id).await {
                        return Err(CaptureError::Retry(format!(
                            "the VM is running and would not stop: {e}"
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(CaptureError::Retry(format!(
                    "cannot confirm the VM is stopped: {e}"
                )));
            }
        }

        self.set_phase(&id, Some("capturing"));
        let cfg = self.cfg.clone();
        let dir = self.dir(&id);
        let staging = self.staging_path(&id);
        let timeout = cfg.timeout;
        let result = match tokio::time::timeout(timeout, self.capture_via_daemon(&cfg, &dir, &sandbox_id, &guest_path, &staging)).await {
            Ok(r) => r,
            Err(_) => Err(CaptureError::Retry(format!("capture exceeded {}s", timeout.as_secs()))),
        };
        self.set_phase(&id, None);

        let captured = result?;
        tracing::info!(
            deployment = %id,
            sandbox = %sandbox_id,
            digest = %captured.digest,
            files = captured.files,
            bytes = captured.bytes,
            "workspace captured",
        );
        let previous = record.digest.clone();
        self.with_record(&id, |r| {
            r.digest = Some(captured.digest.clone());
            r.captured_at = Some(now_secs());
            r.captured_from = Some(sandbox_id.clone());
            r.files = captured.files;
            r.bytes = captured.bytes;
            r.push_pending = true;
            r.initialized = true;
            r.last_error = None;
            let mount_index = r.seeds.get(&sandbox_id).and_then(|s| s.mount_index);
            r.seeds.insert(
                sandbox_id.clone(),
                Seed {
                    digest: Some(captured.digest.clone()),
                    dirty: false,
                    mount_index,
                },
            );
        });
        self.prune_snapshots(&id, previous.as_deref(), &captured.digest);
        self.wake.notify_one();
        Ok(())
    }

    /// The daemon replays the image's journal and extracts it
    /// (`GET /sandboxes/:id/mounts/export`); what arrives here is a tarball.
    /// It is hashed as it lands, so the digest names the bundle as written,
    /// then unpacked beside it into the snapshot tree the next replica is
    /// seeded from.
    async fn capture_via_daemon(
        &self,
        cfg: &WorkspaceConfig,
        dir: &Path,
        sandbox_id: &str,
        guest_path: &str,
        staging: &Path,
    ) -> Result<Captured, CaptureError> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;

        let response = match self.vms.export_mount(sandbox_id, guest_path).await {
            Ok(r) => r,
            Err(crate::vm::VmError::Sdk(heyo_sdk::HeyoError::NotFound(m))) => {
                return Err(CaptureError::Gone(format!("the daemon has no workspace image to export: {m}")));
            }
            Err(e) => return Err(CaptureError::Retry(format!("the daemon would not export the workspace: {e}"))),
        };

        std::fs::create_dir_all(dir.join("bundles")).map_err(|e| CaptureError::Retry(e.to_string()))?;
        let bundle_tmp = staging.with_extension("tar.gz");
        let guard = RemoveOnDrop(bundle_tmp.clone());
        let mut file = tokio::fs::File::create(&bundle_tmp)
            .await
            .map_err(|e| CaptureError::Retry(format!("{}: {e}", bundle_tmp.display())))?;
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| CaptureError::Retry(format!("reading the daemon's export: {e}")))?;
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| CaptureError::Retry(format!("{}: {e}", bundle_tmp.display())))?;
        }
        file.sync_all().await.map_err(|e| CaptureError::Retry(e.to_string()))?;
        drop(file);
        let digest = hex(&hasher.finalize());

        let (cfg, dir, staging, bundle) = (cfg.clone(), dir.to_path_buf(), staging.to_path_buf(), bundle_tmp.clone());
        let installed = tokio::task::spawn_blocking(move || install_capture(&cfg, &dir, &bundle, &staging, &digest))
            .await
            .map_err(|e| CaptureError::Retry(format!("capture task died: {e}")))?;
        std::mem::forget(guard);
        installed.map_err(CaptureError::Retry)
    }

    /// Keep the current snapshot, the one before it, and anything a live
    /// sandbox was seeded from; remove the rest, with their bundles once
    /// pushed.
    fn prune_snapshots(&self, id: &str, previous: Option<&str>, current: &str) {
        let record = self.record(id);
        let mut keep: Vec<String> = vec![current.to_string()];
        keep.extend(previous.map(str::to_string).into_iter().take(KEEP_PREVIOUS));
        keep.extend(record.seeds.values().filter_map(|s| s.digest.clone()));
        keep.extend(record.recoveries.iter().flat_map(|o| std::iter::once(o.request.expected_snapshot.clone()).chain(o.snapshot.clone())));
        keep.extend(record.pushed.clone());
        let snapshots = self.dir(id).join("snapshots");
        if let Ok(entries) = std::fs::read_dir(&snapshots) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !keep.contains(&name) {
                    let _ = std::fs::remove_dir_all(entry.path());
                    // The daemon holds the tree replicas were seeded from
                    // (`ws-<digest>`); let it go there too. Best-effort.
                    let vms = self.vms.clone();
                    let tree = format!("ws-{name}");
                    let registry = self.registry.clone();
                    let id = id.to_string();
                    tokio::spawn(async move {
                        let _retirement=registry.retirement_gate.read().await;
                        // Daemon trees are content-addressed and shared across
                        // deployments. Without a complete reference ledger,
                        // another deployment cannot reclaim a retired tree.
                        if registry.retirement_frozen(&id)
                            || registry.deployments().values().any(|d|d.state().retirement.is_some()) {return;}
                        if let Err(e) = vms.delete_tree(&tree).await {
                            tracing::debug!(tree = %tree, error = %e, "could not remove the pruned snapshot's tree on the daemon");
                        }
                    });
                }
            }
        }
        let bundles = self.dir(id).join("bundles");
        if let Ok(entries) = std::fs::read_dir(&bundles) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let digest = name.trim_end_matches(".tar.gz");
                let unpushed = record.push_pending && record.digest.as_deref() == Some(digest);
                if !keep.contains(&digest.to_string()) && !unpushed {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // -- push ----------------------------------------------------------------

    async fn run_push(&self, spec: &DeploymentSpec) {
        let id = spec.id.clone();
        let Some(ws) = spec.vm.as_ref().and_then(|vm| vm.workspace.clone()) else {
            return;
        };
        let record = self.record(&id);
        let Some(digest) = record.digest.clone() else {
            self.with_record(&id, |r| r.push_pending = false);
            return;
        };
        if record.pushed.as_deref() == Some(digest.as_str()) {
            self.with_record(&id, |r| r.push_pending = false);
            return;
        }
        let bundle = self.bundle_path(&id, &digest);
        if !bundle.is_file() {
            self.note_error(
                &id,
                format!(
                    "the bundle for {} is missing; the snapshot cannot be pushed",
                    short(Some(&digest))
                ),
            );
            self.with_record(&id, |r| r.push_pending = false);
            return;
        }
        self.set_phase(&id, Some("pushing"));
        let result = tokio::time::timeout(
            self.cfg.timeout,
            self.push(&ws, &id, &digest, &bundle, record.pushed.as_deref()),
        )
        .await
        .unwrap_or_else(|_| Err(format!("push exceeded {}s", self.cfg.timeout.as_secs())));
        self.set_phase(&id, None);
        match result {
            Ok(()) => {
                tracing::info!(deployment = %id, digest = %digest, store = %ws.store, "workspace snapshot pushed");
                self.with_record(&id, |r| {
                    r.pushed = Some(digest.clone());
                    r.pushed_at = Some(now_secs());
                    r.push_pending = false;
                    r.last_error = None;
                });
                self.prune_snapshots(&id, None, &digest);
            }
            Err(e) => self.note_error(&id, format!("workspace push to {} failed: {e}", ws.store)),
        }
    }

    /// Send a bundle and move the tag, refusing if the tag has moved under us.
    async fn push(
        &self,
        ws: &WorkspaceSpec,
        deployment_id: &str,
        digest: &str,
        bundle: &Path,
        known: Option<&str>,
    ) -> Result<(), String> {
        let store = ws.backend().ok_or("unusable workspace store")?;
        let remote = self.remote_head(ws, &store, deployment_id).await?;
        if let Some(remote) = &remote
            && Some(remote.as_str()) != known
            && remote != digest
        {
            return Err(format!(
                "the store holds snapshot {} which this host has never seen (last known: {}); \
                 another host may own this workspace now. Not overwriting it — restore from \
                 the store, or retag it by hand",
                short(Some(remote)),
                short(known)
            ));
        }
        match &store {
            WorkspaceStore::S3 { bucket, prefix } => {
                let key = s3_key(prefix, deployment_id, &format!("{digest}.tar.gz"));
                self.aws(
                    &[
                        "s3",
                        "cp",
                        &bundle.to_string_lossy(),
                        &format!("s3://{bucket}/{key}"),
                        "--only-show-errors",
                    ],
                    None,
                )
                .await?;
                let latest = s3_key(prefix, deployment_id, "latest");
                self.aws(
                    &[
                        "s3",
                        "cp",
                        "-",
                        &format!("s3://{bucket}/{latest}"),
                        "--only-show-errors",
                    ],
                    Some(format!("{digest}\n")),
                )
                .await?;
                Ok(())
            }
            WorkspaceStore::Remote(base) => {
                let key = self.api_key(ws)?;
                let url = format!("{base}/blobs/{digest}");
                let file = tokio::fs::File::open(bundle)
                    .await
                    .map_err(|e| format!("{}: {e}", bundle.display()))?;
                let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                let body = reqwest::Body::wrap_stream(file_stream(file));
                let resp = self
                    .authed(
                        self.http
                            .put(&url)
                            .header(reqwest::header::CONTENT_LENGTH, len)
                            .body(body),
                        key.as_deref(),
                    )
                    .send()
                    .await
                    .map_err(|e| format!("PUT {url} failed: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(format!("PUT {url} answered {status}: {}", text.trim()));
                }
                let tag = ws.tag(deployment_id);
                let url = format!("{base}/tags/{tag}");
                let resp = self
                    .authed(self.http.put(&url).body(digest.to_string()), key.as_deref())
                    .send()
                    .await
                    .map_err(|e| format!("PUT {url} failed: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    return Err(format!("PUT {url} answered {status}: {}", text.trim()));
                }
                Ok(())
            }
            WorkspaceStore::Local(root) => {
                let tag = ws.tag(deployment_id);
                let out = self
                    .art(root, &["put", &bundle.to_string_lossy(), "--tag", &tag])
                    .await?;
                let v: serde_json::Value = serde_json::from_str(&out)
                    .map_err(|e| format!("`art put` output is not JSON: {e}"))?;
                match v.get("digest").and_then(|d| d.as_str()) {
                    Some(d) if d == digest => Ok(()),
                    Some(d) => Err(format!("`art put` stored {d}, expected {digest}")),
                    None => Err("`art put` reported no digest".into()),
                }
            }
        }
    }

    /// The digest the store currently publishes for this workspace, if any.
    async fn remote_head(
        &self,
        ws: &WorkspaceSpec,
        store: &WorkspaceStore,
        deployment_id: &str,
    ) -> Result<Option<String>, String> {
        match store {
            WorkspaceStore::S3 { bucket, prefix } => {
                let latest = s3_key(prefix, deployment_id, "latest");
                let uri = format!("s3://{bucket}/{latest}");
                match self
                    .aws(&["s3", "cp", &uri, "-", "--only-show-errors"], None)
                    .await
                {
                    Ok(text) => {
                        let d = text.trim().to_string();
                        if crate::config::is_sha256_hex(&d) {
                            Ok(Some(d))
                        } else {
                            Err(format!(
                                "{uri} does not hold a digest: {:?}",
                                d.chars().take(80).collect::<String>()
                            ))
                        }
                    }
                    Err(e)
                        if e.contains("404")
                            || e.contains("NoSuchKey")
                            || e.contains("does not exist") =>
                    {
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }
            WorkspaceStore::Remote(base) => {
                let key = self.api_key(ws)?;
                let tag = ws.tag(deployment_id);
                let url = format!("{base}/tags/{tag}");
                let resp = self
                    .authed(self.http.get(&url), key.as_deref())
                    .send()
                    .await
                    .map_err(|e| format!("GET {url} failed: {e}"))?;
                match resp.status() {
                    s if s.is_success() => {
                        let text = resp.text().await.map_err(|e| format!("GET {url}: {e}"))?;
                        Ok(Some(parse_tag_body(&text).ok_or_else(|| {
                            format!("GET {url} answered something that is not a digest")
                        })?))
                    }
                    reqwest::StatusCode::NOT_FOUND => Ok(None),
                    s => {
                        let text = resp.text().await.unwrap_or_default();
                        Err(format!("GET {url} answered {s}: {}", text.trim()))
                    }
                }
            }
            WorkspaceStore::Local(root) => {
                let tag = ws.tag(deployment_id);
                match self.art(root, &["stat", &tag]).await {
                    Ok(out) => {
                        let v: serde_json::Value = serde_json::from_str(&out)
                            .map_err(|e| format!("`art stat` output is not JSON: {e}"))?;
                        Ok(v.get("digest").and_then(|d| d.as_str()).map(str::to_string))
                    }
                    Err(e)
                        if e.contains("not found")
                            || e.contains("no such")
                            || e.contains("unknown") =>
                    {
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    // -- restore -------------------------------------------------------------

    async fn run_restore(&self, d: &Arc<Deployment>) {
        let id = d.spec.id.clone();
        let Some(ws) = d.spec.vm.as_ref().and_then(|vm| vm.workspace.clone()) else {
            return;
        };
        self.set_phase(&id, Some("restoring"));
        let result = tokio::time::timeout(self.cfg.timeout, self.restore(&ws, &id))
            .await
            .unwrap_or_else(|_| Err(format!("restore exceeded {}s", self.cfg.timeout.as_secs())));
        self.set_phase(&id, None);
        match result {
            Ok(restored) => {
                match &restored {
                    Some((digest, files, bytes)) => tracing::info!(
                        deployment = %id, digest = %digest, files, bytes, store = %ws.store,
                        "workspace restored from the store",
                    ),
                    None => tracing::info!(
                        deployment = %id, store = %ws.store,
                        "the store has no snapshot for this workspace; starting empty",
                    ),
                }
                self.with_record(&id, |r| {
                    r.initialized = true;
                    r.last_error = None;
                    if let Some((digest, files, bytes)) = restored {
                        r.digest = Some(digest.clone());
                        r.pushed = Some(digest);
                        r.pushed_at = Some(now_secs());
                        r.push_pending = false;
                        r.files = files;
                        r.bytes = bytes;
                    }
                });
                self.runtime
                    .lock()
                    .unwrap()
                    .entry(id.clone())
                    .or_default()
                    .restore_wanted = false;
                d.scale_signal.notify_one();
            }
            Err(e) => self.note_error(
                &id,
                format!("workspace restore from {} failed: {e}", ws.store),
            ),
        }
    }

    /// Fetch the store's newest snapshot into place. `Ok(None)` means the
    /// store has none — a definite answer, not a failure; an unreachable store
    /// is an `Err`, because starting empty in that case would be silent data
    /// loss followed by a push that overwrote the real thing.
    async fn restore(
        &self,
        ws: &WorkspaceSpec,
        id: &str,
    ) -> Result<Option<(String, u64, u64)>, String> {
        let store = ws.backend().ok_or("unusable workspace store")?;
        let record = self.record(id);
        // A record that names a snapshot whose tree was swept: fetch that
        // exact one rather than whatever the store calls newest, so the lineage
        // this host recorded for its sandboxes stays true.
        let wanted = match &record.digest {
            Some(d) if record.initialized => Some(d.clone()),
            _ => self.remote_head(ws, &store, id).await?,
        };
        let Some(digest) = wanted else {
            return Ok(None);
        };
        let tree = self.tree_path(id, Some(&digest));
        if tree.is_dir() {
            return Ok(Some((digest, record.files, record.bytes)));
        }
        let bundle = self.bundle_path(id, &digest);
        std::fs::create_dir_all(bundle.parent().unwrap()).map_err(|e| e.to_string())?;
        if !bundle.is_file() || !verify_file(&bundle, &digest)? {
            let tmp = self.staging_path(id).with_extension("tar.gz");
            match &store {
                WorkspaceStore::S3 { bucket, prefix } => {
                    let key = s3_key(prefix, id, &format!("{digest}.tar.gz"));
                    self.aws(
                        &[
                            "s3",
                            "cp",
                            &format!("s3://{bucket}/{key}"),
                            &tmp.to_string_lossy(),
                            "--only-show-errors",
                        ],
                        None,
                    )
                    .await?;
                }
                WorkspaceStore::Remote(base) => {
                    let key = self.api_key(ws)?;
                    let url = format!("{base}/blobs/{digest}");
                    let resp = self
                        .authed(self.http.get(&url), key.as_deref())
                        .send()
                        .await
                        .map_err(|e| format!("GET {url} failed: {e}"))?;
                    if !resp.status().is_success() {
                        let status = resp.status();
                        return Err(format!("GET {url} answered {status}"));
                    }
                    use futures::StreamExt;
                    use tokio::io::AsyncWriteExt;
                    let mut file = tokio::fs::File::create(&tmp)
                        .await
                        .map_err(|e| format!("{}: {e}", tmp.display()))?;
                    let mut stream = resp.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        let chunk =
                            chunk.map_err(|e| format!("transfer from {url} failed: {e}"))?;
                        file.write_all(&chunk)
                            .await
                            .map_err(|e| format!("{}: {e}", tmp.display()))?;
                    }
                    file.flush().await.map_err(|e| e.to_string())?;
                }
                WorkspaceStore::Local(root) => {
                    self.art(
                        root,
                        &["get", &digest, "-o", &tmp.to_string_lossy(), "--writable"],
                    )
                    .await?;
                }
            }
            if !verify_file(&tmp, &digest)? {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!(
                    "the store answered bytes that do not hash to {digest}; not kept"
                ));
            }
            std::fs::rename(&tmp, &bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
        }
        let cfg = self.cfg.clone();
        let staging = self.staging_path(id);
        let bundle2 = bundle.clone();
        let tree2 = tree.clone();
        let (files, bytes) =
            tokio::task::spawn_blocking(move || extract_bundle(&cfg, &bundle2, &staging, &tree2))
                .await
                .map_err(|e| format!("restore task died: {e}"))??;
        Ok(Some((digest, files, bytes)))
    }

    // -- transports ------------------------------------------------------------

    fn api_key(&self, ws: &WorkspaceSpec) -> Result<Option<String>, String> {
        match &ws.auth {
            None => Ok(None),
            Some(r) => self
                .secrets
                .resolve(r)
                .map(Some)
                .map_err(|e| format!("{e} — `heyctl get secrets` lists what this LB holds")),
        }
    }

    fn authed(
        &self,
        req: reqwest::RequestBuilder,
        api_key: Option<&str>,
    ) -> reqwest::RequestBuilder {
        match api_key {
            Some(k) => req.bearer_auth(k),
            None => req,
        }
    }

    async fn aws(&self, args: &[&str], stdin: Option<String>) -> Result<String, String> {
        use std::process::Stdio;
        let mut cmd = tokio::process::Command::new(&self.cfg.aws_bin);
        cmd.args(args);
        if let Some(endpoint) = &self.cfg.s3_endpoint {
            cmd.arg("--endpoint-url").arg(endpoint);
        }
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not run {}: {e}", self.cfg.aws_bin))?;
        if let Some(body) = stdin {
            use tokio::io::AsyncWriteExt;
            if let Some(mut pipe) = child.stdin.take() {
                pipe.write_all(body.as_bytes())
                    .await
                    .map_err(|e| format!("aws stdin: {e}"))?;
            }
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| format!("aws: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "aws {} exited {}: {}",
                args.first().copied().unwrap_or(""),
                out.status.code().unwrap_or(-1),
                tail(&String::from_utf8_lossy(&out.stderr))
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    async fn art(&self, root: &str, args: &[&str]) -> Result<String, String> {
        let mut cmd = tokio::process::Command::new(&self.cfg.art_bin);
        cmd.arg("--root").arg(root).arg("--json").args(args);
        if let Some(home) = &self.cfg.home {
            cmd.env("HOME", home);
        }
        let out = cmd
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| format!("could not run {}: {e}", self.cfg.art_bin))?;
        if !out.status.success() {
            return Err(format!(
                "{} {} exited {}: {}",
                self.cfg.art_bin,
                args.first().copied().unwrap_or(""),
                out.status.code().unwrap_or(-1),
                tail(&String::from_utf8_lossy(&out.stderr))
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

enum CaptureError {
    /// Try again later; the VM stays stopped and queued.
    Retry(String),
    /// The VM is not from the current lineage; it is kept for a person.
    Stale(String),
    /// There is no image to capture.
    Gone(String),
}

struct Captured {
    digest: String,
    files: u64,
    bytes: u64,
}

/// The blocking half of a capture: unpack the daemon's export beside the
/// bundle it came from, and publish both under the digest.
fn install_capture(
    cfg: &WorkspaceConfig,
    dir: &Path,
    bundle_tmp: &Path,
    staging: &Path,
    digest: &str,
) -> Result<Captured, String> {
    let _guard = RemoveOnDrop(staging.to_path_buf());
    let _guard2 = RemoveOnDrop(bundle_tmp.to_path_buf());
    std::fs::create_dir_all(dir.join("snapshots")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("bundles")).map_err(|e| e.to_string())?;

    std::fs::create_dir_all(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    // System tar rather than the in-process unpacker: a workspace legitimately
    // holds symlinks, which the bundle unpacker refuses for the untrusted
    // input it was written for. This tarball came from the daemon.
    let out = std::process::Command::new(&cfg.tar_bin)
        .arg("--extract")
        .arg("--gzip")
        .arg("--no-same-owner")
        .arg("--file")
        .arg(bundle_tmp)
        .arg("--directory")
        .arg(staging)
        .output()
        .map_err(|e| format!("could not run {}: {e}", cfg.tar_bin))?;
    if !out.status.success() {
        return Err(format!(
            "tar exited {}: {}",
            out.status.code().unwrap_or(-1),
            tail(&String::from_utf8_lossy(&out.stderr))
        ));
    }
    // Every ext4 has one; the daemon drops it, and the next mke2fs makes its own.
    let _ = std::fs::remove_dir_all(staging.join("lost+found"));
    let (files, bytes) = tree_stats(staging);

    let tree = dir.join("snapshots").join(digest);
    if tree.exists() {
        let _ = std::fs::remove_dir_all(&tree);
    }
    std::fs::rename(staging, &tree)
        .map_err(|e| format!("{} -> {}: {e}", staging.display(), tree.display()))?;
    let bundle = dir.join("bundles").join(format!("{digest}.tar.gz"));
    std::fs::rename(bundle_tmp, &bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    Ok(Captured {
        digest: digest.to_string(),
        files,
        bytes,
    })
}

/// The blocking half of a restore: unpack a verified bundle into place.
fn extract_bundle(
    cfg: &WorkspaceConfig,
    bundle: &Path,
    staging: &Path,
    tree: &Path,
) -> Result<(u64, u64), String> {
    let _guard = RemoveOnDrop(staging.to_path_buf());
    std::fs::create_dir_all(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    // System tar rather than the in-process unpacker: a workspace legitimately
    // holds symlinks (`node_modules/.bin` is nothing but), which the bundle
    // unpacker refuses for the untrusted input it was written for. This bundle
    // was made by this code or verified against its digest.
    let out = std::process::Command::new(&cfg.tar_bin)
        .arg("--extract")
        .arg("--gzip")
        .arg("--no-same-owner")
        .arg("--file")
        .arg(bundle)
        .arg("--directory")
        .arg(staging)
        .output()
        .map_err(|e| format!("could not run {}: {e}", cfg.tar_bin))?;
    if !out.status.success() {
        return Err(format!(
            "tar exited {}: {}",
            out.status.code().unwrap_or(-1),
            tail(&String::from_utf8_lossy(&out.stderr))
        ));
    }
    let stats = tree_stats(staging);
    std::fs::create_dir_all(tree.parent().unwrap()).map_err(|e| e.to_string())?;
    if tree.exists() {
        let _ = std::fs::remove_dir_all(tree);
    }
    std::fs::rename(staging, tree)
        .map_err(|e| format!("{} -> {}: {e}", staging.display(), tree.display()))?;
    Ok(stats)
}

/// A file as a stream of chunks, for a request body that must not be held in
/// memory whole: bundles are gigabytes.
fn file_stream(
    file: tokio::fs::File,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    use tokio::io::AsyncReadExt;
    futures::stream::unfold(Some(file), |file| async move {
        let mut file = file?;
        let mut buf = vec![0u8; CHUNK];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(bytes::Bytes::from(buf)), Some(file)))
            }
            Err(e) => Some((Err(e), None)),
        }
    })
}

fn verify_file(path: &Path, digest: &str) -> Result<bool, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()) == digest)
}

fn tree_stats(root: &Path) -> (u64, u64) {
    fn walk(dir: &Path, files: &mut u64, bytes: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                walk(&entry.path(), files, bytes);
            } else if meta.is_file() {
                *files += 1;
                *bytes += meta.len();
            }
        }
    }
    let (mut files, mut bytes) = (0, 0);
    walk(root, &mut files, &mut bytes);
    (files, bytes)
}

fn s3_key(prefix: &str, deployment_id: &str, name: &str) -> String {
    if prefix.is_empty() {
        format!("{deployment_id}/{name}")
    } else {
        format!("{prefix}/{deployment_id}/{name}")
    }
}

/// `GET /tags/{name}` answers either the bare digest or a small JSON object
/// carrying one; both are accepted.
fn parse_tag_body(text: &str) -> Option<String> {
    let t = text.trim();
    if crate::config::is_sha256_hex(t) {
        return Some(t.to_string());
    }
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    v.get("digest")
        .and_then(|d| d.as_str())
        .filter(|d| crate::config::is_sha256_hex(d))
        .map(str::to_string)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn short(digest: Option<&str>) -> String {
    match digest {
        Some(d) => d.chars().take(12).collect(),
        None => "(empty)".into(),
    }
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(4);
    lines[start..].join("; ")
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = std::fs::remove_dir_all(&self.0);
        } else if self.0.exists() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

// ---------------------------------------------------------------------------
// the background service
// ---------------------------------------------------------------------------

pub struct WorkspaceWorker {
    workspaces: Arc<Workspaces>,
}

impl WorkspaceWorker {
    pub fn new(workspaces: Arc<Workspaces>) -> Self {
        Self { workspaces }
    }
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for WorkspaceWorker {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        loop {
            tokio::select! {
                _ = self.workspaces.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
                _ = shutdown.changed() => {
                    tracing::info!("workspace worker shutting down");
                    return;
                }
            }
            self.workspaces.pass().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_keys_join_without_doubled_slashes() {
        assert_eq!(s3_key("", "fastcar", "latest"), "fastcar/latest");
        assert_eq!(s3_key("ws", "fastcar", "a.tar.gz"), "ws/fastcar/a.tar.gz");
    }

    #[test]
    fn a_tag_body_may_be_bare_or_json() {
        let d = "a".repeat(64);
        assert_eq!(parse_tag_body(&format!("{d}\n")), Some(d.clone()));
        assert_eq!(parse_tag_body(&format!("{{\"digest\":\"{d}\"}}")), Some(d));
        assert_eq!(parse_tag_body("nope"), None);
    }

    fn store(tag: &str) -> (Arc<Workspaces>, Arc<Registry>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("app-lb-ws-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        store_at(dir)
    }

    fn store_at(dir: PathBuf) -> (Arc<Workspaces>, Arc<Registry>, PathBuf) {
        let registry = Arc::new(Registry::new(dir.join("state.json")));
        let vms = VmManager::new(
            Some("http://127.0.0.1:1".into()),
            None,
            crate::mounts::MountStore::new(dir.join("mounts"), 0),
        )
        .unwrap();
        let ws = Arc::new(Workspaces::new(
            WorkspaceConfig {
                root: dir.join("workspaces"),
                tar_bin: "tar".into(),
                aws_bin: "aws".into(),
                art_bin: "art".into(),
                s3_endpoint: None,
                home: None,
                timeout: Duration::from_secs(5),
            },
            vms,
            registry.clone(),
            Arc::new(SecretStore::new(dir.join("secrets.json"), None)),
        ));
        (ws, registry, dir)
    }

    fn workspace_spec() -> DeploymentSpec {
        let s: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "demo",
            "routes": [{"host": "demo.example.com"}],
            "vm": {
                "driver": "firecracker",
                "port": 8080,
                "workspace": {"store": "s3://bucket/ws"}
            },
            "scaling": {"min_replicas": 1, "max_replicas": 1}
        }))
        .unwrap();
        s.validate().unwrap();
        s
    }

    #[test]
    fn replacement_refuses_to_proceed_without_a_durable_fence() {
        let (ws, _, _) = store("fence-write-failure");
        let directory = ws.dir("demo");
        std::fs::create_dir_all(directory.parent().unwrap()).unwrap();
        std::fs::write(&directory, b"not a directory").unwrap();
        assert!(ws.begin_replacement("demo", 1).is_err());
        assert!(ws.blocked(&Deployment::new(workspace_spec())).is_some());
    }

    /// The create path's contract: nothing boots until the store has been
    /// consulted; a seeded VM is remembered; a queued capture blocks the next
    /// create; and the sweep is told to keep its hands off anything this
    /// module has not finished with.
    #[test]
    fn lineage_and_queue_bookkeeping() {
        let (ws, registry, dir) = store("lineage");
        let d = registry.upsert(workspace_spec());

        // A brand-new workspace has never asked the store: not ready.
        let why = ws.seed_for_create(&d).unwrap_err();
        assert!(why.contains("restore"), "{why}");
        assert!(ws.blocked(&d).is_some());
        assert!(ws.runtime("demo").1, "a restore was requested");

        // Pretend the store answered "nothing": the workspace starts empty.
        ws.with_record("demo", |r| r.initialized = true);
        ws.runtime
            .lock()
            .unwrap()
            .get_mut("demo")
            .unwrap()
            .restore_wanted = false;
        let seeded = ws.seed_for_create(&d).unwrap().unwrap();
        assert_eq!(seeded.digest, None);
        assert!(seeded.tree.is_dir(), "the empty tree exists for mke2fs -d");

        ws.note_seeded("demo", "sb-1", None, 0);
        assert!(
            ws.holds("demo", "sb-1"),
            "a live VM is dirty until captured"
        );

        // Replacement is exposed only after this durable fence is installed.
        // Model a deliberately delayed stop: even though no capture is queued
        // yet, the fresh deployment cannot boot from the old (empty) seed.
        ws.begin_replacement("demo", 1).unwrap();
        let replacement = registry.upsert(workspace_spec());
        let why = ws.seed_for_create(&replacement).unwrap_err();
        assert!(why.contains("replacement"), "{why}");
        ws.begin_replacement("demo", 0).unwrap();
        assert!(ws.seed_for_create(&replacement).is_err(), "another edit cannot clear a predecessor's fence");

        // Retiring a stopped VM queues it and blocks creates.
        ws.retire_stopped(&d, "sb-1", Then::Kill).unwrap();
        assert!(ws.is_pending("demo", "sb-1"));
        let why = ws.seed_for_create(&d).unwrap_err();
        assert!(why.contains("replacement"), "{why}");
        ws.retire_stopped(&d, "sb-1", Then::Kill).unwrap();
        assert_eq!(ws.record("demo").pending.len(), 1, "queued once");

        // State survives a reload.
        let (ws2, _registry2, _) = store_at(dir.clone());
        assert_eq!(ws2.load(), 1);
        assert!(ws2.is_pending("demo", "sb-1"));
        assert!(
            ws2.seed_for_create(&replacement).unwrap_err().contains("replacement"),
            "the pre-capture replacement fence survives restart"
        );

        // Publish the delayed capture, then release the replacement fence. The
        // replacement can now see only that final snapshot, never the old seed.
        ws.with_record("demo", |r| {
            r.pending.clear();
            r.digest = Some("b".repeat(64));
            r.seeds.insert(
                "sb-1".into(),
                Seed {
                    digest: Some("b".repeat(64)),
                    dirty: false,
                    mount_index: Some(0),
                },
            );
            r.seeds.insert(
                "sb-0".into(),
                Seed {
                    digest: Some("a".repeat(64)),
                    dirty: false,
                    mount_index: Some(0),
                },
            );
        });
        ws.complete_replacement_capture("demo");
        std::fs::create_dir_all(ws.tree_path("demo", Some(&"b".repeat(64)))).unwrap();
        let seeded = ws.seed_for_create(&replacement).unwrap().unwrap();
        assert_eq!(seeded.digest.as_deref(), Some("b".repeat(64).as_str()));

        // A VM captured at the current snapshot is free; one from an older
        // snapshot, or never captured, is held.
        assert!(!ws.holds("demo", "sb-1"));
        assert!(ws.holds("demo", "sb-0"));
        assert!(ws.holds("demo", "sb-unknown"));
        ws.note_resumed("demo", "sb-1");
        assert!(ws.holds("demo", "sb-1"), "resumed means it may write again");

        let status = ws.status(&d).unwrap();
        assert_eq!(status.path, "/workspace");
        assert_eq!(status.store, "s3://bucket/ws");
        assert_eq!(status.digest.as_deref(), Some("b".repeat(64).as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The capture path from the daemon's export: a tarball of the tree
    /// (symlinks and all) lands as a bundle named by its digest and a
    /// snapshot tree beside it, and comes back out of the bundle the same.
    #[test]
    fn a_daemon_export_installs_as_a_snapshot_and_a_bundle() {
        let temp = std::env::temp_dir().join(format!("app-lb-workspace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        // What the daemon streams: `tar --create --gzip` of the extracted tree.
        let export = temp.join("export.tar.gz");
        {
            let file = std::fs::File::create(&export).unwrap();
            let enc = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            let mut tar = tar::Builder::new(enc);
            let mut add = |path: &str, body: &[u8]| {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, path, body).unwrap();
            };
            add("./a.txt", b"hello");
            add("./repo/.git/config", b"[core]");
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_mode(0o777);
            link.set_cksum();
            tar.append_link(&mut link, "./link", "a.txt").unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let digest = {
            let bytes = std::fs::read(&export).unwrap();
            hex(&Sha256::digest(&bytes))
        };

        let cfg = WorkspaceConfig {
            root: temp.join("ws"),
            tar_bin: "tar".into(),
            aws_bin: "aws".into(),
            art_bin: "art".into(),
            s3_endpoint: None,
            home: None,
            timeout: Duration::from_secs(60),
        };
        let dir = cfg.root.join("dep");
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_tmp = dir.join("staging-1.tar.gz");
        std::fs::copy(&export, &bundle_tmp).unwrap();
        let captured = install_capture(&cfg, &dir, &bundle_tmp, &dir.join("staging-1"), &digest).unwrap();
        assert_eq!(captured.digest, digest, "the digest names the bundle as the daemon sent it");
        assert_eq!(captured.files, 2);
        let tree = dir.join("snapshots").join(&captured.digest);
        assert_eq!(std::fs::read_to_string(tree.join("a.txt")).unwrap(), "hello");
        assert!(tree.join("link").is_symlink());
        assert!(!dir.join("staging-1").exists(), "staging is renamed, not copied");
        let bundle = dir.join("bundles").join(format!("{}.tar.gz", captured.digest));
        assert!(bundle.is_file());
        assert!(!bundle_tmp.exists(), "the temp bundle is renamed, not copied");

        // ...and out of the bundle the same.
        let restored = dir.join("restored");
        let stats = extract_bundle(&cfg, &bundle, &dir.join("staging-2"), &restored).unwrap();
        assert_eq!(stats.0, 2);
        assert_eq!(std::fs::read_to_string(restored.join("repo/.git/config")).unwrap(), "[core]");
        let _ = std::fs::remove_dir_all(&temp);
    }
}
