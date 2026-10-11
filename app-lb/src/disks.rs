//! Per-sandbox disk inventory, retention and reclamation.
//!
//! The daemon creates a directory of disk images per sandbox and only removes
//! *some* of it when the sandbox is deleted, so a host that has booted a few
//! hundred VMs accumulates tens of gigabytes that nothing will ever reclaim.
//! Three separate leaks, all of them observed:
//!
//! - `<data>/run/<id>/` — the Firecracker `/workspace` data disk plus a
//!   `snapshot/` directory. On daemons **before heyvm 0.42.5** this was an
//!   outright delete-path bug: mvm-ctrl's `destroy()` unlinked this directory
//!   only inside its `data_disk_path.is_some()` branch, so a sandbox created
//!   *without* `disk_size_gb` still got the directory (the snapshot dir and the
//!   tap allocation live there) and nothing ever removed it. Fixed upstream on
//!   2026-08-03 — `destroy()` now removes both per-sandbox directories derived
//!   from the id — but the fix only runs on delete, so whatever an older daemon
//!   already leaked stays leaked until this module reclaims it, and any host
//!   still running a pre-0.42.5 daemon keeps producing more.
//! - `<data>/kvm/<id>/` — the KVM driver's per-VM `rootfs.ext4` and any
//!   `mount*.ext4`, ~1 GiB each. A clean delete *does* remove the whole state
//!   dir; what accumulates is every sandbox that never got one — a crash, a lost
//!   daemon record, a VM nobody ran `heyvm rm` on.
//! - `/tmp/{firecracker,kvm}-<id>-*` — the per-boot scratch. `stop_vm()` removes
//!   it, so it only survives when the VM died without a clean stop — which, for
//!   a hypervisor process, is routine.
//!
//! app-lb is the right place to fix this despite not owning those paths: it is
//! required to run beside a *local* daemon (`guest_ip` exists nowhere else), so
//! it shares the filesystem, and it already writes into the daemon's image
//! directory for artifact pulls. It also has the one piece of knowledge the
//! daemon lacks — which sandboxes a deployment still expects to resume.
//!
//! Two safety rules run through everything below, because the operation this
//! module performs is "delete gigabytes of somebody's data":
//!
//! 1. **A disk is never classified as orphaned unless both daemon listings
//!    succeeded.** A daemon that is restarting answers neither, and every disk
//!    on the host would otherwise look like residue at exactly the moment it is
//!    least safe to act on that belief. See [`Inventory::complete`].
//! 2. **Paths are constructed, never accepted.** A sandbox id arrives from a URL
//!    path segment; it is validated against a strict charset before it is joined
//!    to anything, so no request can point `remove_dir_all` outside the two
//!    directories this module owns.

use crate::config::LbConfig;
use crate::deployment::now_secs;
use crate::registry::Registry;
use crate::vm::VmManager;
use heyo_sdk::{PurgeParts, SandboxInfo, SandboxStatus, StorageInventory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long an unclaimed disk lives before the sweep reclaims it.
///
/// Seven days: long enough that a VM retired on Friday is still recoverable on
/// the following Friday, short enough that a fleet churning VMs does not need a
/// human to remember this exists.
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// How long a disk the daemon has *no record of* survives.
///
/// Fifteen minutes, against seven days for everything else, and the gap is the
/// whole point. [`DEFAULT_TTL_SECS`] buys the ability to change your mind about
/// a VM you retired — but an orphan is not a retired VM. The daemon has no
/// record of the sandbox in either listing, so there is nothing to resume, no
/// `heyvm start` that brings it back, and no delete coming that would clean it
/// up. It is the disk of a VM that failed to create or died without a trace, and
/// keeping a copy of that for a week is not caution, it is a leak with a
/// calendar on it.
///
/// Not zero, because the classification races creation: a sandbox whose files
/// exist a moment before the daemon has a record of it would otherwise be
/// deleted out from under a VM that is being built right now. Fifteen minutes is
/// far longer than that window and far shorter than a week.
///
/// The other half of the safety argument is in [`DiskStore::sweep`], which
/// refuses to run at all when either daemon listing failed — so "the daemon is
/// restarting" classifies disks `Unknown`, never `Orphan`.
pub const DEFAULT_ORPHAN_TTL_SECS: u64 = 15 * 60;

/// Gap between expiry sweeps. The thing being watched moves on the order of
/// days, so this is deliberately slow — it walks two directories and asks the
/// daemon for its full inactive listing, which is the most expensive question
/// app-lb knows how to ask.
const DEFAULT_SWEEP_SECS: u64 = 3600;


/// Archive records kept in memory. Bounded for the same reason the job history
/// is: this is an operator's recent-activity view, not an audit log.
const ARCHIVE_HISTORY: usize = 64;

/// How many archives may be uploading at once.
///
/// Each one is a `tar --sparse --gzip` reading gigabytes off the same disks the
/// running fleet is using, feeding an upload. Two is a background task; twenty
/// is an incident. Excess archives queue rather than being refused — they are
/// still jobs the operator asked for.
const ARCHIVE_CONCURRENCY: usize = 2;

/// How many archives one expiry sweep may start.
///
/// Separate from, and smaller than, the queue above: a sweep that finds a
/// hundred expired disks would otherwise queue a hundred multi-gigabyte uploads
/// from one tick. The rest are picked up by the next sweep, and the count that
/// was deferred is logged rather than silently dropped.
const ARCHIVES_PER_SWEEP: usize = 4;

/// Subdirectories of the daemon's data directory that hold per-sandbox disks.
///
/// Each is `<data_dir>/<root>/<sandbox-id>/…`. Both are scanned regardless of
/// which driver a deployment uses, because a host routinely has sandboxes from
/// both and the leak is per-directory, not per-deployment.
const DISK_ROOTS: [&str; 2] = ["run", "kvm"];

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DiskConfig {
    /// Where retention decisions persist.
    pub state_path: PathBuf,
    /// How long an unclaimed disk survives. `0` disables expiry entirely; the
    /// inventory and the manual operations stay available.
    pub ttl_secs: u64,
    pub sweep_secs: u64,
    pub aws_bin: String,
    /// Archive destination. Without a bucket the archive routes answer 501 and
    /// `archive_on_expire` is ignored.
    pub bucket: Option<String>,
    /// Key prefix inside the bucket. Never leading- or trailing-slashed.
    pub prefix: String,
    /// `--endpoint-url` for an S3-compatible store.
    pub endpoint: Option<String>,
    /// Whether an expiring disk is archived before it is purged. Off by default:
    /// silently uploading a fleet's disks to S3 is not something to start doing
    /// because a version changed.
    pub archive_on_expire: bool,
    /// Ceiling on one archive, after which both children are killed.
    pub archive_timeout: Duration,
    /// How long a disk with no daemon record survives. Separate from
    /// [`ttl_secs`], and far shorter — see [`DEFAULT_ORPHAN_TTL_SECS`]. `0`
    /// disables orphan expiry and falls back to `ttl_secs` behaviour.
    ///
    /// [`ttl_secs`]: Self::ttl_secs
    pub orphan_ttl_secs: u64,
}

impl DiskConfig {
    /// Resolve from the process configuration and the environment.
    ///
    /// Returns `Err` only when the daemon's data directory cannot be located at
    /// all, which is the one thing this module cannot work around. The caller
    /// warns and runs without disk management rather than refusing to start —
    /// the same trade `images_dir` makes.
    pub fn from_env(cfg: &LbConfig) -> Result<Self, String> {
        for gone in ["APP_LB_VM_DATA_DIR", "APP_LB_VM_TMP_DIR", "APP_LB_TAR_BIN"] {
            if std::env::var(gone).is_ok_and(|v| !v.trim().is_empty()) {
                tracing::warn!(
                    "{gone} is set but no longer read: the daemon inventories and reclaims \
                     its own disks (GET /storage), so app-lb needs neither its data directory \
                     nor a tar binary"
                );
            }
        }

        let state_path = std::env::var("APP_LB_DISKS_PATH")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("app-lb-disks.json"));

        let ttl_secs = parse_secs("APP_LB_DISK_TTL_SECS", DEFAULT_TTL_SECS)?;
        let sweep_secs = parse_secs("APP_LB_DISK_SWEEP_SECS", DEFAULT_SWEEP_SECS)?.max(60);
        let archive_timeout =
            Duration::from_secs(parse_secs("APP_LB_DISK_ARCHIVE_TIMEOUT_SECS", 7200)?.max(60));
        let orphan_ttl_secs =
            parse_secs("APP_LB_DISK_ORPHAN_TTL_SECS", DEFAULT_ORPHAN_TTL_SECS)?;

        Ok(Self {
            state_path,
            ttl_secs,
            sweep_secs,
            aws_bin: cfg.aws_bin.clone(),
            bucket: std::env::var("APP_LB_DISK_ARCHIVE_BUCKET")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            prefix: std::env::var("APP_LB_DISK_ARCHIVE_PREFIX")
                .ok()
                .map(|v| v.trim().trim_matches('/').to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "app-lb/disks".into()),
            endpoint: std::env::var("APP_LB_DISK_ARCHIVE_ENDPOINT")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            archive_on_expire: env_flag("APP_LB_DISK_ARCHIVE_ON_EXPIRE", false),
            archive_timeout,
            orphan_ttl_secs,
        })
    }
}


fn parse_secs(var: &str, default: u64) -> Result<u64, String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{var} must be a whole number of seconds, got {v:?}")),
        _ => Ok(default),
    }
}

fn env_flag(var: &str, default: bool) -> bool {
    match std::env::var(var) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

/// Whether a sandbox id is safe to join to a path.
///
/// The id reaches this module as a URL path segment, and every path it produces
/// is passed to `remove_dir_all`. Anything outside this charset — a dot, a
/// slash, a NUL — is refused rather than sanitized, because a request that has
/// to be sanitized is a request that was never legitimate.
pub fn valid_sandbox_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ---------------------------------------------------------------------------
// the model
// ---------------------------------------------------------------------------

/// What the daemon thinks of the sandbox a disk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskState {
    /// The sandbox is running. Its disks are in use and are never reclaimed.
    Running,
    /// The daemon still has a record, but the sandbox is not running.
    Stopped,
    /// The daemon has no record of this sandbox at all. Pure residue.
    Orphan,
    /// The daemon could not be reached, so nothing is known. Never reclaimed.
    Unknown,
}

impl DiskState {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Orphan => "orphan",
            Self::Unknown => "unknown",
        }
    }
}

/// What one file on the host is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PartKind {
    /// The persistent `/workspace` disk (`run/<id>/data.ext4`).
    Data,
    /// A guest root filesystem — the KVM driver's persistent one, or a
    /// Firecracker per-boot copy left behind in `/tmp`.
    Rootfs,
    /// An archive-mount disk (`kvm/<id>/mount0.ext4`).
    Mount,
    /// A memory/state checkpoint under `run/<id>/snapshot/`.
    Snapshot,
    /// Logs, sockets, configuration — small, and listed so the totals add up.
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskPart {
    pub kind: PartKind,
    pub path: String,
    /// Blocks actually allocated on the host. This is the number that matters:
    /// a `data.ext4` is created sparse at its full nominal size, so `apparent`
    /// routinely reads 8 GiB for 200 MiB of real occupancy.
    pub bytes: u64,
    /// `st_size` — what the guest sees.
    pub apparent_bytes: u64,
    pub modified_at: u64,
}

/// Everything on this host belonging to one sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub sandbox_id: String,
    /// The daemon's name for it, when the daemon still has a record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The deployment that owns it, from an `applb-<deployment>-<nonce>` name.
    /// `None` for a sandbox app-lb did not create, or one whose name is gone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    pub state: DiskState,
    /// Whether a live deployment lists this sandbox as one it intends to resume.
    /// A claimed disk is never reclaimed, at any age.
    pub claimed: bool,
    /// Set by an operator: never reclaim this, whatever its age.
    pub retain: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub modified_at: u64,
    /// When the sweep would reclaim this, or `None` if it never would.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Why it will not be reclaimed, in a phrase the page can show verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held_by: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archived: Option<ArchiveRecord>,
    pub parts: Vec<DiskPart>,
    /// The directories that would be removed by a purge. Shown on the page so
    /// the operator confirms against real paths rather than an id.
    pub roots: Vec<String>,
}

impl DiskInfo {
    /// Whether the expiry sweep may reclaim this disk at `now`.
    ///
    /// Deliberately total and side-effect-free: this is the predicate that
    /// decides whether gigabytes get deleted, so it is exercised directly in the
    /// tests rather than only through a sweep against a live daemon.
    pub fn expired(&self, now: u64, ttl_secs: u64, orphan_ttl_secs: u64) -> bool {
        let ttl = match self.state {
            DiskState::Orphan => orphan_ttl_secs,
            _ => ttl_secs,
        };
        if ttl == 0 || self.held_by.is_some() {
            return false;
        }
        now.saturating_sub(self.modified_at) >= ttl
    }

}

/// Why a disk is exempt from expiry, or `None` if it is a candidate.
///
/// Ordered by how strongly each reason holds: a running VM's disk is not merely
/// exempt, it is in use, and saying so is more useful than reporting the first
/// matching rule.
fn hold_reason(state: DiskState, claimed: bool, retain: bool) -> Option<&'static str> {
    match state {
        DiskState::Running => Some("the sandbox is running"),
        DiskState::Unknown => Some("the daemon could not be reached"),
        _ if claimed => Some("a deployment expects to resume it"),
        _ if retain => Some("marked retained"),
        _ => None,
    }
}

/// A completed upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub uri: String,
    pub at: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveStatus {
    Running,
    Succeeded,
    Failed,
}

/// One archive, in flight or finished.
#[derive(Debug)]
struct ArchiveJob {
    id: String,
    sandbox_id: String,
    uri: String,
    started_at: u64,
    finished_at: Option<u64>,
    status: ArchiveStatus,
    /// Compressed bytes handed to `aws` so far. Shared with the pump task, so a
    /// poll of `GET /disks` reports live progress without taking its lock.
    sent: Arc<AtomicU64>,
    /// Bytes the archive is expected to cover, for a progress percentage.
    expected: u64,
    error: Option<String>,
    /// Whether the disk was purged after a successful upload.
    purged: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveView {
    pub id: String,
    pub sandbox_id: String,
    pub uri: String,
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
    pub status: ArchiveStatus,
    pub bytes: u64,
    pub expected_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub purged: bool,
}

impl ArchiveJob {
    fn view(&self) -> ArchiveView {
        ArchiveView {
            id: self.id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            uri: self.uri.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            status: self.status,
            bytes: self.sent.load(Ordering::Relaxed),
            expected_bytes: self.expected,
            error: self.error.clone(),
            purged: self.purged,
        }
    }
}

/// The operator's decision about one disk. Only what cannot be re-derived from
/// the filesystem is stored; everything else is rebuilt on each scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DiskPolicy {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retain: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    archived: Option<ArchiveRecord>,
}

impl DiskPolicy {
    /// Whether this entry still says anything. An entry that has gone back to
    /// its defaults is dropped rather than written, so the file tracks decisions
    /// rather than every sandbox that ever existed.
    fn is_empty(&self) -> bool {
        !self.retain && self.note.is_none() && self.archived.is_none()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPolicies {
    version: u32,
    #[serde(default)]
    disks: BTreeMap<String, DiskPolicy>,
}

/// The answer to `GET /disks`.
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    /// Whether both daemon listings succeeded. When false, nothing is classified
    /// as an orphan and the sweep declines to run.
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
    pub data_dir: String,
    pub tmp_dir: String,
    /// `0` when expiry is disabled.
    pub ttl_secs: u64,
    pub sweep_secs: u64,
    pub archive_enabled: bool,
    pub archive_on_expire: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_target: Option<String>,
    /// Free and total bytes on the filesystem holding `data_dir`, when it could
    /// be interrogated. `None` means the `statvfs` failed, which is reported as
    /// unknown rather than as zero — nothing reclaims on a failed measurement.
    ///
    /// Present because "why is the host full" was not answerable from this
    /// document: it listed every disk and their sum, but not the one number that
    /// says whether that sum is a problem — a VM create fails on ENOSPC long
    /// before any single disk in the list looks suspicious.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem_bytes: Option<u64>,
    /// How long a disk with no daemon record survives, against `ttl_secs` for
    /// everything else.
    pub orphan_ttl_secs: u64,
    pub totals: Totals,
    pub disks: Vec<DiskInfo>,
    pub archives: Vec<ArchiveView>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Totals {
    pub disks: usize,
    pub bytes: u64,
    pub apparent_bytes: u64,
    pub running: usize,
    pub stopped: usize,
    pub orphan: usize,
    pub retained: usize,
    /// Disks the sweep would reclaim right now, and what that would free.
    pub expiring_now: usize,
    pub reclaimable_bytes: u64,
}

/// What a purge actually did.
#[derive(Debug, Clone, Serialize)]
pub struct PurgeOutcome {
    pub sandbox_id: String,
    /// Whether the daemon was asked to delete the sandbox first.
    pub killed: bool,
    pub removed: Vec<String>,
    /// What was actually reclaimed — the parts under a path that was removed,
    /// not what the sandbox occupied before. The two agree unless some paths
    /// failed, and that is the case where the difference matters.
    pub bytes: u64,
    /// Paths that could not be removed, with the reason. A partial purge is
    /// reported rather than rolled back: the bytes that did go are gone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
}

#[derive(Debug)]
pub enum DiskError {
    /// The id is not a shape this module will join to a path.
    BadId(String),
    NotFound(String),
    /// The disk's state refuses the operation.
    Held {
        sandbox_id: String,
        reason: &'static str,
        /// Whether `force=1` would get past this. False for a running sandbox,
        /// which has no legitimate override — and the message must not offer one,
        /// because the console reads it back to the operator in a confirm dialog
        /// and then retries with `?force=1` if it mentions force.
        forceable: bool,
    },
    /// No archive bucket is configured.
    NoArchiveTarget,
    /// There is nothing durable to archive — only scratch files in `/tmp`.
    NothingToArchive(String),
    AlreadyArchiving(String),
    /// Every path a purge tried to remove failed, so nothing was reclaimed.
    ///
    /// Distinct from a *partial* failure, which stays a success: the bytes that
    /// did go are gone and the caller needs the outcome, not an error. This is
    /// the case where the operation did not happen at all, and reporting it as
    /// a completed purge is what let a whole fleet's worth of residue look
    /// reclaimed while nothing moved. In practice it is nearly always
    /// permissions — heyvmd's data directory belongs to the user the daemon runs
    /// as, and app-lb is usually somebody else.
    PurgeFailed {
        sandbox_id: String,
        failed: Vec<String>,
    },
    Io(String),
}

impl std::fmt::Display for DiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadId(id) => write!(
                f,
                "{id:?} is not a sandbox id: only letters, digits, dashes and underscores"
            ),
            Self::NotFound(id) => write!(f, "no disks on this host for sandbox {id:?}"),
            Self::Held {
                sandbox_id,
                reason,
                forceable,
            } => {
                write!(f, "refusing to touch {sandbox_id}: {reason}")?;
                if *forceable {
                    write!(f, ". Pass force=1 to override")?;
                }
                Ok(())
            }
            Self::NoArchiveTarget => write!(
                f,
                "no archive destination: set APP_LB_DISK_ARCHIVE_BUCKET to an S3 bucket"
            ),
            Self::NothingToArchive(id) => write!(
                f,
                "sandbox {id} has no durable disks — only per-boot scratch, which is not \
                 worth archiving"
            ),
            Self::AlreadyArchiving(id) => write!(f, "an archive of {id} is already running"),
            Self::PurgeFailed { sandbox_id, failed } => write!(
                f,
                "nothing was reclaimed for {sandbox_id}: every path failed to delete. \
                 app-lb runs as {}, and these are usually owned by whichever user heyvmd \
                 runs as — check the ownership of the data directory. {}",
                crate::jobs::whoami(),
                failed.join("; "),
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DiskError {}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

pub struct DiskStore {
    cfg: DiskConfig,
    vms: VmManager,
    registry: Arc<Registry>,
    workspaces: Option<Arc<crate::workspace::Workspaces>>,
    policies: Mutex<BTreeMap<String, DiskPolicy>>,
    archives: Mutex<VecDeque<ArchiveJob>>,
    /// Sandboxes with an archive in flight. Held separately from `archives` so
    /// the check is a set lookup and cannot be confused by history.
    archiving: Mutex<HashSet<String>>,
    /// Distinguishes two archives started in the same second.
    archive_seq: AtomicU64,
    /// Bounds simultaneous uploads. See [`ARCHIVE_CONCURRENCY`].
    archive_slots: tokio::sync::Semaphore,
}

impl DiskStore {
    pub fn new(cfg: DiskConfig, vms: VmManager, registry: Arc<Registry>) -> Self {
        Self {
            cfg,
            vms,
            registry,
            workspaces: None,
            policies: Mutex::new(BTreeMap::new()),
            archives: Mutex::new(VecDeque::new()),
            archiving: Mutex::new(HashSet::new()),
            archive_seq: AtomicU64::new(0),
            archive_slots: tokio::sync::Semaphore::new(ARCHIVE_CONCURRENCY),
        }
    }

    pub fn config(&self) -> &DiskConfig {
        &self.cfg
    }

    pub fn with_workspaces(mut self, workspaces: Arc<crate::workspace::Workspaces>) -> Self {
        self.workspaces = Some(workspaces);
        self
    }

    /// Load retention decisions. A missing file is not an error.
    pub fn load(&self) -> Result<usize, String> {
        let bytes = match std::fs::read(&self.cfg.state_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(format!("{}: {e}", self.cfg.state_path.display())),
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(0);
        }
        let stored: StoredPolicies = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{}: {e}", self.cfg.state_path.display()))?;
        let n = stored.disks.len();
        *self.policies.lock().unwrap() = stored.disks;
        Ok(n)
    }

    fn persist(&self) -> Result<(), String> {
        let disks = self.policies.lock().unwrap().clone();
        let json = serde_json::to_vec_pretty(&StoredPolicies { version: 1, disks })
            .map_err(|e| e.to_string())?;
        if let Some(parent) = self
            .cfg
            .state_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = self.cfg.state_path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.cfg.state_path).map_err(|e| e.to_string())
    }

    // -- inventory ---------------------------------------------------------

    /// The full picture: what is on disk, what the daemon knows, what app-lb
    /// claims.
    pub async fn inventory(&self) -> Inventory {
        // The daemon walks its own directories (`GET /storage`); this only
        // regroups what it reports and joins it with the two listings, for
        // the reason `Autoscaler::sweep_suspended` documents: a stopped KVM
        // sandbox appears in the fleet list with a terminal status while a
        // stopped Firecracker one appears only in the inactive listing.
        // Reading one would classify half the fleet's stopped disks as orphans.
        let storage = self.vms.storage().await;
        let fleet = self.vms.list().await;
        let inactive = self.vms.list_inactive().await;

        let incomplete_reason = match (&storage, &fleet, &inactive) {
            (Err(e), _, _) => Some(format!("the daemon's storage inventory is unavailable: {e}")),
            (_, Err(e), _) => Some(format!("the daemon's sandbox list is unavailable: {e}")),
            (_, _, Err(e)) => Some(format!("the daemon's inactive listing is unavailable: {e}")),
            _ => None,
        };
        let complete = incomplete_reason.is_none();
        let storage = storage.ok();
        let mut groups = storage.as_ref().map(groups_from).unwrap_or_default();

        let mut known: HashMap<String, SandboxInfo> = HashMap::new();
        for info in fleet.into_iter().flatten() {
            known.insert(info.id.clone(), info);
        }
        for info in inactive.into_iter().flatten() {
            // The fleet listing wins: it is the one that can say `Running`.
            known.entry(info.id.clone()).or_insert(info);
        }

        // Which sandboxes a live deployment still expects to resume.
        let deployments = self.registry.deployments();
        let mut claimed: HashSet<String> = HashSet::new();
        for d in deployments.values() {
            claimed.extend(d.state().suspended.iter().cloned());
            claimed.extend(crate::rollout::protected_ids(&d.state()).cloned());
            claimed.extend(known.values().filter(|info| d.state().rollouts.iter().any(|o| info.name.starts_with(&o.prefix))).map(|info| info.id.clone()));
        }
        if let Some(ws) = &self.workspaces { claimed.extend(ws.recovery_pins()); }

        let policies = self.policies.lock().unwrap().clone();
        let now = now_secs();

        // Reported so "why is this host full" is answerable from the inventory
        // itself rather than by shelling into the box.
        let free_bytes = storage.as_ref().map(|s| s.free_bytes);
        let filesystem_bytes = storage.as_ref().map(|s| s.total_bytes);

        let mut disks: Vec<DiskInfo> = Vec::with_capacity(groups.len());
        for (sandbox_id, group) in groups.drain() {
            let info = known.get(&sandbox_id);
            let state = match (complete, info) {
                (false, _) => DiskState::Unknown,
                (true, Some(i)) if i.status == SandboxStatus::Running => DiskState::Running,
                (true, Some(_)) => DiskState::Stopped,
                (true, None) => DiskState::Orphan,
            };
            let policy = policies.get(&sandbox_id).cloned().unwrap_or_default();
            let is_claimed = claimed.contains(&sandbox_id);

            let deployment = info
                .and_then(|i| crate::vm::owner_of(&i.name).map(str::to_string))
                // A purged daemon record takes the name with it, so fall back to
                // asking the deployments themselves — the only other place the
                // association survives.
                .or_else(|| {
                    deployments
                        .values()
                        .find(|d| d.state().suspended.contains(&sandbox_id))
                        .map(|d| d.spec.id.clone())
                });
            // The daemon's storage inventory is host-wide. Absence from this
            // registry does not authorize reclaiming another app-lb's disk,
            // nor a disk whose daemon record (and ownership) has been lost.
            let managed_here = deployment.as_ref()
                .and_then(|id| deployments.get(id))
                .is_some_and(|d| d.spec.is_managed());
            let held_by = hold_reason(state, is_claimed, policy.retain)
                .or_else(|| (!managed_here).then_some("ownership is not established by this app-lb"));

            disks.push(DiskInfo {
                sandbox_id,
                name: info.map(|i| i.name.clone()),
                deployment,
                state,
                claimed: is_claimed,
                retain: policy.retain,
                note: policy.note.clone(),
                bytes: group.bytes,
                apparent_bytes: group.apparent_bytes,
                modified_at: group.modified_at,
                expires_at: (held_by.is_none() && self.cfg.ttl_secs > 0)
                    .then(|| group.modified_at.saturating_add(self.cfg.ttl_secs)),
                held_by,
                archived: policy.archived,
                parts: group.parts,
                roots: group.roots,
            });
        }

        // Biggest first: the page exists to answer "what is eating the disk?".
        disks.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.sandbox_id.cmp(&b.sandbox_id)));

        let mut totals = Totals {
            disks: disks.len(),
            ..Default::default()
        };
        for d in &disks {
            totals.bytes += d.bytes;
            totals.apparent_bytes += d.apparent_bytes;
            match d.state {
                DiskState::Running => totals.running += 1,
                DiskState::Stopped => totals.stopped += 1,
                DiskState::Orphan => totals.orphan += 1,
                DiskState::Unknown => {}
            }
            if d.retain {
                totals.retained += 1;
            }
            if d.expired(now, self.cfg.ttl_secs, self.cfg.orphan_ttl_secs) {
                totals.expiring_now += 1;
                totals.reclaimable_bytes += d.bytes;
            }
        }

        Inventory {
            complete,
            incomplete_reason,
            data_dir: storage.as_ref().map(|s| s.data_dir.clone()).unwrap_or_else(|| "unknown".into()),
            tmp_dir: storage.as_ref().map(|s| s.tmp_dir.clone()).unwrap_or_else(|| "unknown".into()),
            ttl_secs: self.cfg.ttl_secs,
            sweep_secs: self.cfg.sweep_secs,
            archive_enabled: self.cfg.bucket.is_some(),
            archive_on_expire: self.cfg.archive_on_expire && self.cfg.bucket.is_some(),
            archive_target: self
                .cfg
                .bucket
                .as_ref()
                .map(|b| format!("s3://{b}/{}", self.cfg.prefix)),
            free_bytes,
            filesystem_bytes,
            orphan_ttl_secs: self.cfg.orphan_ttl_secs,
            totals,
            disks,
            archives: self.archive_views(),
        }
    }

    /// What the first sweep would find, without talking to the daemon.
    ///
    /// Exists so an operator who turns app-lb on and never opens `/storage`
    /// still learns from the startup log that 15 GiB is scheduled for deletion
    /// in an hour. Synchronous, and safe to call before the runtime exists: it
    /// is a directory walk and some `stat` calls, nothing more.
    ///
    /// An **upper bound**, deliberately. Without the daemon's listings this
    /// cannot tell a running sandbox from residue, so it counts every disk old
    /// enough to be a candidate. The sweep itself never acts on this number.
    pub async fn expiry_preview(&self) -> (usize, usize, u64) {
        let groups = match self.vms.storage().await {
            Ok(inv) => groups_from(&inv),
            Err(e) => {
                tracing::warn!(error = %e, "could not preview disk expiry: the daemon's storage inventory is unavailable");
                return (0, 0, 0);
            }
        };
        let total = groups.len();
        if self.cfg.ttl_secs == 0 {
            return (total, 0, 0);
        }
        let policies = self.policies.lock().unwrap();
        let now = now_secs();
        let mut count = 0;
        let mut bytes = 0;
        for (id, g) in &groups {
            if policies.get(id).is_some_and(|p| p.retain) {
                continue;
            }
            if now.saturating_sub(g.modified_at) >= self.cfg.ttl_secs {
                count += 1;
                bytes += g.bytes;
            }
        }
        (total, count, bytes)
    }

    fn archive_views(&self) -> Vec<ArchiveView> {
        let jobs = self.archives.lock().unwrap();
        jobs.iter().rev().map(ArchiveJob::view).collect()
    }

    /// One disk, or `None`. Goes through the full inventory rather than a
    /// targeted stat, because every decision made about a disk depends on the
    /// daemon's view of it and on what the deployments claim.
    async fn one(&self, sandbox_id: &str) -> Result<(DiskInfo, bool), DiskError> {
        if !valid_sandbox_id(sandbox_id) {
            return Err(DiskError::BadId(sandbox_id.to_string()));
        }
        let inv = self.inventory().await;
        let complete = inv.complete;
        inv.disks
            .into_iter()
            .find(|d| d.sandbox_id == sandbox_id)
            .map(|d| (d, complete))
            .ok_or_else(|| DiskError::NotFound(sandbox_id.to_string()))
    }

    // -- retention ---------------------------------------------------------

    pub fn is_retained(&self, sandbox_id: &str) -> bool {
        self.policies.lock().unwrap().get(sandbox_id).is_some_and(|p| p.retain)
    }

    /// Mark a disk retained (or not) and note why.
    ///
    /// Accepted for a sandbox with no disks on this host, so an operator can
    /// pin one *before* it accumulates any — the entry is kept and applies as
    /// soon as the sandbox writes something.
    pub fn set_policy(
        &self,
        sandbox_id: &str,
        retain: Option<bool>,
        note: Option<Option<String>>,
    ) -> Result<(), DiskError> {
        if !valid_sandbox_id(sandbox_id) {
            return Err(DiskError::BadId(sandbox_id.to_string()));
        }
        {
            let mut policies = self.policies.lock().unwrap();
            let entry = policies.entry(sandbox_id.to_string()).or_default();
            if let Some(r) = retain {
                entry.retain = r;
            }
            if let Some(n) = note {
                entry.note = n.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            }
            if entry.is_empty() {
                policies.remove(sandbox_id);
            }
        }
        self.persist().map_err(DiskError::Io)
    }

    fn record_archive(&self, sandbox_id: &str, record: ArchiveRecord) {
        self.policies
            .lock()
            .unwrap()
            .entry(sandbox_id.to_string())
            .or_default()
            .archived = Some(record);
        if let Err(e) = self.persist() {
            tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to record disk archive");
        }
    }

    fn forget(&self, sandbox_id: &str) {
        if self.policies.lock().unwrap().remove(sandbox_id).is_some()
            && let Err(e) = self.persist()
        {
            tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to persist disk policy");
        }
    }

    // -- purge -------------------------------------------------------------

    /// Delete every trace of a sandbox from this host.
    ///
    /// The daemon is asked to delete the sandbox first, so its own cleanup runs
    /// and its record goes away; whatever it leaves behind is then removed
    /// directly. A daemon that refuses (or has already forgotten the sandbox) is
    /// not fatal — the point of this path is the residue, and residue is exactly
    /// what the daemon cannot see.
    pub async fn purge(&self, sandbox_id: &str, force: bool) -> Result<PurgeOutcome, DiskError> {
        if self.workspaces.as_ref().is_some_and(|ws| ws.recovery_pinned(sandbox_id)) {
            return Err(DiskError::Held { sandbox_id: sandbox_id.into(),
                reason: "explicit workspace recovery permanently pins this source", forceable: false });
        }
        let (disk, complete) = self.one(sandbox_id).await?;
        self.purge_resolved(disk, complete, force).await
    }

    /// [`purge`](Self::purge) against a disk the caller has already resolved.
    ///
    /// Split out for the sweep, which has an inventory in hand and must not
    /// rebuild one per disk: `one()` walks the whole data directory *and* makes
    /// two daemon round-trips, so re-resolving inside the loop would turn a
    /// 105-disk sweep into 105 full scans and 210 requests at the daemon.
    async fn purge_resolved(
        &self,
        disk: DiskInfo,
        complete: bool,
        force: bool,
    ) -> Result<PurgeOutcome, DiskError> {
        let _retirement=self.registry.retirement_gate.read().await;
        if self.registry.allocation_protects(&disk.sandbox_id) {
            return Err(DiskError::Held {sandbox_id:disk.sandbox_id,
                reason:"correlated allocation is not reconciled",forceable:false});
        }
        if self.registry.retirement_protects(&disk.sandbox_id,disk.deployment.as_deref())
            || self.workspaces.as_ref().is_some_and(|ws|ws.retirement_protects(&disk.sandbox_id)) {
            return Err(DiskError::Held {sandbox_id:disk.sandbox_id,
                reason:"permanent deployment retirement preserves all storage",forceable:false});
        }
        // Share admission's lock: a stale sweep inventory cannot race a newly
        // persisted recovery pin. No force flag overrides the selected source.
        let _recovery = match &self.workspaces { Some(ws) => Some(ws.lifecycle_guard().await), None => None };
        if self.workspaces.as_ref().is_some_and(|ws| ws.recovery_pinned(&disk.sandbox_id)) {
            return Err(DiskError::Held { sandbox_id: disk.sandbox_id,
                reason: "explicit workspace recovery permanently pins this source", forceable: false });
        }
        // First, and under no flag. Deleting the disks out from under a live
        // hypervisor corrupts the guest rather than freeing anything, and the
        // operator's actual intent — stop it, then reclaim it — is two clicks
        // away on the dashboard. Checked *before* the forceable guards so the
        // message never offers an override that would be refused anyway.
        if disk.state == DiskState::Running {
            return Err(DiskError::Held {
                sandbox_id: disk.sandbox_id,
                reason: "the sandbox is running; evict or stop it first",
                forceable: false,
            });
        }

        if !force && let Some(reason) = disk.held_by {
            return Err(DiskError::Held {
                sandbox_id: disk.sandbox_id,
                reason,
                forceable: true,
            });
        }
        // An incomplete inventory needs no check of its own: it makes every disk
        // `Unknown`, which `hold_reason` already holds on. Asserted rather than
        // re-tested, so the two cannot drift apart silently.
        debug_assert!(
            complete || force || disk.held_by.is_some(),
            "an unreachable daemon must leave every disk held",
        );

        let killed = match disk.state {
            DiskState::Stopped | DiskState::Unknown => {
                match self.vms.kill(&disk.sandbox_id).await {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            sandbox = %disk.sandbox_id,
                            error = %e,
                            "daemon would not delete the sandbox; removing its disks anyway",
                        );
                        false
                    }
                }
            }
            // Nothing to ask: the daemon has no record of it.
            DiskState::Orphan => false,
            DiskState::Running => unreachable!("refused above"),
        };

        let (removed, failed, bytes) = purge_on_daemon(&self.vms, &disk.sandbox_id, PurgeParts::All).await;

        // Nothing went. Reported as an error rather than as a purge that freed
        // zero bytes, because the two are not the same claim and only one of
        // them is true: the disks are still there, still counted, and still
        // taking the space this was called to reclaim. Returning `Ok` here is
        // what let a sweep report a thousand disks purged while the host filled
        // up — see [`DiskError::PurgeFailed`].
        //
        // Both empty is *not* this case: it means the paths were already gone,
        // which is a purge that had nothing left to do and succeeded.
        if removed.is_empty() && !failed.is_empty() {
            tracing::error!(
                sandbox = %disk.sandbox_id,
                deployment = disk.deployment.as_deref().unwrap_or("-"),
                state = disk.state.label(),
                failed = failed.len(),
                detail = %failed.join("; "),
                "purge removed nothing: every path failed",
            );
            return Err(DiskError::PurgeFailed {
                sandbox_id: disk.sandbox_id,
                failed,
            });
        }

        // Both of these describe a sandbox whose disks are gone, so neither may
        // run until that is actually true. Dropping the claim first would tell
        // the next scale-up not to resume a sandbox that is still perfectly
        // resumable, and forgetting the policy first would lose a `retain` flag
        // protecting a disk this call failed to delete.
        if disk.claimed {
            // Or the next scale-up spends a resume attempt on a sandbox whose
            // disks are gone and then boots a fresh VM anyway.
            self.drop_claim(&disk.sandbox_id);
        }
        self.forget(&disk.sandbox_id);

        // A partial failure stays a success — the bytes that went are gone — but
        // it is not something to log at the same level as a clean one, and the
        // counts are here either way so that "purged" in the log can be checked
        // against what it actually removed.
        if failed.is_empty() {
            tracing::info!(
                sandbox = %disk.sandbox_id,
                deployment = disk.deployment.as_deref().unwrap_or("-"),
                bytes = disk.bytes,
                state = disk.state.label(),
                killed,
                removed = removed.len(),
                "purged sandbox disks",
            );
        } else {
            tracing::warn!(
                sandbox = %disk.sandbox_id,
                deployment = disk.deployment.as_deref().unwrap_or("-"),
                bytes = disk.bytes,
                state = disk.state.label(),
                killed,
                removed = removed.len(),
                failed = failed.len(),
                detail = %failed.join("; "),
                "purged some of a sandbox's disks; the rest could not be removed",
            );
        }

        Ok(PurgeOutcome {
            sandbox_id: disk.sandbox_id,
            killed,
            bytes,
            removed,
            failed,
        })
    }

    /// Remove a sandbox from whichever deployment still expects to resume it.
    fn drop_claim(&self, sandbox_id: &str) {
        for d in self.registry.deployments().values() {
            let changed = d.mutate_state(|s| s.suspended.retain(|id| id != sandbox_id));
            if changed {
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %sandbox_id,
                    "dropped a suspended-VM claim because its disks were purged",
                );
                if let Err(e) = self.registry.persist_one(&d.spec.id) {
                    tracing::error!(deployment = %d.spec.id, error = %e, "failed to persist state");
                }
            }
        }
    }

    // -- archive -----------------------------------------------------------

    /// Start streaming a sandbox's disks to S3, and return the job that is
    /// doing it.
    ///
    /// Returns as soon as the upload task is spawned; progress is reported
    /// through `GET /disks`. `purge_after` reclaims the disks once the upload
    /// *succeeds* — never on failure, which is the whole reason this is one
    /// operation rather than two calls an operator has to sequence correctly.
    pub async fn archive(
        self: &Arc<Self>,
        sandbox_id: &str,
        purge_after: bool,
    ) -> Result<ArchiveView, DiskError> {
        if self.cfg.bucket.is_none() {
            return Err(DiskError::NoArchiveTarget);
        }
        let (disk, _) = self.one(sandbox_id).await?;
        self.archive_resolved(disk, purge_after)
    }

    /// [`archive`](Self::archive) against an already-resolved disk, for the
    /// sweep. See [`purge_resolved`](Self::purge_resolved).
    fn archive_resolved(
        self: &Arc<Self>,
        disk: DiskInfo,
        purge_after: bool,
    ) -> Result<ArchiveView, DiskError> {
        let Some(bucket) = self.cfg.bucket.clone() else {
            return Err(DiskError::NoArchiveTarget);
        };

        // Only the durable directories are worth uploading. A sandbox whose
        // only trace is a `/tmp` rootfs copy has nothing an archive could
        // restore — that file is a copy of a base image plus one boot's writes.
        if disk.roots.is_empty() {
            return Err(DiskError::NothingToArchive(disk.sandbox_id));
        }

        // Uploading a disk that a running VM is writing to produces a corrupt
        // image and a lot of egress. Refused rather than warned about.
        if disk.state == DiskState::Running {
            return Err(DiskError::Held {
                sandbox_id: disk.sandbox_id,
                reason: "the sandbox is running, so its disks are being written to; an archive \
                         taken now would be a torn copy",
                forceable: false,
            });
        }

        if !self
            .archiving
            .lock()
            .unwrap()
            .insert(disk.sandbox_id.clone())
        {
            return Err(DiskError::AlreadyArchiving(disk.sandbox_id));
        }

        let started_at = now_secs();
        let seq = self.archive_seq.fetch_add(1, Ordering::Relaxed);
        let job_id = format!("arch-{started_at:x}-{seq:x}");
        let key = format!("{}/{}/{started_at}.tar.gz", self.cfg.prefix, disk.sandbox_id);
        let uri = format!("s3://{bucket}/{key}");
        let sent = Arc::new(AtomicU64::new(0));

        let view = {
            let mut jobs = self.archives.lock().unwrap();
            let job = ArchiveJob {
                id: job_id.clone(),
                sandbox_id: disk.sandbox_id.clone(),
                uri: uri.clone(),
                started_at,
                finished_at: None,
                status: ArchiveStatus::Running,
                sent: sent.clone(),
                // The compressed stream is smaller than this, always — it is the
                // ceiling the progress bar is drawn against, and the figure the
                // `aws` CLI uses to pick a part size.
                expected: disk.apparent_bytes,
                error: None,
                purged: false,
            };
            let view = job.view();
            jobs.push_back(job);
            while jobs.len() > ARCHIVE_HISTORY {
                jobs.pop_front();
            }
            view
        };

        tracing::info!(
            sandbox = %disk.sandbox_id,
            job = %job_id,
            uri = %uri,
            bytes = disk.bytes,
            purge_after,
            "archiving sandbox disks",
        );

        let store = self.clone();
        let sandbox = disk.sandbox_id.clone();
        tokio::spawn(async move {
            // Queued rather than refused when the host is already uploading:
            // the operator asked for this one too. The job reads `running` with
            // zero bytes sent while it waits, which is what is happening.
            let _slot = store.archive_slots.acquire().await;
            let result = store.run_archive(&sandbox, &uri, disk.apparent_bytes, &sent).await;
            let (status, error) = match &result {
                Ok(()) => (ArchiveStatus::Succeeded, None),
                Err(e) => (ArchiveStatus::Failed, Some(e.clone())),
            };

            let mut purged = false;
            if result.is_ok() {
                store.record_archive(
                    &sandbox,
                    ArchiveRecord {
                        uri: uri.clone(),
                        at: now_secs(),
                        bytes: sent.load(Ordering::Relaxed),
                    },
                );
                if purge_after {
                    match store.purge(&sandbox, false).await {
                        Ok(o) => {
                            purged = true;
                            tracing::info!(
                                sandbox = %sandbox,
                                bytes = o.bytes,
                                "purged sandbox disks after a successful archive",
                            );
                        }
                        Err(e) => tracing::warn!(
                            sandbox = %sandbox,
                            error = %e,
                            "archive succeeded but the purge did not; the disks are still here",
                        ),
                    }
                }
            } else if let Err(e) = &result {
                tracing::error!(sandbox = %sandbox, error = %e, "disk archive failed");
            }

            // The in-flight marker is released last, so a retry cannot start
            // while the purge is still running.
            store.finish_archive(&job_id, status, error, purged);
            store.archiving.lock().unwrap().remove(&sandbox);
        });

        Ok(view)
    }

    /// The sandbox directories that exist, as paths relative to `data_dir`.
    ///
    /// Relative because `tar -C <data_dir> run/<id>` stores them that way, which
    /// is what makes an archive restorable by untarring it back into a data
    /// directory without rewriting any paths.
    /// The daemon's archive stream | `aws s3 cp -`, with app-lb holding the pipe.
    ///
    /// The daemon produces the tarball (`GET /storage/sandboxes/:id/archive`:
    /// `tar --sparse --gzip` over its own state directories, paths relative
    /// to its data dir so the archive restores with `tar -C`). app-lb still
    /// sits in the middle rather than handing the daemon the bucket: the byte
    /// count for the progress bar has to come from somewhere, the S3
    /// credentials are app-lb's, and an upload that fails must drop the
    /// stream rather than leave the daemon writing into a dead pipe.
    async fn run_archive(
        &self,
        sandbox_id: &str,
        uri: &str,
        expected: u64,
        sent: &Arc<AtomicU64>,
    ) -> Result<(), String> {
        use futures::StreamExt;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        use std::process::Stdio;

        let response = self
            .vms
            .archive_disks(sandbox_id)
            .await
            .map_err(|e| format!("could not start the daemon's archive stream: {e}"))?;
        let mut archive = response.bytes_stream();

        let mut aws = Command::new(&self.cfg.aws_bin);
        aws.arg("s3")
            .arg("cp")
            .arg("-")
            .arg(uri)
            // Progress output on a non-tty is noise; errors still reach stderr.
            .arg("--only-show-errors");
        if expected > 0 {
            // Only ever used to choose a part size. The compressed stream is
            // smaller than this, and over-estimating is the safe direction —
            // under-estimating risks exceeding the 10,000-part ceiling.
            aws.arg("--expected-size").arg(expected.to_string());
        }
        if let Some(endpoint) = &self.cfg.endpoint {
            aws.arg("--endpoint-url").arg(endpoint);
        }
        aws.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut aws = aws
            .spawn()
            .map_err(|e| format!("could not run {}: {e}", self.cfg.aws_bin))?;

        let mut aws_in = aws.stdin.take().ok_or("aws would not accept stdin")?;

        let pump = async {
            while let Some(chunk) = archive.next().await {
                let chunk = chunk.map_err(|e| format!("reading the daemon's archive stream: {e}"))?;
                aws_in
                    .write_all(&chunk)
                    .await
                    .map_err(|e| format!("writing to the uploader: {e}"))?;
                sent.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
            aws_in
                .shutdown()
                .await
                .map_err(|e| format!("closing the uploader's input: {e}"))?;
            drop(aws_in);
            Ok::<(), String>(())
        };

        let work = async {
            let pumped = pump.await;
            match aws.wait_with_output().await {
                Ok(out) if !out.status.success() => {
                    let msg = String::from_utf8_lossy(&out.stderr);
                    return Err(format!("aws s3 cp failed ({}): {}", out.status, tail(&msg)));
                }
                Err(e) => return Err(format!("waiting for aws: {e}")),
                Ok(_) => {}
            }
            pumped
        };

        match tokio::time::timeout(self.cfg.archive_timeout, work).await {
            Ok(r) => r,
            Err(_) => Err(format!(
                "archive exceeded APP_LB_DISK_ARCHIVE_TIMEOUT_SECS ({}s); the daemon's stream \
                 was dropped, the uploader killed and the multipart upload abandoned. It may leave incomplete parts \
                 in the bucket — a lifecycle rule on `AbortIncompleteMultipartUpload` is the \
                 usual way to clean those up",
                self.cfg.archive_timeout.as_secs()
            )),
        }
    }

    fn finish_archive(
        &self,
        job_id: &str,
        status: ArchiveStatus,
        error: Option<String>,
        purged: bool,
    ) {
        let mut jobs = self.archives.lock().unwrap();
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            job.status = status;
            job.error = error;
            job.purged = purged;
            job.finished_at = Some(now_secs());
        }
    }

    // -- expiry ------------------------------------------------------------

    /// Reclaim every disk whose time is up.
    ///
    /// Declines to do anything at all when the inventory is incomplete. That is
    /// the single most important line in this module: a daemon that is
    /// restarting answers no listing, every disk on the host then looks like
    /// residue, and one sweep would delete the entire fleet's state.
    pub async fn sweep(self: &Arc<Self>) -> SweepOutcome {
        let mut outcome = SweepOutcome::default();
        if self.cfg.ttl_secs == 0 {
            return outcome;
        }

        let inv = self.inventory().await;
        if !inv.complete {
            tracing::warn!(
                reason = inv.incomplete_reason.as_deref().unwrap_or("unknown"),
                "skipping the disk expiry sweep: without the daemon's listings every disk on \
                 this host would look like residue",
            );
            outcome.skipped = true;
            return outcome;
        }

        let now = now_secs();

        // Owned, not borrowed: `purge_resolved` consumes the `DiskInfo` so the
        // paths it acts on come from the inventory it was handed, not from one
        // re-read partway through the loop.
        let due: Vec<DiskInfo> = inv
            .disks
            .into_iter()
            .filter(|d| d.expired(now, self.cfg.ttl_secs, self.cfg.orphan_ttl_secs))
            .collect();
        if due.is_empty() {
            return outcome;
        }

        let archiving = self.cfg.archive_on_expire && self.cfg.bucket.is_some();
        tracing::info!(
            count = due.len(),
            bytes = due.iter().map(|d| d.bytes).sum::<u64>(),
            ttl_secs = self.cfg.ttl_secs,
            archive = archiving,
            "expiring unclaimed sandbox disks",
        );
        if archiving && due.len() > ARCHIVES_PER_SWEEP {
            // Said out loud rather than left to look like a completed sweep.
            tracing::info!(
                starting = ARCHIVES_PER_SWEEP,
                deferred = due.len() - ARCHIVES_PER_SWEEP,
                "more expired disks than one sweep will archive; the rest wait for the next one",
            );
        }

        for disk in due {
            let age_days = now.saturating_sub(disk.modified_at) / 86_400;
            if archiving {
                if outcome.archived >= ARCHIVES_PER_SWEEP {
                    break;
                }
                // The archive purges on success by itself, so this hands the
                // whole disk over and moves on. A failed upload leaves the disk
                // in place for the next sweep to retry.
                match self.archive_resolved(disk, true) {
                    Ok(_) => outcome.archived += 1,
                    Err(e) => {
                        tracing::warn!(error = %e, "could not archive an expiring disk");
                        outcome.failed += 1;
                    }
                }
                continue;
            }
            tracing::info!(
                sandbox = %disk.sandbox_id,
                deployment = disk.deployment.as_deref().unwrap_or("-"),
                state = disk.state.label(),
                bytes = disk.bytes,
                age_days,
                "expiring sandbox disks",
            );
            // `complete` is true — checked above — and `force` stays false, so
            // every guard still applies to each disk individually.
            match self.purge_resolved(disk, true, false).await {
                Ok(o) => {
                    outcome.purged += 1;
                    outcome.bytes += o.bytes;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not expire a disk");
                    outcome.failed += 1;
                }
            }
        }
        outcome
    }

    /// Reclaim every orphaned disk on the host, at any age.
    ///
    /// The expiry sweep only takes what has sat unclaimed past the TTL; this is
    /// the operator saying "the daemon has no record of these, take them all
    /// now". Age is deliberately not consulted — an orphan is pure residue on
    /// the day it is made, and waiting a week only means a week of paying for
    /// it. What *is* consulted is everything else: the same holds as any other
    /// purge, so a claimed or retained orphan is counted, reported, and left
    /// alone rather than force-flagged through.
    ///
    /// Declines entirely when the inventory is incomplete, for the sweep's
    /// reason: without both daemon listings nothing is classified as an orphan
    /// in the first place, and saying "skipped" beats reporting an empty purge
    /// as if the host were clean.
    pub async fn purge_orphans(self: &Arc<Self>) -> PurgeOrphansOutcome {
        let mut outcome = PurgeOrphansOutcome::default();

        let inv = self.inventory().await;
        if !inv.complete {
            tracing::warn!(
                reason = inv.incomplete_reason.as_deref().unwrap_or("unknown"),
                "refusing to purge orphans: without the daemon's listings nothing can be \
                 classified as one",
            );
            outcome.skipped = true;
            return outcome;
        }

        let mut due = Vec::new();
        for disk in inv.disks {
            if disk.state != DiskState::Orphan {
                continue;
            }
            // An orphan can still be held — a deployment claiming it for a
            // resume, or an operator's retain pin. Those are decisions this
            // bulk path must not override; the row's own Purge button offers
            // force for the operator who means it.
            if disk.held_by.is_some() {
                outcome.held += 1;
                continue;
            }
            due.push(disk);
        }

        if due.is_empty() {
            return outcome;
        }
        tracing::info!(
            count = due.len(),
            held = outcome.held,
            bytes = due.iter().map(|d| d.bytes).sum::<u64>(),
            "purging every orphaned disk on the host",
        );

        for disk in due {
            // `complete` is true — checked above — and `force` stays false, so
            // each disk's guards are still consulted individually against the
            // inventory this loop was built from.
            match self.purge_resolved(disk, true, false).await {
                Ok(o) => {
                    outcome.purged += 1;
                    outcome.bytes += o.bytes;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "could not purge an orphaned disk");
                    outcome.failed += 1;
                }
            }
        }
        outcome
    }
}

/// What one purge-all-orphans pass did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PurgeOrphansOutcome {
    /// True when nothing was attempted because the daemon was unreachable.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    pub purged: usize,
    /// Orphans left alone because a claim or a retain pin holds them.
    pub held: usize,
    pub failed: usize,
    pub bytes: u64,
}

/// What one expiry sweep did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepOutcome {
    /// True when the sweep declined to run because the daemon was unreachable.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
    pub purged: usize,
    pub archived: usize,
    pub failed: usize,
    pub bytes: u64,
}

/// The last few lines of a child's stderr, for an error message that has to fit
/// on a page.
fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(4);
    lines[start..].join("; ")
}

/// Ask the daemon to remove a sandbox's disks, as `(removed, failed, bytes)`.
///
/// A daemon that cannot be reached, or that refuses because the sandbox is
/// running, is one failure and nothing removed — which is what every caller
/// treats as "the disks are still there". The daemon's own partial-failure
/// report (a path it could not unlink) comes through path by path.
pub async fn purge_on_daemon(
    vms: &VmManager,
    sandbox_id: &str,
    parts: PurgeParts,
) -> (Vec<String>, Vec<String>, u64) {
    match vms.purge_disks(sandbox_id, parts).await {
        Ok(outcome) => (
            outcome.removed,
            outcome
                .failed
                .into_iter()
                .map(|f| format!("{}: {}", f.path, f.error))
                .collect(),
            outcome.bytes,
        ),
        Err(e) => (Vec::new(), vec![format!("the daemon would not purge: {e}")], 0),
    }
}

/// Reclaim everything a VM that never came up left behind, data disk
/// included. The daemon refuses while the sandbox is live.
pub async fn discard_failed_boot(vms: &VmManager, sandbox_id: &str) -> (Vec<String>, Vec<String>) {
    let (removed, failed, _) = purge_on_daemon(vms, sandbox_id, PurgeParts::All).await;
    (removed, failed)
}

/// Drop a suspended VM's rootfs copies and nothing else: the daemon rebuilds
/// the copy from the base image on resume, and the data disk, mount images
/// and snapshots stay.
pub async fn discard_rootfs(vms: &VmManager, sandbox_id: &str) -> (Vec<String>, Vec<String>) {
    let (removed, failed, _) = purge_on_daemon(vms, sandbox_id, PurgeParts::Rootfs).await;
    (removed, failed)
}

/// The background service that runs [`DiskStore::sweep`].
pub struct DiskSweeper {
    store: Arc<DiskStore>,
}

impl DiskSweeper {
    pub fn new(store: Arc<DiskStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for DiskSweeper {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let period = Duration::from_secs(self.store.cfg.sweep_secs);
        let mut tick = tokio::time::interval(period);
        // A sweep that overran its period must not then fire back-to-back
        // catch-up ticks, which is `Burst`'s default behaviour. Reclaiming
        // gigabytes is not work to do twice in a row because the first pass was
        // slow.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it. A sweep during startup
        // would race the autoscaler's adoption pass, which is what turns a
        // stopped VM back into a claimed one — and a disk purged in that window
        // is one the fleet was about to resume.
        tick.tick().await;
        // Counted here rather than left for the first sweep to discover,
        // because on a host that has been booting VMs for months the honest
        // answer is "most of them" — and an operator who never opens
        // /storage should still learn that from the log before it happens.
        // An upper bound: without the daemon this cannot tell a running
        // sandbox from residue.
        if self.store.cfg.ttl_secs > 0 {
            let (total, due, bytes) = self.store.expiry_preview().await;
            tracing::warn!(
                ttl_secs = self.store.cfg.ttl_secs,
                sweep_secs = self.store.cfg.sweep_secs,
                archive = self.store.cfg.bucket.is_some(),
                disks = total,
                eligible = due,
                gib = bytes / (1 << 30),
                "disk expiry is ON: up to {due} of {total} sandbox disks on the daemon's host \
                 are already older than the retention window and will be reclaimed by the \
                 first sweep, in {}s. Open /storage to review them, mark the ones to keep as \
                 retained, or set APP_LB_DISK_TTL_SECS=0 to turn expiry off",
                self.store.cfg.sweep_secs,
            );
        }
        loop {
            tokio::select! {
                _ = tick.tick() => { self.store.sweep().await; }
                _ = shutdown.changed() => {
                    tracing::info!("disk sweeper shutting down");
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// scanning
// ---------------------------------------------------------------------------

/// One sandbox's files, accumulated across every directory that holds them.
#[derive(Debug, Default)]
struct Group {
    parts: Vec<DiskPart>,
    /// The durable state directories the daemon holds for this sandbox,
    /// relative to its data dir (`run/<id>`, `kvm/<id>`). Tmp scratch is not
    /// a root: it is listed in `parts` and has nothing an archive could restore.
    roots: Vec<String>,
    bytes: u64,
    apparent_bytes: u64,
    modified_at: u64,
}

/// Group the daemon's storage inventory by sandbox.
///
/// The daemon walks its own directories (`GET /storage`) and reports every
/// file with its allocated size; this only regroups. A `Tmp` part is a
/// per-boot scratch file the daemon found under its tmp dir, classified here
/// by name the way its state-dir siblings are.
fn groups_from(inventory: &StorageInventory) -> HashMap<String, Group> {
    let mut groups: HashMap<String, Group> = HashMap::new();
    for sandbox in &inventory.sandboxes {
        let group = groups.entry(sandbox.sandbox_id.clone()).or_default();
        for part in &sandbox.parts {
            let kind = match part.kind {
                heyo_sdk::DiskPartKind::Data => PartKind::Data,
                heyo_sdk::DiskPartKind::Rootfs => PartKind::Rootfs,
                heyo_sdk::DiskPartKind::Mount => PartKind::Mount,
                heyo_sdk::DiskPartKind::Snapshot => PartKind::Snapshot,
                heyo_sdk::DiskPartKind::Tmp if part.path.ends_with("-rootfs.ext4") => PartKind::Rootfs,
                heyo_sdk::DiskPartKind::Tmp if part.path.contains("-mount") => PartKind::Mount,
                heyo_sdk::DiskPartKind::Tmp | heyo_sdk::DiskPartKind::Other => PartKind::Other,
            };
            group.push(DiskPart {
                kind,
                path: part.path.clone(),
                bytes: part.bytes,
                apparent_bytes: part.apparent_bytes,
                modified_at: part.modified_at,
            });
            // The durable roots, relative to the daemon's data dir, in the
            // form an archive names them. Tmp scratch is not a root.
            for root in DISK_ROOTS {
                let prefix = format!("{root}/{}/", sandbox.sandbox_id);
                if part.path.starts_with(&prefix) {
                    let name = format!("{root}/{}", sandbox.sandbox_id);
                    if !group.roots.contains(&name) {
                        group.roots.push(name);
                    }
                }
            }
        }
    }
    for group in groups.values_mut() {
        group.roots.sort();
        group.recompute();
    }
    groups
}

impl Group {
    fn push(&mut self, part: DiskPart) {
        self.parts.push(part);
    }

    fn recompute(&mut self) {
        self.bytes = self.parts.iter().map(|p| p.bytes).sum();
        self.apparent_bytes = self.parts.iter().map(|p| p.apparent_bytes).sum();
        self.modified_at = self.parts.iter().map(|p| p.modified_at).max().unwrap_or(0);
        // Largest first, so the page's expanded view leads with the file that
        // explains the total.
        self.parts
            .sort_by_key(|p| std::cmp::Reverse((p.bytes, p.apparent_bytes)));
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("app-lb-disks-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cfg_at(root: &Path) -> DiskConfig {
        DiskConfig {
            state_path: root.join("disks.json"),
            ttl_secs: DEFAULT_TTL_SECS,
            sweep_secs: 3600,
            aws_bin: "aws".into(),
            bucket: None,
            prefix: "app-lb/disks".into(),
            endpoint: None,
            archive_on_expire: false,
            archive_timeout: Duration::from_secs(60),
            orphan_ttl_secs: DEFAULT_ORPHAN_TTL_SECS,
        }
    }

    fn disk(state: DiskState, claimed: bool, retain: bool, modified_at: u64) -> DiskInfo {
        DiskInfo {
            sandbox_id: "sb-1".into(),
            name: None,
            deployment: None,
            state,
            claimed,
            retain,
            note: None,
            bytes: 1024,
            apparent_bytes: 1024,
            modified_at,
            expires_at: None,
            held_by: hold_reason(state, claimed, retain),
            archived: None,
            parts: vec![],
            roots: vec![],
        }
    }

    /// The id is a URL path segment on its way to `remove_dir_all`. Everything
    /// that could escape the two directories this module owns must be refused
    /// before it is joined to anything.
    mod ids {
        use super::*;

        #[test]
        fn plain_sandbox_ids_are_accepted() {
            assert!(valid_sandbox_id("sb-0226245f"));
            assert!(valid_sandbox_id("sb_1"));
            assert!(valid_sandbox_id("A0"));
        }

        #[test]
        fn traversal_and_separators_are_refused() {
            for bad in [
                "", "..", ".", "../etc", "sb/../..", "sb-1/", "/sb-1", "sb 1", "sb-1\0", "sb.1",
                "~", "*",
            ] {
                assert!(!valid_sandbox_id(bad), "accepted {bad:?}");
            }
            assert!(!valid_sandbox_id(&"x".repeat(129)));
        }

        /// A dot is refused, which is what keeps `..` from ever reaching a join
        /// — the traversal case above is a consequence of this rule, not a
        /// separate check that could drift away from it.
        #[test]
        fn a_dot_alone_is_enough_to_refuse() {
            assert!(!valid_sandbox_id("sb-1.ext4"));
        }
    }

    mod expiry {
        use super::*;

        #[test]
        fn an_old_unclaimed_disk_expires() {
            // `Stopped`, not `Orphan`: these two cover the ordinary age rule, and
            // the long TTL is now the one that governs a sandbox the daemon can
            // still start. An orphan answers to a much shorter clock — see
            // `an_orphan_expires_in_minutes_not_days`.
            let d = disk(DiskState::Stopped, false, false, 0);
            assert!(d.expired(DEFAULT_TTL_SECS, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS));
        }

        #[test]
        fn a_young_disk_does_not() {
            let d = disk(DiskState::Stopped, false, false, 100);
            assert!(!d.expired(100 + DEFAULT_TTL_SECS - 1, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS));
            assert!(d.expired(100 + DEFAULT_TTL_SECS, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS));
        }

        /// The four guards, each on its own. Any one of them holding is enough,
        /// and no age makes it go away — which is the property that matters,
        /// because the sweep only ever consults `expired`.
        #[test]
        fn every_hold_survives_any_age() {
            let ancient = u64::MAX / 2;
            for d in [
                disk(DiskState::Running, false, false, 0),
                disk(DiskState::Unknown, false, false, 0),
                disk(DiskState::Stopped, true, false, 0),
                disk(DiskState::Stopped, false, true, 0),
            ] {
                assert!(d.held_by.is_some(), "expected a hold for {:?}", d.state);
                assert!(!d.expired(ancient, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS), "{:?} expired", d.state);
            }
        }

        /// A running VM's disk reports *why* it is held rather than the first
        /// rule that matched, so the page says something true even when several
        /// reasons apply at once.
        #[test]
        fn the_strongest_hold_is_the_one_reported() {
            let d = disk(DiskState::Running, true, true, 0);
            assert_eq!(d.held_by, Some("the sandbox is running"));
            let d = disk(DiskState::Stopped, true, true, 0);
            assert_eq!(d.held_by, Some("a deployment expects to resume it"));
        }

        #[test]
        fn ttl_zero_disables_expiry_entirely() {
            let d = disk(DiskState::Orphan, false, false, 0);
            assert!(!d.expired(u64::MAX / 2, 0, 0));
        }

        /// The disk of a VM that never created is worth nothing, and the policy
        /// has to say so.
        ///
        /// `DEFAULT_TTL_SECS` buys the chance to change your mind about a VM you
        /// retired — a real thing to want, for a sandbox the daemon still has a
        /// record of and could start again. An orphan is not that. There is no
        /// record in either listing, so nothing resumes it and no delete is ever
        /// coming for it; the seven-day grace was retaining a copy of a disk
        /// whose VM failed to create. It gets minutes instead.
        #[test]
        fn an_orphan_expires_in_minutes_not_days() {
            let d = disk(DiskState::Orphan, false, false, 0);

            assert!(
                !d.expired(DEFAULT_ORPHAN_TTL_SECS - 1, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS),
                "inside the creation-race window it must survive",
            );
            assert!(
                d.expired(DEFAULT_ORPHAN_TTL_SECS, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS),
                "past it there is nothing left to protect",
            );
            assert!(
                !d.expired(DEFAULT_ORPHAN_TTL_SECS, DEFAULT_TTL_SECS, 0),
                "an orphan TTL of 0 disables orphan expiry rather than making it instant",
            );

            // A sandbox the daemon still knows about keeps the long TTL: it is
            // recoverable, which is exactly what the seven days are for.
            let stopped = disk(DiskState::Stopped, false, false, 0);
            assert!(
                !stopped.expired(DEFAULT_ORPHAN_TTL_SECS, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS),
                "a stopped sandbox is not residue and must not inherit the orphan TTL",
            );
            assert!(stopped.expired(DEFAULT_TTL_SECS, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS));

            // A hold still outranks age, on either clock.
            for held in [
                disk(DiskState::Orphan, true, false, 0),
                disk(DiskState::Orphan, false, true, 0),
            ] {
                assert!(held.held_by.is_some(), "the fixture should be held");
                assert!(
                    !held.expired(u64::MAX / 2, DEFAULT_TTL_SECS, DEFAULT_ORPHAN_TTL_SECS),
                    "an operator who pinned a disk meant it",
                );
            }
        }
    }

    mod policy {
        use super::*;

        #[tokio::test]
        async fn retirement_refuses_forced_purge_from_stale_unclaimed_inventory() {
            use std::sync::atomic::{AtomicUsize,Ordering};
            let root=tempfile::tempdir().unwrap();
            let deletes=Arc::new(AtomicUsize::new(0));
            let count=deletes.clone();
            let backend=axum::Router::new().fallback(move |request:axum::extract::Request| {
                let count=count.clone();async move {
                    if request.method()==axum::http::Method::DELETE {count.fetch_add(1,Ordering::SeqCst);}
                    axum::http::StatusCode::NO_CONTENT
                }
            });
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url=format!("http://{}",listener.local_addr().unwrap());
            tokio::spawn(async move {axum::serve(listener,backend).await.unwrap();});
            let registry=Arc::new(Registry::new(root.path().join("state.json")));
            let d=registry.upsert(serde_json::from_value(serde_json::json!({
                "id":"service","routes":[],"vm":{"driver":"kvm","port":8080}
            })).unwrap());
            d.set_pending(vec![crate::deployment::PendingVm::new("sb-1".into())]);
            crate::retirement::freeze(&registry,&d,serde_json::from_value(serde_json::json!({
                "operation_id":"retire-1","expected_revision":d.state().rollout_revision,
                "expected_spec_sha256":crate::rollout::fingerprint(&d.spec),"targets":[{
                    "backendServerId":"host","backendSandboxId":"sb-1","createdAtUnixNanos":"1780000000000000001",
                    "libvirtConnectionUri":"qemu:///system","libvirtDomainUuid":"00000000-0000-0000-0000-000000000001"
                }]
            })).unwrap()).unwrap();
            let vm=VmManager::new(Some(url),None,crate::mounts::MountStore::new(root.path().join("mounts"),0)).unwrap();
            let store=DiskStore::new(cfg_at(root.path()),vm,registry);
            // No claimed/deployment/retain hints: the immutable retirement pin
            // must outrank a stale sweep and the explicit force flag alike.
            let stale=disk(DiskState::Orphan,false,false,0);
            for force in [false,true] {
                assert!(matches!(store.purge_resolved(stale.clone(),true,force).await,
                    Err(DiskError::Held {forceable:false,..})));
            }
            assert_eq!(deletes.load(Ordering::SeqCst),0);
        }

        fn store(root: &Path) -> DiskStore {
            DiskStore::new(
                cfg_at(root),
                VmManager::new(
                    Some("http://127.0.0.1:1".into()),
                    None,
                    crate::mounts::MountStore::new(root.join("mounts"), 0),
                )
                .unwrap(),
                Arc::new(Registry::new(
                    root.join("state.json").to_str().unwrap(),
                )),
            )
        }

        #[test]
        fn retention_round_trips_through_the_file() {
            let root = scratch("policy");
            let s = store(&root);
            s.set_policy("sb-1", Some(true), Some(Some("keeps the demo".into())))
                .unwrap();

            let reloaded = store(&root);
            assert_eq!(reloaded.load().unwrap(), 1);
            let p = reloaded.policies.lock().unwrap();
            assert!(p["sb-1"].retain);
            assert_eq!(p["sb-1"].note.as_deref(), Some("keeps the demo"));
        }

        /// An absent field leaves the other alone, so the page can offer a pin
        /// toggle and a note field without either clobbering the other.
        #[test]
        fn a_partial_update_leaves_the_rest_alone() {
            let root = scratch("partial");
            let s = store(&root);
            s.set_policy("sb-1", Some(true), Some(Some("why".into()))).unwrap();
            s.set_policy("sb-1", Some(false), None).unwrap();

            let p = s.policies.lock().unwrap();
            assert_eq!(p["sb-1"].note.as_deref(), Some("why"));
            assert!(!p["sb-1"].retain);
        }


        /// The daemon's part of a purge, faked over `GET /storage` and
        /// `DELETE /storage/sandboxes/:id`: an inventory with one orphan whose
        /// removal the daemon reports as failed path by path.
        async fn fake_daemon(purge: serde_json::Value) -> String {
            use axum::extract::Path as AxPath;
            use axum::routing::{delete, get};
            use axum::{Json, Router};
            let purge = std::sync::Arc::new(purge);
            let app = Router::new()
                .route(
                    "/storage",
                    get(|| async {
                        Json(serde_json::json!({
                            "data_dir": "/data", "tmp_dir": "/tmp", "free_bytes": 10, "total_bytes": 20,
                            "sandboxes": [{"sandbox_id": "sb-1", "parts": [
                                {"kind": "data", "path": "run/sb-1/data.ext4", "bytes": 4096,
                                 "apparent_bytes": 32, "modified_at": 1}
                            ]}]
                        }))
                    }),
                )
                .route("/deployed-sandboxes", get(|| async { Json(serde_json::json!([])) }))
                .route(
                    "/sandboxes/inactive",
                    get(|| async { Json(serde_json::json!({"sandboxes": [], "next_cursor": null})) }),
                )
                .route(
                    "/storage/sandboxes/:id",
                    delete(move |AxPath(_id): AxPath<String>| {
                        let purge = purge.clone();
                        async move { Json((*purge).clone()) }
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{addr}")
        }

        #[tokio::test]
        async fn unidentified_disks_are_not_automatically_reclaimed() {
            let url = fake_daemon(serde_json::json!({
                "removed": ["/data/run/sb-1"], "failed": [], "bytes": 4096,
            })).await;
            let root = tempfile::tempdir().unwrap();
            let registry = Arc::new(Registry::new(root.path().join("state.json")));
            let vms = VmManager::new(
                Some(url), None,
                crate::mounts::MountStore::new(root.path().join("mounts"), 0),
            ).unwrap();
            let store = Arc::new(DiskStore::new(cfg_at(root.path()), vms, registry.clone()));
            for populated in [false, true] {
                if populated {
                    registry.upsert(serde_json::from_value(serde_json::json!({
                        "id": "another-service", "routes": [],
                        "vm": {"driver": "kvm", "port": 8080}
                    })).unwrap());
                }
                let inventory = store.inventory().await;
                assert!(inventory.complete);
                assert_eq!(inventory.disks.len(), 1);
                let disk = &inventory.disks[0];
                assert!(disk.held_by.is_some());
                assert!(!disk.expired(u64::MAX / 2, 1, 1));
                assert!(matches!(store.purge("sb-1", false).await,
                    Err(DiskError::Held { .. })));
            }
        }

        /// The whole failed-purge path, end to end.
        ///
        /// A purge that removed nothing must say so rather than returning an
        /// outcome claiming the size it *would* have freed — that is what let a
        /// sweep report a thousand disks reclaimed while the host filled up. It
        /// must also leave the policy alone: forgetting a `retain` flag that is
        /// still protecting a disk still on disk is the wrong half of the
        /// operation to complete.
        #[tokio::test]
        async fn a_purge_that_removes_nothing_is_an_error_and_keeps_its_policy() {
            let url = fake_daemon(serde_json::json!({
                "removed": [],
                "failed": [{"path": "/data/run/sb-1", "error": "Permission denied (os error 13)"}],
                "bytes": 0,
            }))
            .await;
            let root = scratch("purge-denied");
            let vms = VmManager::new(
                Some(url),
                None,
                crate::mounts::MountStore::new(root.join("mounts"), 0),
            )
            .unwrap();
            let s = DiskStore::new(
                cfg_at(&root),
                vms,
                Arc::new(Registry::new(root.join("state.json"))),
            );
            s.set_policy("sb-1", Some(true), Some(Some("still needed".into())))
                .unwrap();

            // Forced, because the disk is retained and therefore held.
            match s.purge("sb-1", true).await {
                Err(DiskError::PurgeFailed { sandbox_id, failed }) => {
                    assert_eq!(sandbox_id, "sb-1");
                    assert!(failed.iter().any(|f| f.contains("run/sb-1")), "{failed:?}");
                    // The message has to point at the actual cause; an operator
                    // reading "0 bytes freed" learns nothing.
                    let shown = DiskError::PurgeFailed {
                        sandbox_id: "sb-1".into(),
                        failed,
                    }
                    .to_string();
                    assert!(shown.contains("nothing was reclaimed"), "{shown}");
                }
                other => panic!("expected PurgeFailed, got {other:?}"),
            }

            let p = s.policies.lock().unwrap().clone();
            assert!(p["sb-1"].retain, "the policy survives a purge that reclaimed nothing");
            assert_eq!(p["sb-1"].note.as_deref(), Some("still needed"));
            let _ = std::fs::remove_dir_all(&root);
        }

        /// An entry that says nothing is dropped, so the file tracks decisions
        /// rather than growing one line per sandbox that ever booted.
        #[test]
        fn an_entry_back_at_its_defaults_is_forgotten() {
            let root = scratch("empty-policy");
            let s = store(&root);
            s.set_policy("sb-1", Some(true), None).unwrap();
            assert!(s.policies.lock().unwrap().contains_key("sb-1"));
            s.set_policy("sb-1", Some(false), Some(None)).unwrap();
            assert!(s.policies.lock().unwrap().is_empty());
        }

        #[test]
        fn a_bad_id_never_reaches_the_file() {
            let root = scratch("bad-policy");
            let s = store(&root);
            assert!(matches!(
                s.set_policy("../etc", Some(true), None),
                Err(DiskError::BadId(_))
            ));
            assert!(s.policies.lock().unwrap().is_empty());
        }

        #[test]
        fn a_missing_state_file_loads_as_empty() {
            let root = scratch("no-state");
            assert_eq!(store(&root).load().unwrap(), 0);
        }
    }

    mod config {
        use super::*;

        #[test]
        fn the_default_ttl_is_seven_days() {
            assert_eq!(DEFAULT_TTL_SECS, 604_800);
        }

        /// The archive key carries a timestamp, so re-archiving a disk never
        /// overwrites the copy that is already in the bucket.
        #[test]
        fn tail_keeps_the_last_lines_of_a_childs_stderr() {
            assert_eq!(tail(""), "");
            assert_eq!(tail("one\n\ntwo\n"), "one; two");
            let many = (1..=10).map(|i| i.to_string()).collect::<Vec<_>>().join("\n");
            assert_eq!(tail(&many), "7; 8; 9; 10");
        }
    }
}
