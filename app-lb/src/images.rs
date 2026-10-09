//! The heyvm image catalog, as app-lb manages it: what is on the host, what
//! uses it, and what can leave.
//!
//! heyvm keeps every image anyone ever uploaded, and app-lb used to upload one
//! per deployment. This module is the other half of content-addressed pulls
//! (`ArtifactSpec::image_for`): with one image per blob instead of one per
//! deployment, what remains is noticing when nothing uses an image any more and
//! getting it off the host without losing it.
//!
//! ## What keeps an image
//!
//! [`references`] — any one is enough, and an image with one is never touched:
//! a deployment's `vm.image`; a rollout's spec or prepared candidate, for as
//! long as the operation is kept (it is the rollback target); a sandbox, live
//! or inactive, created from it; a running job that names it; an operator pin.
//!
//! ## Offload, after pg-fc
//!
//! An image no reference has held for `APP_LB_IMAGE_IDLE_SECS` is offloaded,
//! one at a time, by a pacer that yields while any pool is booting:
//!
//! * **pulled** — the store it came from is the offload tier. The blob is
//!   verified to still be there at the recorded size (`HEAD /blobs/<digest>`,
//!   or `art stat` for a store root), the record is flipped to `offloaded`
//!   durably, and only then is the catalog file deleted.
//! * **built** — it exists nowhere else, so it is pushed to
//!   `APP_LB_IMAGE_OFFLOAD_STORE` and tagged `app-lb-offload:<name>` first;
//!   the store's own digest check is the verification. Without that setting a
//!   build is never offloaded.
//! * **unknown** — an image app-lb did not make is listed and never deleted.
//!
//! Above `APP_LB_IMAGE_PRESSURE_PCT` of the image disk the idle age is
//! ignored, but nothing else is: a referenced or unverified image stays.
//! An image is never deleted when what references it cannot be known — heyvm
//! unreachable, its sandbox listing failing — and never within ten minutes of
//! being first seen, which covers a pull between its upload and its rollout.
//!
//! ## Thaw
//!
//! [`ImageCatalog::ensure_image`] is asked before the autoscaler creates a VM.
//! A deployment whose image is not on heyvm does not get a VM booted from the
//! daemon's default image instead (which is what happened before its first
//! pull): an `artifact` deployment gets a pull started, an image this module
//! offloaded is pulled back under its own name, and the VM is created on a
//! later tick once the image is there.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::artifact::Puller;
use crate::config::ArtifactSpec;
use crate::deployment::{Deployment, now_secs};
use crate::jobs::{JobRecord, JobStatus, Jobs};
use crate::registry::Registry;
use crate::secrets::{SecretRef, SecretStore};
use crate::vm::{ImageDelete, VmManager};

pub const DEFAULT_IDLE_SECS: u64 = 86_400;
pub const DEFAULT_SWEEP_SECS: u64 = 600;
pub const DEFAULT_PRESSURE_PCT: u8 = 85;
pub const DEFAULT_WARM_SECS: u64 = 900;
/// Where a warm-set entry without a `<store>|` prefix is pulled from.
pub const DEFAULT_WARM_STORE: &str = "https://hub.heyo.work";
/// No image is offloaded within this long of being first seen: a pull's
/// upload lands before the rollout that references it.
pub const MIN_AGE_SECS: u64 = 600;
/// A routine pass offloads at most this many; a pressure pass keeps going.
const ROUTINE_PER_PASS: usize = 4;
/// How stale a positive "heyvm has this image" may be before it is re-asked.
const PRESENT_TTL: Duration = Duration::from_secs(60);
const FIRST_SWEEP_DELAY: Duration = Duration::from_secs(120);

/// Whether `name` is something heyvm's catalog could hold, and so something
/// it is safe to put in a URL path or a file name. Kernels are excluded on
/// purpose: nothing here may ever delete one.
pub fn is_catalog_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.starts_with("vmlinux")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `app-lb-state.json` -> `app-lb-images.d`, beside it.
pub fn image_dir(state_path: &str) -> PathBuf {
    let path = Path::new(state_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app-lb-state");
    let name = match stem.strip_suffix("-state") {
        Some(prefix) => format!("{prefix}-images.d"),
        None => format!("{stem}-images.d"),
    };
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

// ---- configuration ----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ImagesConfig {
    /// `APP_LB_IMAGE_OFFLOAD` (default on): whether the pacer offloads. Off
    /// leaves the inventory and the explicit routes.
    pub offload: bool,
    /// `APP_LB_IMAGE_IDLE_SECS`.
    pub idle_secs: u64,
    /// `APP_LB_IMAGE_SWEEP_SECS`; `0` stops the pacer.
    pub sweep_secs: u64,
    /// `APP_LB_IMAGE_PRESSURE_PCT`.
    pub pressure_pct: u8,
    /// `APP_LB_IMAGE_OFFLOAD_STORE`: where a built image goes before it is
    /// deleted. An `art serve` URL or a store root on this host.
    pub offload_store: Option<String>,
    /// `APP_LB_IMAGE_OFFLOAD_STORE_KEY`: the store's API key, as a secret id
    /// (`<secret>` or `<secret>/<key>`), resolved per use.
    pub offload_store_key: Option<SecretRef>,
    /// `APP_LB_IMAGE_CACHE_BUDGET_GB`: how many bytes of unreferenced pulled
    /// images may stay as cache before the least recently used go. Unset:
    /// only disk pressure removes a pulled image.
    pub cache_budget_bytes: Option<u64>,
    /// `APP_LB_IMAGE_WARM`: images pulled ahead of any deployment asking,
    /// and held so nothing removes them.
    pub warm: Vec<WarmEntry>,
    /// `APP_LB_IMAGE_WARM_SECS`: how often the warm set's tags are
    /// re-resolved; `0` warms once at startup.
    pub warm_secs: u64,
}

/// One entry of the warm set: a reference in a store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmEntry {
    pub store: String,
    pub artifact_ref: String,
}

impl WarmEntry {
    /// `<store>|<ref>`, or a bare `<ref>` in `default_store`. Entries are
    /// separated by commas or whitespace.
    pub fn parse_list(list: &str, default_store: &str) -> Vec<Self> {
        list.split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let (store, r) = e.split_once('|').unwrap_or((default_store, e));
                let (store, r) = (store.trim().trim_end_matches('/'), r.trim());
                (!store.is_empty() && !r.is_empty()).then(|| Self {
                    store: store.to_string(),
                    artifact_ref: r.to_string(),
                })
            })
            .collect()
    }

    /// `<store>/<ref>`: how the warm set names an entry in logs and on
    /// [`Reference::Warm`].
    pub fn label(&self) -> String {
        format!("{}/{}", self.store, self.artifact_ref)
    }

    fn holds(&self, record: &ImageRecord) -> bool {
        record.store.as_deref().map(|s| s.trim().trim_end_matches('/')) == Some(self.store.as_str())
            && record.artifact_ref.as_deref() == Some(self.artifact_ref.as_str())
    }
}

impl Default for ImagesConfig {
    fn default() -> Self {
        Self {
            offload: true,
            idle_secs: DEFAULT_IDLE_SECS,
            sweep_secs: DEFAULT_SWEEP_SECS,
            pressure_pct: DEFAULT_PRESSURE_PCT,
            offload_store: None,
            offload_store_key: None,
            cache_budget_bytes: None,
            warm: Vec::new(),
            warm_secs: DEFAULT_WARM_SECS,
        }
    }
}

impl ImagesConfig {
    pub fn from_env() -> Self {
        let num = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let flag = |k: &str| {
            std::env::var(k).ok().map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
        };
        let d = Self::default();
        Self {
            offload: flag("APP_LB_IMAGE_OFFLOAD").unwrap_or(d.offload),
            idle_secs: num("APP_LB_IMAGE_IDLE_SECS").unwrap_or(d.idle_secs),
            sweep_secs: num("APP_LB_IMAGE_SWEEP_SECS").unwrap_or(d.sweep_secs),
            pressure_pct: num("APP_LB_IMAGE_PRESSURE_PCT")
                .map(|p| p.clamp(1, 100) as u8)
                .unwrap_or(d.pressure_pct),
            offload_store: std::env::var("APP_LB_IMAGE_OFFLOAD_STORE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            offload_store_key: std::env::var("APP_LB_IMAGE_OFFLOAD_STORE_KEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let (secret, key) = s.split_once('/').unwrap_or((s.as_str(), "token"));
                    SecretRef {
                        secret: secret.to_string(),
                        key: key.to_string(),
                        username: None,
                        namespace: None,
                    }
                }),
            cache_budget_bytes: num("APP_LB_IMAGE_CACHE_BUDGET_GB").map(|gb| gb.saturating_mul(1 << 30)),
            warm: WarmEntry::parse_list(
                &std::env::var("APP_LB_IMAGE_WARM").unwrap_or_default(),
                std::env::var("APP_LB_IMAGE_WARM_STORE")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .as_deref()
                    .unwrap_or(DEFAULT_WARM_STORE),
            ),
            warm_secs: num("APP_LB_IMAGE_WARM_SECS").unwrap_or(d.warm_secs),
        }
    }
}

// ---- records ----------------------------------------------------------------

/// How an image came to be on this host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageSource {
    /// An artifact pull: the store it came from still has it.
    Pull,
    /// A `heyvm mvm build`: nowhere else has it.
    Build,
    /// Seen in the catalog; app-lb did not make it.
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// In heyvm's catalog.
    #[default]
    Local,
    /// Deleted from the catalog; `offloaded_to` holds the copy.
    Offloaded,
}

/// One image, kept whether or not anything references it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageRecord {
    pub name: String,
    #[serde(default)]
    pub source: ImageSource,
    #[serde(default)]
    pub tier: Tier,
    /// The blob's digest, for a pull or an offloaded build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The store that holds `digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// The reference that was pulled (a tag or digest), for the record.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// The store's API key, as a secret reference — never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<SecretRef>,
    /// `grow_gb` the image was materialized with, so a thaw grows it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grow_gb: Option<u64>,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub first_seen: u64,
    /// Last time any reference held it.
    #[serde(default)]
    pub last_used: u64,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offloaded_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offloaded_at: Option<u64>,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub next_attempt_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ImageRecord {
    fn new(name: &str, now: u64) -> Self {
        Self {
            name: name.to_string(),
            first_seen: now,
            last_used: now,
            ..Default::default()
        }
    }

    /// Backoff after a failed offload: 30 minutes, doubling, capped at a day.
    fn fail(&mut self, error: String, now: u64) {
        self.failures = self.failures.saturating_add(1);
        let delay = (1800u64 << (self.failures - 1).min(6)).min(86_400);
        self.next_attempt_at = now + delay;
        self.last_error = Some(error);
    }
}

/// One JSON file per image, in the shape the plugin and namespace stores use.
#[derive(Debug)]
pub struct ImageStore {
    dir: PathBuf,
    records: Mutex<BTreeMap<String, ImageRecord>>,
}

impl ImageStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            records: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `(loaded, skipped)`.
    pub fn load(&self) -> (usize, usize) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return (0, 0);
        };
        let mut loaded = BTreeMap::new();
        let mut skipped = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<ImageRecord>(&b).ok())
                .filter(|r| is_catalog_name(&r.name))
            {
                Some(r) => {
                    loaded.insert(r.name.clone(), r);
                }
                None => {
                    tracing::warn!(
                        "skipping unreadable image record {}; it is still on disk",
                        path.display()
                    );
                    skipped += 1;
                }
            }
        }
        let n = loaded.len();
        *self.records.lock().unwrap() = loaded;
        (n, skipped)
    }

    pub fn get(&self, name: &str) -> Option<ImageRecord> {
        self.records.lock().unwrap().get(name).cloned()
    }

    pub fn all(&self) -> Vec<ImageRecord> {
        self.records.lock().unwrap().values().cloned().collect()
    }

    /// Write-then-rename, then publish.
    pub fn put(&self, record: ImageRecord) -> std::io::Result<()> {
        if !is_catalog_name(&record.name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not an image name",
            ));
        }
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(format!("{}.json", record.name));
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        self.records
            .lock()
            .unwrap()
            .insert(record.name.clone(), record);
        Ok(())
    }

    pub fn remove(&self, name: &str) -> std::io::Result<()> {
        if !is_catalog_name(name) {
            return Ok(());
        }
        match std::fs::remove_file(self.dir.join(format!("{name}.json"))) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.records.lock().unwrap().remove(name);
        Ok(())
    }

    fn update(
        &self,
        name: &str,
        f: impl FnOnce(&mut ImageRecord),
    ) -> std::io::Result<Option<ImageRecord>> {
        let Some(mut r) = self.get(name) else {
            return Ok(None);
        };
        f(&mut r);
        self.put(r.clone())?;
        Ok(Some(r))
    }
}

// ---- references -------------------------------------------------------------

/// Why an image is held.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reference {
    Deployment {
        id: String,
    },
    Rollout {
        deployment: String,
        operation: String,
    },
    Sandbox {
        id: String,
    },
    Job {
        deployment: String,
        job: String,
    },
    Pinned,
    /// The current digest of an `APP_LB_IMAGE_WARM` entry.
    Warm {
        #[serde(rename = "ref")]
        artifact_ref: String,
    },
}

/// The catalog name a sandbox listing's `image` field names: heyvm reports
/// either the name or the path of the `.ext4` it was created from.
fn image_name_of(reported: &str) -> Option<String> {
    let base = reported.rsplit('/').next().unwrap_or(reported);
    let base = base.strip_suffix(".ext4").unwrap_or(base);
    is_catalog_name(base).then(|| base.to_string())
}

fn spec_image(spec: &crate::config::DeploymentSpec) -> Option<&str> {
    spec.vm.as_ref().and_then(|vm| vm.image.as_deref())
}

/// Everything that holds an image, by image name. Pure.
pub fn references<'a>(
    deployments: impl IntoIterator<Item = &'a Arc<Deployment>>,
    sandboxes: impl IntoIterator<Item = (&'a str, &'a str)>,
    jobs: &[JobRecord],
    pinned: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, Vec<Reference>> {
    let mut out: BTreeMap<String, Vec<Reference>> = BTreeMap::new();
    let mut add = |image: &str, r: Reference| {
        if let Some(name) = image_name_of(image) {
            let refs = out.entry(name).or_default();
            if !refs.contains(&r) {
                refs.push(r);
            }
        }
    };
    for d in deployments {
        if let Some(image) = spec_image(&d.spec) {
            add(
                image,
                Reference::Deployment {
                    id: d.spec.id.clone(),
                },
            );
        }
        for op in &d.state().rollouts {
            for spec in std::iter::once(&op.spec).chain(op.prepared.as_ref()) {
                if let Some(image) = spec_image(spec) {
                    add(
                        image,
                        Reference::Rollout {
                            deployment: d.spec.id.clone(),
                            operation: op.operation_id.clone(),
                        },
                    );
                }
            }
        }
    }
    for (id, image) in sandboxes {
        add(image, Reference::Sandbox { id: id.to_string() });
    }
    for j in jobs.iter().filter(|j| j.status == JobStatus::Running) {
        if let Some(image) = &j.image {
            add(
                image,
                Reference::Job {
                    deployment: j.deployment.clone(),
                    job: j.id.clone(),
                },
            );
        }
    }
    for name in pinned {
        add(name, Reference::Pinned);
    }
    out
}

// ---- the decision -----------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub now: u64,
    pub idle_secs: u64,
    pub min_age_secs: u64,
    /// Over the pressure watermark: idle age no longer protects an image.
    pub pressure: bool,
    /// Whether a built image has somewhere to go.
    pub offload_store: bool,
    /// Unreferenced pulled images are over `APP_LB_IMAGE_CACHE_BUDGET_GB`.
    pub cache_over_budget: bool,
}

/// Why `record` may not be offloaded right now, or `Ok` if it may. Pure.
pub fn eligibility(
    record: &ImageRecord,
    present: bool,
    refs: &[Reference],
    p: &Policy,
) -> Result<(), String> {
    if !present {
        return Err("not in heyvm's catalog".into());
    }
    if !refs.is_empty() {
        return Err(format!("in use by {} reference(s)", refs.len()));
    }
    if record.pinned {
        return Err("pinned".into());
    }
    match record.source {
        ImageSource::Unknown => {
            return Err("app-lb did not make this image, so it never removes it".into());
        }
        ImageSource::Pull if record.digest.is_none() || record.store.is_none() => {
            return Err("no recorded store to verify against".into());
        }
        ImageSource::Build if !p.offload_store => {
            return Err(
                "a built image exists nowhere else; set APP_LB_IMAGE_OFFLOAD_STORE to offload it"
                    .into(),
            );
        }
        _ => {}
    }
    if p.now.saturating_sub(record.first_seen) < p.min_age_secs {
        return Err("first seen too recently".into());
    }
    if p.now < record.next_attempt_at {
        return Err(format!("backing off after {} failure(s)", record.failures));
    }
    // A pulled image is the cache: removing it saves only disk, and the next
    // VM that wants it pays a full fetch. So idle age alone never removes
    // one; pressure or the cache budget does, least recently used first.
    if record.source == ImageSource::Pull {
        if p.pressure || p.cache_over_budget {
            return Ok(());
        }
        return Err("kept as cache until the disk is under pressure or the cache is over budget".into());
    }
    if !p.pressure && p.now.saturating_sub(record.last_used) < p.idle_secs {
        return Err("used recently".into());
    }
    Ok(())
}

/// The offload candidates, least recently used first, largest first among
/// equals. Pure, so the order a pass works in is testable without a daemon.
pub fn pick_offload(
    records: &[ImageRecord],
    present: &HashSet<String>,
    refs: &BTreeMap<String, Vec<Reference>>,
    p: &Policy,
) -> Vec<String> {
    let none = Vec::new();
    let mut eligible: Vec<&ImageRecord> = records
        .iter()
        .filter(|r| {
            eligibility(
                r,
                present.contains(&r.name),
                refs.get(&r.name).unwrap_or(&none),
                p,
            )
            .is_ok()
        })
        .collect();
    eligible.sort_by(|a, b| a.last_used.cmp(&b.last_used).then(b.bytes.cmp(&a.bytes)));
    eligible.into_iter().map(|r| r.name.clone()).collect()
}

// ---- views ------------------------------------------------------------------

/// One image as `GET /images` shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ImageView {
    #[serde(flatten)]
    pub record: ImageRecord,
    pub present: bool,
    pub references: Vec<Reference>,
    /// Why the pacer would leave it alone; absent when it would offload it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kept_because: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryView {
    pub generated_at: u64,
    /// False when heyvm or its sandbox listing could not be read: the
    /// references are then unknown, and nothing is offloaded or deleted.
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether heyvm has an image-delete route; `null` until one was tried.
    pub delete_supported: Option<bool>,
    pub offload: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_used_pct: Option<f64>,
    pub pressure_pct: u8,
    /// Bytes of unreferenced pulled images: the cache. `None` when the
    /// references could not be read.
    pub cache_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_budget_bytes: Option<u64>,
    /// Pulls since app-lb started that found their image already on heyvm,
    /// and those that fetched it.
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub local_bytes: u64,
    pub images: Vec<ImageView>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WarmReport {
    pub warmed: Vec<WarmOutcome>,
    /// `(entry, why)`.
    pub failed: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WarmOutcome {
    pub entry: String,
    pub image: String,
    /// Whether this pass fetched it, rather than finding it on heyvm.
    pub fetched: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    pub pressure: bool,
    pub offloaded: Vec<String>,
    pub failed: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum ImageError {
    NotFound(String),
    InUse(String, Vec<Reference>, Vec<String>),
    NotEligible(String, String),
    Unclassifiable(String),
    Unverified(String, String),
    Unsupported,
    Failed(String),
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "no image {n:?}"),
            Self::InUse(n, refs, sandboxes) if !refs.is_empty() => {
                let what: Vec<String> = refs.iter().map(describe).collect();
                write!(f, "image {n:?} is in use: {}", what.join(", "))
            }
            Self::InUse(n, _, sandboxes) => {
                write!(
                    f,
                    "heyvm says image {n:?} is in use by {}",
                    sandboxes.join(", ")
                )
            }
            Self::NotEligible(n, why) => write!(f, "image {n:?} cannot be offloaded: {why}"),
            Self::Unclassifiable(why) => write!(
                f,
                "what references images cannot be determined ({why}); nothing is removed until it can"
            ),
            Self::Unverified(n, why) => write!(
                f,
                "image {n:?} was kept: its remote copy did not verify ({why})"
            ),
            Self::Unsupported => write!(
                f,
                "this heyvm has no DELETE /images route; upgrade heyvm to remove images"
            ),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

fn describe(r: &Reference) -> String {
    match r {
        Reference::Deployment { id } => format!("deployment {id}"),
        Reference::Rollout {
            deployment,
            operation,
        } => format!("rollout {operation} of {deployment}"),
        Reference::Sandbox { id } => format!("sandbox {id}"),
        Reference::Job { deployment, job } => format!("job {job} of {deployment}"),
        Reference::Pinned => "an operator pin".into(),
        Reference::Warm { artifact_ref } => format!("the warm set ({artifact_ref})"),
    }
}

// ---- the catalog --------------------------------------------------------------

struct Snapshot {
    present: HashMap<String, u64>,
    refs: BTreeMap<String, Vec<Reference>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ThawState {
    attempts: u32,
    next_at: u64,
}

pub struct ImageCatalog {
    cfg: ImagesConfig,
    store: ImageStore,
    vms: VmManager,
    registry: Arc<Registry>,
    secrets: Arc<SecretStore>,
    puller: Puller,
    jobs: OnceLock<Weak<Jobs>>,
    delete_supported: Mutex<Option<bool>>,
    /// One offload, delete or thaw changes the catalog at a time.
    busy: tokio::sync::Mutex<()>,
    present_cache: Mutex<HashMap<String, Instant>>,
    thaws: Mutex<HashMap<String, ThawState>>,
    thawing: Mutex<HashSet<String>>,
    cache_hits: std::sync::atomic::AtomicU64,
    cache_misses: std::sync::atomic::AtomicU64,
    /// Warm-set label → the image its reference last resolved to.
    warm: Mutex<BTreeMap<String, String>>,
}

impl ImageCatalog {
    pub fn new(
        cfg: ImagesConfig,
        store: ImageStore,
        vms: VmManager,
        registry: Arc<Registry>,
        secrets: Arc<SecretStore>,
        puller: Puller,
    ) -> Arc<Self> {
        let catalog = Arc::new(Self {
            cfg,
            store,
            vms,
            registry,
            secrets,
            puller,
            jobs: OnceLock::new(),
            delete_supported: Mutex::new(None),
            busy: tokio::sync::Mutex::new(()),
            present_cache: Mutex::new(HashMap::new()),
            thaws: Mutex::new(HashMap::new()),
            thawing: Mutex::new(HashSet::new()),
            cache_hits: Default::default(),
            cache_misses: Default::default(),
            warm: Mutex::new(BTreeMap::new()),
        });
        catalog.recall_from_records();
        catalog
    }

    /// What the records already say, so a restart holds the warm set and
    /// can fall back on known digests before the first warm pass or pull.
    fn recall_from_records(&self) {
        let mut records = self.store.all();
        records.retain(|r| r.source == ImageSource::Pull && r.tier == Tier::Local);
        // Oldest first, so the newest pull of a reference is the one kept.
        records.sort_by_key(|r| r.first_seen);
        let mut warm = self.warm.lock().unwrap();
        for r in &records {
            if let (Some(store), Some(reference), Some(digest)) = (&r.store, &r.artifact_ref, &r.digest) {
                crate::artifact::remember_resolution(store, reference, digest, r.bytes);
            }
            for entry in self.cfg.warm.iter().filter(|e| e.holds(r)) {
                warm.insert(entry.label(), r.name.clone());
            }
        }
    }

    /// Pull every warm-set entry that is not on heyvm yet, and hold the
    /// image each one currently resolves to. A tag that moved releases its
    /// old image to the cache; an entry that fails keeps what it held.
    pub async fn warm(&self) -> WarmReport {
        let mut report = WarmReport::default();
        for entry in &self.cfg.warm {
            let label = entry.label();
            let spec = ArtifactSpec {
                store: entry.store.clone(),
                artifact_ref: entry.artifact_ref.clone(),
                auth: None,
                grow_gb: None,
                image_name: None,
                strip_components: None,
            };
            let mut log = |line: String| tracing::debug!(entry = %label, "warm: {line}");
            match self.puller.pull("warm", &spec, None, false, &mut log).await {
                Ok(pulled) => {
                    self.note_pulled(&pulled.image, &pulled.digest, &spec, pulled.size, pulled.reused);
                    let before = self.warm.lock().unwrap().insert(label.clone(), pulled.image.clone());
                    if before.as_deref() != Some(pulled.image.as_str()) {
                        tracing::info!(entry = %label, image = %pulled.image, previous = ?before, fetched = !pulled.reused, "warm set holds a new image");
                    }
                    report.warmed.push(WarmOutcome { entry: label, image: pulled.image, fetched: !pulled.reused });
                }
                Err(e) => {
                    tracing::warn!(entry = %label, error = %e, "could not warm an image; keeping what the entry held");
                    report.failed.push((label, e));
                }
            }
        }
        report
    }

    fn warm_images(&self) -> Vec<(String, String)> {
        self.warm
            .lock()
            .unwrap()
            .iter()
            .map(|(label, image)| (image.clone(), label.clone()))
            .collect()
    }

    pub fn config(&self) -> &ImagesConfig {
        &self.cfg
    }

    pub fn store(&self) -> &ImageStore {
        &self.store
    }

    /// The job runner, for references from running jobs and for starting a
    /// pull on thaw. Set once both exist; they hold each other.
    pub fn set_jobs(&self, jobs: &Arc<Jobs>) {
        let _ = self.jobs.set(Arc::downgrade(jobs));
    }

    fn jobs(&self) -> Option<Arc<Jobs>> {
        self.jobs.get().and_then(Weak::upgrade)
    }

    /// A pull put `image` in the catalog from `spec.store`.
    pub fn note_pulled(&self, image: &str, digest: &str, spec: &ArtifactSpec, bytes: u64, reused: bool) {
        let counter = if reused { &self.cache_hits } else { &self.cache_misses };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = now_secs();
        let mut r = self
            .store
            .get(image)
            .unwrap_or_else(|| ImageRecord::new(image, now));
        r.source = ImageSource::Pull;
        r.tier = Tier::Local;
        r.digest = Some(digest.to_string());
        r.store = Some(spec.store.trim().to_string());
        r.artifact_ref = Some(spec.artifact_ref.clone());
        r.auth = spec.auth.clone();
        r.grow_gb = spec.grow_gb;
        r.bytes = bytes;
        r.last_used = now;
        r.failures = 0;
        r.next_attempt_at = 0;
        r.last_error = None;
        if let Err(e) = self.store.put(r) {
            tracing::warn!(image, error = %e, "could not record a pulled image");
        }
        self.present_cache
            .lock()
            .unwrap()
            .insert(image.to_string(), Instant::now());
    }

    /// A build put `image` in the catalog.
    pub fn note_built(&self, image: &str, bytes: u64) {
        let now = now_secs();
        let mut r = self
            .store
            .get(image)
            .unwrap_or_else(|| ImageRecord::new(image, now));
        r.source = ImageSource::Build;
        r.tier = Tier::Local;
        r.bytes = bytes;
        r.last_used = now;
        if let Err(e) = self.store.put(r) {
            tracing::warn!(image, error = %e, "could not record a built image");
        }
        self.present_cache
            .lock()
            .unwrap()
            .insert(image.to_string(), Instant::now());
    }

    fn pinned_names(&self) -> Vec<String> {
        self.store
            .all()
            .into_iter()
            .filter(|r| r.pinned)
            .map(|r| r.name)
            .collect()
    }

    /// The catalog and everything that references it, merged into the
    /// records: an image seen for the first time is recorded (as `unknown`
    /// unless a job said otherwise), a present image is `local`, a referenced
    /// one is marked used.
    async fn snapshot(&self) -> Result<Snapshot, String> {
        let images = self
            .vms
            .list_images()
            .await
            .map_err(|e| format!("heyvm's image list: {e}"))?;
        let live = self
            .vms
            .list()
            .await
            .map_err(|e| format!("heyvm's sandbox list: {e}"))?;
        let inactive = self
            .vms
            .list_inactive()
            .await
            .map_err(|e| format!("heyvm's inactive sandbox list: {e}"))?;
        if self.registry.require_complete_load().is_err() {
            return Err("the deployment registry did not load completely".into());
        }
        let jobs = self.jobs().map(|j| j.records(None)).unwrap_or_default();
        let deployments = self.registry.deployments();
        let pinned = self.pinned_names();
        let mut refs = references(
            deployments.values(),
            live.iter()
                .chain(inactive.iter())
                .map(|s| (s.id.as_str(), s.image.as_str())),
            &jobs,
            pinned.iter().map(String::as_str),
        );
        for (image, label) in self.warm_images() {
            refs.entry(image).or_default().push(Reference::Warm { artifact_ref: label });
        }

        let now = now_secs();
        let present: HashMap<String, u64> = images
            .into_iter()
            .filter(|i| is_catalog_name(&i.name))
            .map(|i| (i.name, i.size_bytes))
            .collect();
        for (name, bytes) in &present {
            let existing = self.store.get(name);
            let mut r = existing
                .clone()
                .unwrap_or_else(|| ImageRecord::new(name, now));
            r.bytes = *bytes;
            r.tier = Tier::Local;
            if refs.contains_key(name) {
                r.last_used = now;
            }
            // Persist only what changed meaningfully: `last_used` moves every
            // pass for a referenced image, and a write per image per pass is
            // churn nobody reads.
            let changed = match &existing {
                None => true,
                Some(old) => {
                    old.tier != r.tier
                        || old.bytes != r.bytes
                        || r.last_used.saturating_sub(old.last_used) >= 3600
                }
            };
            if changed && let Err(e) = self.store.put(r) {
                tracing::warn!(image = %name, error = %e, "could not record an image");
            }
        }
        Ok(Snapshot { present, refs })
    }

    async fn disk_used_pct(&self) -> Option<f64> {
        let s = self.vms.storage().await.ok()?;
        (s.total_bytes > 0).then(|| 100.0 * (1.0 - s.free_bytes as f64 / s.total_bytes as f64))
    }

    fn policy(&self, pressure: bool) -> Policy {
        Policy {
            now: now_secs(),
            idle_secs: self.cfg.idle_secs,
            min_age_secs: MIN_AGE_SECS,
            pressure,
            offload_store: self.cfg.offload_store.is_some(),
            cache_over_budget: false,
        }
    }

    /// Bytes of pulled images on heyvm that nothing references or pins:
    /// what the cache budget is measured against.
    fn cache_bytes(&self, snapshot: &Snapshot) -> u64 {
        self.store
            .all()
            .iter()
            .filter(|r| r.source == ImageSource::Pull && !r.pinned)
            .filter(|r| !snapshot.refs.contains_key(&r.name))
            .filter_map(|r| snapshot.present.get(&r.name))
            .sum()
    }

    fn over_budget(&self, cache_bytes: u64) -> bool {
        self.cfg.cache_budget_bytes.is_some_and(|b| cache_bytes > b)
    }

    /// `GET /images`.
    pub async fn inventory(&self) -> InventoryView {
        let disk = self.disk_used_pct().await;
        let pressure = disk.is_some_and(|d| d >= f64::from(self.cfg.pressure_pct));
        let (snapshot, error) = match self.snapshot().await {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(e)),
        };
        let cache_bytes = snapshot.as_ref().map(|s| self.cache_bytes(s));
        let mut policy = self.policy(pressure);
        policy.cache_over_budget = cache_bytes.is_some_and(|b| self.over_budget(b));
        let mut images: Vec<ImageView> = self
            .store
            .all()
            .into_iter()
            .map(|record| {
                let (present, refs) = match &snapshot {
                    Some(s) => (
                        s.present.contains_key(&record.name),
                        s.refs.get(&record.name).cloned().unwrap_or_default(),
                    ),
                    None => (record.tier == Tier::Local, Vec::new()),
                };
                let kept_because = match &snapshot {
                    None => Some("references unknown".to_string()),
                    Some(_) => eligibility(&record, present, refs.as_slice(), &policy).err(),
                };
                ImageView {
                    present,
                    references: refs,
                    kept_because,
                    record,
                }
            })
            .collect();
        images.sort_by_key(|i| std::cmp::Reverse(i.record.bytes));
        InventoryView {
            generated_at: now_secs(),
            complete: snapshot.is_some(),
            error,
            delete_supported: *self.delete_supported.lock().unwrap(),
            offload: self.cfg.offload,
            disk_used_pct: disk.map(|d| (d * 10.0).round() / 10.0),
            pressure_pct: self.cfg.pressure_pct,
            cache_bytes,
            cache_budget_bytes: self.cfg.cache_budget_bytes,
            cache_hits: self.cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            cache_misses: self.cache_misses.load(std::sync::atomic::Ordering::Relaxed),
            local_bytes: images
                .iter()
                .filter(|i| i.present)
                .map(|i| i.record.bytes)
                .sum(),
            images,
        }
    }

    /// Whether any pool is booting. The pacer stands down while one is: an
    /// offload competes for the same disk as a rootfs copy.
    fn booting(&self) -> bool {
        self.registry
            .deployments()
            .values()
            .any(|d| !d.pending().is_empty())
    }

    /// One pass of the pacer, or `POST /images/sweep`.
    pub async fn sweep(&self) -> SweepReport {
        let disk = self.disk_used_pct().await;
        let pressure = disk.is_some_and(|d| d >= f64::from(self.cfg.pressure_pct));
        let mut report = SweepReport {
            pressure,
            ..Default::default()
        };
        if !pressure && self.booting() {
            report.skipped = Some("a pool is booting".into());
            return report;
        }
        if *self.delete_supported.lock().unwrap() == Some(false) {
            report.skipped = Some(ImageError::Unsupported.to_string());
            return report;
        }
        let snapshot = match self.snapshot().await {
            Ok(s) => s,
            Err(e) => {
                report.skipped = Some(ImageError::Unclassifiable(e).to_string());
                return report;
            }
        };
        let present: HashSet<String> = snapshot.present.keys().cloned().collect();
        let mut cache_bytes = self.cache_bytes(&snapshot);
        let mut policy = self.policy(pressure);
        policy.cache_over_budget = self.over_budget(cache_bytes);
        let records = self.store.all();
        let picks = pick_offload(&records, &present, &snapshot.refs, &policy);
        let mut routine = 0;
        for name in picks {
            let pulled = records.iter().any(|r| r.name == name && r.source == ImageSource::Pull);
            // Below pressure a pulled image goes only to bring the cache
            // back under budget, and that is not rationed per pass.
            if !pressure && pulled && !self.over_budget(cache_bytes) {
                continue;
            }
            if !pressure && !pulled && routine >= ROUTINE_PER_PASS {
                continue;
            }
            if pressure
                && let Some(d) = self.disk_used_pct().await
                && d < f64::from(self.cfg.pressure_pct).max(5.0) - 5.0
            {
                break;
            }
            match self.offload(&name, false).await {
                Ok(()) => {
                    if pulled {
                        cache_bytes = cache_bytes.saturating_sub(snapshot.present.get(&name).copied().unwrap_or(0));
                    } else {
                        routine += 1;
                    }
                    report.offloaded.push(name)
                }
                Err(ImageError::Unsupported) => {
                    report
                        .failed
                        .push((name, ImageError::Unsupported.to_string()));
                    break;
                }
                Err(e) => report.failed.push((name, e.to_string())),
            }
        }
        if !report.offloaded.is_empty() || !report.failed.is_empty() {
            tracing::info!(
                offloaded = ?report.offloaded,
                failed = report.failed.len(),
                pressure,
                "image offload pass",
            );
        }
        report
    }

    /// Offload one image: verify its remote copy, record it as offloaded,
    /// then delete it from heyvm. `explicit` is an operator asking for this
    /// image, which skips the idle age and nothing else.
    pub async fn offload(&self, name: &str, explicit: bool) -> Result<(), ImageError> {
        let _held = self.busy.lock().await;
        let snapshot = self.snapshot().await.map_err(ImageError::Unclassifiable)?;
        let Some(record) = self.store.get(name) else {
            return Err(ImageError::NotFound(name.into()));
        };
        let refs = snapshot.refs.get(name).cloned().unwrap_or_default();
        if !refs.is_empty() {
            return Err(ImageError::InUse(name.into(), refs, Vec::new()));
        }
        let mut policy = self.policy(true);
        if !explicit {
            policy.pressure = self
                .disk_used_pct()
                .await
                .is_some_and(|d| d >= f64::from(self.cfg.pressure_pct));
            policy.cache_over_budget = self.over_budget(self.cache_bytes(&snapshot));
        }
        if explicit {
            policy.min_age_secs = 0;
            policy.now = policy.now.max(record.next_attempt_at);
        }
        eligibility(&record, snapshot.present.contains_key(name), &[], &policy)
            .map_err(|why| ImageError::NotEligible(name.into(), why))?;

        // 1. A verified copy elsewhere.
        let copy = match self.verify_remote(&record).await {
            Ok(copy) => copy,
            Err(why) => {
                let _ = self.store.update(name, |r| r.fail(why.clone(), now_secs()));
                return Err(ImageError::Unverified(name.into(), why));
            }
        };
        // 2. The record says so, durably, before anything is deleted.
        let before = record.clone();
        let now = now_secs();
        self.store
            .update(name, |r| {
                r.tier = Tier::Offloaded;
                r.digest = Some(copy.digest.clone());
                r.store = Some(copy.store.clone());
                if copy.auth.is_some() {
                    r.auth = copy.auth.clone();
                }
                r.offloaded_to = Some(copy.location.clone());
                r.offloaded_at = Some(now);
                r.failures = 0;
                r.next_attempt_at = 0;
                r.last_error = None;
            })
            .map_err(|e| ImageError::Failed(format!("could not record the offload: {e}")))?;
        // 3. Only now, the delete.
        match self.delete_on_daemon(name).await {
            Ok(()) => {
                tracing::info!(image = name, to = %copy.location, bytes = record.bytes, "image offloaded");
                Ok(())
            }
            Err(e) => {
                let _ = self.store.put(ImageRecord {
                    last_error: Some(e.to_string()),
                    ..before
                });
                if !matches!(e, ImageError::Unsupported) {
                    let _ = self
                        .store
                        .update(name, |r| r.fail(e.to_string(), now_secs()));
                }
                Err(e)
            }
        }
    }

    async fn delete_on_daemon(&self, name: &str) -> Result<(), ImageError> {
        match self.vms.delete_image(name, true).await {
            Ok(ImageDelete::Deleted | ImageDelete::Missing) => {
                *self.delete_supported.lock().unwrap() = Some(true);
                self.present_cache.lock().unwrap().remove(name);
                Ok(())
            }
            Ok(ImageDelete::InUse(sandboxes)) => {
                *self.delete_supported.lock().unwrap() = Some(true);
                Err(ImageError::InUse(name.into(), Vec::new(), sandboxes))
            }
            Ok(ImageDelete::Unsupported) => {
                if self.delete_supported.lock().unwrap().replace(false) != Some(false) {
                    tracing::warn!(
                        "heyvm has no DELETE /images route; images are inventoried but not \
                         removed until heyvm is upgraded"
                    );
                }
                Err(ImageError::Unsupported)
            }
            Err(e) => Err(ImageError::Failed(format!("heyvm: {e}"))),
        }
    }

    /// `DELETE /images/:name`: remove an unreferenced image outright. An
    /// operator act, so no idle age and no remote copy is required — but a
    /// reference still refuses it, and so does not knowing the references.
    pub async fn delete(&self, name: &str) -> Result<(), ImageError> {
        let _held = self.busy.lock().await;
        let snapshot = self.snapshot().await.map_err(ImageError::Unclassifiable)?;
        let refs = snapshot.refs.get(name).cloned().unwrap_or_default();
        if !refs.is_empty() {
            return Err(ImageError::InUse(name.into(), refs, Vec::new()));
        }
        if !snapshot.present.contains_key(name) && self.store.get(name).is_none() {
            return Err(ImageError::NotFound(name.into()));
        }
        if snapshot.present.contains_key(name) {
            self.delete_on_daemon(name).await?;
        }
        self.store
            .remove(name)
            .map_err(|e| ImageError::Failed(format!("could not remove the record: {e}")))?;
        tracing::info!(image = name, "image deleted");
        Ok(())
    }

    /// `PATCH /images/:name {pinned}`.
    pub fn set_pinned(&self, name: &str, pinned: bool) -> Result<ImageRecord, ImageError> {
        self.store
            .update(name, |r| r.pinned = pinned)
            .map_err(|e| ImageError::Failed(e.to_string()))?
            .ok_or_else(|| ImageError::NotFound(name.into()))
    }

    async fn store_key(&self, auth: Option<&SecretRef>) -> Result<Option<String>, String> {
        match auth {
            None => Ok(None),
            Some(r) => self
                .secrets
                .resolve(r)
                .map(Some)
                .map_err(|e| format!("cannot resolve the store's API key: {e}")),
        }
    }

    /// The copy an offload leaves behind, proven to exist.
    async fn verify_remote(&self, record: &ImageRecord) -> Result<RemoteCopy, String> {
        match record.source {
            ImageSource::Pull => {
                let (Some(store), Some(digest)) = (&record.store, &record.digest) else {
                    return Err("no recorded store".into());
                };
                let key = self.store_key(record.auth.as_ref()).await?;
                // The catalog file is the grown image; the blob is not, so
                // only an ungrown image's size says anything about the blob.
                let size = record
                    .grow_gb
                    .is_none()
                    .then_some(record.bytes)
                    .filter(|b| *b > 0);
                self.puller
                    .verify_blob(store, digest, key.as_deref(), size)
                    .await?;
                Ok(RemoteCopy {
                    location: format!("{store}#{digest}"),
                    store: store.clone(),
                    digest: digest.clone(),
                    auth: None,
                })
            }
            ImageSource::Build => {
                let Some(store) = &self.cfg.offload_store else {
                    return Err("APP_LB_IMAGE_OFFLOAD_STORE is not set".into());
                };
                let info = self
                    .vms
                    .image(&record.name)
                    .await
                    .map_err(|e| format!("heyvm: {e}"))?
                    .ok_or("heyvm no longer has it")?;
                let key = self.store_key(self.cfg.offload_store_key.as_ref()).await?;
                let tag = offload_tag(&record.name);
                let (digest, _) = self
                    .puller
                    .push_image(store, Path::new(&info.path), &tag, key.as_deref())
                    .await?;
                // The store's own answer is the proof, not ours.
                self.puller
                    .verify_blob(store, &digest, key.as_deref(), None)
                    .await?;
                Ok(RemoteCopy {
                    location: format!("{store}#{digest} ({tag})"),
                    store: store.clone(),
                    digest,
                    auth: self.cfg.offload_store_key.clone(),
                })
            }
            ImageSource::Unknown => Err("unknown source".into()),
        }
    }

    /// Pull an offloaded image back under its own name.
    pub async fn thaw(&self, name: &str) -> Result<(), String> {
        let _held = self.busy.lock().await;
        let record = self
            .store
            .get(name)
            .ok_or_else(|| format!("no record of image {name:?}"))?;
        let (Some(store), Some(digest)) = (record.store.clone(), record.digest.clone()) else {
            return Err(format!("image {name:?} has no recorded copy to thaw from"));
        };
        let key = self.store_key(record.auth.as_ref()).await?;
        let spec = ArtifactSpec {
            store,
            artifact_ref: digest.clone(),
            auth: record.auth.clone(),
            grow_gb: record.grow_gb,
            image_name: None,
            strip_components: None,
        };
        let mut log = |line: String| tracing::info!(image = name, "thaw: {line}");
        let pulled = self
            .puller
            .pull_as(name, &spec, key.as_deref(), &mut log)
            .await?;
        self.store
            .update(name, |r| {
                r.tier = Tier::Local;
                r.bytes = pulled.size;
                r.last_used = now_secs();
                r.offloaded_at = None;
            })
            .map_err(|e| e.to_string())?;
        self.present_cache
            .lock()
            .unwrap()
            .insert(name.to_string(), Instant::now());
        tracing::info!(image = name, digest, "image thawed");
        Ok(())
    }

    async fn present(&self, name: &str) -> Result<bool, String> {
        if self
            .present_cache
            .lock()
            .unwrap()
            .get(name)
            .is_some_and(|t| t.elapsed() < PRESENT_TTL)
        {
            return Ok(true);
        }
        let found = self
            .vms
            .image(name)
            .await
            .map_err(|e| e.to_string())?
            .is_some();
        if found {
            self.present_cache
                .lock()
                .unwrap()
                .insert(name.to_string(), Instant::now());
        }
        Ok(found)
    }

    /// Before a VM is created for `d`: whether its image is on heyvm. When it
    /// is not and app-lb can get it — the deployment's artifact, or a copy
    /// this module offloaded — that is started and `false` is answered, so
    /// the create waits for the image instead of booting heyvm's default.
    /// Anything this cannot decide answers `true` and leaves it to the create.
    pub async fn ensure_image(self: &Arc<Self>, d: &Arc<Deployment>) -> bool {
        let Some(vm) = d.spec.vm.as_ref() else {
            return true;
        };
        if vm.driver.heyvm().is_none() {
            return true;
        }
        let id = d.spec.id.clone();
        let image = vm.image.clone();
        let has_artifact = d.spec.artifact.is_some();
        match &image {
            Some(name) => match self.present(name).await {
                Ok(true) => {
                    self.thaws.lock().unwrap().remove(&id);
                    return true;
                }
                Ok(false) => {}
                // heyvm unreachable: the create will say so, on its own path.
                Err(_) => return true,
            },
            // No image at all: heyvm's default, unless the spec means to pull.
            None if !has_artifact => return true,
            None => {}
        }

        let now = now_secs();
        {
            let mut thaws = self.thaws.lock().unwrap();
            let state = thaws.entry(id.clone()).or_default();
            if now < state.next_at {
                return false;
            }
            state.attempts = state.attempts.saturating_add(1);
            state.next_at = now + (30u64 << (state.attempts - 1).min(6)).min(1800);
        }

        let offloaded = image
            .as_deref()
            .and_then(|n| self.store.get(n))
            .filter(|r| r.tier == Tier::Offloaded && r.digest.is_some() && r.store.is_some());
        if let Some(record) = offloaded {
            let name = record.name.clone();
            if self.thawing.lock().unwrap().insert(name.clone()) {
                tracing::info!(deployment = %id, image = %name, "image is offloaded; pulling it back before creating a VM");
                let me = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = me.thaw(&name).await {
                        tracing::warn!(image = %name, error = %e, "thaw failed");
                    }
                    me.thawing.lock().unwrap().remove(&name);
                });
            }
            return false;
        }
        if has_artifact {
            match self.jobs().map(|j| j.start_pull(&id, None, false)) {
                Some(Ok(job)) => {
                    tracing::info!(
                        deployment = %id,
                        image = ?image,
                        job = %job.id,
                        "image is not on heyvm; pulling it before creating a VM",
                    );
                }
                Some(Err(crate::jobs::StartError::AlreadyRunning(_))) => {}
                Some(Err(e)) => {
                    tracing::warn!(deployment = %id, error = %e, "could not start the pull a VM needs")
                }
                None => return true,
            }
            return false;
        }
        // Missing, not ours to fetch: let the create fail and report it.
        true
    }
}

struct RemoteCopy {
    location: String,
    store: String,
    digest: String,
    auth: Option<SecretRef>,
}

/// The tag an offloaded build is kept under, in a repository of its own so it
/// never collides with anything a person pushed.
pub fn offload_tag(name: &str) -> String {
    let flat: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("app-lb-offload:{flat}")
}

/// Runs [`ImageCatalog::sweep`] every `APP_LB_IMAGE_SWEEP_SECS`.
pub struct ImagePacer {
    catalog: Arc<ImageCatalog>,
}

impl ImagePacer {
    pub fn new(catalog: Arc<ImageCatalog>) -> Self {
        Self { catalog }
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for ImagePacer {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let cfg = self.catalog.config().clone();
        if !cfg.offload || cfg.sweep_secs == 0 {
            tracing::info!("image offload pacer off; the inventory and /images routes still work");
            return;
        }
        let mut wait = FIRST_SWEEP_DELAY;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            let _ = self.catalog.sweep().await;
            wait = Duration::from_secs(cfg.sweep_secs);
        }
    }
}

/// Keeps the warm set on heyvm: once at startup, then every
/// `APP_LB_IMAGE_WARM_SECS`.
pub struct ImageWarmer {
    catalog: Arc<ImageCatalog>,
}

impl ImageWarmer {
    pub fn new(catalog: Arc<ImageCatalog>) -> Self {
        Self { catalog }
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for ImageWarmer {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let cfg = self.catalog.config().clone();
        if cfg.warm.is_empty() {
            return;
        }
        tracing::info!(entries = ?cfg.warm.iter().map(WarmEntry::label).collect::<Vec<_>>(), "warming images");
        loop {
            let report = self.catalog.warm().await;
            tracing::info!(
                warmed = report.warmed.len(),
                fetched = report.warmed.iter().filter(|w| w.fetched).count(),
                failed = report.failed.len(),
                "warm pass",
            );
            if cfg.warm_secs == 0 {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(cfg.warm_secs)) => {}
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, source: ImageSource) -> ImageRecord {
        ImageRecord {
            name: name.into(),
            source,
            digest: Some("ab".repeat(32)),
            store: Some("https://hub.example".into()),
            bytes: 100,
            first_seen: 0,
            last_used: 0,
            ..Default::default()
        }
    }

    fn policy(now: u64) -> Policy {
        Policy {
            now,
            idle_secs: 1000,
            min_age_secs: 600,
            pressure: false,
            offload_store: false,
            cache_over_budget: false,
        }
    }

    #[test]
    fn catalog_names_are_safe_and_never_kernels() {
        assert!(is_catalog_name("img-0123456789abcdef"));
        assert!(is_catalog_name("web-cb5f2d273ff3"));
        for bad in [
            "",
            ".hidden",
            "vmlinux.bin",
            "vmlinux",
            "a/b",
            "a b",
            "../x",
            &"x".repeat(129),
        ] {
            assert!(!is_catalog_name(bad), "{bad:?}");
        }
        assert_eq!(
            image_dir("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-images.d")
        );
        assert_eq!(offload_tag("Web_Build-1"), "app-lb-offload:web_build-1");
    }

    #[test]
    fn eligibility_keeps_anything_referenced_pinned_unknown_new_or_recent() {
        // A build with somewhere to go: the image idle age still governs.
        let p = Policy {
            offload_store: true,
            ..policy(10_000)
        };
        let ok = rec("a", ImageSource::Build);
        assert_eq!(eligibility(&ok, true, &[], &p), Ok(()));
        assert!(eligibility(&ok, false, &[], &p).is_err(), "not present");
        assert!(
            eligibility(&ok, true, &[Reference::Pinned], &p).is_err(),
            "referenced"
        );
        assert!(
            eligibility(
                &ImageRecord {
                    pinned: true,
                    ..ok.clone()
                },
                true,
                &[],
                &p
            )
            .is_err()
        );
        assert!(
            eligibility(&rec("u", ImageSource::Unknown), true, &[], &p).is_err(),
            "unknown source"
        );
        assert!(
            eligibility(
                &ImageRecord {
                    digest: None,
                    ..rec("a", ImageSource::Pull)
                },
                true,
                &[],
                &Policy {
                    pressure: true,
                    ..p
                }
            )
            .is_err(),
            "pull without digest"
        );
        assert!(
            eligibility(&rec("b", ImageSource::Build), true, &[], &policy(10_000)).is_err(),
            "build with nowhere to go"
        );
        assert_eq!(
            eligibility(
                &rec("b", ImageSource::Build),
                true,
                &[],
                &Policy {
                    offload_store: true,
                    ..p
                }
            ),
            Ok(())
        );
        assert!(
            eligibility(
                &ImageRecord {
                    first_seen: 9_900,
                    last_used: 0,
                    ..ok.clone()
                },
                true,
                &[],
                &p
            )
            .is_err(),
            "too new"
        );
        assert!(
            eligibility(
                &ImageRecord {
                    last_used: 9_500,
                    ..ok.clone()
                },
                true,
                &[],
                &p
            )
            .is_err(),
            "recent"
        );
        assert_eq!(
            eligibility(
                &ImageRecord {
                    last_used: 9_500,
                    ..ok.clone()
                },
                true,
                &[],
                &Policy {
                    pressure: true,
                    ..p
                }
            ),
            Ok(()),
            "pressure ignores idle age"
        );
        assert!(
            eligibility(
                &ImageRecord {
                    first_seen: 9_900,
                    ..ok.clone()
                },
                true,
                &[],
                &Policy {
                    pressure: true,
                    ..p
                }
            )
            .is_err(),
            "pressure never ignores the minimum age"
        );
        assert!(
            eligibility(
                &ImageRecord {
                    next_attempt_at: 20_000,
                    ..ok
                },
                true,
                &[],
                &p
            )
            .is_err(),
            "backing off"
        );
    }

    #[test]
    fn a_pulled_image_is_cache_that_only_pressure_or_the_budget_removes() {
        let p = policy(1_000_000);
        let idle = rec("a", ImageSource::Pull);
        let why = eligibility(&idle, true, &[], &p).unwrap_err();
        assert!(why.contains("cache"), "{why}");
        for p in [
            Policy { pressure: true, ..p },
            Policy { cache_over_budget: true, ..p },
        ] {
            assert_eq!(eligibility(&idle, true, &[], &p), Ok(()));
            let recent = ImageRecord { last_used: p.now - 1, ..idle.clone() };
            assert_eq!(eligibility(&recent, true, &[], &p), Ok(()), "LRU order, not idle age, decides");
            let new = ImageRecord { first_seen: p.now - 1, ..idle.clone() };
            assert!(eligibility(&new, true, &[], &p).is_err(), "the minimum age still holds");
            assert!(eligibility(&idle, true, &[Reference::Pinned], &p).is_err(), "references still hold");
        }
    }

    #[test]
    fn picks_least_recently_used_first_then_largest() {
        let p = Policy {
            cache_over_budget: true,
            ..policy(100_000)
        };
        let records = vec![
            ImageRecord {
                last_used: 50,
                bytes: 10,
                ..rec("newer", ImageSource::Pull)
            },
            ImageRecord {
                last_used: 10,
                bytes: 10,
                ..rec("small", ImageSource::Pull)
            },
            ImageRecord {
                last_used: 10,
                bytes: 99,
                ..rec("big", ImageSource::Pull)
            },
            ImageRecord {
                last_used: 1,
                ..rec("held", ImageSource::Pull)
            },
        ];
        let present: HashSet<String> = records.iter().map(|r| r.name.clone()).collect();
        let refs = BTreeMap::from([(
            "held".to_string(),
            vec![Reference::Deployment { id: "web".into() }],
        )]);
        assert_eq!(
            pick_offload(&records, &present, &refs, &p),
            vec!["big", "small", "newer"]
        );
    }

    #[test]
    fn a_failure_backs_off_doubling_to_a_day() {
        let mut r = rec("a", ImageSource::Pull);
        r.fail("x".into(), 0);
        assert_eq!(r.next_attempt_at, 1800);
        r.fail("x".into(), 0);
        assert_eq!(r.next_attempt_at, 3600);
        for _ in 0..10 {
            r.fail("x".into(), 0);
        }
        assert_eq!(r.next_attempt_at, 86_400);
    }

    #[test]
    fn references_cover_deployments_rollouts_sandboxes_jobs_and_pins() {
        let mut spec: crate::config::DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [],
            "vm": {"driver": "firecracker", "port": 8080, "image": "img-aaaaaaaaaaaaaaaa"}
        }))
        .unwrap();
        spec.normalize();
        let d = Arc::new(Deployment::new(spec.clone()));
        let mut candidate = spec.clone();
        candidate.vm.as_mut().unwrap().image = Some("rollout-2-bbbbbbbbbbbb".into());
        d.mutate_state(|s| {
            s.rollouts.push(crate::rollout::Operation {
                operation_id: "op-1".into(),
                deployment: "web".into(),
                source_revision: "r".into(),
                target_spec_sha256: String::new(),
                status: "running".into(),
                phase: "warming".into(),
                readiness_verified: false,
                previous_stopped: false,
                error: None,
                preparation_stage: None,
                spec: spec.clone(),
                prepared: Some(candidate),
                prefix: "p".into(),
                allocations: vec![],
                previous: vec![],
                stopped: vec![],
                deadline: 0,
                drain_deadline: None,
                reclaimed_candidate_ids: vec![],
                failure_settled: false,
            })
        });
        let job: JobRecord = serde_json::from_value(serde_json::json!({
            "id": "job-1", "deployment": "api", "kind": "artifact-pull", "status": "running",
            "started_at": 1, "image": "img-cccccccccccccccc", "log": []
        }))
        .unwrap();
        let done: JobRecord = serde_json::from_value(serde_json::json!({
            "id": "job-0", "deployment": "api", "kind": "artifact-pull", "status": "succeeded",
            "started_at": 1, "image": "img-dddddddddddddddd", "log": []
        }))
        .unwrap();
        let refs = references(
            [&d],
            [
                (
                    "sb-1",
                    "/var/lib/heyvm/images/firecracker/img-eeeeeeeeeeeeeeee.ext4",
                ),
                ("sb-2", ""),
            ],
            &[job, done],
            ["pinned-one"],
        );
        assert_eq!(
            refs["img-aaaaaaaaaaaaaaaa"],
            vec![
                Reference::Deployment { id: "web".into() },
                Reference::Rollout {
                    deployment: "web".into(),
                    operation: "op-1".into()
                },
            ]
        );
        assert_eq!(
            refs["rollout-2-bbbbbbbbbbbb"],
            vec![Reference::Rollout {
                deployment: "web".into(),
                operation: "op-1".into()
            }]
        );
        assert_eq!(
            refs["img-cccccccccccccccc"],
            vec![Reference::Job {
                deployment: "api".into(),
                job: "job-1".into()
            }]
        );
        assert!(
            !refs.contains_key("img-dddddddddddddddd"),
            "a finished job holds nothing"
        );
        assert_eq!(
            refs["img-eeeeeeeeeeeeeeee"],
            vec![Reference::Sandbox { id: "sb-1".into() }]
        );
        assert_eq!(refs["pinned-one"], vec![Reference::Pinned]);
    }

    // ---- against a fake heyvm and a fake art store ----------------------

    use axum::Router;
    use axum::extract::{Path as AxPath, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use std::sync::atomic::{AtomicU16, Ordering};

    const DIGEST: &str = "abababababababababababababababababababababababababababababababab";

    #[derive(Default)]
    struct Fake {
        log: Mutex<Vec<String>>,
        images: Mutex<Vec<String>>,
        blob: AtomicU16,
        delete: AtomicU16,
        /// What every manifest resolves to and `GET /blobs` serves; at most
        /// 100 bytes, the size the fake catalog reports for every image.
        content: Mutex<Vec<u8>>,
    }

    fn content_digest(f: &Fake) -> String {
        crate::artifact::sha256_hex(&f.content.lock().unwrap())
    }

    async fn fake(f: Arc<Fake>) -> String {
        let app = Router::new()
            .route("/images", get(|State(f): State<Arc<Fake>>| async move {
                let names = f.images.lock().unwrap().clone();
                axum::Json(names.iter().map(|n| serde_json::json!({
                    "name": n, "path": format!("/imgs/{n}.ext4"), "size_bytes": 100, "modified_at": 1
                })).collect::<Vec<_>>())
            }))
            .route("/images/:name", get(|State(f): State<Arc<Fake>>, AxPath(n): AxPath<String>| async move {
                if f.images.lock().unwrap().contains(&n) {
                    axum::Json(serde_json::json!({"name": n, "path": "", "size_bytes": 100, "modified_at": 1})).into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }).put(|State(f): State<Arc<Fake>>, AxPath(n): AxPath<String>, _body: axum::body::Bytes| async move {
                f.log.lock().unwrap().push(format!("upload {n}"));
                f.images.lock().unwrap().push(n.clone());
                axum::Json(serde_json::json!({"name": n, "path": format!("/imgs/{n}.ext4"), "size_bytes": 100, "modified_at": 1}))
            }).delete(|State(f): State<Arc<Fake>>, AxPath(n): AxPath<String>| async move {
                f.log.lock().unwrap().push(format!("delete {n}"));
                let status = f.delete.load(Ordering::SeqCst);
                if status == 204 {
                    f.images.lock().unwrap().retain(|i| i != &n);
                }
                let body = if status == 409 { serde_json::json!({"error": "busy", "sandboxes": ["sb-9"]}) } else { serde_json::json!({}) };
                (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
            }))
            .route("/deployed-sandboxes", get(|| async { axum::Json(serde_json::json!([])) }))
            .route("/sandboxes/inactive", get(|| async { axum::Json(serde_json::json!({"sandboxes": [], "next_cursor": null})) }))
            .route("/storage", get(|| async { axum::Json(serde_json::json!({
                "data_dir": "/d", "tmp_dir": "/t", "free_bytes": 90, "total_bytes": 100, "sandboxes": []
            })) }))
            .route("/blobs/:digest", axum::routing::head(|State(f): State<Arc<Fake>>| async move {
                f.log.lock().unwrap().push("verify".into());
                let status = f.blob.load(Ordering::SeqCst);
                (StatusCode::from_u16(status).unwrap(), [(axum::http::header::CONTENT_LENGTH, "100")]).into_response()
            }).get(|State(f): State<Arc<Fake>>| async move {
                f.log.lock().unwrap().push("fetch".into());
                f.content.lock().unwrap().clone()
            }))
            .route("/manifests/*reference", get(|State(f): State<Arc<Fake>>| async move {
                let size = f.content.lock().unwrap().len();
                axum::Json(serde_json::json!({
                    "schema": 1, "kind": "heyvm.rootfs.v1", "annotations": {},
                    "entries": [{"name": "rootfs.ext4", "digest": content_digest(&f), "size": size}]
                }))
            }))
            .with_state(f);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    struct Harness {
        catalog: Arc<ImageCatalog>,
        fake: Arc<Fake>,
        url: String,
        _dir: tempfile::TempDir,
    }

    async fn harness(images: &[&str]) -> Harness {
        // A zero budget: every unreferenced pulled image is over it, so the
        // sweep tests see pulls go as idle builds would.
        harness_with(images, |_| ImagesConfig {
            cache_budget_bytes: Some(0),
            ..ImagesConfig::default()
        })
        .await
    }

    /// `cfg` is handed the fake's URL, so a warm set can point at it.
    async fn harness_with(images: &[&str], cfg: impl FnOnce(&str) -> ImagesConfig) -> Harness {
        let f = Arc::new(Fake::default());
        *f.images.lock().unwrap() = images.iter().map(|s| s.to_string()).collect();
        f.blob.store(200, Ordering::SeqCst);
        f.delete.store(204, Ordering::SeqCst);
        *f.content.lock().unwrap() = b"first".to_vec();
        let url = fake(f.clone()).await;
        let cfg = cfg(&url);
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(Registry::new(dir.path().join("state.json")));
        let mut held: crate::config::DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [],
            "vm": {"driver": "firecracker", "port": 8080, "image": "img-held00000000000"}
        }))
        .unwrap();
        held.normalize();
        registry.upsert(held);
        let vms = VmManager::new(
            Some(url.clone()),
            None,
            crate::mounts::MountStore::new(dir.path().join("mounts"), 0),
        )
        .unwrap();
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
        let puller = Puller::new("art".into(), dir.path().join("scratch"), None, vms.clone());
        let catalog = ImageCatalog::new(
            cfg,
            ImageStore::new(dir.path().join("images.d")),
            vms,
            registry,
            secrets,
            puller,
        );
        Harness {
            catalog,
            fake: f,
            url,
            _dir: dir,
        }
    }

    fn pulled(h: &Harness, name: &str) -> ImageRecord {
        ImageRecord {
            name: name.into(),
            source: ImageSource::Pull,
            digest: Some(DIGEST.into()),
            store: Some(h.url.clone()),
            bytes: 100,
            first_seen: 0,
            last_used: 0,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn an_idle_pull_is_verified_then_recorded_then_deleted_and_a_held_one_is_kept() {
        let h = harness(&["img-idle0000000000", "img-held00000000000", "stranger"]).await;
        h.catalog
            .store()
            .put(pulled(&h, "img-idle0000000000"))
            .unwrap();
        h.catalog
            .store()
            .put(pulled(&h, "img-held00000000000"))
            .unwrap();

        let report = h.catalog.sweep().await;
        assert_eq!(report.skipped, None, "{report:?}");
        assert_eq!(report.offloaded, vec!["img-idle0000000000".to_string()]);
        assert_eq!(
            *h.fake.log.lock().unwrap(),
            vec!["verify", "delete img-idle0000000000"],
            "the remote copy is proven first"
        );
        let r = h.catalog.store().get("img-idle0000000000").unwrap();
        assert_eq!(r.tier, Tier::Offloaded);
        assert!(r.offloaded_to.unwrap().contains(DIGEST));
        assert_eq!(
            h.catalog.store().get("img-held00000000000").unwrap().tier,
            Tier::Local
        );
        // An image app-lb did not make is recorded and left alone.
        assert_eq!(
            h.catalog.store().get("stranger").unwrap().source,
            ImageSource::Unknown
        );
        assert!(
            h.fake
                .images
                .lock()
                .unwrap()
                .contains(&"stranger".to_string())
        );

        let inv = h.catalog.inventory().await;
        assert!(inv.complete);
        assert_eq!(inv.delete_supported, Some(true));
        let held = inv
            .images
            .iter()
            .find(|i| i.record.name == "img-held00000000000")
            .unwrap();
        assert_eq!(
            held.references,
            vec![Reference::Deployment { id: "web".into() }]
        );
        assert!(held.kept_because.as_deref().unwrap().contains("in use"));
    }

    #[tokio::test]
    async fn without_pressure_or_a_budget_an_idle_pulled_image_stays_as_cache() {
        let h = harness_with(&["img-idle0000000000"], |_| ImagesConfig::default()).await;
        h.catalog.store().put(pulled(&h, "img-idle0000000000")).unwrap();
        let report = h.catalog.sweep().await;
        assert!(report.offloaded.is_empty() && report.failed.is_empty(), "{report:?}");
        assert!(h.fake.log.lock().unwrap().is_empty(), "nothing verified or deleted");
        let inv = h.catalog.inventory().await;
        assert_eq!(inv.cache_bytes, Some(100));
        let kept = inv.images.iter().find(|i| i.record.name == "img-idle0000000000").unwrap();
        assert!(kept.kept_because.as_deref().unwrap().contains("cache"));
    }

    #[tokio::test]
    async fn over_budget_the_least_recently_used_pulls_go_until_the_cache_fits() {
        let names = ["img-aaaa000000000000", "img-bbbb000000000000", "img-cccc000000000000"];
        let h = harness_with(&names, |_| ImagesConfig {
            cache_budget_bytes: Some(150),
            ..ImagesConfig::default()
        })
        .await;
        for (i, name) in names.iter().enumerate() {
            h.catalog
                .store()
                .put(ImageRecord { last_used: i as u64 + 1, ..pulled(&h, name) })
                .unwrap();
        }
        let report = h.catalog.sweep().await;
        assert_eq!(report.offloaded, vec![names[0], names[1]], "300 bytes over a 150 budget: two go, oldest first");
        assert_eq!(h.catalog.store().get(names[2]).unwrap().tier, Tier::Local);
        assert_eq!(h.catalog.inventory().await.cache_bytes, Some(100));
    }

    #[test]
    fn warm_entries_name_a_store_or_take_the_default() {
        assert_eq!(
            WarmEntry::parse_list(" heyo/alpine:3.24, https://art.example/|team/web:v1\nheyo/postgres:18 ,,", DEFAULT_WARM_STORE),
            vec![
                WarmEntry { store: DEFAULT_WARM_STORE.into(), artifact_ref: "heyo/alpine:3.24".into() },
                WarmEntry { store: "https://art.example".into(), artifact_ref: "team/web:v1".into() },
                WarmEntry { store: DEFAULT_WARM_STORE.into(), artifact_ref: "heyo/postgres:18".into() },
            ]
        );
        assert!(WarmEntry::parse_list("|x, y|", DEFAULT_WARM_STORE).is_empty());
    }

    /// A warm image is otherwise the first thing a zero budget removes.
    fn warm_harness(url: &str) -> ImagesConfig {
        ImagesConfig {
            cache_budget_bytes: Some(0),
            warm: vec![WarmEntry { store: url.into(), artifact_ref: "heyo/alpine:3.24".into() }],
            ..ImagesConfig::default()
        }
    }

    fn age(h: &Harness, name: &str) {
        h.catalog.store().update(name, |r| { r.first_seen = 0; r.last_used = 0; }).unwrap();
    }

    #[tokio::test]
    async fn the_warm_set_is_pulled_once_held_and_follows_a_moved_tag() {
        let h = harness_with(&[], warm_harness).await;
        let first = h.catalog.warm().await;
        assert!(first.failed.is_empty(), "{first:?}");
        let old = first.warmed[0].image.clone();
        assert!(first.warmed[0].fetched && old.starts_with("img-"));
        let again = h.catalog.warm().await;
        assert!(!again.warmed[0].fetched, "a second pass finds it on heyvm");
        assert_eq!(h.fake.log.lock().unwrap().iter().filter(|l| l.starts_with("upload")).count(), 1);

        age(&h, &old);
        assert!(h.catalog.sweep().await.offloaded.is_empty(), "held by the warm set, even over budget");
        let inv = h.catalog.inventory().await;
        let held = inv.images.iter().find(|i| i.record.name == old).unwrap();
        assert!(matches!(&held.references[..], [Reference::Warm { artifact_ref }] if artifact_ref.ends_with("/heyo/alpine:3.24")));

        // The tag moves: the new digest is held, the old one is cache again.
        *h.fake.content.lock().unwrap() = b"second".to_vec();
        let moved = h.catalog.warm().await;
        let new = moved.warmed[0].image.clone();
        assert!(moved.warmed[0].fetched && new != old);
        age(&h, &old);
        age(&h, &new);
        assert_eq!(h.catalog.sweep().await.offloaded, vec![old]);
        assert_eq!(h.catalog.store().get(&new).unwrap().tier, Tier::Local);
    }

    #[tokio::test]
    async fn a_restart_holds_the_warm_set_from_its_records_before_any_pass() {
        let h = harness_with(&[], warm_harness).await;
        let image = h.catalog.warm().await.warmed[0].image.clone();
        let store = ImageStore::new(h.catalog.store().dir());
        store.load();
        let c = &h.catalog;
        let restarted = ImageCatalog::new(
            c.cfg.clone(),
            store,
            c.vms.clone(),
            c.registry.clone(),
            c.secrets.clone(),
            Puller::new("art".into(), h._dir.path().join("scratch"), None, c.vms.clone()),
        );
        assert_eq!(restarted.warm_images(), vec![(image, format!("{}/heyo/alpine:3.24", h.url))]);
    }

    #[tokio::test]
    async fn an_unverified_copy_keeps_the_image_and_backs_off() {
        let h = harness(&["img-idle0000000000"]).await;
        h.fake.blob.store(404, Ordering::SeqCst);
        h.catalog
            .store()
            .put(pulled(&h, "img-idle0000000000"))
            .unwrap();
        let report = h.catalog.sweep().await;
        assert!(report.offloaded.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            *h.fake.log.lock().unwrap(),
            vec!["verify"],
            "nothing deleted"
        );
        let r = h.catalog.store().get("img-idle0000000000").unwrap();
        assert_eq!(r.tier, Tier::Local);
        assert_eq!(r.failures, 1);
        assert!(r.next_attempt_at > now_secs());
    }

    #[tokio::test]
    async fn a_heyvm_without_delete_reverts_the_record_and_stops_trying() {
        let h = harness(&["img-idle0000000000", "img-idle1111111111"]).await;
        h.fake.delete.store(405, Ordering::SeqCst);
        h.catalog
            .store()
            .put(pulled(&h, "img-idle0000000000"))
            .unwrap();
        h.catalog
            .store()
            .put(pulled(&h, "img-idle1111111111"))
            .unwrap();
        let report = h.catalog.sweep().await;
        assert!(report.offloaded.is_empty());
        assert_eq!(report.failed.len(), 1, "the first refusal ends the pass");
        for n in ["img-idle0000000000", "img-idle1111111111"] {
            assert_eq!(h.catalog.store().get(n).unwrap().tier, Tier::Local, "{n}");
        }
        assert_eq!(h.catalog.inventory().await.delete_supported, Some(false));
        assert!(
            h.catalog
                .sweep()
                .await
                .skipped
                .unwrap()
                .contains("DELETE /images")
        );
    }

    #[tokio::test]
    async fn heyvm_refusing_an_image_in_use_is_reported_and_kept() {
        let h = harness(&["img-idle0000000000"]).await;
        h.fake.delete.store(409, Ordering::SeqCst);
        h.catalog
            .store()
            .put(pulled(&h, "img-idle0000000000"))
            .unwrap();
        let e = h
            .catalog
            .offload("img-idle0000000000", true)
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ImageError::InUse(_, _, s) if s == &vec!["sb-9".to_string()]),
            "{e}"
        );
        assert_eq!(
            h.catalog.store().get("img-idle0000000000").unwrap().tier,
            Tier::Local
        );
    }

    #[tokio::test]
    async fn an_operator_cannot_offload_or_delete_a_referenced_image_but_can_pin_and_delete_others()
    {
        let h = harness(&["img-held00000000000", "img-idle0000000000"]).await;
        h.catalog
            .store()
            .put(pulled(&h, "img-held00000000000"))
            .unwrap();
        h.catalog
            .store()
            .put(ImageRecord {
                last_used: now_secs(),
                first_seen: now_secs(),
                ..pulled(&h, "img-idle0000000000")
            })
            .unwrap();
        assert!(matches!(
            h.catalog.offload("img-held00000000000", true).await,
            Err(ImageError::InUse(..))
        ));
        assert!(matches!(
            h.catalog.delete("img-held00000000000").await,
            Err(ImageError::InUse(..))
        ));
        // Explicit offload skips the idle and minimum age.
        h.catalog.set_pinned("img-idle0000000000", true).unwrap();
        assert!(
            matches!(
                h.catalog.offload("img-idle0000000000", true).await,
                Err(ImageError::InUse(..))
            ),
            "a pin is a reference"
        );
        h.catalog.set_pinned("img-idle0000000000", false).unwrap();
        h.catalog.offload("img-idle0000000000", true).await.unwrap();
        assert_eq!(
            h.catalog.store().get("img-idle0000000000").unwrap().tier,
            Tier::Offloaded
        );
        assert!(matches!(
            h.catalog.delete("nope").await,
            Err(ImageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn ensure_image_lets_a_present_or_default_image_through_and_holds_a_missing_offloaded_one()
     {
        let h = harness(&["img-held00000000000"]).await;
        let deployment = |image: Option<&str>| {
            let mut spec: crate::config::DeploymentSpec =
                serde_json::from_value(serde_json::json!({
                    "id": "x", "routes": [], "vm": {"driver": "firecracker", "port": 8080}
                }))
                .unwrap();
            spec.vm.as_mut().unwrap().image = image.map(str::to_string);
            spec.normalize();
            Arc::new(Deployment::new(spec))
        };
        assert!(
            h.catalog
                .ensure_image(&deployment(Some("img-held00000000000")))
                .await
        );
        assert!(
            h.catalog.ensure_image(&deployment(None)).await,
            "no image and no artifact: heyvm's default"
        );
        assert!(
            h.catalog
                .ensure_image(&deployment(Some("built-elsewhere")))
                .await,
            "missing and not ours: the create reports it"
        );
        // Offloaded by this module: held, and a thaw is started (it fails
        // here — the fake store serves no manifest — which is fine).
        h.catalog
            .store()
            .put(ImageRecord {
                tier: Tier::Offloaded,
                ..pulled(&h, "img-gone0000000000")
            })
            .unwrap();
        let gone = deployment(Some("img-gone0000000000"));
        assert!(!h.catalog.ensure_image(&gone).await);
        assert!(
            !h.catalog.ensure_image(&gone).await,
            "still held, and backing off rather than re-thawing"
        );
    }

    #[test]
    fn the_store_round_trips_and_skips_what_it_cannot_read() {
        let dir = std::env::temp_dir().join(format!("app-lb-images-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = ImageStore::new(&dir);
        store
            .put(rec("img-aaaaaaaaaaaaaaaa", ImageSource::Pull))
            .unwrap();
        assert!(store.put(rec("../escape", ImageSource::Pull)).is_err());
        std::fs::write(dir.join("junk.json"), b"not json").unwrap();
        let again = ImageStore::new(&dir);
        assert_eq!(again.load(), (1, 1));
        assert_eq!(
            again.get("img-aaaaaaaaaaaaaaaa").unwrap().source,
            ImageSource::Pull
        );
        again.remove("img-aaaaaaaaaaaaaaaa").unwrap();
        assert!(again.get("img-aaaaaaaaaaaaaaaa").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
