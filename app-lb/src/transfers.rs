//! Moving large files in and out of a sandbox through one-time URLs.
//!
//! A sandbox's console carries tens of KB/s, so a 30 MB repository archive
//! over it takes a quarter of an hour. The guest's network does not have that
//! problem. A transfer therefore never puts the bytes on the console: app-lb
//! keeps them on its own disk for a while and hands out single-use URLs, and
//! the guest fetches or pushes them with `curl` (or `wget`) at network speed.
//!
//! - **In:** the caller creates a transfer and gets an `upload_url`; `PUT`ting
//!   the bytes there stores them. app-lb then has the guest fetch them from a
//!   URL of its own, check the sha256, and place them at `path` or unpack them
//!   there. With `apply_on_upload` (the default) that happens as part of the
//!   upload.
//! - **Out:** app-lb has the guest `PUT` the file (or a tarball of the
//!   directory) to a URL of its own, and the caller downloads it from the
//!   `download_url`.
//!
//! The URLs are capabilities: `/transfers/<token>`, outside every gate, where
//! the token is 32 random bytes of which only a sha256 is stored. Every token
//! has one purpose (the caller's upload, one guest fetch, one guest push, the
//! caller's downloads) and expires; anything that does not match answers the
//! same `404`. Tokens reach the guest in its exec environment, never in the
//! command line.
//!
//! The blobs live under `<state>.transfers/`, within a byte budget, and are
//! swept with their records when they expire.

use crate::deployment::{Deployment, VmBackend, now_secs};
use crate::registry::Registry;
use crate::vm::VmManager;
use base64::Engine as _;
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;

/// Default and ceiling for how long a transfer and its URLs live.
pub const DEFAULT_TTL_SECS: u64 = 3600;
pub const MAX_TTL_SECS: u64 = 21_600;
/// How long a guest fetch or push token is good for.
const GUEST_TOKEN_SECS: u64 = 600;
/// Complete downloads of an outbound transfer before its URL stops working.
const MAX_DOWNLOADS: u32 = 3;
/// Open (unexpired) transfers per deployment.
pub const MAX_OPEN_PER_DEPLOYMENT: usize = 8;
/// How long the guest side of an apply or push may take.
const GUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// Largest transfer moved over the console when the guest has no curl or wget.
/// The console carries tens of KB/s, so this is minutes at most.
pub const CONSOLE_FALLBACK_BYTES: u64 = 8 * 1024 * 1024;
/// Bound on each console chunk command.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);

/// What a guest without a fetch tool, or without curl to push with, reports.
const NO_FETCH_TOOL: &str = "the guest has neither curl nor wget to fetch with";
const NO_CURL_PUSH: &str = "the guest has no curl to push with";

/// How often expired transfers are swept.
pub const SWEEP: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Extract {
    /// Place the bytes at `path` as one file.
    #[default]
    None,
    Tar,
    #[serde(rename = "tar.gz")]
    TarGz,
    /// `tar.gz` if the bytes start with gzip's magic, else `tar`.
    Auto,
}

impl Extract {
    fn word(self) -> &'static str {
        match self {
            Extract::None => "none",
            Extract::Tar => "tar",
            Extract::TarGz => "tar.gz",
            Extract::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// In: waiting for the caller's `PUT`.
    AwaitingUpload,
    /// In: stored, not yet in the guest.
    Uploaded,
    /// In: the guest is fetching and placing it.
    Applying,
    /// In: in place in the guest.
    Applied,
    /// Out: the guest is pushing it.
    Collecting,
    /// Out: stored; the download URL works.
    Ready,
    Failed,
}

/// The persisted record. Token fields hold sha256 hex of the token, never the
/// token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub deployment: String,
    pub direction: Direction,
    pub path: String,
    #[serde(default)]
    pub extract: Extract,
    #[serde(default)]
    pub strip_components: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_bytes: u64,
    pub state: TransferState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub apply_on_upload: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upload_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    download_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_token: Option<String>,
    #[serde(default)]
    guest_token_expires_at: u64,
    #[serde(default)]
    downloads: u32,
}

/// A transfer as the API shows it: no token hashes.
#[derive(Debug, Clone, Serialize)]
pub struct TransferView {
    pub id: String,
    pub deployment: String,
    pub direction: Direction,
    pub path: String,
    pub extract: Extract,
    #[serde(skip_serializing_if = "is_zero")]
    pub strip_components: u32,
    pub state: TransferState,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// In: where to `PUT` the bytes. Shown once, when the transfer is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_url: Option<String>,
    /// Out: where to `GET` them, up to three times. Shown when created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Transfer {
    pub fn view(&self) -> TransferView {
        TransferView {
            id: self.id.clone(),
            deployment: self.deployment.clone(),
            direction: self.direction,
            path: self.path.clone(),
            extract: self.extract,
            strip_components: self.strip_components,
            state: self.state,
            created_at: self.created_at,
            expires_at: self.expires_at,
            max_bytes: self.max_bytes,
            size: self.size,
            sha256: self.sha256.clone(),
            sandbox_id: self.sandbox_id.clone(),
            error: self.error.clone(),
            upload_url: None,
            download_url: None,
        }
    }
}

/// What a create asks for.
#[derive(Debug, Clone, Deserialize)]
pub struct NewTransfer {
    pub direction: Direction,
    pub path: String,
    #[serde(default)]
    pub extract: Extract,
    #[serde(default)]
    pub strip_components: u32,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default = "yes")]
    pub apply_on_upload: bool,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    /// Out: how long the create waits for the guest's push before answering
    /// `202` with `collecting`.
    #[serde(default)]
    pub wait_secs: Option<u64>,
}

fn yes() -> bool {
    true
}

/// Why a request was refused, with the status it maps to.
#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    NotConfigured,
    Invalid(String),
    TooMany(String),
    NoSpace(String),
    NotFound,
    Conflict(String),
    TooLarge(u64),
    Guest(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "transfers are not enabled on this app-lb: set APP_LB_TRANSFER_URL to the public \
                 base URL its /transfers/ route is reachable at"
            ),
            Self::Invalid(m)
            | Self::TooMany(m)
            | Self::NoSpace(m)
            | Self::Conflict(m)
            | Self::Guest(m) => f.write_str(m),
            Self::NotFound => f.write_str("no such transfer"),
            Self::TooLarge(max) => write!(
                f,
                "the upload is larger than this transfer allows ({max} bytes)"
            ),
        }
    }
}

/// Settings, from the environment.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Public base URL, e.g. `https://admin.us5.heyo.work`: what callers' URLs
    /// start with.
    pub public_url: String,
    /// The base the guest reaches app-lb at, when not the public one.
    pub guest_url: String,
    pub dir: PathBuf,
    pub max_bytes: u64,
    pub budget_bytes: u64,
}

impl TransferConfig {
    /// `None` when `APP_LB_TRANSFER_URL` is unset: transfers are off.
    pub fn from_env(dir: PathBuf) -> Option<Self> {
        let public = std::env::var("APP_LB_TRANSFER_URL")
            .ok()?
            .trim()
            .trim_end_matches('/')
            .to_string();
        if public.is_empty() {
            return None;
        }
        let guest = std::env::var("APP_LB_TRANSFER_GUEST_URL")
            .ok()
            .map(|g| g.trim().trim_end_matches('/').to_string())
            .filter(|g| !g.is_empty())
            .unwrap_or_else(|| public.clone());
        let num = |key: &str, default: u64| {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        Some(Self {
            public_url: public,
            guest_url: guest,
            dir,
            max_bytes: num("APP_LB_TRANSFER_MAX_BYTES", 1 << 30),
            budget_bytes: num("APP_LB_TRANSFER_DISK_BUDGET", 10 << 30),
        })
    }
}

// -- tokens ----------------------------------------------------------------

/// A fresh token and its stored hash.
fn mint() -> (String, String) {
    let mut bytes = [0u8; 32];
    openssl::rand::rand_bytes(&mut bytes).expect("entropy for a transfer token");
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash(&token);
    (token, hash)
}

fn hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

/// Constant-time comparison of a stored hash with a presented token's.
fn matches(stored: Option<&String>, presented: &str) -> bool {
    stored.is_some_and(|s| {
        s.len() == presented.len() && openssl::memcmp::eq(s.as_bytes(), presented.as_bytes())
    })
}

fn new_id() -> String {
    let mut bytes = [0u8; 8];
    openssl::rand::rand_bytes(&mut bytes).expect("entropy for a transfer id");
    format!(
        "tr_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

// -- guest scripts -----------------------------------------------------------

/// Whether `path` can be named in a guest command.
pub fn valid_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("path must be absolute: {path:?}"));
    }
    if path.contains('\'') || path.contains('\n') || path.contains('\r') || path.contains('\\') {
        return Err(format!(
            "path cannot contain a quote, backslash or newline: {path:?}"
        ));
    }
    Ok(())
}

/// Where [`apply_script`] keeps the blob before placing it: inside the
/// destination when unpacking, beside it otherwise.
pub fn staged_path(id: &str, path: &str, extract: Extract) -> String {
    if extract != Extract::None {
        return format!("{}/.heyo-transfer-{id}", path.trim_end_matches('/'));
    }
    let dir = match path.rfind('/') {
        Some(0) | None => "",
        Some(i) => &path[..i],
    };
    format!("{dir}/.heyo-transfer-{id}")
}

/// Stage `path` for a console read: a file as it is, a directory as a tarball
/// beside the other staged files. Prints `staged=<file>` and `size=<bytes>`.
pub fn stage_out_script(id: &str, path: &str) -> String {
    format!(
        "P='{path}'; if [ -d \"$P\" ]; then F=/tmp/.heyo-transfer-{id}.tgz; tar -czf \"$F\" -C \"$P\" . || \
         {{ echo 'error=could not pack the directory'; exit 1; }}; elif [ -f \"$P\" ]; then F=\"$P\"; \
         else echo 'error=no such file or directory'; exit 2; fi; \
         echo \"staged=$F\"; echo \"size=$(wc -c < \"$F\" | tr -d ' ')\""
    )
}

/// Fetch the blob from `$HEYO_TRANSFER_URL`, check it, and place or unpack it.
///
/// The temporary file sits beside the destination (inside it, when
/// unpacking), so a large archive lands on `/workspace` rather than on the
/// small root filesystem. Prints `applied` and the size, or `error=…`;
/// `error=no-fetch-tool` when the guest has neither curl nor wget.
pub fn apply_script(id: &str, path: &str, extract: Extract, strip: u32, sha256: &str) -> String {
    let unpack = extract != Extract::None;
    let dir_setup = if unpack {
        "mkdir -p \"$P\" || { echo 'error=cannot create the destination'; exit 1; }; T=\"$P/.heyo-transfer-$I\""
    } else {
        "Q=$(dirname \"$P\"); mkdir -p \"$Q\" || { echo 'error=cannot create the destination'; exit 1; }; T=\"$Q/.heyo-transfer-$I\""
    };
    let strip_flag = if strip > 0 {
        format!(" --strip-components={strip}")
    } else {
        String::new()
    };
    let place = match extract {
        Extract::None => "mv -f \"$T\" \"$P\" || { echo 'error=could not move the file into place'; rm -f \"$T\"; exit 1; }".to_string(),
        _ => format!(
            "X={word}; if [ \"$X\" = auto ]; then m=$(head -c 2 \"$T\" | od -An -tx1 | tr -d ' '); \
             if [ \"$m\" = 1f8b ]; then X=tar.gz; else X=tar; fi; fi; \
             if [ \"$X\" = tar.gz ]; then tar -xzf \"$T\" -C \"$P\"{strip_flag}; else tar -xf \"$T\" -C \"$P\"{strip_flag}; fi; \
             r=$?; rm -f \"$T\"; [ $r -eq 0 ] || {{ echo \"error=tar failed (exit $r)\"; exit 1; }}",
            word = extract.word(),
        ),
    };
    format!(
        "I={id}; P='{path}'; S={sha256}; {dir_setup}; \
         if [ -z \"$HEYO_TRANSFER_URL\" ]; then [ -f \"$T\" ] || {{ echo 'error=nothing was staged'; exit 1; }}; \
         elif command -v curl >/dev/null 2>&1; then \
         curl -fsS --retry 3 --connect-timeout 15 --max-time 540 -o \"$T\" \"$HEYO_TRANSFER_URL\" \
         || {{ r=$?; rm -f \"$T\"; echo \"error=download failed (curl exit $r)\"; exit 1; }}; \
         elif command -v wget >/dev/null 2>&1; then \
         wget -q -O \"$T\" \"$HEYO_TRANSFER_URL\" || {{ rm -f \"$T\"; echo 'error=download failed (wget)'; exit 1; }}; \
         else echo 'error=no-fetch-tool'; exit 127; fi; \
         if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum \"$T\" | cut -d' ' -f1); \
         [ \"$h\" = \"$S\" ] || {{ rm -f \"$T\"; echo \"error=checksum mismatch: got $h\"; exit 1; }}; fi; \
         {place}; echo applied"
    )
}

/// Push `path` (a file, or a directory as a tar.gz stream) to
/// `$HEYO_TRANSFER_URL`. Prints `pushed` or `error=…`.
pub fn push_script(path: &str) -> String {
    format!(
        "P='{path}'; command -v curl >/dev/null 2>&1 || {{ echo 'error={NO_CURL_PUSH}'; exit 127; }}; \
         if [ -d \"$P\" ]; then tar -czf - -C \"$P\" . | curl -fsS --connect-timeout 15 --max-time 540 -X PUT \
         -H 'Content-Type: application/octet-stream' -T - \"$HEYO_TRANSFER_URL\"; r=$?; \
         elif [ -f \"$P\" ]; then curl -fsS --connect-timeout 15 --max-time 540 -X PUT \
         -H 'Content-Type: application/octet-stream' -T \"$P\" \"$HEYO_TRANSFER_URL\"; r=$?; \
         else echo 'error=no such file or directory'; exit 2; fi; \
         [ $r -eq 0 ] || {{ echo \"error=upload failed (curl exit $r)\"; exit 1; }}; echo pushed"
    )
}

/// The `error=` line a guest script printed, if any.
pub fn guest_error(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("error=").map(str::to_string))
}

// -- the store -------------------------------------------------------------

/// What an upload or download through `/transfers/:token` turned out to be for.
pub enum Claim {
    /// The caller's inbound upload.
    Upload(Transfer),
    /// The guest's outbound push.
    Push(Transfer),
    /// The guest fetching an inbound blob.
    Fetch(Transfer),
    /// The caller downloading an outbound blob.
    Download(Transfer),
}

pub struct Transfers {
    cfg: TransferConfig,
    registry: Arc<Registry>,
    vms: VmManager,
    metrics: Arc<crate::metrics::Metrics>,
    feed: Arc<crate::feed::Feed>,
    records: Mutex<BTreeMap<String, Transfer>>,
}

impl Transfers {
    pub fn open(
        cfg: TransferConfig,
        registry: Arc<Registry>,
        vms: VmManager,
        metrics: Arc<crate::metrics::Metrics>,
        feed: Arc<crate::feed::Feed>,
    ) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(&cfg.dir)?;
        let records = match std::fs::read(cfg.dir.join("transfers.json")) {
            Ok(bytes) => serde_json::from_slice::<Vec<Transfer>>(&bytes)
                .map(|list| list.into_iter().map(|t| (t.id.clone(), t)).collect())
                .unwrap_or_default(),
            Err(_) => BTreeMap::new(),
        };
        let this = Arc::new(Self {
            cfg,
            registry,
            vms,
            metrics,
            feed,
            records: Mutex::new(records),
        });
        this.sweep();
        Ok(this)
    }

    fn blob(&self, id: &str) -> PathBuf {
        self.cfg.dir.join(format!("{id}.blob"))
    }

    fn persist(&self) {
        let list: Vec<Transfer> = self.records.lock().unwrap().values().cloned().collect();
        let path = self.cfg.dir.join("transfers.json");
        let tmp = path.with_extension("json.tmp");
        let result = serde_json::to_vec_pretty(&list)
            .map_err(std::io::Error::other)
            .and_then(|b| std::fs::write(&tmp, b))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = result {
            tracing::error!(error = %e, "could not persist transfers");
        }
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut Transfer)) -> Option<Transfer> {
        let t = {
            let mut records = self.records.lock().unwrap();
            let t = records.get_mut(id)?;
            f(t);
            t.clone()
        };
        self.persist();
        Some(t)
    }

    pub fn get(&self, deployment: &str, id: &str) -> Option<Transfer> {
        self.records
            .lock()
            .unwrap()
            .get(id)
            .filter(|t| t.deployment == deployment)
            .cloned()
    }

    pub fn list(&self, deployment: &str) -> Vec<TransferView> {
        let mut list: Vec<TransferView> = self
            .records
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.deployment == deployment)
            .map(Transfer::view)
            .collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        list
    }

    /// Bytes held on disk now plus those promised to transfers still waiting
    /// for their upload.
    fn committed_bytes(&self) -> u64 {
        self.records
            .lock()
            .unwrap()
            .values()
            .map(|t| {
                t.size.unwrap_or(match t.state {
                    TransferState::AwaitingUpload | TransferState::Collecting => t.max_bytes,
                    _ => 0,
                })
            })
            .sum()
    }

    /// Create a transfer. Returns its view with the caller's URL (`upload_url`
    /// for in; `download_url` for out, which works once the push completes).
    pub fn create(
        &self,
        deployment: &Deployment,
        req: &NewTransfer,
    ) -> Result<(Transfer, TransferView), TransferError> {
        valid_path(&req.path).map_err(TransferError::Invalid)?;
        if req.direction == Direction::Out && req.extract != Extract::None {
            return Err(TransferError::Invalid(
                "extract applies to inbound transfers only".into(),
            ));
        }
        let ttl = req.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return Err(TransferError::Invalid(format!(
                "ttl_secs must be 1..={MAX_TTL_SECS}"
            )));
        }
        let max_bytes = req
            .max_bytes
            .unwrap_or(self.cfg.max_bytes)
            .min(self.cfg.max_bytes);
        let open = self
            .records
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.deployment == deployment.spec.id && t.expires_at > now_secs())
            .count();
        if open >= MAX_OPEN_PER_DEPLOYMENT {
            return Err(TransferError::TooMany(format!(
                "deployment {:?} already has {MAX_OPEN_PER_DEPLOYMENT} open transfers; delete one or let it expire",
                deployment.spec.id
            )));
        }
        if self.committed_bytes() + max_bytes > self.cfg.budget_bytes {
            return Err(TransferError::NoSpace(format!(
                "this app-lb's transfer space is committed ({} of {} bytes); try a smaller max_bytes or later",
                self.committed_bytes(),
                self.cfg.budget_bytes
            )));
        }
        let now = now_secs();
        let (caller_token, caller_hash) = mint();
        let t = Transfer {
            id: new_id(),
            deployment: deployment.spec.id.clone(),
            direction: req.direction,
            path: req.path.clone(),
            extract: req.extract,
            strip_components: req.strip_components,
            created_at: now,
            expires_at: now + ttl,
            max_bytes,
            state: match req.direction {
                Direction::In => TransferState::AwaitingUpload,
                Direction::Out => TransferState::Collecting,
            },
            size: None,
            sha256: None,
            sandbox_id: req.sandbox_id.clone(),
            error: None,
            apply_on_upload: req.apply_on_upload,
            upload_token: (req.direction == Direction::In).then(|| caller_hash.clone()),
            download_token: (req.direction == Direction::Out).then_some(caller_hash),
            guest_token: None,
            guest_token_expires_at: 0,
            downloads: 0,
        };
        self.records.lock().unwrap().insert(t.id.clone(), t.clone());
        self.persist();
        let mut view = t.view();
        let url = format!("{}/transfers/{caller_token}", self.cfg.public_url);
        match req.direction {
            Direction::In => view.upload_url = Some(url),
            Direction::Out => view.download_url = Some(url),
        }
        Ok((t, view))
    }

    /// Which transfer a presented token belongs to, and for what.
    pub fn claim(&self, token: &str, method_is_put: bool) -> Option<Claim> {
        let presented = hash(token);
        let now = now_secs();
        let records = self.records.lock().unwrap();
        for t in records.values().filter(|t| t.expires_at > now) {
            if method_is_put {
                if t.state == TransferState::AwaitingUpload
                    && matches(t.upload_token.as_ref(), &presented)
                {
                    return Some(Claim::Upload(t.clone()));
                }
                if t.state == TransferState::Collecting
                    && t.guest_token_expires_at > now
                    && matches(t.guest_token.as_ref(), &presented)
                {
                    return Some(Claim::Push(t.clone()));
                }
            } else {
                if t.direction == Direction::In
                    && t.guest_token_expires_at > now
                    && matches(t.guest_token.as_ref(), &presented)
                {
                    return Some(Claim::Fetch(t.clone()));
                }
                if t.state == TransferState::Ready
                    && t.downloads < MAX_DOWNLOADS
                    && matches(t.download_token.as_ref(), &presented)
                {
                    return Some(Claim::Download(t.clone()));
                }
            }
        }
        None
    }

    /// Store a request body as the transfer's blob: streamed to disk, hashed
    /// on the way, refused past `max_bytes`. Records the size and digest and
    /// moves the transfer on (`uploaded`, or `ready` for a guest push). The
    /// caller's upload token is spent only by a complete body.
    pub async fn receive(
        &self,
        t: &Transfer,
        body: axum::body::Body,
    ) -> Result<Transfer, TransferError> {
        let part = self.cfg.dir.join(format!("{}.part", t.id));
        let mut file = tokio::fs::File::create(&part)
            .await
            .map_err(|e| TransferError::Guest(format!("could not store the upload: {e}")))?;
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&part).await;
                    return Err(TransferError::Invalid(format!(
                        "the upload was interrupted: {e}"
                    )));
                }
            };
            size += chunk.len() as u64;
            if size > t.max_bytes {
                drop(file);
                let _ = tokio::fs::remove_file(&part).await;
                return Err(TransferError::TooLarge(t.max_bytes));
            }
            hasher.update(&chunk);
            if let Err(e) = file.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&part).await;
                return Err(TransferError::Guest(format!(
                    "could not store the upload: {e}"
                )));
            }
        }
        file.flush().await.ok();
        drop(file);
        tokio::fs::rename(&part, self.blob(&t.id))
            .await
            .map_err(|e| TransferError::Guest(format!("could not store the upload: {e}")))?;
        let digest = format!("{:x}", hasher.finalize());
        self.update(&t.id, |r| {
            r.size = Some(size);
            r.sha256 = Some(digest);
            match r.direction {
                Direction::In => {
                    r.upload_token = None;
                    r.state = TransferState::Uploaded;
                }
                Direction::Out => {
                    r.guest_token = None;
                    r.state = TransferState::Ready;
                }
            }
        })
        .ok_or(TransferError::NotFound)
    }

    /// The blob, for a fetch or a download. A download counts once it is
    /// opened; a fetch token is spent by being used.
    pub async fn open_blob(&self, claim: &Claim) -> Result<(tokio::fs::File, u64), TransferError> {
        let t = match claim {
            Claim::Fetch(t) | Claim::Download(t) => t,
            _ => return Err(TransferError::NotFound),
        };
        let file = tokio::fs::File::open(self.blob(&t.id))
            .await
            .map_err(|_| TransferError::NotFound)?;
        let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        if let Claim::Download(_) = claim {
            self.update(&t.id, |r| r.downloads += 1);
        }
        Ok((file, len))
    }

    /// A VM to run the guest side in: the transfer's own, else the pool's,
    /// waking one when there is none.
    async fn vm_for(
        &self,
        t: &Transfer,
    ) -> Result<(Arc<Deployment>, Arc<VmBackend>), TransferError> {
        let d = self
            .registry
            .get(&t.deployment)
            .ok_or(TransferError::NotFound)?;
        if let Some(want) = &t.sandbox_id {
            return d
                .backends()
                .iter()
                .find(|b| &b.sandbox_id == want)
                .cloned()
                .map(|b| (d.clone(), b))
                .ok_or_else(|| TransferError::Conflict(format!("VM {want} is not running")));
        }
        if let Some(b) = d.select(&[]) {
            return Ok((d, b));
        }
        if d.spec.scaling.max_replicas == 0 {
            return Err(TransferError::Conflict(format!(
                "deployment {:?} is stopped; start it first",
                d.spec.id
            )));
        }
        let b = crate::request_control::wait_for_capacity(&d, &[], &self.metrics, &self.feed)
            .await
            .ok_or_else(|| TransferError::Conflict("no VM became available".into()))?;
        Ok((d, b))
    }

    /// A fresh guest token, recorded on the transfer, and the URL it opens.
    fn guest_url(&self, id: &str) -> Option<String> {
        let (token, h) = mint();
        self.update(id, |t| {
            t.guest_token = Some(h);
            t.guest_token_expires_at = now_secs() + GUEST_TOKEN_SECS;
        })?;
        Some(format!("{}/transfers/{token}", self.cfg.guest_url))
    }

    async fn run_guest(
        &self,
        sandbox_id: &str,
        script: &str,
        url: String,
    ) -> Result<String, TransferError> {
        let options = heyo_sdk::CommandRunOptions {
            cwd: None,
            env: Some(std::collections::HashMap::from([(
                "HEYO_TRANSFER_URL".to_string(),
                url,
            )])),
            timeout: Some(GUEST_TIMEOUT),
        };
        let out = self
            .vms
            .exec(sandbox_id, script, options)
            .await
            .map_err(|e| {
                TransferError::Guest(format!("could not run the transfer in {sandbox_id}: {e}"))
            })?;
        if let Some(e) = guest_error(&out.stdout) {
            return Err(TransferError::Guest(if e == "no-fetch-tool" {
                NO_FETCH_TOOL.into()
            } else {
                e
            }));
        }
        if out.exit_code != 0 {
            return Err(TransferError::Guest(format!(
                "the guest side failed (exit {}): {}",
                out.exit_code,
                out.output.trim()
            )));
        }
        Ok(out.stdout)
    }

    /// Put an uploaded blob in place in the guest.
    pub async fn apply(&self, id: &str) -> Result<Transfer, TransferError> {
        let t = self
            .records
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(TransferError::NotFound)?;
        if t.direction != Direction::In {
            return Err(TransferError::Invalid(
                "only an inbound transfer is applied".into(),
            ));
        }
        let Some(sha) = t.sha256.clone() else {
            return Err(TransferError::Conflict(
                "nothing has been uploaded yet".into(),
            ));
        };
        let (_d, backend) = self.vm_for(&t).await?;
        let _slot = backend.try_hold();
        self.update(id, |r| {
            r.state = TransferState::Applying;
            r.sandbox_id = Some(backend.sandbox_id.clone());
            r.error = None;
        });
        let url = self.guest_url(id).ok_or(TransferError::NotFound)?;
        let script = apply_script(&t.id, &t.path, t.extract, t.strip_components, &sha);
        let mut result = self.run_guest(&backend.sandbox_id, &script, url).await;
        if matches!(&result, Err(TransferError::Guest(m)) if m.starts_with(NO_FETCH_TOOL)) {
            result = self
                .apply_over_console(&t, &backend.sandbox_id, &script)
                .await;
        }
        let updated = self.update(id, |r| {
            r.guest_token = None;
            match &result {
                Ok(_) => r.state = TransferState::Applied,
                Err(e) => {
                    r.state = TransferState::Failed;
                    r.error = Some(e.to_string());
                }
            }
        });
        result?;
        Ok(updated.unwrap_or(t))
    }

    /// The inbound fallback for a guest with no curl or wget: write the blob to
    /// its staged path over the console, then run the same apply with nothing
    /// to fetch. Only up to [`CONSOLE_FALLBACK_BYTES`].
    async fn apply_over_console(
        &self,
        t: &Transfer,
        sandbox_id: &str,
        script: &str,
    ) -> Result<String, TransferError> {
        let size = t.size.unwrap_or(0);
        if size > CONSOLE_FALLBACK_BYTES {
            return Err(TransferError::Guest(format!(
                "{NO_FETCH_TOOL}, and {size} bytes is too much for the console (at most \
                 {CONSOLE_FALLBACK_BYTES}); add curl or wget to the image"
            )));
        }
        let bytes = tokio::fs::read(self.blob(&t.id))
            .await
            .map_err(|e| TransferError::Guest(format!("could not read the stored upload: {e}")))?;
        let staged = staged_path(&t.id, &t.path, t.extract);
        for chunk in crate::guest_files::write_scripts(&staged, &bytes, false) {
            self.console(sandbox_id, &chunk).await?;
        }
        self.run_guest(sandbox_id, script, String::new()).await
    }

    /// One short console command, its stdout, or why it failed.
    async fn console(&self, sandbox_id: &str, script: &str) -> Result<String, TransferError> {
        let out = self
            .vms
            .exec(
                sandbox_id,
                script,
                heyo_sdk::CommandRunOptions {
                    cwd: None,
                    env: None,
                    timeout: Some(CHUNK_TIMEOUT),
                },
            )
            .await
            .map_err(|e| {
                TransferError::Guest(format!("console transfer to {sandbox_id} failed: {e}"))
            })?;
        if let Some(e) = guest_error(&out.stdout) {
            return Err(TransferError::Guest(e));
        }
        if out.exit_code != 0 {
            return Err(TransferError::Guest(format!(
                "console transfer step failed (exit {}): {}",
                out.exit_code,
                out.output.trim()
            )));
        }
        Ok(out.stdout)
    }

    /// The outbound fallback for a guest with no curl: stage the path, read it
    /// back over the console, and store it as the transfer's blob.
    async fn collect_over_console(
        &self,
        t: &Transfer,
        sandbox_id: &str,
    ) -> Result<(), TransferError> {
        let out = self
            .console(sandbox_id, &stage_out_script(&t.id, &t.path))
            .await?;
        let field = |k: &str| {
            out.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(k)
                    .and_then(|v| v.strip_prefix('='))
                    .map(str::to_string)
            })
        };
        let staged = field("staged")
            .ok_or_else(|| TransferError::Guest("the guest did not stage the path".into()))?;
        let size: u64 = field("size").and_then(|s| s.parse().ok()).unwrap_or(0);
        let packed = staged.starts_with("/tmp/.heyo-transfer-");
        let rm = packed.then(|| format!("rm -f '{staged}'"));
        if size > CONSOLE_FALLBACK_BYTES.min(t.max_bytes) {
            if let Some(rm) = &rm {
                let _ = self.console(sandbox_id, rm).await;
            }
            return Err(TransferError::Guest(format!(
                "{NO_CURL_PUSH}, and {size} bytes is too much for the console (at most \
                 {CONSOLE_FALLBACK_BYTES}); add curl to the image"
            )));
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(size as usize);
        while (bytes.len() as u64) < size {
            let script = crate::guest_files::read_script(
                &staged,
                bytes.len() as u64,
                crate::guest_files::MAX_READ_BYTES,
            );
            let page = self.console(sandbox_id, &script).await?;
            let (_, chunk) = crate::guest_files::parse_read(&page).map_err(TransferError::Guest)?;
            if chunk.is_empty() {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        if let Some(rm) = &rm {
            let _ = self.console(sandbox_id, rm).await;
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        tokio::fs::write(self.blob(&t.id), &bytes)
            .await
            .map_err(|e| TransferError::Guest(format!("could not store the download: {e}")))?;
        let n = bytes.len() as u64;
        self.update(&t.id, |r| {
            r.size = Some(n);
            r.sha256 = Some(digest);
            r.guest_token = None;
            r.state = TransferState::Ready;
        });
        Ok(())
    }

    /// Have the guest push an outbound transfer's path.
    pub async fn collect(&self, id: &str) -> Result<Transfer, TransferError> {
        let t = self
            .records
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(TransferError::NotFound)?;
        let (_d, backend) = self.vm_for(&t).await?;
        let _slot = backend.try_hold();
        self.update(id, |r| r.sandbox_id = Some(backend.sandbox_id.clone()));
        let url = self.guest_url(id).ok_or(TransferError::NotFound)?;
        let mut result = self
            .run_guest(&backend.sandbox_id, &push_script(&t.path), url)
            .await;
        if matches!(&result, Err(TransferError::Guest(m)) if m.starts_with(NO_CURL_PUSH)) {
            result = self
                .collect_over_console(&t, &backend.sandbox_id)
                .await
                .map(|()| String::new());
        }
        if let Err(e) = &result {
            self.update(id, |r| {
                r.state = TransferState::Failed;
                r.error = Some(e.to_string());
                r.guest_token = None;
            });
        }
        result?;
        Ok(self.records.lock().unwrap().get(id).cloned().unwrap_or(t))
    }

    /// Forget a transfer and its blob.
    pub fn discard(&self, id: &str) {
        self.records.lock().unwrap().remove(id);
        let _ = std::fs::remove_file(self.blob(id));
        let _ = std::fs::remove_file(self.cfg.dir.join(format!("{id}.part")));
        self.persist();
    }

    /// Drop expired transfers and any blob no record names.
    pub fn sweep(&self) {
        let now = now_secs();
        let expired: Vec<String> = self
            .records
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.expires_at <= now)
            .map(|t| t.id.clone())
            .collect();
        for id in &expired {
            self.discard(id);
        }
        let known: std::collections::HashSet<String> =
            self.records.lock().unwrap().keys().cloned().collect();
        if let Ok(entries) = std::fs::read_dir(&self.cfg.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let id = name
                    .strip_suffix(".blob")
                    .or_else(|| name.strip_suffix(".part"));
                if let Some(id) = id
                    && !known.contains(id)
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

}

/// The expiry sweep, as a pingora background service (see
/// [`crate::operations::Watcher`]).
pub struct Sweeper(pub Arc<Transfers>);

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for Sweeper {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let mut interval = tokio::time::interval(SWEEP);
        loop {
            tokio::select! {
                _ = interval.tick() => self.0.sweep(),
                _ = shutdown.changed() => return,
            }
        }
    }
}

/// `/transfers/<token>` with the token cut, for anything that records paths.
pub fn redact(path: &str) -> std::borrow::Cow<'_, str> {
    if path.starts_with("/transfers/") && path.len() > "/transfers/".len() {
        std::borrow::Cow::Borrowed("/transfers/<token>")
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_stored_hashed_and_compared_whole() {
        let (token, h) = mint();
        assert_ne!(token, h);
        assert_eq!(hash(&token), h);
        assert!(matches(Some(&h), &hash(&token)));
        assert!(!matches(Some(&h), &hash("other")));
        assert!(!matches(None, &hash(&token)));
    }

    #[test]
    fn guest_scripts_carry_no_backslash() {
        for s in [
            apply_script("tr_1", "/workspace/app", Extract::Auto, 1, "abc"),
            apply_script("tr_1", "/workspace/f.bin", Extract::None, 0, "abc"),
            push_script("/workspace/dist"),
        ] {
            assert!(!s.contains('\\'), "{s}");
            assert!(
                !s.contains("transfers/"),
                "the URL comes from the environment: {s}"
            );
        }
        assert!(apply_script("tr_1", "/w", Extract::Tar, 2, "x").contains("--strip-components=2"));
        assert!(!apply_script("tr_1", "/w", Extract::Tar, 0, "x").contains("--strip-components"));
    }

    #[test]
    fn paths_are_redacted_only_under_transfers() {
        assert_eq!(redact("/transfers/abc"), "/transfers/<token>");
        assert_eq!(redact("/transfers/"), "/transfers/");
        assert_eq!(redact("/deployments/x"), "/deployments/x");
    }

    #[test]
    fn guest_errors_are_found() {
        assert_eq!(
            guest_error("x\nerror=checksum mismatch: got 1\n").as_deref(),
            Some("checksum mismatch: got 1")
        );
        assert_eq!(guest_error("applied\n"), None);
    }
}
