//! The heyo-sdk boundary.
//!
//! Everything that knows about sandboxes lives here so the traps are in one
//! place. Two are worth stating up front, because both fail silently:
//!
//! 1. `Sandbox::wait_for_ready` returning `Ok` does **not** mean the VM is
//!    usable — its match has a `_ => return Ok(info)` arm, so `Stopped`,
//!    `Paused`, and `ColdStored` all come back `Ok`. Against a local daemon a
//!    broken VM surfaces as `Stopped`, never `Failed`. Always check the status.
//! 2. `guest_ip` is only populated for tap-networked Firecracker/KVM on a local
//!    daemon. It is the only address we can route to, so its absence is a hard
//!    error, not something to retry.
//! 3. `SandboxCreateOptions` cannot express guest mounts, so [`VmManager::create`]
//!    posts the create body itself rather than calling `Sandbox::create`. The
//!    body is still the SDK's own serialization of that struct — only the
//!    `mounts` array and the four defaults the SDK would have filled in are
//!    added here. See [`sdk_create_defaults`].

use crate::config::{DeploymentSpec, VmSpec};
use crate::mounts::MountStore;
use heyo_sdk::{
    BindRequest, CommandResult, CommandRunOptions, Daemon, DaemonCreateRequest, DaemonMount,
    HeyoClient, HeyoClientOptions, ImageInfo, ImageUploadOptions, InactiveSandbox, LogEntry,
    LogsQuery, PurgeOutcome, PurgeParts, Sandbox, SandboxInfo, SandboxStatus,
    ShellOptions, ShellSession, StorageInventory, TreeInfo, UploadStream,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Marks a sandbox as ours and records which deployment owns it, so VMs can be
/// re-adopted after an LB restart instead of being orphaned or duplicated.
pub const OWNER_PREFIX: &str = "applb";

/// Sandbox name for a replica: `applb-<deployment>-<nonce>`.
///
/// The nonce is *hex* on purpose. The daemon derives a VM's tap subnet from the
/// sandbox id via `from_str_radix(hex, 16).unwrap_or(0)`, so an id that isn't
/// valid hex silently collapses to `172.16.0.2` and collides with every other
/// non-hex VM. The daemon assigns the id, not us, but keeping our names hex-safe
/// avoids feeding it anything pathological.
pub fn replica_name(deployment_id: &str, nonce: u64) -> String {
    format!("{OWNER_PREFIX}-{deployment_id}-{nonce:012x}")
}

/// Which deployment a sandbox belongs to, or `None` if it isn't ours.
pub fn owner_of(sandbox_name: &str) -> Option<&str> {
    let rest = sandbox_name.strip_prefix(OWNER_PREFIX)?.strip_prefix('-')?;
    // Trailing `-<nonce>` is ours; everything before it is the deployment id,
    // which may itself contain dashes.
    let (id, _nonce) = rest.rsplit_once('-')?;
    (!id.is_empty()).then_some(id)
}

#[derive(Debug)]
pub enum VmError {
    Sdk(heyo_sdk::HeyoError),
    /// The daemon reported a state that means this VM will never serve.
    NotRunning {
        sandbox_id: String,
        status: SandboxStatus,
        reason: Option<String>,
    },
    /// No `guest_ip`: the VM is unroutable by us. Happens for non-tap backends
    /// or a remote daemon.
    NoGuestIp {
        sandbox_id: String,
    },
    /// `guest_ip` was not parseable as an IP address.
    BadGuestIp {
        sandbox_id: String,
        value: String,
    },
    /// A guest mount has no tree on this host, so the VM would boot without the
    /// data its spec says it has. Refused rather than created: a replica missing
    /// a mount is a replica that answers health checks and then fails on the
    /// first request that needs the data, which is the failure mode this whole
    /// path exists to avoid.
    /// A template's `env_from` names a secret (or key) the store does not
    /// hold in the deployment's namespace. Refused before the daemon is asked,
    /// for the same reason a missing mount is.
    SecretUnresolved {
        env: String,
        detail: String,
    },
    MountNotPulled {
        path: String,
        digest: Option<String>,
    },
    /// A spec whose driver this manager cannot boot reached it anyway. heyvmd
    /// has no name for `lxc`, so the create body could not even be addressed.
    WrongRuntime {
        driver: String,
    },
    /// The runtime a deployment names exists, but not on this host — an `lxc`
    /// deployment on a host with no Incus. Distinct from [`Self::Runtime`],
    /// which is that runtime saying no: this one is fixed by the *operator*,
    /// not by the spec.
    RuntimeUnavailable {
        driver: String,
        detail: String,
    },
    /// A runtime other than heyvmd failed. Carried as a string because the
    /// error is that runtime's own type and nothing here can act on it beyond
    /// reporting it.
    Runtime(String),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sdk(e) => write!(f, "{e}"),
            Self::NotRunning {
                sandbox_id,
                status,
                reason,
            } => {
                write!(f, "sandbox {sandbox_id} is {status:?}, not running")?;
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::NoGuestIp { sandbox_id } => write!(
                f,
                "sandbox {sandbox_id} has no guest_ip; the daemon only exposes one for \
                 tap-networked firecracker/kvm backends running locally"
            ),
            Self::BadGuestIp { sandbox_id, value } => {
                write!(
                    f,
                    "sandbox {sandbox_id} reported unparseable guest_ip {value:?}"
                )
            }
            Self::SecretUnresolved { env, detail } => write!(
                f,
                "env_from for {env}: {detail} — `heyctl get secrets` lists what this namespace holds"
            ),
            Self::RuntimeUnavailable { driver, detail } => write!(
                f,
                "no {driver} runtime on this host: {detail}"
            ),
            Self::Runtime(detail) => write!(f, "{detail}"),
            Self::WrongRuntime { driver } => write!(
                f,
                "driver {driver} is not a heyvm driver; this sandbox cannot be created \
                 through the daemon"
            ),
            Self::MountNotPulled { path, digest } => match digest {
                Some(d) => write!(
                    f,
                    "the tree for guest mount {path} ({d}) is not on this host; run \
                     `POST /deployments/<id>/mounts/pull` to fetch it, or point the mount at \
                     a digest this host still holds"
                ),
                None => write!(
                    f,
                    "guest mount {path} has never been pulled; run \
                     `POST /deployments/<id>/mounts/pull` to resolve its ref and unpack it"
                ),
            },
        }
    }
}

impl std::error::Error for VmError {}

impl From<heyo_sdk::HeyoError> for VmError {
    fn from(e: heyo_sdk::HeyoError) -> Self {
        Self::Sdk(e)
    }
}

/// A daemon-side proxy bind of a VM port and the deployment it belongs to,
/// as the SDK types them.
pub use heyo_sdk::{ProxyBind, ProxyDeployment};

/// Live host + per-sandbox resource usage from the daemon's `GET /system/usage`,
/// as the SDK types it. Cheap to fetch — a cache read, not a per-VM probe —
/// and safe to poll on the reconcile tick.
pub use heyo_sdk::{SandboxUsage, SystemUsage};

/// How long to wait on the daemon for a guest's captured output.
///
/// Short, and much shorter than the SDK's 30s: this runs inside a reconcile
/// tick, and a diagnostic is not worth stalling the autoscaler for. Missing the
/// log costs one field on one error line; blocking the tick costs every
/// deployment on the host.
const GUEST_LOG_TIMEOUT: Duration = Duration::from_secs(3);

/// Cap on the rendered tail. A boot-timeout line becomes one record at the log
/// shipper, and a guest that spent five minutes printing a stack trace a second
/// must not turn one diagnostic into a megabyte.
const GUEST_LOG_MAX_CHARS: usize = 2000;


/// The defaults `heyo_sdk::Sandbox::create` fills in before posting, applied
/// here because this posts the body itself.
///
/// Replicated rather than skipped, and it is not cosmetic. `size_class` is the
/// one that bites: the daemon treats an absent size class as "no size class",
/// falls through to `cpus`/`memory` — which app-lb never sends — and boots a
/// Firecracker guest at **1 vCPU and 128 MB**. A spec that simply omitted
/// `size_class` would go from `small` to unusable, and the only symptom would be
/// guests that OOM under load.
///
/// `image` matters for the same reason in a quieter way: the SDK's default is
/// `ubuntu:24.04` and the daemon's own is `microsandbox/python`, so a spec with
/// no image would silently change operating systems.
///
/// Keep this in step with `augment_create_body` in the SDK.
/// Who a VM is metered to: the deployment's owner, as stamped on its spec by
/// the admin API (see `DeploymentSpec::account_id`).
///
/// Carried to the daemon as top-level `account_id` / `user_id` on the create
/// body, which a daemon that meters honours from a trusted caller and an older
/// one ignores. Both optional: a self-hosted app-lb stamps nothing and sends
/// nothing, so its create bodies are byte-for-byte what they were.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmOwner {
    pub account_id: Option<String>,
    pub user_id: Option<String>,
}

impl VmOwner {
    pub fn of(spec: &DeploymentSpec) -> Self {
        Self {
            account_id: spec.account_id.clone(),
            user_id: spec.user_id.clone(),
        }
    }
}

/// The daemon's create body for one replica: the template, the mounts as
/// trees the daemon holds, the owner, and — when the template names them —
/// the catalog image source and the workspace archive. Everything the SDK
/// types; the defaults every SDK create applies (`size_class: small` above
/// all — without it a Firecracker guest boots at 1 vCPU and 128 MB) are
/// [`Daemon::create`]'s to add.
fn create_request(
    spec: &VmSpec,
    name: String,
    open_ports: Vec<u16>,
    env_vars: Option<HashMap<String, String>>,
    mounts: Vec<DaemonMount>,
    owner: &VmOwner,
) -> DaemonCreateRequest {
    // A workspace archive turns the create into the daemon's from-archive
    // create: same body, plus the object key and the guest path to unpack at.
    // `DeploymentSpec::validate` has already refused an archive with no key.
    let archive_key = spec.workspace_archive.as_ref().and_then(|a| a.key().map(str::to_string));
    DaemonCreateRequest {
        name,
        driver: spec.driver.heyvm(),
        image: spec.image.clone(),
        start_command: spec.start_command.clone(),
        size_class: spec.size_class.map(|s| serde_json::to_value(s).ok()).flatten().and_then(|v| v.as_str().map(str::to_string)),
        disk_size_gb: spec.disk_size_gb.map(u64::from),
        working_directory: spec.working_directory.clone(),
        env_vars,
        setup_hooks: spec.setup_hooks.clone(),
        open_ports,
        // Backstop: if this LB dies without reaping, the VM still expires.
        ttl_seconds: Some(spec.ttl_seconds),
        mounts,
        account_id: owner.account_id.clone(),
        user_id: owner.user_id.clone(),
        // Where the daemon may fetch the image from when it does not hold it.
        // The daemon verifies the download against the size and digest; a
        // URL alone is still accepted, it just cannot be checked.
        image_download_url: spec.image_download_url.clone(),
        image_size_bytes: spec.image_download_url.as_ref().and(spec.image_size_bytes),
        image_sha256: spec.image_download_url.as_ref().and(spec.image_sha256.clone()),
        sandbox_path: archive_key.as_ref().map(|_| crate::config::DEFAULT_WORKSPACE_PATH.to_string()),
        s3_archive_key: archive_key,
        extra: rootfs_extra(spec),
        ..DaemonCreateRequest::default()
    }
}

/// Fields heyo-sdk 0.1.11's typed create body has no slot for yet, carried in
/// its flattened `extra` map. `rootfs_mode` is absent for the default, so a
/// copy-mode body is unchanged; a heyvm without per-sandbox rootfs modes
/// ignores the field and copies, which is the behaviour it already had.
fn rootfs_extra(spec: &VmSpec) -> serde_json::Map<String, serde_json::Value> {
    let mut extra = serde_json::Map::new();
    if let Some(mode) = spec.rootfs.daemon_mode() {
        extra.insert("rootfs_mode".into(), serde_json::Value::from(mode));
    }
    extra
}

/// What `DELETE /images/:name` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageDelete {
    /// Gone from the catalog (or never there).
    Deleted,
    /// The daemon had no such image.
    Missing,
    /// Still referenced by these sandboxes, live or inactive.
    InUse(Vec<String>),
    /// This heyvm has no image-delete route (`404`/`405` on the route itself).
    Unsupported,
}

/// A guest mount, resolved: the tree on this host, the id it is known to
/// the daemon by, and the mount the create body carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedMount {
    tree_id: String,
    tree: PathBuf,
    mount: DaemonMount,
}

/// A workspace tree to seed a replica from: where it is on this host, and
/// the id the daemon holds it under. See `workspace::Workspaces::seed_for_create`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSeed {
    pub tree_id: String,
    pub tree: PathBuf,
}

/// The daemon-side id of a tree on this host: its directory name, which the
/// mount store already makes content-addressed (`<digest>[-s<strip>]`).
fn tree_id_of(tree: &Path) -> String {
    tree.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A directory as a `tar.gz` stream, produced on a blocking thread as the
/// upload reads it. Symlinks are kept as symlinks — a workspace has them.
pub fn tar_gz_stream(dir: PathBuf) -> UploadStream {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(16);
    tokio::task::spawn_blocking(move || {
        struct ChannelWriter(tokio::sync::mpsc::Sender<std::io::Result<bytes::Bytes>>);
        impl std::io::Write for ChannelWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .blocking_send(Ok(bytes::Bytes::copy_from_slice(buf)))
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "upload closed"))?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let result = (|| -> std::io::Result<()> {
            let writer = std::io::BufWriter::with_capacity(1 << 20, ChannelWriter(tx.clone()));
            let gz = flate2::write::GzEncoder::new(writer, flate2::Compression::fast());
            let mut tar = tar::Builder::new(gz);
            tar.follow_symlinks(false);
            tar.append_dir_all(".", &dir)?;
            let gz = tar.into_inner()?;
            let mut writer = gz.finish()?;
            std::io::Write::flush(&mut writer)?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = tx.blocking_send(Err(e));
        }
    });
    Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

/// The last `lines` of guest output on one line, bounded.
///
/// One line because this becomes a tracing *field*, and a field that spans
/// twenty lines breaks every consumer that reads a record per line. The stream
/// is kept because which one a message came out of is most of the diagnosis: a
/// server announcing its port on stdout and a stack trace on stderr mean
/// opposite things about the same boot.
fn render_guest_log(logs: &[LogEntry], lines: usize) -> String {
    let start = logs.len().saturating_sub(lines);
    let mut out = String::new();
    for entry in &logs[start..] {
        let text = entry.message.trim();
        if text.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str(" | ");
        }
        if !entry.source.is_empty() {
            out.push_str(&entry.source);
            out.push_str(": ");
        }
        out.push_str(text);
        // Checked as it grows rather than truncated at the end, so the cap
        // cannot be overshot by one enormous final line.
        if out.chars().count() >= GUEST_LOG_MAX_CHARS {
            let kept: String = out.chars().take(GUEST_LOG_MAX_CHARS).collect();
            return format!("{kept}… (truncated)");
        }
    }
    out
}

/// How long a daemon call may take before it is abandoned. Unchanged from the
/// TCP-only client this replaced; a socket is faster, not more patient.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(30);

/// Talks to the heyvm daemon.
#[derive(Clone)]
pub struct VmManager {
    /// The daemon transport, built once and shared by every call here.
    ///
    /// One client rather than an options struct each call site rebuilds: a unix
    /// socket cannot be described by [`HeyoClientOptions`] — it has a URL and a
    /// socket has a path — so a client built by `local_auto_with` has to be
    /// passed through. Sharing it is also what makes the bearer uniform: the
    /// routes the SDK does not wrap used to carry their own copy of the key,
    /// which is a 401 on the diagnostics the moment the two drift apart.
    client: HeyoClient,
    /// The same client, as the daemon's typed routes.
    daemon: Daemon,
    /// What `client` ended up dialing, for the startup log. `base_url` cannot
    /// answer it — a socket client reports `http://localhost`.
    transport: String,
    /// Where a guest mount's tree lives on this host. Held here rather than
    /// passed in by the autoscaler so that a mount that has not been pulled
    /// fails the *create*, and therefore travels the create-failure path that
    /// already counts, reports and backs off — instead of needing a second one.
    mounts: MountStore,
}

/// `HeyoClient` is not `Debug`, and which daemon was reached is the half of
/// this struct worth printing anyway.
impl std::fmt::Debug for VmManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmManager")
            .field("transport", &self.transport)
            .field("mounts", &self.mounts)
            .finish()
    }
}

impl VmManager {
    /// Targets the local daemon, which is the only place `guest_ip` is
    /// available.
    ///
    /// With no `daemon_url`, prefers a unix socket: `HEYVM_SOCKET`, then
    /// `socket_path` from `~/.heyo/daemon.json`, each connect-verified before
    /// it is trusted — the daemon only clears that field on a graceful
    /// shutdown, so a crash leaves a path pointing at nothing. Falling back to
    /// `http://127.0.0.1:34099` costs nothing, because socket mode is additive
    /// on the daemon side: the TCP listener is there either way.
    ///
    /// An explicit `daemon_url` is an instruction, not a hint, and is honoured
    /// as given. It is how a non-default or remote daemon is named, and a
    /// local socket silently winning over it would quietly talk to the wrong
    /// machine.
    pub fn new(
        daemon_url: Option<String>,
        api_key: Option<String>,
        mounts: MountStore,
    ) -> Result<Self, VmError> {
        let explicit = daemon_url.is_some();
        let opts = HeyoClientOptions {
            base_url: daemon_url,
            api_key,
            timeout: Some(DAEMON_TIMEOUT),
        };
        let client = if explicit {
            HeyoClient::new(opts)?
        } else {
            HeyoClient::local_auto_with(opts)?
        };
        let transport = match client.socket_path() {
            Some(path) => format!("unix:{}", path.display()),
            None => client.base_url().to_string(),
        };
        Ok(Self {
            daemon: Daemon::new(client.clone()),
            client,
            transport,
            mounts,
        })
    }

    /// Which daemon endpoint this manager reached — a socket path or a URL.
    pub fn transport(&self) -> &str {
        &self.transport
    }

    pub(crate) fn prepare_allocation(&self, request: &DaemonCreateRequest, scope: &str) -> Result<crate::allocation::Prepared, VmError> {
        if self.client.api_key().is_none_or(|key| key.is_empty()) {
            return Err(VmError::Runtime("correlated creation requires internal service authentication".into()));
        }
        crate::allocation::prepare(request, &self.transport, scope).map_err(VmError::Runtime)
    }

    pub(crate) async fn submit_allocation(&self, prepared: &crate::allocation::Prepared) -> Result<crate::allocation::Receipt, VmError> {
        crate::allocation::submit(&self.client, &self.transport, prepared).await.map_err(VmError::Runtime)
    }

    pub(crate) async fn recover_allocation(&self, intent: &crate::allocation::Intent) -> Result<crate::allocation::Receipt, VmError> {
        crate::allocation::recover(&self.client, &self.transport, intent).await.map_err(VmError::Runtime)
    }

    async fn retirement_request(&self,target:&crate::retirement::Target,operation:Option<&str>) -> Result<serde_json::Value,String> {
        let key=self.client.api_key().filter(|v|!v.is_empty()).ok_or("backend retirement requires service authentication")?;
        let mut builder=reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never()).timeout(std::time::Duration::from_secs(30));
        #[cfg(unix)]
        if let Some(socket)=self.client.socket_path() {builder=builder.unix_socket(socket.to_path_buf());}
        let client=builder.build().map_err(|_|"cannot build exact retirement transport")?;
        let url=format!("{}/sandboxes/{}/retirement",self.client.base_url().trim_end_matches('/'),target.backend_sandbox_id);
        let request=match operation {
            Some(id)=>client.post(&url).json(&serde_json::json!({"operationId":id,"target":target})),
            None=>client.get(&url),
        };
        let mut response=request.bearer_auth(key).send().await.map_err(|_|"retirement transport outcome unknown")?;
        if response.status()!=reqwest::StatusCode::OK {return Err("backend has not confirmed retirement".into());}
        let mut bytes=Vec::new();
        while let Some(chunk)=response.chunk().await.map_err(|_|"retirement response incomplete")? {
            if bytes.len()+chunk.len()>65536 {return Err("retirement response exceeds limit".into());}
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_|"invalid retirement response".into())
    }

    /// Require the lifecycle-locked host receipt; ordinary NotFound is not
    /// evidence that all Firecracker state was reclaimed.
    pub async fn firecracker_reclaimed(&self, sandbox_id: &str) -> Result<bool, String> {
        if !crate::disks::valid_sandbox_id(sandbox_id) { return Err("invalid sandbox identity".into()); }
        let key = self.client.api_key().filter(|v| !v.is_empty()).ok_or("reclamation receipt requires service authentication")?;
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never()).timeout(Duration::from_secs(10));
        #[cfg(unix)]
        if let Some(socket) = self.client.socket_path() { builder = builder.unix_socket(socket.to_path_buf()); }
        let client = builder.build().map_err(|_| "cannot build exact reclamation transport")?;
        let url = format!("{}/sandboxes/{}/firecracker-reclamation", self.client.base_url().trim_end_matches('/'), sandbox_id);
        let response = client.get(url).bearer_auth(key).send().await.map_err(|_| "reclamation receipt unavailable")?;
        if response.status() != reqwest::StatusCode::OK { return Err("reclamation receipt unavailable".into()); }
        #[derive(serde::Deserialize)]
        struct Receipt { protocol: String, sandbox_id: String, reclaimed: bool }
        let receipt: Receipt = response.json().await.map_err(|_| "invalid reclamation receipt")?;
        Ok(receipt.protocol == "firecracker-reclamation-v1" && receipt.sandbox_id == sandbox_id && receipt.reclaimed)
    }

    /// The tail of what a guest itself printed, as the daemon captured it.
    ///
    /// heyvmd starts vsock forwarders inside the guest before it runs the start
    /// command, piping the workload's `/var/log/heyvm-start.log` and
    /// `heyvm-start.err.log` into a per-sandbox ring buffer it serves at
    /// `GET /sandboxes/:id/logs`. `heyo_sdk` wraps exec, shell and the lifecycle
    /// but not that route, so this goes through the client's raw request helper
    /// — same transport and same bearer as everything else here.
    ///
    /// **Best-effort by construction**: an unreachable daemon, a guest with no
    /// `socat` or `/dev/vsock` to run the forwarders, a response shape we do not
    /// recognise — all return `None`. Every caller is already reporting a
    /// failure, and a diagnostic that can turn into a second failure is worse
    /// than no diagnostic at all.
    ///
    /// Call it while the sandbox still exists: the ring buffer belongs to the
    /// sandbox and goes when it does.
    pub async fn guest_log_tail(&self, sandbox_id: &str, lines: usize) -> Option<String> {
        // The id reaches the daemon inside a URL path. It comes from the daemon
        // in the first place, but it is validated rather than escaped here for
        // the same reason the disk routes validate it: refusing an id that
        // cannot be one is a smaller surface than getting the escaping right.
        if !crate::disks::valid_sandbox_id(sandbox_id) {
            return None;
        }
        let query = LogsQuery {
            limit: Some(lines),
            ..LogsQuery::default()
        };
        let body = match tokio::time::timeout(GUEST_LOG_TIMEOUT, self.daemon.logs(sandbox_id, &query)).await {
            Ok(Ok(body)) => body,
            // Both are ordinary here — an older daemon has no such route, and a
            // sandbox killed between the decision and this call is gone. Debug,
            // not warn: the caller's own error line is the event.
            Ok(Err(e)) => {
                tracing::debug!(sandbox = %sandbox_id, error = %e, "no guest logs");
                return None;
            }
            Err(_) => {
                tracing::debug!(sandbox = %sandbox_id, "guest log fetch timed out");
                return None;
            }
        };

        Some(render_guest_log(&body.logs, lines)).filter(|s| !s.is_empty())
    }

    /// Every sandbox the daemon knows about.
    ///
    /// Callers should hit this **once per reconcile tick** and index the result:
    /// `Sandbox::info()` fetches this same full list and filters client-side, so
    /// per-VM polling is quadratic.
    pub async fn list(&self) -> Result<Vec<SandboxInfo>, VmError> {
        Ok(self.list_detailed().await?.sandboxes)
    }

    /// [`Self::list`], plus what the SDK's [`SandboxInfo`] does not carry.
    ///
    /// The daemon's listing says whose sandbox each one is (`account_id`) and
    /// when it was created; the SDK struct predates both fields and drops them
    /// on the floor. Rather than pin a newer SDK for two strings, the raw JSON
    /// is read once, the SDK's own type is deserialized from it — so what the
    /// autoscaler sees is exactly what it always saw — and the extras are
    /// picked off beside it. One request, not two.
    pub async fn list_detailed(&self) -> Result<Listing, VmError> {
        Ok(Listing::from_infos(self.daemon.list().await?))
    }

    /// Create a VM and return immediately, without waiting for boot.
    ///
    /// Returning immediately is deliberate: the autoscaler must not block its
    /// reconcile loop for the ~minutes a VM can take. Readiness is tracked
    /// across subsequent ticks instead.
    ///
    /// Posts the create body directly rather than going through
    /// `Sandbox::create`, because `SandboxCreateOptions` has no `mounts` field
    /// and the daemon's `CreateSandboxRequest` does. The body is still that
    /// struct's own serialization — see [`sdk_create_defaults`] for the four
    /// fields the SDK would have added, and why leaving them out would quietly
    /// change what boots.
    ///
    /// Fails before touching the daemon if any of the spec's mounts has no tree
    /// on this host; see [`VmError::MountNotPulled`].
    ///
    /// `workspace` is the deployment's workspace tree, when it has one — see
    /// [`crate::workspace`]. It goes **last** in the mount list, writable, so
    /// its image index on the daemon is `spec.mounts.len()`; the capture path
    /// relies on that to find the image again.
    ///
    /// `owner` is who the VM is metered to — see [`VmOwner`].
    pub async fn create(
        &self,
        spec: &VmSpec,
        name: String,
        workspace: Option<&WorkspaceSeed>,
        owner: &VmOwner,
        secret_env: HashMap<String, String>,
    ) -> Result<Sandbox, VmError> {
        let req = self.prepare_create(spec, name, workspace, owner, secret_env).await?;
        // Readiness is tracked across reconcile ticks, not by this request.
        let created = self.daemon.create(&req).await?;
        Ok(self.daemon.sandbox(&created.id))
    }

    /// Resolve mounts and secrets before choosing the allocation protocol.
    /// This may upload immutable trees, but does not allocate a sandbox.
    pub(crate) async fn prepare_create(
        &self,
        spec: &VmSpec,
        name: String,
        workspace: Option<&WorkspaceSeed>,
        owner: &VmOwner,
        secret_env: HashMap<String, String>,
    ) -> Result<DaemonCreateRequest, VmError> {
        // `validate` refuses these at registration, so this is unreachable in
        // practice — but it was a `debug_assert` before, which compiled out in
        // release. Now that the type can say it, say it for real: creating a
        // container's worth of VM on the wrong daemon is not a debug concern.
        if spec.driver.heyvm().is_none() {
            return Err(VmError::WrongRuntime {
                driver: spec.driver.to_string(),
            });
        }

        // The proxied port must be open, plus whatever else the spec asks for.
        let mut open_ports = spec.open_ports.clone();
        if !open_ports.contains(&spec.port) {
            open_ports.push(spec.port);
        }

        // Literal env plus the resolved secrets, with a secret winning over a
        // literal of the same name — the same rule `update.env_from` follows.
        let env_vars = if secret_env.is_empty() {
            spec.env_vars.clone()
        } else {
            let mut env = spec.env_vars.clone().unwrap_or_default();
            env.extend(secret_env);
            Some(env)
        };

        // Resolved before the request, so a deployment whose mounts have not
        // been pulled fails without asking the daemon for anything.
        let mut resolved = self.guest_mounts(spec)?;
        if let (Some(seed), Some(ws)) = (workspace, spec.workspace.as_ref()) {
            resolved.push(ResolvedMount {
                tree_id: seed.tree_id.clone(),
                tree: seed.tree.clone(),
                mount: DaemonMount::from_tree(seed.tree_id.clone(), ws.guest_path(), false),
            });
        }
        // Every tree the daemon does not hold yet goes up first. Content-
        // addressed ids make the check cheap and the upload one-time.
        for m in &resolved {
            self.ensure_tree(&m.tree_id, &m.tree).await?;
        }
        let mounts: Vec<DaemonMount> = resolved.into_iter().map(|m| m.mount).collect();

        Ok(create_request(spec, name, open_ports, env_vars, mounts, owner))
    }

    /// The daemon's `mounts` array for a spec: one host directory per guest
    /// mount, in spec order.
    ///
    /// Order is load-bearing. heyvmd letters the devices `/dev/vdb`, `/dev/vdc`
    /// … in exactly this order and mounts them in it, so two mounts swapping
    /// places between one create and the next would hand a restarted replica a
    /// different filesystem under the same path.
    fn guest_mounts(&self, spec: &VmSpec) -> Result<Vec<ResolvedMount>, VmError> {
        spec.mounts
            .iter()
            .map(|mount| {
                let tree =
                    self.mounts
                        .resolve(mount)
                        .ok_or_else(|| VmError::MountNotPulled {
                            path: mount.guest_path().to_string(),
                            digest: mount.digest.clone(),
                        })?;
                let tree_id = tree_id_of(&tree);
                Ok(ResolvedMount {
                    mount: DaemonMount::from_tree(tree_id.clone(), mount.guest_path(), mount.read_only),
                    tree_id,
                    tree,
                })
            })
            .collect()
    }

    pub fn connect(&self, sandbox_id: String) -> Result<Sandbox, VmError> {
        Ok(Sandbox::connect_with_client(self.client.clone(), sandbox_id))
    }

    /// Fetch the daemon's cached host + per-sandbox usage snapshot.
    ///
    /// Like `list`, this is a single daemon round-trip meant for once-per-tick
    /// use — the daemon already samples in the background, so this just reads
    /// its cache. There is no typed SDK method for it, so we go through the
    /// client's generic request helper.
    pub async fn system_usage(&self) -> Result<SystemUsage, VmError> {
        Ok(self.daemon.system_usage().await?)
    }

    /// `GET /storage`: the daemon's disk inventory and free space.
    pub async fn storage(&self) -> Result<StorageInventory, VmError> {
        Ok(self.daemon.storage().await?)
    }

    /// `DELETE /storage/sandboxes/:id?parts=`: remove a stopped sandbox's
    /// disks on the daemon. A sandbox with nothing on disk is a no-op.
    pub async fn purge_disks(&self, sandbox_id: &str, parts: PurgeParts) -> Result<PurgeOutcome, VmError> {
        Ok(self.daemon.purge_disks(sandbox_id, parts).await?)
    }

    /// `GET /storage/sandboxes/:id/archive`: the sandbox's state as a
    /// `tar.gz` stream, for the archive pipe.
    pub async fn archive_disks(&self, sandbox_id: &str) -> Result<reqwest::Response, VmError> {
        Ok(self.daemon.archive_disks(sandbox_id).await?)
    }

    /// `GET /sandboxes/:id/mounts/export`: the contents of a stopped
    /// sandbox's mount as a `tar.gz` stream, for a workspace capture.
    pub async fn export_mount(&self, sandbox_id: &str, sandbox_path: &str) -> Result<reqwest::Response, VmError> {
        Ok(self.daemon.export_mount(sandbox_id, sandbox_path).await?)
    }

    /// Put a directory on the daemon as a tree, unless it already has one
    /// by that id. Content-addressed ids make this a cheap check most of the
    /// time and a one-time upload the rest.
    pub async fn ensure_tree(&self, id: &str, dir: &Path) -> Result<TreeInfo, VmError> {
        if let Some(existing) = self.daemon.tree(id).await? {
            return Ok(existing);
        }
        let stream = tar_gz_stream(dir.to_path_buf());
        Ok(self.daemon.upload_tree(id, stream).await?)
    }

    /// `DELETE /trees/:id`.
    pub async fn delete_tree(&self, id: &str) -> Result<(), VmError> {
        Ok(self.daemon.delete_tree(id).await?)
    }

    /// The daemon's catalog entry for an image, if it has one.
    pub async fn image(&self, name: &str) -> Result<Option<ImageInfo>, VmError> {
        Ok(self.daemon.image(name).await?)
    }

    /// `GET /images`: every image in the daemon's catalog.
    pub async fn list_images(&self) -> Result<Vec<ImageInfo>, VmError> {
        Ok(self.daemon.list_images().await?)
    }

    /// `DELETE /images/:name`.
    ///
    /// Not in heyo-sdk 0.1.11, so sent raw. heyvm answers `204` once the file
    /// is gone, `404` with no such image, and `409 {error, sandboxes}` while a
    /// sandbox still references it. A heyvm that predates the route also
    /// answers `404` (or `405`), indistinguishable from "no such image" by
    /// status alone — so the caller asks only about an image it has just seen
    /// in the catalog, and a `404` for one is read as the route missing.
    pub async fn delete_image(&self, name: &str, known_present: bool) -> Result<ImageDelete, VmError> {
        if !crate::images::is_catalog_name(name) {
            return Err(VmError::Runtime(format!("{name:?} is not an image name heyvm would hold")));
        }
        let resp = self
            .client
            .raw_request(
                reqwest::Method::DELETE,
                &format!("/images/{name}"),
                None::<&()>,
                heyo_sdk::RequestOptions::default(),
            )
            .await?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        Ok(match status {
            200..=299 => ImageDelete::Deleted,
            404 if known_present => ImageDelete::Unsupported,
            404 => ImageDelete::Missing,
            405 | 501 => ImageDelete::Unsupported,
            409 => ImageDelete::InUse(
                body.get("sandboxes")
                    .and_then(|s| s.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default(),
            ),
            other => {
                let detail = body.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string();
                return Err(VmError::Runtime(format!("DELETE /images/{name} answered {other}: {detail}")));
            }
        })
    }

    /// Put an ext4 rootfs on this host into the daemon's catalog as `name`.
    pub async fn upload_image(&self, name: &str, path: &Path, opts: &ImageUploadOptions) -> Result<ImageInfo, VmError> {
        let stream = heyo_sdk::file_stream(path).await?;
        Ok(self.daemon.upload_image(name, stream, opts).await?)
    }

    /// The daemon-side proxy binds of a VM: `GET /sandboxes/{id}/proxy`.
    pub async fn binds(&self, sandbox_id: &str) -> Result<Vec<ProxyBind>, VmError> {
        Ok(self.daemon.list_binds(sandbox_id).await?)
    }

    /// Bind a VM's port on the daemon as a proxy endpoint that is a member of
    /// `deployment`, and return the subdomain the daemon minted for it.
    ///
    /// The daemon carries the bind to the cloud; the cloud's URL for the
    /// deployment fans out to every member bind. This is app-lb's whole part
    /// in a cloud URL — see [`crate::config::IngressSpec`].
    ///
    /// Idempotent: a bind for the same port and deployment that the daemon
    /// already holds — from before an app-lb restart, say — is reused rather
    /// than doubled, since the daemon mints a fresh subdomain per call.
    pub async fn bind(
        &self,
        sandbox_id: &str,
        port: u16,
        public: bool,
        deployment: &ProxyDeployment,
    ) -> Result<String, VmError> {
        if let Some(existing) = self
            .binds(sandbox_id)
            .await?
            .into_iter()
            .find(|b| b.port == port && b.deployment.as_ref() == Some(deployment))
        {
            return Ok(existing.subdomain);
        }
        let created = self
            .daemon
            .bind(
                sandbox_id,
                &BindRequest {
                    port,
                    is_public: public,
                    deployment: Some(deployment.clone()),
                },
            )
            .await?;
        Ok(created.subdomain)
    }

    /// Withdraw a bind. A bind (or VM) the daemon has already forgotten
    /// counts as withdrawn.
    pub async fn unbind(&self, sandbox_id: &str, subdomain: &str) -> Result<(), VmError> {
        Ok(self.daemon.unbind(sandbox_id, subdomain).await?)
    }

    /// Destroy a VM. A VM the daemon has already forgotten counts as killed.
    pub async fn kill(&self, sandbox_id: &str) -> Result<(), VmError> {
        match self.connect(sandbox_id.to_string()) {
            Ok(sandbox) => match sandbox.kill().await {
                Ok(()) => Ok(()),
                Err(heyo_sdk::HeyoError::NotFound(_)) => Ok(()),
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e),
        }
    }

    /// Keep a VM's TTL backstop from expiring under a long-lived deployment.
    pub async fn renew_ttl(&self, sandbox_id: &str, ttl_seconds: u64) -> Result<(), VmError> {
        let sandbox = self.connect(sandbox_id.to_string())?;
        match sandbox.set_ttl(ttl_seconds).await {
            Ok(()) => Ok(()),
            Err(heyo_sdk::HeyoError::NotFound(_)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Run one command in a VM and wait for it to finish.
    ///
    /// `POST /sandbox/:id/exec` daemon-side, which runs the string through
    /// `sh -c`. There is no streaming and no way to cancel: whatever the guest
    /// prints is buffered until it exits, so `options.timeout` is the only thing
    /// bounding a command that never returns.
    pub async fn exec(
        &self,
        sandbox_id: &str,
        command: &str,
        options: CommandRunOptions,
    ) -> Result<CommandResult, VmError> {
        let sandbox = self.connect(sandbox_id.to_string())?;
        Ok(sandbox.commands().run(command, options).await?)
    }

    /// Open an interactive PTY on a VM.
    ///
    /// Returns once the daemon has answered the session handshake, so a failure
    /// to attach surfaces here rather than as a socket that closes immediately.
    /// The session carries its own sequence/ack and reconnect handling.
    pub async fn shell(
        &self,
        sandbox_id: &str,
        options: ShellOptions,
    ) -> Result<ShellSession, VmError> {
        let sandbox = self.connect(sandbox_id.to_string())?;
        Ok(sandbox.shell(options).await?)
    }

    /// Stop a VM without destroying it — `scaling.idle_action: retain`.
    ///
    /// The sandbox record and its `/workspace` data disk survive; memory does
    /// not. Rootfs writes do not survive either, but the two drivers get there
    /// differently: Firecracker's per-boot copy lives in `/tmp` and is recopied
    /// from the base image on every boot, while the KVM driver *would* reuse a
    /// persisted `kvm/<id>/rootfs.ext4` if one still existed — which is why the
    /// autoscaler discards that copy right after a successful suspend (see
    /// [`crate::disks::discard_rootfs`]), so a replica behaves the same on both
    /// drivers and a scaled-to-zero pool is not parking a gigabyte per VM.
    ///
    /// **A stopped sandbox disappears from [`list`](Self::list).** mvm-ctrl's
    /// `stop` removes it from the in-memory map that backs `GET /sandboxes`, so
    /// after this returns the daemon will not mention this sandbox again until
    /// it is resumed. Whoever calls this owns remembering the id — see
    /// [`list_inactive`](Self::list_inactive) — or the VM is leaked, still
    /// holding its disk, with nothing left to reap it.
    pub async fn suspend(&self, sandbox_id: &str) -> Result<(), VmError> {
        let sandbox = self.connect(sandbox_id.to_string())?;
        match sandbox.stop().await {
            Ok(()) => Ok(()),
            // Already gone: the caller wanted it not running, and it isn't.
            Err(heyo_sdk::HeyoError::NotFound(_)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Restart a suspended VM and wait for the daemon to call it `Running`.
    ///
    /// The status check is not optional. `Sandbox::start` answers as soon as the
    /// daemon accepts the request, and `wait_for_ready` cannot be used to
    /// confirm the outcome — it has a `_ => return Ok(info)` arm, so a sandbox
    /// that failed to come back reports `Stopped` *and* `Ok`. Reading the status
    /// ourselves is what turns that into an error.
    ///
    /// Returns the info for the resumed VM; the caller still has to health-probe
    /// the guest, exactly as it would after a cold boot.
    pub async fn resume(&self, sandbox_id: &str) -> Result<SandboxInfo, VmError> {
        let sandbox = self.connect(sandbox_id.to_string())?;
        sandbox.start().await?;
        let info = sandbox.info().await?;
        if info.status != SandboxStatus::Running {
            return Err(VmError::NotRunning {
                sandbox_id: info.id.clone(),
                status: info.status.clone(),
                reason: info.error_message.clone(),
            });
        }
        Ok(info)
    }

    /// Every sandbox the daemon has *stopped but not deleted*.
    ///
    /// The counterpart to [`list`](Self::list), which only reports running ones.
    /// There is no SDK method for this, so it goes through the client's generic
    /// request helper against `GET /sandboxes/inactive`.
    ///
    /// **Expensive.** The daemon answers it by walking its persistence directory
    /// and loading metadata per sandbox — every sandbox ever created, not just
    /// the stopped ones — and it is cursor-paginated with a default page of 10.
    /// This pages to the end, so it belongs on a slow sweep and never on the
    /// reconcile tick. `max_pages` bounds a cursor that fails to advance.
    pub async fn list_inactive(&self) -> Result<Vec<SandboxInfo>, VmError> {
        const PAGE: usize = 200;
        const MAX_PAGES: usize = 200;

        let mut out = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let page = self.daemon.list_inactive(PAGE, cursor.as_deref()).await?;
            let empty = page.sandboxes.is_empty();
            out.extend(page.sandboxes.into_iter().map(InactiveSandbox::into_info));
            match page.next_cursor {
                // A cursor that repeats itself would loop forever.
                Some(next) if !empty && Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => return Ok(out),
            }
        }
        tracing::warn!(
            pages = MAX_PAGES,
            "inactive sandbox listing did not terminate; treating it as complete",
        );
        Ok(out)
    }
}

#[async_trait::async_trait]
impl crate::retirement::Backend for VmManager {
    async fn status(&self,target:&crate::retirement::Target)->Result<serde_json::Value,String> {
        self.retirement_request(target,None).await
    }
    async fn retire(&self,operation:&str,target:&crate::retirement::Target)->Result<serde_json::Value,String> {
        self.retirement_request(target,Some(operation)).await
    }
}

/// `GET /deployed-sandboxes`, as the autoscaler consumes it: the SDK's
/// `SandboxInfo` per VM, plus the two host-only fields the dashboard scopes
/// and dates by. Both now ride on `SandboxInfo` itself; `details` remains
/// so callers that index by id keep their shape.
#[derive(Debug, Default)]
pub struct Listing {
    pub sandboxes: Vec<SandboxInfo>,
    pub details: HashMap<String, SandboxDetail>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxDetail {
    pub account_id: Option<String>,
    pub created_at: Option<String>,
}

impl Listing {
    pub fn from_infos(sandboxes: Vec<SandboxInfo>) -> Self {
        let details = sandboxes
            .iter()
            .map(|info| {
                (
                    info.id.clone(),
                    SandboxDetail {
                        account_id: info.account_id.clone(),
                        created_at: info.created_at.clone(),
                    },
                )
            })
            .collect();
        Self { sandboxes, details }
    }
}

/// Extract the routable address, rejecting anything we could not proxy to.
///
/// This is where the two SDK traps are enforced together: a VM is only routable
/// if it is *actually* `Running` and *actually* has a `guest_ip`.
pub fn routable_addr(info: &SandboxInfo, port: u16) -> Result<SocketAddr, VmError> {
    if info.status != SandboxStatus::Running {
        return Err(VmError::NotRunning {
            sandbox_id: info.id.clone(),
            status: info.status.clone(),
            reason: info.error_message.clone(),
        });
    }
    let Some(raw) = info.guest_ip.as_deref().filter(|s| !s.is_empty()) else {
        return Err(VmError::NoGuestIp {
            sandbox_id: info.id.clone(),
        });
    };
    let ip: IpAddr = raw.parse().map_err(|_| VmError::BadGuestIp {
        sandbox_id: info.id.clone(),
        value: raw.to_string(),
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// Whether a status means the VM will never serve and should be reaped, as
/// opposed to still being on its way up.
pub fn is_terminal(status: &SandboxStatus) -> bool {
    match status {
        // Still booting, or the daemon hasn't classified it yet.
        SandboxStatus::Provisioning | SandboxStatus::Unknown | SandboxStatus::Running => false,
        // Against a local daemon a broken VM shows up as Stopped, not Failed,
        // so Stopped has to count as terminal for a VM we just asked to start.
        SandboxStatus::Stopped
        | SandboxStatus::Paused
        | SandboxStatus::Failed
        | SandboxStatus::ColdStored => true,
    }
}

/// Index a sandbox list by id for O(1) lookup during reconcile.
pub fn index_by_id(infos: Vec<SandboxInfo>) -> HashMap<String, SandboxInfo> {
    infos.into_iter().map(|i| (i.id.clone(), i)).collect()
}

#[cfg(test)]
mod guest_log_tests {
    use super::*;

    fn line(source: Option<&str>, message: &str) -> LogEntry {
        LogEntry {
            timestamp: 0,
            source: source.unwrap_or_default().to_string(),
            level: None,
            message: message.into(),
        }
    }

    /// The tail, and the stream each line came from — a server announcing its
    /// port and a stack trace mean opposite things about the same boot.
    #[test]
    fn keeps_the_last_lines_and_says_which_stream_they_came_from() {
        let logs = vec![
            line(Some("stdout"), "starting"),
            line(Some("stdout"), "migrations ok"),
            line(Some("stderr"), "connection refused"),
        ];
        assert_eq!(
            render_guest_log(&logs, 2),
            "stdout: migrations ok | stderr: connection refused",
        );
    }

    /// A daemon that stops sending `source` still has to produce a message.
    #[test]
    fn a_line_with_no_stream_still_renders() {
        assert_eq!(render_guest_log(&[line(None, "boom")], 5), "boom");
    }

    /// Fewer lines than asked for is the normal case for a guest that died early.
    #[test]
    fn asking_for_more_than_there_is_returns_what_there_is() {
        assert_eq!(
            render_guest_log(&[line(Some("stderr"), "boom")], 20),
            "stderr: boom"
        );
    }

    /// Blank lines are padding in a terminal and noise in a log field.
    #[test]
    fn empty_lines_are_dropped_rather_than_joined_as_gaps() {
        let logs = vec![
            line(Some("stdout"), "a"),
            line(Some("stdout"), "   "),
            line(Some("stdout"), "b"),
        ];
        assert_eq!(render_guest_log(&logs, 10), "stdout: a | stdout: b");
    }

    /// Nothing captured is not an empty string dressed up as output —
    /// `guest_log_tail` turns this into `None` and the caller says why.
    #[test]
    fn nothing_captured_renders_to_nothing() {
        assert!(render_guest_log(&[], 20).is_empty());
        assert!(render_guest_log(&[line(Some("stdout"), "")], 20).is_empty());
    }

    /// One enormous final line must not overshoot the cap — the check runs as
    /// the string grows, not once at the end.
    #[test]
    fn a_single_huge_line_is_still_bounded() {
        let huge = "x".repeat(GUEST_LOG_MAX_CHARS * 3);
        let out = render_guest_log(&[line(Some("stderr"), &huge)], 20);
        assert!(out.ends_with("… (truncated)"), "{}", &out[out.len() - 40..]);
        assert!(
            out.chars().count() <= GUEST_LOG_MAX_CHARS + "… (truncated)".chars().count(),
            "{} chars",
            out.chars().count(),
        );
    }

    /// Truncation counts characters, not bytes: slicing a multi-byte guest
    /// message on a byte boundary would panic on the failure path.
    #[test]
    fn truncation_does_not_split_a_multibyte_character() {
        let huge = "é".repeat(GUEST_LOG_MAX_CHARS * 2);
        let out = render_guest_log(&[line(Some("stderr"), &huge)], 20);
        assert!(out.ends_with("… (truncated)"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::config::{Driver, MountSpec};

    /// A mount store over a directory that does not exist, which is all the
    /// tests that never resolve a mount need.
    fn test_mounts() -> MountStore {
        MountStore::new(std::path::PathBuf::from("/nonexistent/app-lb-mounts"), 0)
    }

    fn mount(path: &str, digest: Option<&str>) -> MountSpec {
        MountSpec {
            path: path.into(),
            store: "/srv/art".into(),
            artifact_ref: "corpus".into(),
            auth: None,
            strip_components: None,
            read_only: true,
            digest: digest.map(Into::into),
        }
    }

    fn spec_with(mounts: Vec<MountSpec>) -> VmSpec {
        VmSpec {
            correlated_creates: false,
            env_from: vec![],
            workspace_archive: None,
            image_download_url: None,
            image_size_bytes: None,
            image_sha256: None,
            driver: Driver::Firecracker,
            image: None,
            rootfs: Default::default(),
            port: 8080,
            start_command: None,
            size_class: None,
            disk_size_gb: None,
            working_directory: None,
            env_vars: None,
            setup_hooks: None,
            open_ports: vec![],
            mounts,
            workspace: None,
            ttl_seconds: 3600,
        }
    }

    fn info(id: &str, status: SandboxStatus, guest_ip: Option<&str>) -> SandboxInfo {
        SandboxInfo {
            id: id.into(),
            name: id.into(),
            status,
            image: "ubuntu:24.04".into(),
            region: None,
            start_command: None,
            working_directory: None,
            size_class: None,
            // Added to `SandboxInfo` after 0.1.6; unset for the same
            // reason the rest of these are — nothing here reads it.
            disk_size_gb: None,
            env_vars: None,
            setup_hooks: None,
            uptime_secs: 0,
            ttl_seconds: None,
            is_deployed: true,
            error_message: None,
            status_changed_at: String::new(),
            urls: vec![],
            guest_ip: guest_ip.map(Into::into),
            metadata: None,
            account_id: None,
            created_at: None,
            cpus: None,
            memory: None,
            backend_type: None,
        }
    }

    #[test]
    fn daemon_api_key_reaches_every_daemon_request() {
        let manager = VmManager::new(
            Some("http://host.internal:3000".into()),
            Some("service-token".into()),
            test_mounts(),
        )
        .unwrap();

        // One client serves the lifecycle calls and the guest-log diagnostics
        // alike, so the bearer cannot reach one and miss the other. The
        // separate request builder this replaced had to be kept in step with
        // `opts.api_key` by hand, and a drift there was a silent 401 on
        // exactly the path you reach for when something is already wrong.
        assert_eq!(manager.client.api_key(), Some("service-token"));
        assert_eq!(manager.transport(), "http://host.internal:3000");
    }

    #[test]
    fn an_explicit_daemon_url_is_never_traded_for_a_socket() {
        // Holds even on a host serving a live socket: a named address is how a
        // non-default or remote daemon is reached, so preferring a local
        // socket over it would quietly talk to the wrong machine.
        let manager =
            VmManager::new(Some("http://127.0.0.1:34099".into()), None, test_mounts()).unwrap();

        assert_eq!(manager.transport(), "http://127.0.0.1:34099");
        assert!(manager.client.socket_path().is_none());
    }

    #[test]
    fn routable_addr_accepts_running_vm_with_guest_ip() {
        let i = info("sb-1", SandboxStatus::Running, Some("172.16.0.2"));
        assert_eq!(
            routable_addr(&i, 8080).unwrap(),
            "172.16.0.2:8080".parse::<SocketAddr>().unwrap()
        );
    }

    /// The trap: wait_for_ready returns Ok for a Stopped VM, so this check is
    /// the only thing standing between a dead VM and the pool.
    #[test]
    fn routable_addr_rejects_non_running_even_with_an_ip() {
        for status in [
            SandboxStatus::Stopped,
            SandboxStatus::Paused,
            SandboxStatus::Provisioning,
            SandboxStatus::Failed,
            SandboxStatus::ColdStored,
        ] {
            let i = info("sb-1", status, Some("172.16.0.2"));
            assert!(
                matches!(routable_addr(&i, 8080), Err(VmError::NotRunning { .. })),
                "expected NotRunning",
            );
        }
    }

    #[test]
    fn routable_addr_rejects_missing_or_empty_guest_ip() {
        let i = info("sb-1", SandboxStatus::Running, None);
        assert!(matches!(
            routable_addr(&i, 8080),
            Err(VmError::NoGuestIp { .. })
        ));

        let i = info("sb-1", SandboxStatus::Running, Some(""));
        assert!(matches!(
            routable_addr(&i, 8080),
            Err(VmError::NoGuestIp { .. })
        ));
    }

    #[test]
    fn routable_addr_rejects_garbage_guest_ip() {
        let i = info("sb-1", SandboxStatus::Running, Some("not-an-ip"));
        assert!(matches!(
            routable_addr(&i, 8080),
            Err(VmError::BadGuestIp { .. })
        ));
    }

    #[test]
    fn terminal_states_are_reaped_and_transient_ones_are_not() {
        assert!(!is_terminal(&SandboxStatus::Provisioning));
        assert!(!is_terminal(&SandboxStatus::Running));
        assert!(!is_terminal(&SandboxStatus::Unknown));
        assert!(is_terminal(&SandboxStatus::Stopped));
        assert!(is_terminal(&SandboxStatus::Failed));
        assert!(is_terminal(&SandboxStatus::Paused));
        assert!(is_terminal(&SandboxStatus::ColdStored));
    }

    #[test]
    fn replica_names_round_trip_through_owner_of() {
        let n = replica_name("demo", 42);
        assert_eq!(owner_of(&n), Some("demo"));
        // Deployment ids containing dashes survive.
        let n = replica_name("my-app-v2", 7);
        assert_eq!(owner_of(&n), Some("my-app-v2"));
    }

    #[test]
    fn replica_nonce_is_hex_to_stay_clear_of_subnet_derivation() {
        let n = replica_name("demo", 0xdead_beef);
        assert!(n.ends_with("0000deadbeef"), "got {n}");
    }

    #[test]
    fn owner_of_ignores_foreign_sandboxes() {
        assert_eq!(owner_of("some-other-vm"), None);
        assert_eq!(owner_of("applb"), None);
        assert_eq!(owner_of("applb-"), None);
        // No nonce segment => not one of ours.
        assert_eq!(owner_of("applb-demo"), None);
    }

    #[test]
    fn index_by_id_builds_a_lookup() {
        let idx = index_by_id(vec![
            info("sb-1", SandboxStatus::Running, Some("172.16.0.2")),
            info("sb-2", SandboxStatus::Stopped, None),
        ]);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx["sb-1"].status, SandboxStatus::Running);
    }

    // -- guest mounts ------------------------------------------------------

    fn store_holding(digests: &[(&str, usize)]) -> (std::path::PathBuf, MountStore) {
        let root = std::env::temp_dir().join(format!(
            "app-lb-vm-mounts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = MountStore::new(root.clone(), 0);
        for (digest, strip) in digests {
            std::fs::create_dir_all(store.tree_path(digest, *strip)).unwrap();
        }
        (root, store)
    }

    const D1: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const D2: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    /// A VM whose data is not on the host is refused before the daemon is asked
    /// for anything. The alternative — creating it anyway — is a replica that
    /// passes its health check and then fails on the first request that reads
    /// the mount.
    #[test]
    fn a_mount_with_no_tree_refuses_the_create() {
        let (root, store) = store_holding(&[]);
        let manager = VmManager::new(None, None, store).unwrap();

        let never_pulled = manager
            .guest_mounts(&spec_with(vec![mount("/data", None)]))
            .unwrap_err();
        assert!(
            matches!(&never_pulled, VmError::MountNotPulled { path, digest }
                if path == "/data" && digest.is_none()),
            "{never_pulled}",
        );
        assert!(
            never_pulled.to_string().contains("mounts/pull"),
            "the error must say what fixes it: {never_pulled}",
        );

        // Pinned to bytes this host does not hold — a tree reclaimed by the
        // sweep, or a spec copied from another host.
        let elsewhere = manager
            .guest_mounts(&spec_with(vec![mount("/data", Some(D1))]))
            .unwrap_err();
        assert!(
            matches!(&elsewhere, VmError::MountNotPulled { digest, .. } if digest.is_some()),
            "{elsewhere}",
        );
        assert!(elsewhere.to_string().contains(D1));

        std::fs::remove_dir_all(&root).ok();
    }

    /// The daemon's `MountConfig` spelling, and the order it letters devices in.
    #[test]
    fn resolved_mounts_carry_the_daemons_field_names_in_spec_order() {
        let (root, store) = store_holding(&[(D1, 0), (D2, 0)]);
        let tree_one = store.tree_path(D1, 0);
        let tree_two = store.tree_path(D2, 0);
        let stripped = store.tree_path(D1, 2);
        let manager = VmManager::new(None, None, store).unwrap();

        let writable = MountSpec {
            read_only: false,
            ..mount("/scratch", Some(D2))
        };
        let mounts = manager
            .guest_mounts(&spec_with(vec![mount("/data", Some(D1)), writable]))
            .unwrap();

        assert_eq!(
            mounts,
            vec![
                ResolvedMount {
                    tree_id: D1.to_string(),
                    tree: tree_one.clone(),
                    mount: DaemonMount::from_tree(D1, "/data", true),
                },
                ResolvedMount {
                    tree_id: D2.to_string(),
                    tree: tree_two.clone(),
                    mount: DaemonMount::from_tree(D2, "/scratch", false),
                },
            ],
            "order is load-bearing: heyvmd letters /dev/vdb, /dev/vdc in this order",
        );
        // The daemon's id for a tree is its directory name — content-addressed
        // by the store, with the strip suffix when there is one.
        assert_eq!(tree_id_of(&stripped), format!("{D1}-s2"));

        std::fs::remove_dir_all(&root).ok();
    }

    /// A deployment with no mounts must produce exactly the body it always did,
    /// so the array is absent rather than empty.
    #[test]
    fn a_spec_with_no_mounts_sends_none() {
        let (root, store) = store_holding(&[]);
        let manager = VmManager::new(None, None, store).unwrap();
        assert!(manager.guest_mounts(&spec_with(vec![])).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    fn template() -> VmSpec {
        spec_with(vec![])
    }

    /// `vm.rootfs: shared` reaches heyvm as `rootfs_mode`; the default adds
    /// nothing, so a copy-mode body is what it always was.
    #[test]
    fn a_shared_rootfs_is_asked_for_and_the_default_says_nothing() {
        let plain = serde_json::to_value(create_request(
            &template(), "web-1".into(), vec![8080], None, vec![], &VmOwner::default(),
        ))
        .unwrap();
        assert!(plain.get("rootfs_mode").is_none(), "{plain}");
        let mut shared = template();
        shared.rootfs = crate::config::RootfsMode::Shared;
        let body = serde_json::to_value(create_request(
            &shared, "web-1".into(), vec![8080], None, vec![], &VmOwner::default(),
        ))
        .unwrap();
        assert_eq!(body["rootfs_mode"], "shared");
    }

    /// `DELETE /images/:name`, each answer heyvm can give, read the way the
    /// image inventory needs it — including a heyvm with no such route.
    #[tokio::test]
    async fn image_delete_answers_are_told_apart() {
        use axum::extract::Path as AxPath;
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        let app = axum::Router::new().route(
            "/images/:name",
            axum::routing::delete(|AxPath(name): AxPath<String>| async move {
                match name.as_str() {
                    "gone" => StatusCode::NO_CONTENT.into_response(),
                    "busy" => (StatusCode::CONFLICT, axum::Json(json!({"error": "in use", "sandboxes": ["sb-1", "sb-2"]}))).into_response(),
                    "old" => StatusCode::METHOD_NOT_ALLOWED.into_response(),
                    "boom" => (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": "disk"}))).into_response(),
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let m = VmManager::new(Some(url), None, test_mounts()).unwrap();

        assert_eq!(m.delete_image("gone", true).await.unwrap(), ImageDelete::Deleted);
        assert_eq!(
            m.delete_image("busy", true).await.unwrap(),
            ImageDelete::InUse(vec!["sb-1".into(), "sb-2".into()])
        );
        assert_eq!(m.delete_image("old", true).await.unwrap(), ImageDelete::Unsupported);
        assert_eq!(m.delete_image("absent", false).await.unwrap(), ImageDelete::Missing);
        assert_eq!(
            m.delete_image("absent", true).await.unwrap(),
            ImageDelete::Unsupported,
            "a 404 for an image just seen in the catalog means the route is missing"
        );
        assert!(m.delete_image("boom", true).await.is_err());
        assert!(m.delete_image("../etc", true).await.is_err(), "never sent");
        assert!(m.delete_image("vmlinux.bin", true).await.is_err(), "kernels are never deleted");
    }

    /// The daemon's own field names, in a body the SDK types: the owner,
    /// the image source and the workspace archive ride only when the
    /// template has them, so a plain self-hosted body is what it always was.
    #[test]
    fn the_create_request_carries_the_image_source_and_the_archive() {
        let plain = serde_json::to_value(create_request(
            &template(), "web-1".into(), vec![8080], None, vec![], &VmOwner::default(),
        ))
        .unwrap();
        for absent in ["image_download_url", "image_size_bytes", "image_sha256", "s3_archive_key", "sandbox_path", "account_id", "user_id", "mounts"] {
            assert!(plain.get(absent).is_none(), "{absent} leaked into a plain body: {plain}");
        }
        assert_eq!(plain["name"], "web-1");
        assert_eq!(plain["driver"], "firecracker");
        assert_eq!(plain["open_ports"], json!([8080]));
        assert_eq!(plain["ttl_seconds"], template().ttl_seconds);

        let mut full = template();
        full.image_download_url = Some("https://cloud.example/public-images/img-1".into());
        full.image_size_bytes = Some(1024);
        full.image_sha256 = Some("abc".into());
        full.workspace_archive = Some(crate::config::WorkspaceArchive {
            archive_id: Some("ar-1".into()),
            s3_key: Some("users/u1/archives/ar-1.tar.gz".into()),
            size_bytes: Some(10),
        });
        let body = serde_json::to_value(create_request(
            &full, "web-1".into(), vec![], None, vec![], &VmOwner::default(),
        ))
        .unwrap();
        assert_eq!(body["image_download_url"], "https://cloud.example/public-images/img-1");
        assert_eq!(body["image_size_bytes"], 1024);
        assert_eq!(body["image_sha256"], "abc");
        assert_eq!(body["s3_archive_key"], "users/u1/archives/ar-1.tar.gz");
        assert_eq!(body["sandbox_path"], "/workspace");

        // An archive whose key was never resolved is not guessed at.
        let mut unresolved = template();
        unresolved.workspace_archive = Some(crate::config::WorkspaceArchive {
            archive_id: Some("ar-2".into()),
            s3_key: None,
            size_bytes: None,
        });
        let body = serde_json::to_value(create_request(
            &unresolved, "web-1".into(), vec![], None, vec![], &VmOwner::default(),
        ))
        .unwrap();
        assert!(body.get("s3_archive_key").is_none());
        assert!(body.get("sandbox_path").is_none());
    }

    #[test]
    fn the_create_request_carries_the_owner_and_the_mounts_only_when_there_are_any() {
        let owner = VmOwner {
            account_id: Some("acc-1".into()),
            user_id: Some("u-1".into()),
        };
        let owned = serde_json::to_value(create_request(
            &template(), "applb-demo-01".into(), vec![], None,
            vec![DaemonMount::from_tree("abc", "/data", true)], &owner,
        ))
        .unwrap();
        assert_eq!(owned["account_id"], "acc-1");
        assert_eq!(owned["user_id"], "u-1");
        assert_eq!(owned["mounts"], json!([{"tree_id": "abc", "sandbox_path": "/data", "read_only": true}]));

        // An account with no user — the spec was stamped by hand — is fine.
        let half = VmOwner {
            account_id: Some("acc-1".into()),
            user_id: None,
        };
        let body = serde_json::to_value(create_request(&template(), "x".into(), vec![], None, vec![], &half)).unwrap();
        assert_eq!(body["account_id"], "acc-1");
        assert!(body.get("user_id").is_none());

        // ...and the owner rides straight off a spec.
        let mut spec: DeploymentSpec = serde_json::from_value(json!({
            "id": "web", "routes": [], "upstreams": ["127.0.0.1:1"],
        }))
        .unwrap();
        assert_eq!(VmOwner::of(&spec), VmOwner::default());
        spec.account_id = Some("acc-2".into());
        assert_eq!(VmOwner::of(&spec).account_id.as_deref(), Some("acc-2"));
    }

    /// A directory streams as a tarball the daemon can unpack, symlinks and
    /// all — this is what carries a workspace or a mount tree to a daemon
    /// that does not share this host's filesystem.
    #[tokio::test]
    async fn a_directory_streams_as_a_tarball() {
        use futures::StreamExt;
        let (root, _store) = store_holding(&[]);
        let dir = root.join("tree");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/file.txt"), b"hello").unwrap();
        std::os::unix::fs::symlink("sub/file.txt", dir.join("link")).unwrap();

        let mut stream = tar_gz_stream(dir.clone());
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(bytes)));
        let mut seen = std::collections::BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            seen.insert(path.trim_start_matches("./").to_string(), entry.header().entry_type());
        }
        assert_eq!(seen.get("sub/file.txt"), Some(&tar::EntryType::Regular), "{seen:?}");
        assert_eq!(seen.get("link"), Some(&tar::EntryType::Symlink), "{seen:?}");
        std::fs::remove_dir_all(&root).ok();
    }

}
