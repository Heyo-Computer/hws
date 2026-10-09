//! The heyvm boundary: creating a VM on a runner and running steps in it.
//!
//! Everything that knows about sandboxes lives here so the traps are in one
//! place. Four are worth stating up front, because every one of them fails
//! silently. The first three are queue-fn's findings
//! (`queue-fn/src/vm.rs`), re-verified against this SDK version; the fourth is
//! ours and is the reason this module does not use the SDK's exec at all.
//!
//! 1. **`wait_for_ready` returning `Ok` does not mean the VM is usable.** Its
//!    match has a `_ => return Ok(info)` arm (`sdk-rs/src/sandbox.rs:182`), so
//!    `Stopped`, `Paused` and `ColdStored` all come back `Ok`. Only `Running`
//!    can run anything. [`Vm::ensure_running`] is the check.
//!
//! 2. **The firecracker serial path returns an empty `stderr`.** The daemon runs
//!    `(cmd) 2>&1` and builds its response with stderr empty
//!    (`mvm-ctrl/src/driver/firecracker.rs:1752`). Reading `stdout` alone loses
//!    everything the command wrote to stderr, so [`ExecOutput::combined`] folds
//!    the `output` field back in.
//!
//! 3. **Two concurrent execs against one sandbox do not queue.** The second gets
//!    `SandboxNotFound`, because the first holds the handle out of the manager's
//!    map for its duration (`mvm-ctrl/src/sandbox.rs:3648`). [`Vms`] keeps a
//!    per-sandbox lock so that is impossible from this process.
//!
//! 4. **The SDK's `Commands::run` cannot raise the guest timeout.** It posts to
//!    the cloud-compat route `POST /sandbox/{id}/exec` with a body of only
//!    `{command, cwd, env}` (`sdk-rs/src/commands.rs:42`) — `CommandRunOptions::timeout`
//!    sets the *HTTP client's* timeout and never reaches the guest. The
//!    firecracker serial path then caps the command at 30 seconds
//!    (`mvm-ctrl/src/driver/firecracker.rs:2178`). No CI step survives that, so
//!    this module drives the daemon's own async route instead:
//!    `POST /sandboxes/{id}/exec-operations`, which does take `timeoutSecs`.
//!
//! ## Why the async exec route is the right primitive anyway
//!
//! It is **idempotent by `operationId` and persisted to disk**, and a replay
//! with a different command for the same id is rejected
//! (`mvm-ctrl/src/api.rs:5164`). That makes a JetStream redelivery safe: re-posting
//! a step reattaches to the operation already running instead of starting the
//! build twice. A `queued` record that has not moved in 30s is respawned by the
//! daemon on re-POST, so a daemon restart mid-step self-heals.

use heyo_sdk::{
    HeyoClientOptions, HeyoError, RequestOptions, Sandbox, SandboxCreateOptions, SandboxDriver,
    SandboxInfo, SandboxSize, SandboxStatus,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// How long the daemon may sit in `queued` before a re-POST respawns it
/// (`EXEC_OPERATION_QUEUED_RESTART_AFTER_SECS`, mvm-ctrl/src/api.rs:21). We poll
/// well under this so a stuck operation is noticed rather than waited out.
const POLL_MIN: Duration = Duration::from_millis(250);
const POLL_MAX: Duration = Duration::from_secs(2);

/// Slack between the timeout we hand the guest and the deadline we stop polling
/// at. The daemon's own timeout must fire first, so that a slow step comes back
/// as a `failed` record naming the timeout rather than as our own give-up, which
/// would leave the command running with nobody reading it.
const POLL_SLACK: Duration = Duration::from_secs(30);

/// How many times a request on the exec route is re-sent after a transport
/// failure before the failure is reported.
///
/// Both requests this covers are safe to repeat: the POST is idempotent by
/// `operationId` (a replay reattaches to the operation already running — see
/// the module docs) and the GET reads a file. What they are retried *against*
/// is a pooled keep-alive connection through the iroh tunnel that the far end
/// has already closed: `hey-proxy` does not propagate the daemon's EOF until
/// both directions of the stream are done, so a connection the daemon closed
/// still looks idle-and-alive to reqwest, and the next request on it comes
/// back as `Connection reset by peer`. Seen in the wild as a checkout dying on
/// its second upload chunk, seconds after the same tunnel had created and
/// booted the VM.
///
/// A fresh connection is a fresh iroh stream, so a reset of that kind is gone
/// on the first retry. A tunnel that is actually dead fails every attempt the
/// same way and is reported after the last one — the caller then evicts it
/// (`DispatchError::is_tunnel_failure`), which retrying cannot substitute for.
const TRANSPORT_RETRIES: u32 = 2;
const TRANSPORT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Base64 bytes per upload exec. See [`Vm::upload_bytes`] for where this number
/// comes from — it is measured against a real guest, not chosen.
///
/// **28 KiB — the ceiling
/// `the_upload_chunk_stays_under_the_measured_guest_limit` allows**, which is
/// the measured-good 32 KiB less the 4 KiB margin that test reserves for the
/// wrapper (`mkdir -p`, a `printf`, a `base64 -d`, and a path of unknown
/// length).
///
/// Raised from 24 KiB because **chunk count is checkout latency**: uploads are
/// strictly serial — the per-sandbox exec lock forbids two execs at once — so
/// every chunk is a POST plus at least one poll over the iroh tunnel. This
/// repository's 3.65 MiB packfile is ~4.9 MiB of base64: 210 chunks at 24 KiB,
/// 179 at 28.
///
/// Going higher means moving that test's margin, and the margin is the reason a
/// bad value fails at compile time instead of as a hung build. A chunk size that
/// overshoots `MAX_ARG_STRLEN` breaks *every* upload, so it wants a probe
/// against a real guest rather than an argument from arithmetic.
const UPLOAD_CHUNK: usize = 28 * 1024;

/// Raw bytes per download exec. See [`Vm::download_file`] for the shape of
/// the transfer this sizes.
///
/// The bound on an upload is the guest's argv limit; a download has none of
/// that — its payload is the exec's *output*, and nothing in the guest caps a
/// line count. What bounds a chunk here is time: on the firecracker path every
/// byte of output crosses the emulated serial console, and one chunk has to
/// fit under [`DOWNLOAD_CHUNK_TIMEOUT`] on the slowest guest that is still
/// healthy. 1 MiB raw is ~1.4 MiB of base64, ~18k wrapped lines; and it keeps
/// a 40 MiB artifact to ~40 execs, each a POST plus a few polls over the iroh
/// tunnel — a minute or two of overhead against a transfer that takes longer
/// than that anyway.
pub const DOWNLOAD_CHUNK: u64 = 1024 * 1024;

/// Guest timeout for one download chunk.
///
/// Generous against the chunk: a chunk that needs all of it is a console
/// moving ~5 KiB/s, which is a broken VM, not a big artifact. The point of
/// chunking is that the artifact's *size* never meets a fixed ceiling — each
/// exec is bounded by this, and the whole transfer by the caller's budget.
const DOWNLOAD_CHUNK_TIMEOUT: Duration = Duration::from_secs(300);

/// One line of a VM's own log, as `GET /sandboxes/{id}/logs` returns it.
///
/// Re-declared rather than imported: the daemon's `LogEntry` lives in
/// `mvm-ctrl`, which this crate deliberately does not depend on. Every field is
/// defaulted so a daemon that adds or drops one does not break the parse of the
/// rest — a VM log is diagnostic, and half of it beats an error.
#[derive(Debug, Clone, Deserialize)]
struct LogsResponse {
    #[serde(default)]
    logs: Vec<LogLine>,
    #[serde(default)]
    total: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct LogLine {
    /// `stdout`, `stderr` or `console`.
    #[serde(default = "unknown_source")]
    source: String,
    #[serde(default)]
    message: String,
}

fn unknown_source() -> String {
    "?".to_string()
}

/// The daemon's log listing, rendered for a person.
///
/// Two transformations, both learned from reading a real capture:
///
/// * **The daemon answers most-recent-first** (mvm-ctrl `get_logs` reverses
///   before paginating), which is right for a dashboard tail and exactly wrong
///   for a log attached to a run. Flipped back to chronological here.
/// * **The serial shell echoes every command it is fed**, so each step's whole
///   wrapped script lands in the console channel — quote-mangled, wrapped, and
///   interleaved with the exec protocol's own `__HEYVM_…` marker lines. None
///   of that is the guest saying anything. Those runs are folded into one
///   `[ci] (…elided)` line each, so the log keeps its shape without the noise.
///   The scripts themselves are in the workflow file, and the step's real
///   output is in the step's own log.
fn render_log_lines(logs: &[LogLine], total: usize) -> String {
    let mut out = String::new();
    if total > logs.len() {
        // Said once at the top rather than left for someone to infer from a
        // log that starts mid-boot.
        out.push_str(&format!(
            "[ci] showing the last {} of {} lines\n",
            logs.len(),
            total
        ));
    }
    let mut elided = 0usize;
    let mut flush = |out: &mut String, elided: &mut usize| {
        if *elided > 0 {
            out.push_str(&format!(
                "[ci] ({} line{} of step-script echo elided)\n",
                elided,
                if *elided == 1 { "" } else { "s" }
            ));
            *elided = 0;
        }
    };
    for entry in logs.iter().rev() {
        let msg = &entry.message;
        // The `> ` prefix is the shell's continuation prompt — the echo of a
        // multi-line command being typed, never guest output. The marker
        // strings are the exec protocol itself, echoed or emitted.
        let is_echo = entry.source == "console"
            && (msg.starts_with("> ")
                || msg == ">"
                || msg.contains("__HEYVM_")
                || msg.contains("__HEYYVM_")
                || msg.contains("__ci_rc=$?"));
        if is_echo {
            elided += 1;
            continue;
        }
        flush(&mut out, &mut elided);
        out.push_str(&format!("{:<7} {}\n", entry.source, msg));
    }
    flush(&mut out, &mut elided);
    out
}

/// `vm.build` — the Dockerfile a job's image is made from.
///
/// Both paths are repository-relative and validated like `cache_key_files`: the
/// build runs against a tree somebody submitted, so a path that escapes it is
/// refused when the workflow is parsed rather than when a build reads a file.
///
/// The resulting image name is *derived*, never written by the author — it is
/// the content hash of the Dockerfile and its context (see
/// [`crate::image::Dockerfile::fingerprint`]). That is what makes "reused until
/// cache busted" fall out: identical inputs name an image the host already has,
/// and any change names one it does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageBuild {
    pub dockerfile: String,
    /// Defaults to the Dockerfile's own directory, as `docker build` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Rootfs size in MB. Absent means the daemon auto-sizes from the exported
    /// tree (× 1.2 + 64 MB) — right for an image that only ever reads itself,
    /// too tight for one whose workload writes into the rootfs at runtime, the
    /// way a crate registry cache under `CARGO_HOME` does. Part of the image
    /// fingerprint: a different ext4 size is a different image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_mb: Option<u64>,
}

impl ImageBuild {
    /// The context directory, defaulted the way `docker build -f` does.
    pub fn context_dir(&self) -> &str {
        match self.context.as_deref() {
            Some(c) => c,
            None => match self.dockerfile.rsplit_once('/') {
                Some((dir, _)) => dir,
                None => ".",
            },
        }
    }
}

/// The `vm:` block of a workflow job.
///
/// Mirrors the subset of `SandboxCreateOptions` that makes sense to declare in a
/// workflow. `cache_key_files` is not passed to the daemon at all — it feeds the
/// pool fingerprint (see `pool`), and lives here because it is part of what the
/// author writes under `vm:`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSpec {
    pub driver: SandboxDriver,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Build the image from a Dockerfile in the submitted tree instead of
    /// naming one the host already has.
    ///
    /// Mutually exclusive with `image`, and refused at parse time when both are
    /// set: the name is derived from the Dockerfile, so an author-supplied one
    /// could only disagree with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<ImageBuild>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_class: Option<SandboxSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_size_gb: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// Baked into the fingerprint, so changing one busts the pool.
    ///
    /// `BTreeMap` rather than `HashMap` because the fingerprint is a hash of the
    /// serialized spec, and a `HashMap`'s iteration order would make it differ
    /// between processes — every restart would rebuild every VM.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_vars: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setup_hooks: Vec<String>,
    /// Repo-relative files whose contents bust the pool when they change.
    /// Consumed by the fingerprint, never sent to the daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_key_files: Vec<String>,
    /// Whether a finished job's VM may be handed to the next job with the same
    /// fingerprint.
    #[serde(default = "default_reuse")]
    pub reuse: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

impl Default for VmSpec {
    fn default() -> Self {
        Self { driver: SandboxDriver::Firecracker, image: None, build: None,
            size_class: None, disk_size_gb: None, working_directory: None,
            env_vars: BTreeMap::new(), setup_hooks: Vec::new(), cache_key_files: Vec::new(),
            reuse: true, ttl_seconds: None }
    }
}

fn default_reuse() -> bool {
    true
}

impl VmSpec {
    pub fn validate(&self) -> Result<(), VmSpecError> {
        // Libvirt is refused for the same reason queue-fn refuses it: the pool
        // depends on per-VM rootfs cloning and on the exec paths that only the
        // tap-networked backends implement well here. Refusing at parse time
        // means the author sees it when they write the workflow, not when a job
        // has already been queued against a runner.
        if self.driver == SandboxDriver::Libvirt {
            return Err(VmSpecError::UnsupportedDriver);
        }
        // "Both are set" is an authoring mistake with its own fix, so it is
        // stated separately from everything else.
        if let Some(build) = &self.build {
            if self.image.is_some() {
                return Err(VmSpecError::ImageAndBuild);
            }
            for path in [build.dockerfile.as_str(), build.context_dir()] {
                if path.starts_with('/') || path.split('/').any(|s| s == "..") {
                    return Err(VmSpecError::EscapingBuildPath(path.to_string()));
                }
            }
            if build.dockerfile.trim().is_empty() {
                return Err(VmSpecError::EmptyDockerfilePath);
            }
            if build.size_mb == Some(0) {
                return Err(VmSpecError::ZeroImageSize);
            }
        }
        if let Some(d) = self.disk_size_gb
            && d == 0
        {
            return Err(VmSpecError::ZeroDisk);
        }
        if let Some(t) = self.ttl_seconds
            && t == 0
        {
            return Err(VmSpecError::ZeroTtl);
        }
        for key in self.env_vars.keys() {
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(VmSpecError::InvalidEnvKey(key.clone()));
            }
        }
        for path in &self.cache_key_files {
            if path.starts_with('/') || path.split('/').any(|s| s == "..") {
                return Err(VmSpecError::EscapingCacheKeyFile(path.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VmSpecError {
    UnsupportedDriver,
    ZeroDisk,
    ZeroTtl,
    InvalidEnvKey(String),
    EscapingCacheKeyFile(String),
    ImageAndBuild,
    EscapingBuildPath(String),
    EmptyDockerfilePath,
    ZeroImageSize,
}

impl fmt::Display for VmSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDriver => write!(
                f,
                "vm.driver must be `firecracker` or `kvm`; `libvirt` is not supported \
                 for CI VMs"
            ),
            Self::ZeroDisk => write!(f, "vm.disk_size_gb must be greater than zero"),
            Self::ZeroTtl => write!(f, "vm.ttl_seconds must be greater than zero"),
            Self::InvalidEnvKey(k) => write!(
                f,
                "vm.env_vars key {k:?} is not a shell-safe name; use only letters, \
                 digits and underscores"
            ),
            Self::EscapingCacheKeyFile(p) => write!(
                f,
                "vm.cache_key_files entry {p:?} must be a relative path inside the \
                 repository, with no `..` segments"
            ),
            Self::ImageAndBuild => write!(
                f,
                "vm.image and vm.build cannot both be set: a built image's name is \
                 the hash of its Dockerfile and context, so naming one as well \
                 could only disagree with it. Drop `image:` to build, or drop \
                 `build:` to use an image the host already has."
            ),
            Self::EscapingBuildPath(p) => write!(
                f,
                "vm.build path {p:?} must be a relative path inside the repository, \
                 with no `..` segments"
            ),
            Self::EmptyDockerfilePath => {
                write!(f, "vm.build.dockerfile must name a file in the repository")
            }
            Self::ZeroImageSize => write!(f, "vm.build.size_mb must be greater than zero"),
        }
    }
}

impl std::error::Error for VmSpecError {}

/// What a step produced.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// The daemon's combined stream. On the firecracker serial path this is the
    /// only field that carries everything.
    pub output: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl ExecOutput {
    /// The text to show and store for this step.
    ///
    /// Prefers `output`, because on the firecracker serial path `stderr` is
    /// always empty and `stdout` alone silently loses every diagnostic a build
    /// tool wrote — which is most of what anyone reads a failed build for. Falls
    /// back to concatenation for backends that populate the split streams and
    /// leave `output` empty.
    pub fn combined(&self) -> String {
        if !self.output.is_empty() {
            return self.output.clone();
        }
        let mut s = self.stdout.clone();
        if !self.stderr.is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        s
    }

    /// A non-zero exit is a failed step but a successful exec — the command ran.
    pub fn succeeded(&self) -> bool {
        self.exit_code == 0
    }
}

/// `POST /sandboxes/{id}/exec-operations` request body.
///
/// camelCase, matching `StartExecOperationRequest` (mvm-ctrl/src/api.rs:5074).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartExecOperation<'a> {
    operation_id: &'a str,
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<&'a HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_secs: Option<u64>,
}

/// The daemon's operation record.
///
/// **The casing is mixed and that is not a mistake in this struct.** The
/// envelope is camelCase (`ExecOperationRecord` carries `rename_all`), but the
/// nested `result` is `ExecuteCommandResponse`, which carries no rename at all
/// (mvm-ctrl/src/models.rs:1058) and so serializes `exit_code` in snake_case.
/// Verified against records the daemon wrote to `~/.heyo/exec-operations`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecOperationRecord {
    status: String,
    #[serde(default)]
    result: Option<ExecResult>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExecResult {
    #[serde(default)]
    output: String,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    exit_code: i32,
}

impl ExecOperationRecord {
    /// `queued` and `running` are in-flight; `completed` and `failed` are
    /// terminal. `completed` means the command *ran* — its exit code may still
    /// be non-zero. `failed` means the daemon could not run it at all.
    fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed")
    }
}

/// Mints operation ids, and owns the per-sandbox exec lock.
#[derive(Default)]
pub struct Vms {
    /// One lock per sandbox id, so trap 3 is impossible from this process
    /// regardless of which task holds a [`Vm`].
    ///
    /// The pool is the outer guarantee — it hands a sandbox to one job at a
    /// time — but that guarantee lives in a different module and covers only
    /// jobs. TTL renewal, teardown and a step run from the same process too.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl Vms {
    pub fn new() -> Self {
        Self::default()
    }

    async fn lock_for(&self, sandbox_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks
            .entry(sandbox_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Adopt an existing sandbox on a runner.
    ///
    /// `options` come from [`crate::runners::Runners::options_for`] and point at
    /// that runner's tunnel. Issues no network call.
    pub async fn open(
        &self,
        options: impl Into<crate::runners::Connection>,
        sandbox_id: String,
    ) -> Result<Vm, VmError> {
        let connection = options.into();
        let sandbox =
            Sandbox::connect(sandbox_id.clone(), connection.options.clone()).map_err(|e| VmError::Daemon {
                sandbox: sandbox_id.clone(),
                what: "connecting to the sandbox",
                source: e,
            })?;
        let lock = self.lock_for(&sandbox_id).await;
        Ok(Vm {
            sandbox,
            id: sandbox_id,
            lock,
            _connection: connection,
        })
    }

    /// Allocate a VM identity. Persist ownership before calling ensure_running:
    /// boot failure must not discard the only cleanup handle.
    pub async fn create(
        &self,
        options: impl Into<crate::runners::Connection>,
        name: &str,
        spec: &VmSpec,
        ttl: Duration,
    ) -> Result<Vm, VmError> {
        let connection = options.into();
        let opts = SandboxCreateOptions {
            name: Some(name.to_string()),
            driver: Some(spec.driver),
            image: spec.image.clone(),
            size_class: spec.size_class,
            disk_size_gb: spec.disk_size_gb,
            working_directory: spec.working_directory.clone(),
            env_vars: (!spec.env_vars.is_empty()).then(|| {
                spec.env_vars
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            }),
            setup_hooks: (!spec.setup_hooks.is_empty()).then(|| spec.setup_hooks.clone()),
            ttl_seconds: Some(spec.ttl_seconds.unwrap_or(ttl.as_secs())),
            // Return the identity before polling boot. The dispatcher must
            // persist ownership before a failed boot can discard the handle.
            wait_for_ready: Some(Duration::ZERO),
            ..Default::default()
        };

        // Goes to the daemon's cloud-compat `POST /sandbox-deploy`, which renames
        // `driver` to the native `backend_type` and passes `size_class`,
        // `setup_hooks`, `disk_size_gb`, `working_directory`, `env_vars` and
        // `ttl_seconds` straight through (mvm-ctrl/src/api.rs:2449). So the whole
        // `vm:` block lands, and none of it is silently defaulted.
        let sandbox = Sandbox::create(opts, connection.options.clone())
            .await
            .map_err(|e| VmError::Create {
                name: name.to_string(),
                source: e,
            })?;

        let id = sandbox.sandbox_id().to_string();
        let lock = self.lock_for(&id).await;
        let vm = Vm { sandbox, id, lock, _connection: connection };
        Ok(vm)
    }
}

/// One VM on one runner.
pub struct Vm {
    sandbox: Sandbox,
    id: String,
    lock: Arc<Mutex<()>>,
    _connection: crate::runners::Connection,
}

impl Vm {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub async fn info(&self) -> Result<SandboxInfo, VmError> {
        self.sandbox.info().await.map_err(|e| VmError::Daemon {
            sandbox: self.id.clone(),
            what: "reading sandbox info",
            source: e,
        })
    }

    /// Make sure the VM is `Running`, starting it if it is merely stopped.
    ///
    /// This is the check trap 1 requires. A pooled VM that was stopped between
    /// jobs is a normal, recoverable state; `Failed` and `ColdStored` are not,
    /// and are reported rather than retried into a timeout.
    pub async fn ensure_running(&self, timeout: Duration) -> Result<(), VmError> {
        let info = self.info().await?;
        match info.status {
            SandboxStatus::Running => return Ok(()),
            SandboxStatus::Stopped | SandboxStatus::Paused |
            SandboxStatus::Provisioning | SandboxStatus::Unknown => {}
            other => {
                return Err(VmError::NotRunnable {
                    sandbox: self.id.clone(),
                    status: format!("{other:?}"),
                    reason: info.error_message.clone(),
                });
            }
        }

        // Serialized: `start` takes the handle out of the manager's map exactly
        // as `execute` does.
        if matches!(info.status, SandboxStatus::Stopped | SandboxStatus::Paused) {
            let _guard = self.lock.lock().await;
            self.sandbox.start().await.map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "starting the sandbox",
                source: e,
            })?;
        }

        let info = self
            .sandbox
            .wait_for_ready(timeout)
            .await
            .map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "waiting for the sandbox to start",
                source: e,
            })?;
        if info.status != SandboxStatus::Running {
            return Err(VmError::NotRunnable {
                sandbox: self.id.clone(),
                status: format!("{:?}", info.status),
                reason: info.error_message,
            });
        }
        Ok(())
    }

    /// Run one step and wait for it to finish.
    ///
    /// `operation_id` makes this idempotent: re-calling with the same id and the
    /// same command reattaches to the operation already in flight rather than
    /// running the step twice. That is what makes a queue redelivery safe.
    pub async fn exec(
        &self,
        operation_id: &str,
        command: &str,
        env: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<ExecOutput, VmError> {
        if !valid_operation_id(operation_id) {
            return Err(VmError::BadOperationId(operation_id.to_string()));
        }

        // Held for the whole exec, including the poll loop: the daemon holds the
        // handle for the command's duration, so a second exec started while this
        // one polls would fail with `SandboxNotFound` (trap 3).
        let _guard = self.lock.lock().await;

        let body = StartExecOperation {
            operation_id,
            command,
            env: (!env.is_empty()).then_some(env),
            timeout_secs: Some(timeout.as_secs().max(1)),
        };
        let path = format!("/sandboxes/{}/exec-operations", encode_segment(&self.id));
        // A short HTTP timeout, not the step's: this call only enqueues.
        let start: ExecOperationRecord = self
            .daemon_request(
                Method::POST,
                &path,
                Some(&body),
                "starting an exec operation",
                None,
            )
            .await?;

        if start.is_terminal() {
            return self.finish(operation_id, start);
        }

        let deadline = Instant::now() + timeout + POLL_SLACK;
        let mut interval = POLL_MIN;
        let get_path = format!(
            "/sandboxes/{}/exec-operations/{}",
            encode_segment(&self.id),
            encode_segment(operation_id)
        );
        loop {
            // **Ask before sleeping.** The sleep used to come first, which made
            // `POLL_MIN` a floor on every exec rather than a gap between polls —
            // and most execs here are not builds. `upload_bytes` sends the whole
            // repository as ~200 sequential chunk writes, each finishing in
            // milliseconds inside the guest and each then waiting out 250ms
            // before anybody asked: a minute of pure sleep in a checkout that
            // takes five.
            //
            // The cost is one extra round trip for a command that really is
            // long, which `cargo build` pays once against 3600 seconds of
            // compiling.
            let record: ExecOperationRecord = self
                .daemon_request(
                    Method::GET,
                    &get_path,
                    None::<&()>,
                    "polling an exec operation",
                    Some(deadline),
                )
                .await?;

            if record.is_terminal() {
                return self.finish(operation_id, record);
            }

            // Backoff moved to the tail with the sleep. Exponential up to a
            // ceiling: a `cargo build` polled every 250ms for ten minutes is
            // 2400 pointless round trips over an iroh tunnel.
            tokio::time::sleep(interval).await;
            interval = (interval * 2).min(POLL_MAX);

            if Instant::now() >= deadline {
                return Err(VmError::ExecTimeout {
                    sandbox: self.id.clone(),
                    operation: operation_id.to_string(),
                    // Naming the guest timeout matters: exceeding *our* deadline
                    // when the guest's should have fired first means the daemon
                    // stopped answering, which is a different fault.
                    after: timeout + POLL_SLACK,
                });
            }
        }
    }

    /// One request on the exec route, re-sent on a transport or temporary
    /// upstream dependency failure (502/503/504) up to
    /// [`TRANSPORT_RETRIES`] times. Only for requests that are safe to repeat —
    /// see the constant for why both of this route's are.
    ///
    /// `deadline` is the poll loop's: a retry that could not land before it is
    /// not attempted, so the loop's own timeout is still the one that fires.
    async fn daemon_request<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
        what: &'static str,
        deadline: Option<Instant>,
    ) -> Result<T, VmError> {
        let mut attempt = 0;
        loop {
            let result = self
                .sandbox
                .client()
                .request(
                    method.clone(),
                    path,
                    body,
                    RequestOptions {
                        timeout: Some(Duration::from_secs(30)),
                        query: Vec::new(),
                    },
                )
                .await;
            let e = match result {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            let retry_lands_in_time =
                deadline.is_none_or(|d| Instant::now() + TRANSPORT_RETRY_DELAY < d);
            let retryable = is_transport(&e)
                || matches!(&e, HeyoError::Api { status: 502 | 503 | 504, .. });
            if !retryable || attempt >= TRANSPORT_RETRIES || !retry_lands_in_time {
                return Err(VmError::Daemon {
                    sandbox: self.id.clone(),
                    what,
                    source: e,
                });
            }
            attempt += 1;
            tracing::warn!(
                sandbox = %self.id,
                attempt,
                of = TRANSPORT_RETRIES,
                "{what} hit a transient transport or dependency error, retrying: {e}"
            );
            tokio::time::sleep(TRANSPORT_RETRY_DELAY).await;
        }
    }

    fn finish(
        &self,
        operation_id: &str,
        record: ExecOperationRecord,
    ) -> Result<ExecOutput, VmError> {
        match record.status.as_str() {
            "completed" => {
                let r = record.result.ok_or_else(|| VmError::MalformedRecord {
                    sandbox: self.id.clone(),
                    operation: operation_id.to_string(),
                    detail: "status was `completed` but no result was attached".to_string(),
                })?;
                Ok(ExecOutput {
                    output: r.output,
                    stdout: r.stdout,
                    stderr: r.stderr,
                    exit_code: r.exit_code,
                })
            }
            // `failed` means the daemon could not run the command — a missing
            // sandbox, a guest timeout, a driver fault. It is not a non-zero
            // exit code, which arrives as `completed`.
            "failed" => Err(VmError::ExecFailed {
                sandbox: self.id.clone(),
                operation: operation_id.to_string(),
                reason: record
                    .error
                    .unwrap_or_else(|| "no reason reported".to_string()),
            }),
            other => Err(VmError::MalformedRecord {
                sandbox: self.id.clone(),
                operation: operation_id.to_string(),
                detail: format!("unexpected terminal status {other:?}"),
            }),
        }
    }

    /// Write bytes into the guest filesystem, in chunks, through exec.
    ///
    /// **Not the SDK's `Files::write`, and not the daemon's upload route.** Both
    /// go to `SandboxManager::upload_file`, which writes into a host-side
    /// *mount* directory and only syncs that into the guest on Hyper-V
    /// (`mvm-ctrl/src/sandbox.rs:8183`). On Firecracker a sandbox has no mounts,
    /// so the call fails with `Mount not found: /workspace (available mounts:
    /// [])` — and if it had one, the bytes would land on the host rather than in
    /// the VM. It also caps at 10 MB. Exec is the only transport that actually
    /// reaches the guest on every backend.
    ///
    /// The chunk size is set by measurement, not guesswork. The daemon renders a
    /// command as `env … sh -lc '<script>'`, so the script is one argv entry and
    /// Linux's `MAX_ARG_STRLEN` (128 KiB) bounds it. Probed against a real
    /// Firecracker guest: 32 KiB succeeds, 128 KiB returns `bash:
    /// /usr/bin/env: Argument list too long`. [`UPLOAD_CHUNK`] is that measured
    /// 32 KiB less a 4 KiB margin for the wrapper.
    ///
    /// **Chunk count is checkout latency.** The loop below is strictly serial —
    /// one exec per chunk, and the per-sandbox lock forbids two at once — so
    /// every chunk costs a POST and at least one poll over the iroh tunnel.
    /// Halving the chunk size doubles the checkout.
    ///
    /// Base64's alphabet is `A-Za-z0-9+/=`, none of which is special inside
    /// single quotes, so a chunk needs no escaping — which is also why it cannot
    /// break out of them.
    pub async fn upload_bytes(
        &self,
        operation_prefix: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<(), VmError> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let quoted = shell_single_quote(path);

        // An empty payload still has to create the file.
        let chunks: Vec<&str> = if encoded.is_empty() {
            vec![""]
        } else {
            encoded
                .as_bytes()
                .chunks(UPLOAD_CHUNK)
                .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
                .collect()
        };

        for (i, chunk) in chunks.iter().enumerate() {
            // The first chunk truncates, the rest append — so a retried upload
            // does not concatenate onto a half-written file.
            let redirect = if i == 0 { ">" } else { ">>" };
            let script = format!(
                "mkdir -p \"$(dirname {quoted})\" && printf %s '{chunk}' | base64 -d {redirect} {quoted}"
            );
            let out = self
                .exec(
                    &format!("{operation_prefix}.u{i}"),
                    &script,
                    &HashMap::new(),
                    Duration::from_secs(120),
                )
                .await?;
            if !out.succeeded() {
                return Err(VmError::UploadFailed {
                    sandbox: self.id.clone(),
                    path: path.to_string(),
                    chunk: i,
                    of: chunks.len(),
                    detail: out.combined(),
                });
            }
        }

        // The loop above proves every exec exited 0, which is a claim about
        // the shell, not about the bytes: a guest whose exec channel or
        // filesystem is corrupting data acknowledges every write and hands
        // back garbage — seen in the wild as a source tarball that uploads
        // cleanly and then fails `tar` with "not in gzip format". Hashing
        // both ends turns that silent corruption into a named error at the
        // layer that caused it, before anything downstream consumes the file.
        use sha2::{Digest, Sha256};
        let expected = format!("{:x}", Sha256::digest(bytes));
        let out = self
            .exec(
                &format!("{operation_prefix}.uv"),
                &format!("sha256sum {quoted}"),
                &HashMap::new(),
                Duration::from_secs(120),
            )
            .await?;
        let combined = out.combined();
        if !out.succeeded() {
            // 127 is an image without coreutils — a gap in the image, not in
            // the upload, so the upload stands unverified. Any other failure
            // is the guest unable to read back a file it just acknowledged,
            // which is exactly what this check exists to catch.
            if out.exit_code == 127 {
                tracing::warn!(
                    sandbox = %self.id,
                    path,
                    "upload not verified: the guest has no sha256sum"
                );
                return Ok(());
            }
            return Err(VmError::UploadCorrupted {
                sandbox: self.id.clone(),
                path: path.to_string(),
                expected,
                actual: format!("no hash; sha256sum failed with: {}", combined.trim()),
            });
        }
        let reported = combined
            .split_whitespace()
            .find(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()));
        match reported {
            Some(hash) if hash == expected => Ok(()),
            Some(hash) => Err(VmError::UploadCorrupted {
                sandbox: self.id.clone(),
                path: path.to_string(),
                expected,
                actual: hash.to_string(),
            }),
            // Exit 0 with no hash in the output is a backend quirk, not
            // evidence about the bytes; log it rather than fail on it.
            None => {
                tracing::warn!(
                    sandbox = %self.id,
                    path,
                    "upload not verified: sha256sum exited 0 without printing a hash"
                );
                Ok(())
            }
        }
    }

    /// Read a file out of the guest, in chunks, through exec and base64.
    ///
    /// The mirror of [`Vm::upload_bytes`], for the same reason: the daemon's
    /// file routes address a host-side mount, not the VM, so exec is the only
    /// channel that reaches a guest path. The bytes come back the slow way —
    /// on firecracker each one crosses the emulated serial console — which is
    /// why this is chunked at all. One exec for the whole file meets one fixed
    /// guest timeout, and past some size the file simply cannot fit under it.
    /// That was `ci/upload-artifact` at a flat 600 seconds: it held the app-lb
    /// tarball and timed out on app-obs's, whose two binaries carry arrow and
    /// parquet. Chunked, each exec is bounded by [`DOWNLOAD_CHUNK_TIMEOUT`]
    /// whatever the file's size, and the whole transfer by `budget` — the
    /// step's remaining time, so a genuinely enormous artifact fails as the
    /// step's timeout, with the chunk count in the message, not as a
    /// mysterious daemon-side kill.
    ///
    /// Three details of the guest side, each learned against a real image:
    ///
    /// - `dd` rather than `tail -c +N | head -c M`, because busybox `dd` takes
    ///   `bs=`, `skip=` and `count=` exactly as coreutils does. Its byte
    ///   statistics go to stderr, and the daemon folds stderr into the output
    ///   stream, so they are sent to /dev/null before they can land in the
    ///   base64.
    /// - `base64` without `-w0`: `-w` is GNU-only, and the firecracker serial
    ///   path frames a command's output with newline-delimited markers, so
    ///   output that ends mid-line never matches the end marker and the
    ///   operation hangs in `running` forever. The trailing `echo` is that
    ///   newline; the wrapping is stripped here.
    /// - The size and hash are taken before the first byte moves, so a file
    ///   that changes under the transfer is caught by the final check rather
    ///   than shipped torn.
    ///
    /// Every chunk is checked for length and the assembled file against the
    /// hash the guest reports, so a corrupting channel is a named error at the
    /// layer that caused it — [`VmError::DownloadCorrupted`] — rather than an
    /// artifact that fails to untar on somebody else's machine.
    pub async fn download_file(
        &self,
        operation_prefix: &str,
        path: &str,
        budget: Duration,
    ) -> Result<Vec<u8>, VmError> {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let deadline = Instant::now() + budget;
        let quoted = shell_single_quote(path);
        let fail = |chunk: usize, of: usize, detail: String| VmError::DownloadFailed {
            sandbox: self.id.clone(),
            path: path.to_string(),
            chunk,
            of,
            detail,
        };
        // What one exec may take: its own cap, or what is left of the budget.
        // `None` once the budget is spent, so the loop stops with a message
        // naming the budget instead of handing the guest a one-second timeout.
        let slice = |cap: Duration| {
            let left = deadline.saturating_duration_since(Instant::now());
            (left >= Duration::from_secs(1)).then(|| cap.min(left))
        };

        let Some(timeout) = slice(Duration::from_secs(120)) else {
            return Err(fail(0, 0, format!("no time left in the {budget:?} budget")));
        };
        let stat = self
            .exec(
                &format!("{operation_prefix}.ds"),
                &format!(
                    "f={quoted}; [ -f \"$f\" ] || {{ echo \"$f: no such file\"; exit 1; }}; \
                     printf 'size=%s\\n' \"$(wc -c < \"$f\" | tr -d ' ')\"; \
                     sha256sum \"$f\" 2>/dev/null || echo 'sha256=unavailable'"
                ),
                &HashMap::new(),
                timeout,
            )
            .await?;
        let text = stat.combined();
        if !stat.succeeded() {
            return Err(fail(0, 0, format!("could not stat it: {}", text.trim())));
        }
        let (size, expected) = parse_download_stat(&text).map_err(|d| fail(0, 0, d))?;
        if expected.is_none() {
            // 127 territory: an image without coreutils. The transfer stands,
            // unverified, as an upload does in the same image.
            tracing::warn!(sandbox = %self.id, path, "download not verified: the guest has no sha256sum");
        }

        let of = usize::try_from(size.div_ceil(DOWNLOAD_CHUNK)).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        for i in 0..of {
            let want = usize::try_from((size - i as u64 * DOWNLOAD_CHUNK).min(DOWNLOAD_CHUNK))
                .unwrap_or(usize::MAX);
            let Some(timeout) = slice(DOWNLOAD_CHUNK_TIMEOUT) else {
                return Err(fail(
                    i,
                    of,
                    format!(
                        "the {budget:?} budget for the transfer ran out with {} of {size} bytes read",
                        bytes.len()
                    ),
                ));
            };
            let out = self
                .exec(
                    &format!("{operation_prefix}.d{i}"),
                    &format!(
                        "dd if={quoted} bs={DOWNLOAD_CHUNK} skip={i} count=1 2>/dev/null | base64; echo"
                    ),
                    &HashMap::new(),
                    timeout,
                )
                .await?;
            if !out.succeeded() {
                return Err(fail(i, of, out.combined().trim().to_string()));
            }
            let encoded: String = out
                .combined()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let chunk = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|e| fail(i, of, format!("the guest returned unreadable data: {e}")))?;
            if chunk.len() != want {
                return Err(fail(
                    i,
                    of,
                    format!("expected {want} bytes, the guest returned {}", chunk.len()),
                ));
            }
            bytes.extend_from_slice(&chunk);
            tracing::debug!(
                sandbox = %self.id,
                path,
                chunk = i + 1,
                of,
                read = bytes.len(),
                "download chunk"
            );
        }

        if let Some(expected) = expected {
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != expected {
                return Err(VmError::DownloadCorrupted {
                    sandbox: self.id.clone(),
                    path: path.to_string(),
                    expected,
                    actual,
                });
            }
        }
        Ok(bytes)
    }

    /// Push the TTL out so a pooled VM does not expire while it is still wanted.
    /// The VM's own logs — console, stdout and stderr as the daemon collected
    /// them — rendered as text.
    ///
    /// Not in the SDK, so it goes through the raw client like the exec routes
    /// above. Bounded by `limit` because this is a whole VM's console since
    /// boot and the point is to attach it to a run, not to stream it.
    ///
    /// Read *before* the VM is released: a job's VM may be destroyed the moment
    /// it finishes, and a log nobody captured is a log nobody can read.
    pub async fn logs(&self, limit: usize) -> Result<String, VmError> {
        let path = format!("/sandboxes/{}/logs", encode_segment(&self.id));
        let response: LogsResponse = self
            .sandbox
            .client()
            .request(
                Method::GET,
                &path,
                None::<&()>,
                RequestOptions {
                    timeout: Some(Duration::from_secs(30)),
                    query: vec![("limit".to_string(), limit.to_string())],
                },
            )
            .await
            .map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "reading the VM's logs",
                source: e,
            })?;

        Ok(render_log_lines(&response.logs, response.total))
    }

    pub async fn renew_ttl(&self, ttl: Duration) -> Result<(), VmError> {
        self.sandbox
            .set_ttl(ttl.as_secs())
            .await
            .map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "renewing the TTL",
                source: e,
            })
    }

    /// What the daemon says this VM was given.
    ///
    /// Read from the native `GET /sandboxes/<id>` rather than the SDK's
    /// `info()`: the compat shape the SDK deserializes has room for a class
    /// name only, and the numbers are the point — a daemon too old to name a
    /// class still knows its vCPU count, and "8 CPU, 16 GB" is the answer to
    /// "is this VM the size I asked for" whatever it is called. Every field is
    /// optional and an absent one is *unreported*, never a default: a daemon
    /// that says nothing must not be read as saying `small`.
    pub async fn size(&self) -> Result<VmSize, VmError> {
        self.sandbox
            .client()
            .request::<VmSize>(
                reqwest::Method::GET,
                &format!("/sandboxes/{}", self.id),
                None::<&()>,
                RequestOptions::default(),
            )
            .await
            .map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "reading the VM's size",
                source: e,
            })
    }

    /// Give the VM a different size class, in place.
    ///
    /// The daemon rewrites the VM's persisted cpus and memory and restarts it
    /// — disks kept, so the build cache survives — which is the whole reason
    /// this exists: the workflow's `size_class` is part of the pool
    /// fingerprint, so changing it *there* retires the warm VM and pays a cold
    /// build, while changing it here does not. Held under the sandbox lock
    /// like `exec` and `destroy`, because a restart takes the handle out of the
    /// manager's map.
    ///
    /// `timeout` is the boot budget, not the SDK's 60-second default: the
    /// daemon answers only once the VM is back, and for a *running* VM that is
    /// a stop and a full boot. (A stopped one — the pool's normal state — is
    /// resized in place by a daemon new enough to skip the restart, and comes
    /// back stopped; an older daemon boots it, and the caller parks it again.)
    pub async fn resize(&self, class: SandboxSize, timeout: Duration) -> Result<(), VmError> {
        let _guard = self.lock.lock().await;
        self.sandbox
            .client()
            .request::<serde_json::Value>(
                reqwest::Method::POST,
                &format!("/sandboxes/{}/resize", self.id),
                Some(&serde_json::json!({ "size_class": class.as_str() })),
                RequestOptions {
                    timeout: Some(timeout),
                    query: Vec::new(),
                },
            )
            .await
            .map(|_| ())
            .map_err(|e| VmError::Daemon {
                sandbox: self.id.clone(),
                what: "resizing the sandbox",
                source: e,
            })
    }

    /// Stop the VM, keeping its disks.
    ///
    /// This is how a VM is parked between jobs. The daemon keeps the rootfs
    /// clone and the data disk — only `destroy` removes them — so a stopped VM
    /// started again by [`Self::ensure_running`] boots with its build cache
    /// exactly as the last job left it, and costs the host nothing but disk
    /// while it waits. Serialized on the sandbox lock like `exec` and `destroy`:
    /// `stop` takes the handle out of the manager's map, and racing a command
    /// against that is how a step ends with "no VM handle found".
    pub async fn stop(&self) -> Result<(), VmError> {
        let _guard = self.lock.lock().await;
        self.sandbox.stop().await.map_err(|e| VmError::Daemon {
            sandbox: self.id.clone(),
            what: "stopping the sandbox",
            source: e,
        })
    }

    /// Delete the VM. A 404 is success — the SDK already treats it that way.
    pub async fn destroy(&self) -> Result<(), VmError> {
        let _guard = self.lock.lock().await;
        self.sandbox.kill().await.map_err(|e| VmError::Daemon {
            sandbox: self.id.clone(),
            what: "destroying the sandbox",
            source: e,
        })
    }
}

/// Whether the daemon will accept this as an `operationId`.
///
/// Mirrors `validate_exec_operation_id` (mvm-ctrl/src/api.rs:5306): 1..=160
/// bytes of `[A-Za-z0-9._-]`. Checked here so a bad id fails where it is
/// generated rather than as an opaque 400 in the middle of a job.
pub fn valid_operation_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 160
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Mint an id usable as both an `operationId` and a NATS subject token:
/// `<epoch_ms:012x>-<seq:08x>-<random_uuid:032x>`.
///
/// The timestamp and local counter retain ordering within a process. Random
/// identity prevents two regional processes starting their counters in the
/// same millisecond from creating the same run or external operation.
pub fn new_id() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{:012x}-{:08x}-{}", ms, seq & 0xffff_ffff, uuid::Uuid::new_v4().simple())
}

/// Sandbox name for a pooled VM: `ci-<workflow>-<fingerprint>-<nonce>`.
///
/// **The nonce is hex on purpose.** The daemon derives a VM's tap subnet from
/// its id with `from_str_radix(hex, 16).unwrap_or(0)`, so an id that is not
/// valid hex silently collapses to `172.16.0.2` — and every such VM collides on
/// one address. The daemon assigns the id rather than us, but keeping our names
/// hex-safe avoids feeding it anything pathological.
pub fn sandbox_name(workflow: &str, fingerprint: &str, nonce: u64) -> String {
    let workflow: String = workflow
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("ci-{workflow}-{fingerprint}-{nonce:012x}")
}

/// Single-quote a value for `sh`.
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Percent-encode one path segment. Sandbox ids are `sb-…`/`dep-…` so this is
/// almost always a no-op, but an id is server-assigned and interpolated into a
/// URL.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Whether an SDK error is the transport, not the request.
///
/// The SDK folds every failure to *send* a request into `Api { status: 0 }`
/// ("network error calling …"); a real HTTP answer always carries its status.
/// `Connection` is the same condition on the shell WebSocket. Either one over a
/// cached iroh tunnel means the tunnel is dead — the daemon restarted, the
/// relay dropped it — and retrying through it can only fail the same way.
pub(crate) fn is_transport(e: &HeyoError) -> bool {
    matches!(
        e,
        HeyoError::Api { status: 0, .. } | HeyoError::Connection(_)
    )
}

/// A VM's resources as its daemon reports them.
///
/// Deserialized leniently from the daemon's own `SandboxInfo`: every field is
/// optional and unknown ones are ignored, so a daemon from before it reported
/// sizing yields an all-`None` value rather than an error. That value renders
/// as "unreported", which is a finding in itself — it says the runner's heyvmd
/// is too old to be checked, not that the VM is any particular size.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmSize {
    /// The daemon's class name: the one the create request named, or the tier
    /// its cpus and memory match exactly (newer daemons derive it).
    #[serde(default)]
    pub size_class: Option<String>,
    #[serde(default)]
    pub cpus: Option<u32>,
    /// Bytes.
    #[serde(default)]
    pub memory: Option<u64>,
}

impl VmSize {
    pub fn is_reported(&self) -> bool {
        self.size_class.is_some() || self.cpus.is_some() || self.memory.is_some()
    }

    /// `xlarge (8 CPU, 16 GB)`, or whichever parts the daemon gave, or
    /// `unreported`.
    pub fn label(&self) -> String {
        let numbers = match (self.cpus, self.memory) {
            (Some(c), Some(m)) => Some(format!("{c} CPU, {}", human_bytes(m))),
            (Some(c), None) => Some(format!("{c} CPU")),
            (None, Some(m)) => Some(human_bytes(m)),
            (None, None) => None,
        };
        match (&self.size_class, numbers) {
            (Some(class), Some(n)) => format!("{class} ({n})"),
            (Some(class), None) => class.clone(),
            (None, Some(n)) => n,
            (None, None) => "unreported".to_string(),
        }
    }

    /// How what the daemon gave stands against the class a job declared.
    ///
    /// Judged by tier when the daemon names one — `large` is more than
    /// `medium` whatever the numbers — and by the numbers when it does not: an
    /// explicitly sized VM, or a daemon that reports cpus and memory but no
    /// class, is still an answer to "is this at least a `large`". Only a
    /// daemon that reports nothing at all is [`SizeCheck::Unreported`], and
    /// that is never read as `small`: an old daemon is not a wrong-sized VM.
    ///
    /// Memory gets a tenth of slack on the numeric path (`cpus` is exact). The
    /// tiers double from one to the next, so the slack cannot confuse two of
    /// them, and it keeps a daemon that counts in MB rather than MiB — 8 GB
    /// reported as 8 000 000 000 — from being called short of the 8 GiB tier.
    pub fn check(&self, wanted: SandboxSize) -> SizeCheck {
        use std::cmp::Ordering;
        if let Some(got) = self.size_class.as_deref().and_then(parse_size_class) {
            return match tier_rank(got).cmp(&tier_rank(wanted)) {
                Ordering::Less => SizeCheck::TooSmall,
                Ordering::Equal => SizeCheck::AsDeclared,
                Ordering::Greater => SizeCheck::Larger,
            };
        }
        let (want_cpus, want_memory) = tier_resources(wanted);
        let floor = want_memory - want_memory / 10;
        let axes = [
            self.cpus.map(|c| c.cmp(&want_cpus)),
            self.memory.map(|m| {
                if m < floor {
                    Ordering::Less
                } else if m > want_memory {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }),
        ];
        let mut reported = false;
        let mut larger = false;
        for axis in axes.into_iter().flatten() {
            reported = true;
            match axis {
                Ordering::Less => return SizeCheck::TooSmall,
                Ordering::Greater => larger = true,
                Ordering::Equal => {}
            }
        }
        match (reported, larger) {
            (false, _) => SizeCheck::Unreported,
            (true, true) => SizeCheck::Larger,
            (true, false) => SizeCheck::AsDeclared,
        }
    }
}

/// The verdict of [`VmSize::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeCheck {
    /// The daemon reported nothing the VM could be judged by.
    Unreported,
    /// The class asked for, or numbers that are that class.
    AsDeclared,
    /// More than asked for. A build runs as the workflow expects on it.
    Larger,
    /// Less than asked for on at least one axis. A build does not run slowly
    /// on it; it runs out its timeout. See `Dispatcher::ensure_sized`.
    TooSmall,
}

const MIB: u64 = 1024 * 1024;

/// The daemon's tiers, smallest first, and the vcpus and memory each stands
/// for — `SizeClass::resources` in `mvm-ctrl/src/models.rs`. `micro` and
/// `mini` are one vcpu on a CPU quota, so on the numbers they sit below
/// `small` by memory alone; by rank they sit below it outright.
const TIERS: [(SandboxSize, u32, u64); 6] = [
    (SandboxSize::Micro, 1, 512 * MIB),
    (SandboxSize::Mini, 1, 1024 * MIB),
    (SandboxSize::Small, 1, 2048 * MIB),
    (SandboxSize::Medium, 2, 4096 * MIB),
    (SandboxSize::Large, 4, 8192 * MIB),
    (SandboxSize::Xlarge, 8, 16384 * MIB),
];

/// The tier a daemon's class name stands for, if it is one this knows.
pub fn parse_size_class(name: &str) -> Option<SandboxSize> {
    TIERS.iter().map(|t| t.0).find(|c| c.as_str() == name)
}

fn tier_rank(class: SandboxSize) -> usize {
    TIERS
        .iter()
        .position(|t| t.0 == class)
        .expect("every SandboxSize is a tier")
}

/// `(vcpus, memory bytes)` the daemon gives a VM of this class.
fn tier_resources(class: SandboxSize) -> (u32, u64) {
    let t = TIERS[tier_rank(class)];
    (t.1, t.2)
}

/// `16 GB`, `512 MB`, `1.5 GB` — bytes at the scale a size class is spoken in.
fn human_bytes(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    if bytes >= GB {
        if bytes % GB == 0 {
            format!("{} GB", bytes / GB)
        } else {
            format!("{:.1} GB", bytes as f64 / GB as f64)
        }
    } else {
        format!("{} MB", bytes / MB)
    }
}

#[derive(Debug)]
pub enum VmError {
    Create {
        name: String,
        source: HeyoError,
    },
    Daemon {
        sandbox: String,
        what: &'static str,
        source: HeyoError,
    },
    NotRunnable {
        sandbox: String,
        status: String,
        reason: Option<String>,
    },
    BadOperationId(String),
    ExecFailed {
        sandbox: String,
        operation: String,
        reason: String,
    },
    ExecTimeout {
        sandbox: String,
        operation: String,
        after: Duration,
    },
    MalformedRecord {
        sandbox: String,
        operation: String,
        detail: String,
    },
    UploadFailed {
        sandbox: String,
        path: String,
        chunk: usize,
        of: usize,
        detail: String,
    },
    /// Every chunk exec exited 0 and the assembled file still hashes to
    /// something other than what was sent. There is no innocent reading of
    /// that: either the exec channel garbled the payload in flight or the
    /// guest's filesystem is returning different bytes than it acknowledged —
    /// and in both cases nothing else this VM reports can be trusted either,
    /// which is why [`crate::dispatch::DispatchError::indicates_guest_corruption`]
    /// treats it as grounds to destroy the VM rather than repool it.
    UploadCorrupted {
        sandbox: String,
        path: String,
        expected: String,
        actual: String,
    },
    /// A chunk of a [`Vm::download_file`] did not come back: the exec failed,
    /// the payload was not base64, or it was the wrong length. `chunk` and
    /// `of` are both zero when it was the size-and-hash probe that failed.
    DownloadFailed {
        sandbox: String,
        path: String,
        chunk: usize,
        of: usize,
        detail: String,
    },
    /// Every chunk came back the right length and the assembled file still
    /// hashes to something other than what the guest reported for it. The
    /// reading is the same as [`VmError::UploadCorrupted`]'s, in the other
    /// direction: the channel or the guest's filesystem is handing back bytes
    /// it does not hold, and `indicates_guest_corruption` treats it the same.
    DownloadCorrupted {
        sandbox: String,
        path: String,
        expected: String,
        actual: String,
    },
}

impl VmError {
    /// True when the failure was reaching the daemon at all, not anything the
    /// daemon said. See [`is_transport`] — the caller's right move is to drop
    /// the tunnel this rode in on so the retry redials.
    pub fn is_transport(&self) -> bool {
        match self {
            Self::Create { source, .. } | Self::Daemon { source, .. } => is_transport(source),
            _ => false,
        }
    }

    /// The daemon explicitly rejected a create because its Firecracker TAP
    /// subnet pool is full. Keep this deliberately narrower than a generic
    /// create failure: only this backend verdict makes deleting a warm cache a
    /// safe and useful recovery action.
    pub fn is_subnet_capacity(&self) -> bool {
        const VERDICT: &str = "has no usable /30 TAP subnet";
        match self {
            Self::Create {
                source: HeyoError::Api { status, message, body },
                ..
            } if *status != 0 => {
                message.contains(VERDICT)
                    || body
                        .as_ref()
                        .is_some_and(|value| value.to_string().contains(VERDICT))
            }
            Self::Create {
                source: HeyoError::SandboxFailed { reason, .. },
                ..
            } => reason.contains(VERDICT),
            _ => false,
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create { name, source } => {
                write!(f, "could not create VM {name:?}: {source}")
            }
            Self::Daemon {
                sandbox,
                what,
                source,
            } => write!(f, "{what} for {sandbox}: {source}"),
            Self::NotRunnable {
                sandbox,
                status,
                reason,
            } => {
                write!(f, "VM {sandbox} is {status} and cannot run steps")?;
                if let Some(r) = reason {
                    write!(f, ": {r}")?;
                }
                Ok(())
            }
            Self::BadOperationId(id) => write!(
                f,
                "operation id {id:?} is not acceptable to the daemon; it must be \
                 1-160 bytes of letters, digits, '.', '_' or '-'"
            ),
            Self::ExecFailed {
                sandbox,
                operation,
                reason,
            } => write!(
                f,
                "the daemon could not run operation {operation} on {sandbox}: {reason}"
            ),
            Self::ExecTimeout {
                sandbox,
                operation,
                after,
            } => write!(
                f,
                "operation {operation} on {sandbox} did not finish within {after:?}. \
                 The guest timeout should have fired first, so the daemon most \
                 likely stopped responding."
            ),
            Self::MalformedRecord {
                sandbox,
                operation,
                detail,
            } => write!(
                f,
                "the daemon returned an exec record for {operation} on {sandbox} that \
                 could not be interpreted: {detail}"
            ),
            Self::UploadFailed {
                sandbox,
                path,
                chunk,
                of,
                detail,
            } => write!(
                f,
                "writing {path} into {sandbox} failed on chunk {} of {of}: {detail}",
                chunk + 1
            ),
            Self::UploadCorrupted {
                sandbox,
                path,
                expected,
                actual,
            } => write!(
                f,
                "writing {path} into {sandbox} completed, but the guest does not \
                 hold the bytes that were sent (sha256 mismatch: sent {expected}, \
                 guest reports {actual}) — the exec channel or the guest \
                 filesystem corrupted the data"
            ),
            Self::DownloadFailed {
                sandbox,
                path,
                chunk,
                of,
                detail,
            } => {
                if *of == 0 {
                    write!(
                        f,
                        "reading {path} out of {sandbox} failed before the first chunk: {detail}"
                    )
                } else {
                    write!(
                        f,
                        "reading {path} out of {sandbox} failed on chunk {} of {of}: {detail}",
                        chunk + 1
                    )
                }
            }
            Self::DownloadCorrupted {
                sandbox,
                path,
                expected,
                actual,
            } => write!(
                f,
                "reading {path} out of {sandbox} completed, but the bytes received are \
                 not the ones the guest holds (sha256 mismatch: guest reports \
                 {expected}, received {actual}) — the exec channel or the guest \
                 filesystem corrupted the data"
            ),
        }
    }
}

/// The size and sha256 a [`Vm::download_file`] probe printed.
///
/// `size=` is the line the probe writes itself; the hash is wherever
/// `sha256sum` put it, found by shape rather than position so a guest that
/// prefixes its output with something (a login banner leaking through the
/// serial path, a `dd`-style note) does not break the parse. `None` for the
/// hash is an image without `sha256sum`, which the probe reports as
/// `sha256=unavailable`.
fn parse_download_stat(text: &str) -> Result<(u64, Option<String>), String> {
    let size = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("size="))
        .ok_or_else(|| format!("the guest reported no size: {}", text.trim()))?
        .trim()
        .parse::<u64>()
        .map_err(|e| {
            format!(
                "the guest reported an unreadable size: {e}: {}",
                text.trim()
            )
        })?;
    let hash = text
        .split_whitespace()
        .find(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_string);
    Ok((size, hash))
}

impl std::error::Error for VmError {}

#[cfg(test)]
mod log_render_tests {
    use super::{LogLine, render_log_lines};

    fn line(source: &str, message: &str) -> LogLine {
        LogLine {
            source: source.into(),
            message: message.into(),
        }
    }

    /// The daemon answers newest-first and full of the serial shell's command
    /// echo; what a run keeps must be chronological with the echo folded away.
    #[test]
    fn chronological_with_the_echo_folded() {
        // As the daemon would answer: newest first.
        let logs = vec![
            line("stdout", "   Compiling serde v1.0.229"),
            line(
                "console",
                "> }; __ci_rc=$?; printf ... echo __HEYYVM_abc_END__ $?",
            ),
            line("console", "> cargo build --release"),
            line("console", "HEYVM_READY"),
            line("console", "[    0.000000] Linux version 6.1.102"),
        ];
        let text = render_log_lines(&logs, logs.len());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            vec![
                "console [    0.000000] Linux version 6.1.102",
                "console HEYVM_READY",
                "[ci] (2 lines of step-script echo elided)",
                "stdout     Compiling serde v1.0.229",
            ],
        );
    }

    /// Only the console channel is folded: a build whose own output happens to
    /// start with `> ` is the guest speaking, and it stays.
    #[test]
    fn stdout_is_never_elided() {
        let logs = vec![line("stdout", "> some quoted diff line")];
        let text = render_log_lines(&logs, 1);
        assert_eq!(text, "stdout  > some quoted diff line\n");
    }

    #[test]
    fn truncation_is_announced_once_at_the_top() {
        let logs = vec![line("console", "late line")];
        let text = render_log_lines(&logs, 400);
        assert!(
            text.starts_with("[ci] showing the last 1 of 400 lines\n"),
            "{text}"
        );
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn failed_boot_still_returns_a_cleanup_identity() {
        use super::*;
        use axum::{Json, Router, routing::{get, post}};
        let probes = Arc::new(AtomicU64::new(0));
        let reads = probes.clone();
        let app = Router::new()
            .route("/sandbox-deploy", post(|| async { Json(serde_json::json!({"id":"sb-failed-boot"})) }))
            .route("/deployed-sandboxes/{id}", get(move || {
                let reads = reads.clone();
                async move {
                    reads.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"id":"sb-failed-boot","status":"failed","status_changed_at":"2026-09-25T00:00:00Z","error_message":"boot failed"}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let spec = VmSpec::default();
        let vm = Vms::new().create(HeyoClientOptions { base_url: Some(base), api_key: None, timeout: None },
            "job", &spec, Duration::from_secs(600)).await.unwrap();
        assert_eq!(vm.id(), "sb-failed-boot");
        assert_eq!(probes.load(Ordering::SeqCst), 0, "boot must not be polled before ownership is persisted");
        assert!(vm.ensure_running(Duration::from_secs(1)).await.is_err());
        assert_eq!(vm.id(), "sb-failed-boot", "failed boot must retain the deletion handle");
        server.abort();
    }

    #[tokio::test]
    async fn exec_retries_temporary_dependencies_but_not_rejected_credentials() {
        use axum::{Json, Router, routing::{get, post}, response::IntoResponse};
        for (status, failures, succeeds) in [(502, 1, true), (503, 2, true),
            (504, 1, true), (503, 3, false), (401, 1, false), (403, 1, false)] {
            let polls = Arc::new(AtomicU64::new(0));
            let app = Router::new()
                .route("/sandboxes/{id}/exec-operations", post(|| async {
                    Json(serde_json::json!({"status":"queued"}))
                }))
                .route("/sandboxes/{id}/exec-operations/{operation}", get(move || {
                    let polls = polls.clone();
                    async move {
                        if polls.fetch_add(1, Ordering::SeqCst) < failures {
                            (axum::http::StatusCode::from_u16(status).unwrap(),
                                Json(serde_json::json!({"error":"dependency or credential failure"}))).into_response()
                        } else {
                            Json(serde_json::json!({"status":"completed",
                                "result":{"output":"finished once", "exit_code":0}})).into_response()
                        }
                    }
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
            let vm = Vms::new().open(HeyoClientOptions {
                base_url: Some(base), api_key: None, timeout: None,
            }, "sb-retry".into()).await.unwrap();
            let result = vm.exec("dependency-retry", "true", &HashMap::new(), Duration::from_secs(5)).await;
            server.abort();
            if succeeds {
                let output = result.unwrap_or_else(|e| panic!("HTTP {status}: {e}"));
                assert_eq!(output.exit_code, 0);
                assert_eq!(output.output, "finished once");
            } else {
                assert!(result.is_err(), "HTTP {status} must stop without reaching the later success");
            }
        }
    }

    #[test]
    fn a_vm_size_is_labelled_from_whatever_the_daemon_gave() {
        let full = VmSize {
            size_class: Some("xlarge".into()),
            cpus: Some(8),
            memory: Some(16 * 1024 * 1024 * 1024),
        };
        assert_eq!(full.label(), "xlarge (8 CPU, 16 GB)");
        assert_eq!(full.check(SandboxSize::Xlarge), SizeCheck::AsDeclared);
        assert_eq!(full.check(SandboxSize::Large), SizeCheck::Larger);

        // An explicitly sized VM, or a daemon that names no class: the numbers
        // are still an answer.
        let numbers = VmSize {
            size_class: None,
            cpus: Some(2),
            memory: Some(1536 * 1024 * 1024),
        };
        assert_eq!(numbers.label(), "2 CPU, 1.5 GB");
        // Short of `small`'s 2 GB however many vcpus it has; past `mini` on both.
        assert_eq!(numbers.check(SandboxSize::Small), SizeCheck::TooSmall);
        assert_eq!(numbers.check(SandboxSize::Mini), SizeCheck::Larger);
        assert!(numbers.is_reported());

        // A daemon too old to report sizing is unreported, never `small`.
        let nothing: VmSize = serde_json::from_str(r#"{"id":"sb-1","status":"stopped"}"#).unwrap();
        assert!(!nothing.is_reported());
        assert_eq!(nothing.label(), "unreported");
        assert_eq!(nothing.check(SandboxSize::Small), SizeCheck::Unreported);
    }

    /// The check that stops a `large` build being started on a `small` VM:
    /// the failure that produced this was 75 minutes of timeout with nothing
    /// to say why, because a smaller VM does not build slowly, it builds
    /// past its deadline. What counts as too small has to be right in both
    /// directions — a false "too small" refuses a VM that would have worked.
    #[test]
    fn a_vm_smaller_than_declared_is_caught_by_class_or_by_numbers() {
        let by_class = |name: &str| VmSize {
            size_class: Some(name.into()),
            cpus: None,
            memory: None,
        };
        // The daemon's `small` default handed to a `large` job: the case that
        // looks exactly like a slow build.
        assert_eq!(
            by_class("small").check(SandboxSize::Large),
            SizeCheck::TooSmall
        );
        assert_eq!(
            by_class("medium").check(SandboxSize::Large),
            SizeCheck::TooSmall
        );
        assert_eq!(
            by_class("large").check(SandboxSize::Large),
            SizeCheck::AsDeclared
        );
        // A manual resize *up* from /vms is an override worth keeping.
        assert_eq!(
            by_class("xlarge").check(SandboxSize::Large),
            SizeCheck::Larger
        );
        // The quota tiers rank below `small` although they have its one vcpu.
        assert_eq!(
            by_class("mini").check(SandboxSize::Small),
            SizeCheck::TooSmall
        );
        assert_eq!(
            by_class("micro").check(SandboxSize::Mini),
            SizeCheck::TooSmall
        );

        // A class this does not know falls through to the numbers rather
        // than being guessed at either way.
        let odd = VmSize {
            size_class: Some("custom".into()),
            cpus: Some(4),
            memory: Some(8192 * MIB),
        };
        assert_eq!(odd.check(SandboxSize::Large), SizeCheck::AsDeclared);
        let odd_and_mute = by_class("custom");
        assert_eq!(
            odd_and_mute.check(SandboxSize::Large),
            SizeCheck::Unreported
        );

        // Numbers only: short on either axis is short.
        let few_cpus = VmSize {
            size_class: None,
            cpus: Some(2),
            memory: Some(8192 * MIB),
        };
        assert_eq!(few_cpus.check(SandboxSize::Large), SizeCheck::TooSmall);
        let little_memory = VmSize {
            size_class: None,
            cpus: Some(4),
            memory: Some(4096 * MIB),
        };
        assert_eq!(little_memory.check(SandboxSize::Large), SizeCheck::TooSmall);
        // One axis is still an answer — a daemon that reports cpus only.
        let cpus_only = VmSize {
            size_class: None,
            cpus: Some(1),
            memory: None,
        };
        assert_eq!(cpus_only.check(SandboxSize::Large), SizeCheck::TooSmall);
        assert_eq!(cpus_only.check(SandboxSize::Small), SizeCheck::AsDeclared);

        // 8 GB counted in MB rather than MiB is a `large`, not a short one;
        // half of it is short whichever way it is counted.
        let decimal = VmSize {
            size_class: None,
            cpus: Some(4),
            memory: Some(8_000_000_000),
        };
        assert_eq!(decimal.check(SandboxSize::Large), SizeCheck::AsDeclared);
        let half = VmSize {
            size_class: None,
            cpus: Some(4),
            memory: Some(4_000_000_000),
        };
        assert_eq!(half.check(SandboxSize::Large), SizeCheck::TooSmall);

        assert_eq!(parse_size_class("xlarge"), Some(SandboxSize::Xlarge));
        assert_eq!(parse_size_class("XLARGE"), None);
        assert_eq!(parse_size_class(""), None);
    }

    use super::*;

    #[test]
    fn only_explicit_subnet_capacity_rejections_are_destructive() {
        let capacity = VmError::Create {
            name: "new".into(),
            source: HeyoError::Api {
                status: 500,
                message: "Firecracker virtual network fc has no usable /30 TAP subnet in \
                          10.0.0.0/24 after retained reservations"
                    .into(),
                body: None,
            },
        };
        assert!(capacity.is_subnet_capacity());

        let transport = VmError::Create {
            name: "new".into(),
            source: HeyoError::Api {
                status: 0,
                message: "network error calling /sandbox-deploy".into(),
                body: None,
            },
        };
        assert!(!transport.is_subnet_capacity());
        assert!(transport.is_transport());

        let unknown = VmError::Create {
            name: "new".into(),
            source: HeyoError::Timeout(Duration::from_secs(1), "create timed out".into()),
        };
        assert!(!unknown.is_subnet_capacity());
    }

    /// A daemon stand-in on a local port that answers one HTTP request per
    /// connection: the POST with `queued`, the *first* poll with nothing —
    /// the socket is closed after the request is read, which is what a
    /// keep-alive connection the far end already closed looks like from
    /// reqwest — and every later poll with `completed`. Returns the port and
    /// a counter of connections accepted.
    async fn flaky_daemon() -> (u16, Arc<AtomicU64>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let n = counter.fetch_add(1, Ordering::SeqCst);
                // Read the whole request — headers plus a `Content-Length`
                // body — so the drop below is a clean close, not a reset
                // with unread bytes, which is the subtler of the two cases.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let k = sock.read(&mut chunk).await.unwrap();
                    if k == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..k]);
                    let text = String::from_utf8_lossy(&buf);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let body = match n {
                    0 => r#"{"status":"queued"}"#,
                    1 => {
                        drop(sock);
                        continue;
                    }
                    _ => r#"{"status":"completed","result":{"output":"ok\n","exit_code":0}}"#,
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(response.as_bytes()).await.unwrap();
                let _ = sock.shutdown().await;
            }
        });
        (port, accepted)
    }

    /// The observed failure: a poll that dies on the transport while the
    /// operation is still running. It is safe to ask again — the GET reads a
    /// file, and the POST is idempotent by `operationId` — so one lost
    /// connection must not fail the exec.
    #[tokio::test]
    async fn exec_survives_a_lost_connection_on_the_poll() {
        let (port, accepted) = flaky_daemon().await;
        let vm = Vms::new()
            .open(
                HeyoClientOptions {
                    api_key: None,
                    base_url: Some(format!("http://127.0.0.1:{port}")),
                    timeout: None,
                },
                "sb-704de5df".into(),
            )
            .await
            .unwrap();

        let out = vm
            .exec(
                "01a036000dd8-00000000.app-obs.checkout.u1",
                "true",
                &HashMap::new(),
                Duration::from_secs(5),
            )
            .await
            .unwrap_or_else(|e| panic!("the retry should have carried this: {e}"));
        assert_eq!(out.exit_code, 0);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "POST, the poll that was dropped, and the poll that answered"
        );
    }

    fn spec() -> VmSpec {
        VmSpec {
            driver: SandboxDriver::Firecracker,
            image: Some("ubuntu:24.04".into()),
            build: None,
            size_class: Some(SandboxSize::Medium),
            disk_size_gb: Some(20),
            working_directory: Some("/workspace".into()),
            env_vars: BTreeMap::new(),
            setup_hooks: vec![],
            cache_key_files: vec![],
            reuse: true,
            ttl_seconds: None,
        }
    }

    #[test]
    fn a_reasonable_spec_validates() {
        assert_eq!(spec().validate(), Ok(()));
    }

    #[test]
    fn libvirt_is_refused_at_parse_time() {
        let mut s = spec();
        s.driver = SandboxDriver::Libvirt;
        assert_eq!(s.validate(), Err(VmSpecError::UnsupportedDriver));
        assert!(
            VmSpecError::UnsupportedDriver
                .to_string()
                .contains("firecracker"),
            "the error must name what to use instead"
        );
    }

    /// A `..` in a cache-key path would let a workflow hash files outside its
    /// own checkout, which is both a traversal and a fingerprint that no other
    /// runner could reproduce.
    #[test]
    fn cache_key_files_may_not_escape_the_checkout() {
        for bad in ["../secrets", "/etc/passwd", "a/../../b"] {
            let mut s = spec();
            s.cache_key_files = vec![bad.to_string()];
            assert_eq!(
                s.validate(),
                Err(VmSpecError::EscapingCacheKeyFile(bad.to_string())),
                "{bad} must be rejected"
            );
        }
        let mut s = spec();
        s.cache_key_files = vec!["Cargo.lock".into(), "a/b/rust-toolchain.toml".into()];
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn env_keys_must_be_shell_safe() {
        let mut s = spec();
        s.env_vars.insert("PATH; rm -rf /".into(), "x".into());
        assert!(matches!(s.validate(), Err(VmSpecError::InvalidEnvKey(_))));

        let mut s = spec();
        s.env_vars.insert("CARGO_TERM_COLOR".into(), "never".into());
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn zero_sizes_are_rejected() {
        let mut s = spec();
        s.disk_size_gb = Some(0);
        assert_eq!(s.validate(), Err(VmSpecError::ZeroDisk));
        let mut s = spec();
        s.ttl_seconds = Some(0);
        assert_eq!(s.validate(), Err(VmSpecError::ZeroTtl));
    }

    /// The SDK marks a failure to *send* a request as `Api { status: 0 }`; a
    /// real answer always carries its status. Only the former means the cached
    /// tunnel is dead and worth evicting — treating a daemon's 500 as a tunnel
    /// failure would redial on every genuine error.
    #[test]
    fn only_a_transport_failure_reads_as_one() {
        let api = |status: u16| HeyoError::Api {
            status,
            message: "network error calling /sandbox-deploy".into(),
            body: None,
        };
        let dead = VmError::Create {
            name: "vm".into(),
            source: api(0),
        };
        assert!(dead.is_transport());
        let refused = VmError::Create {
            name: "vm".into(),
            source: api(500),
        };
        assert!(!refused.is_transport(), "a 500 arrived; the tunnel works");
        let exec = VmError::ExecFailed {
            sandbox: "vm".into(),
            operation: "op".into(),
            reason: "exit 1".into(),
        };
        assert!(!exec.is_transport(), "a failed step is not a dead link");
    }

    /// The fingerprint hashes the serialized spec, so map ordering has to be
    /// stable across processes or every restart rebuilds every VM.
    #[test]
    fn env_vars_serialize_in_a_stable_order() {
        let mut a = spec();
        let mut b = spec();
        for (k, v) in [("Z", "1"), ("A", "2"), ("M", "3")] {
            a.env_vars.insert(k.into(), v.into());
        }
        for (k, v) in [("M", "3"), ("Z", "1"), ("A", "2")] {
            b.env_vars.insert(k.into(), v.into());
        }
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    #[test]
    fn reuse_defaults_to_true() {
        let s: VmSpec = serde_yaml::from_str("driver: firecracker\nimage: ubuntu:24.04\n").unwrap();
        assert!(s.reuse);
        assert_eq!(s.driver, SandboxDriver::Firecracker);
    }

    #[test]
    fn operation_ids_match_the_daemons_rule() {
        assert!(valid_operation_id("019f7c7ef325-00000000"));
        assert!(valid_operation_id("a.b_c-1"));
        assert!(!valid_operation_id(""));
        assert!(!valid_operation_id("has space"));
        assert!(!valid_operation_id("has/slash"));
        assert!(!valid_operation_id(&"a".repeat(161)));
        assert!(valid_operation_id(&"a".repeat(160)));
    }

    #[test]
    fn minted_ids_are_valid_operation_ids_and_subject_tokens() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b, "two calls in the same millisecond must still differ");
        for id in [&a, &b] {
            assert!(valid_operation_id(id), "{id}");
            // Also usable as a NATS subject token — no dots.
            assert!(crate::config::is_subject_token(id), "{id}");
            let random = uuid::Uuid::parse_str(id.rsplit('-').next().unwrap()).unwrap();
            assert_eq!(random.get_version_num(), 4, "identity must not rely on the process-local counter");
        }
        assert_ne!(a.rsplit('-').next(), b.rsplit('-').next(), "each id has its own random identity");
        assert!(a < b, "ids must sort chronologically");
    }

    /// Non-hex characters in a VM name feed an id the daemon parses with
    /// `from_str_radix(_, 16).unwrap_or(0)`, collapsing every VM onto one tap
    /// address.
    #[test]
    fn sandbox_names_are_hex_safe_and_sanitized() {
        let n = sandbox_name("my/weird workflow", "a1b2c3d4e5f6", 1);
        assert_eq!(n, "ci-my-weird-workflow-a1b2c3d4e5f6-000000000001");
        assert!(
            n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "{n}"
        );
    }

    /// Trap 2. On the firecracker serial path the daemon returns an empty
    /// `stderr` and puts everything in `output`; reading `stdout` alone loses
    /// every diagnostic a failing build wrote.
    #[test]
    fn combined_output_prefers_the_daemons_combined_stream() {
        let o = ExecOutput {
            output: "compiling\nerror: no such file\n".into(),
            stdout: "compiling\n".into(),
            stderr: String::new(),
            exit_code: 1,
        };
        assert_eq!(o.combined(), "compiling\nerror: no such file\n");
        assert!(!o.succeeded());
    }

    /// Backends that populate the split streams and leave `output` empty must
    /// still produce everything.
    #[test]
    fn combined_output_falls_back_to_concatenating_the_split_streams() {
        let o = ExecOutput {
            output: String::new(),
            stdout: "line one".into(),
            stderr: "a warning".into(),
            exit_code: 0,
        };
        assert_eq!(o.combined(), "line one\na warning");
        assert!(o.succeeded());
    }

    /// Pinned to a record the daemon actually wrote
    /// (`~/.heyo/exec-operations/sb-3aac9a30/019f7c7ef325-00000000.json`). The
    /// envelope is camelCase while the nested result is snake_case, and getting
    /// that wrong silently yields `exit_code: 0` for every step.
    #[test]
    fn a_real_daemon_record_deserializes_with_its_mixed_casing() {
        let json = r#"{
          "operationId": "019f7c7ef325-00000000",
          "sandboxId": "sb-3aac9a30",
          "status": "completed",
          "command": "echo hi",
          "result": { "output": "hi\n", "stdout": "hi\n", "stderr": "", "exit_code": 7 },
          "createdAt": "2026-07-19T22:30:00.081149324+00:00",
          "updatedAt": "2026-07-19T22:30:00.136611374+00:00",
          "completedAt": "2026-07-19T22:30:00.136611374+00:00"
        }"#;
        let rec: ExecOperationRecord = serde_json::from_str(json).unwrap();
        assert!(rec.is_terminal());
        let r = rec.result.expect("result");
        assert_eq!(r.exit_code, 7, "snake_case exit_code must be read");
        assert_eq!(r.output, "hi\n");
    }

    #[test]
    fn queued_and_running_are_not_terminal() {
        for s in ["queued", "running"] {
            let rec: ExecOperationRecord =
                serde_json::from_str(&format!(r#"{{"status":"{s}"}}"#)).unwrap();
            assert!(!rec.is_terminal(), "{s}");
        }
        for s in ["completed", "failed"] {
            let rec: ExecOperationRecord =
                serde_json::from_str(&format!(r#"{{"status":"{s}"}}"#)).unwrap();
            assert!(rec.is_terminal(), "{s}");
        }
    }

    /// The request body has to be camelCase or the daemon defaults every field,
    /// most damagingly `timeoutSecs` — which is the whole reason this module
    /// bypasses the SDK's exec.
    #[test]
    fn the_start_request_is_camel_case() {
        let env: HashMap<String, String> = [("A".to_string(), "b".to_string())].into();
        let body = StartExecOperation {
            operation_id: "op-1",
            command: "true",
            env: Some(&env),
            timeout_secs: Some(1800),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["operationId"], "op-1");
        assert_eq!(json["timeoutSecs"], 1800);
        assert!(json.get("operation_id").is_none());
        assert!(json.get("timeout_secs").is_none());
    }

    #[test]
    fn an_absent_env_is_omitted_rather_than_sent_as_null() {
        let body = StartExecOperation {
            operation_id: "op-1",
            command: "true",
            env: None,
            timeout_secs: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("env").is_none());
        assert!(json.get("timeoutSecs").is_none());
    }

    #[test]
    fn a_download_probe_is_read_by_shape_not_position() {
        let (size, hash) = parse_download_stat(
            "size=12345\n\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /tmp/x.tar.gz\n",
        )
        .unwrap();
        assert_eq!(size, 12345);
        assert_eq!(
            hash.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        // An image without sha256sum: the size stands, the hash does not.
        let (size, hash) = parse_download_stat("size=0\nsha256=unavailable\n").unwrap();
        assert_eq!((size, hash), (0, None));

        // Noise before the probe's own lines is not the probe's problem.
        let (size, _) = parse_download_stat("Welcome to the guest\n size=7 \n").unwrap();
        assert_eq!(size, 7);

        assert!(parse_download_stat("/tmp/x: no such file\n").is_err());
        assert!(parse_download_stat("size=lots\n").is_err());
    }

    /// The chunk is a time budget, not a guest limit, so what is pinned is
    /// that it stays in the range where the per-chunk timeout is a sane
    /// throughput floor: at 1 MiB and 300s a chunk that times out is a
    /// console under ~5 KiB/s. Larger chunks lower that floor toward speeds a
    /// healthy VM actually runs at; smaller ones turn a big artifact into
    /// hundreds of round trips.
    #[test]
    fn the_download_chunk_keeps_its_timeout_a_sane_floor() {
        const _: () = assert!(DOWNLOAD_CHUNK >= 256 * 1024);
        const _: () = assert!(DOWNLOAD_CHUNK <= 4 * 1024 * 1024);
        const _: () = assert!(DOWNLOAD_CHUNK_TIMEOUT.as_secs() >= 120);
        // A 40 MiB artifact — app-obs with its two arrow/parquet binaries,
        // stripped and gzipped, is in that range — in well under a hundred
        // execs.
        assert!((40 * 1024 * 1024u64).div_ceil(DOWNLOAD_CHUNK) <= 80);
    }

    #[test]
    fn the_upload_chunk_stays_under_the_measured_guest_limit() {
        // The chunk size is a measured limit, not a guess: 32 KiB commands
        // succeed against a real Firecracker guest and 128 KiB returns
        // `bash: /usr/bin/env: Argument list too long`, because the daemon
        // renders the script as one argv entry and Linux bounds that at
        // MAX_ARG_STRLEN. This pins the margin the wrapper needs.
        // Both bounds are compile-time constants; the point of asserting them
        // is that changing UPLOAD_CHUNK past what a guest accepts fails here
        // rather than as a hung build.
        const _: () = assert!(UPLOAD_CHUNK <= 32 * 1024 - 4096);
        const _: () = assert!(UPLOAD_CHUNK >= 8 * 1024);
    }

    /// Chunk count is checkout latency, so it is asserted as a number rather
    /// than left to be rediscovered from a slow run.
    ///
    /// Uploads are strictly serial — one exec per chunk, and the per-sandbox
    /// lock forbids overlap — so every chunk is a POST plus at least one poll
    /// over the iroh tunnel. At roughly a second each, this bound is the
    /// difference between a checkout measured in minutes and one measured in
    /// many. Lowering `UPLOAD_CHUNK` is therefore a latency decision, and this
    /// makes it one somebody has to take deliberately.
    #[test]
    fn a_repository_sized_upload_does_not_regress_into_hundreds_of_chunks() {
        // This repository's packfile, the payload a bundle submit actually
        // sends. Base64 is 4 bytes out for every 3 in.
        const PACKFILE_BYTES: usize = 3_827_000; // ~3.65 MiB
        let encoded = PACKFILE_BYTES.div_ceil(3) * 4;
        let chunks = encoded.div_ceil(UPLOAD_CHUNK);
        assert!(
            chunks <= 190,
            "a bundle submit would take {chunks} serial execs; at ~1s each that is \
             {}s of checkout before a single build step runs",
            chunks,
        );
    }

    /// Base64 is `A-Za-z0-9+/=` — nothing special inside single quotes — which
    /// is why a chunk is interpolated without escaping. If that ever stopped
    /// being true, the upload would become a shell injection.
    #[test]
    fn base64_output_contains_nothing_that_needs_shell_escaping() {
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode((0u8..=255).collect::<Vec<u8>>());
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
            "{encoded}"
        );
        assert!(!encoded.contains('\''));
    }

    #[test]
    fn a_path_with_a_quote_is_escaped_for_the_shell() {
        assert_eq!(shell_single_quote("/workspace"), "'/workspace'");
        let escaped = shell_single_quote("/tmp/a'b");
        assert!(
            escaped.starts_with('\'') && escaped.ends_with('\''),
            "{escaped}"
        );
        assert!(escaped.contains(r"'\''"), "{escaped}");
    }

    #[test]
    fn path_segments_are_encoded() {
        assert_eq!(encode_segment("sb-3aac9a30"), "sb-3aac9a30");
        assert_eq!(encode_segment("a/b"), "a%2Fb");
        assert_eq!(encode_segment("a b"), "a%20b");
    }

    /// Boots a real VM on the local `heyvmd` and runs steps in it. Run with:
    /// `cargo test -- --ignored --nocapture local_daemon`
    ///
    /// Env overrides: `CI_TEST_IMAGE` (default `debian`), `CI_TEST_DRIVER`
    /// (`firecracker` or `kvm`, default `firecracker`), `CI_TEST_DAEMON`
    /// (default `http://127.0.0.1:34099`).
    ///
    /// `firecracker` is the default because `kvm` re-execs the daemon's own
    /// binary as `kvm-run <id>` (mvm-ctrl/src/lib.rs), so it fails with
    /// "No such file or directory" whenever `heyvmd` is running from a path that
    /// has since been rebuilt or moved — which is the normal state of a
    /// development machine.
    ///
    /// The middle assertion is the point of this whole module: a command that
    /// runs for longer than 30 seconds. The SDK's own exec cannot express that
    /// — its timeout never reaches the guest, so the firecracker serial path
    /// caps at 30s — and no CI step of any interest fits under that.
    #[tokio::test]
    #[ignore = "boots a real VM on the local heyvmd"]
    async fn local_daemon_runs_steps_past_the_thirty_second_ceiling() {
        let base = std::env::var("CI_TEST_DAEMON")
            .unwrap_or_else(|_| "http://127.0.0.1:34099".to_string());
        let image = std::env::var("CI_TEST_IMAGE").unwrap_or_else(|_| "debian".to_string());
        let driver = match std::env::var("CI_TEST_DRIVER").as_deref() {
            Ok("kvm") => SandboxDriver::Kvm,
            _ => SandboxDriver::Firecracker,
        };
        let options = HeyoClientOptions {
            // The local daemon runs without JWT_SECRET, so no bearer is sent.
            api_key: None,
            base_url: Some(base),
            timeout: None,
        };

        let spec = VmSpec {
            driver,
            image: Some(image),
            build: None,
            size_class: Some(SandboxSize::Micro),
            disk_size_gb: None,
            working_directory: None,
            env_vars: BTreeMap::new(),
            setup_hooks: vec![],
            cache_key_files: vec![],
            reuse: true,
            ttl_seconds: Some(900),
        };
        spec.validate().expect("spec validates");

        let vms = Vms::new();
        let vm = vms
            .create(
                options,
                &sandbox_name("selftest", "000000000000", 1),
                &spec,
                Duration::from_secs(900),
            )
            .await
            .expect("VM boots");
        println!("booted {}", vm.id());

        // Everything after this point must run even on failure, or a panicking
        // assertion strands a VM on the developer's machine.
        let outcome = run_local_daemon_checks(&vm).await;
        if let Err(e) = vm.destroy().await {
            eprintln!("warning: could not destroy {}: {e}", vm.id());
        }
        outcome.expect("all checks pass");
    }

    async fn run_local_daemon_checks(vm: &Vm) -> Result<(), String> {
        vm.ensure_running(Duration::from_secs(240)).await.map_err(|e| e.to_string())?;
        let env = HashMap::new();

        let out = vm
            .exec(&new_id(), "echo hello", &env, Duration::from_secs(60))
            .await
            .map_err(|e| format!("basic exec: {e}"))?;
        if !out.combined().contains("hello") {
            return Err(format!("expected 'hello', got {:?}", out.combined()));
        }
        if !out.succeeded() {
            return Err(format!("expected exit 0, got {}", out.exit_code));
        }

        // The whole reason this module bypasses the SDK's exec.
        let started = Instant::now();
        let out = vm
            .exec(
                &new_id(),
                "sleep 40; echo survived",
                &env,
                Duration::from_secs(180),
            )
            .await
            .map_err(|e| format!("long exec: {e}"))?;
        let elapsed = started.elapsed();
        if !out.combined().contains("survived") {
            return Err(format!(
                "a 40s command did not survive the 30s guest ceiling; got {:?} after {elapsed:?}",
                out.combined()
            ));
        }
        if elapsed < Duration::from_secs(35) {
            return Err(format!(
                "the long step returned suspiciously fast: {elapsed:?}"
            ));
        }
        println!("40s step completed in {elapsed:?}");

        // A non-zero exit is a failed step but a successful exec, and stderr has
        // to survive — on the serial path it arrives only via `output`.
        let out = vm
            .exec(
                &new_id(),
                "echo to-stdout; echo to-stderr >&2; exit 3",
                &env,
                Duration::from_secs(60),
            )
            .await
            .map_err(|e| format!("failing exec: {e}"))?;
        if out.exit_code != 3 {
            return Err(format!("expected exit 3, got {}", out.exit_code));
        }
        let combined = out.combined();
        for want in ["to-stdout", "to-stderr"] {
            if !combined.contains(want) {
                return Err(format!("combined output lost {want:?}: {combined:?}"));
            }
        }

        // Idempotency: the same operation id and command must reattach rather
        // than run twice. This is what makes a queue redelivery safe.
        let op = new_id();
        let cmd = "date +%s%N";
        let first = vm
            .exec(&op, cmd, &env, Duration::from_secs(60))
            .await
            .map_err(|e| format!("idempotent exec (first): {e}"))?;
        let second = vm
            .exec(&op, cmd, &env, Duration::from_secs(60))
            .await
            .map_err(|e| format!("idempotent exec (replay): {e}"))?;
        if first.combined() != second.combined() {
            return Err(format!(
                "replaying an operation id re-ran the command: {:?} vs {:?}",
                first.combined(),
                second.combined()
            ));
        }

        // Env vars must reach the guest.
        let mut env2 = HashMap::new();
        env2.insert("CI_SELFTEST".to_string(), "marker-value".to_string());
        let out = vm
            .exec(
                &new_id(),
                "echo $CI_SELFTEST",
                &env2,
                Duration::from_secs(60),
            )
            .await
            .map_err(|e| format!("env exec: {e}"))?;
        if !out.combined().contains("marker-value") {
            return Err(format!(
                "env var did not reach the guest: {:?}",
                out.combined()
            ));
        }

        // A download that spans several chunks, with a ragged last one, comes
        // back byte-for-byte — the hash check inside `download_file` is what
        // proves it, and it also proves the guest has `dd`, `base64` and
        // `sha256sum` where `ci/upload-artifact` needs them.
        let size = 2 * DOWNLOAD_CHUNK + 12345;
        let out = vm
            .exec(
                &new_id(),
                &format!("head -c {size} /dev/urandom > /tmp/ci-selftest.bin && echo written"),
                &env,
                Duration::from_secs(60),
            )
            .await
            .map_err(|e| format!("writing the download fixture: {e}"))?;
        if !out.combined().contains("written") {
            return Err(format!("could not write the fixture: {:?}", out.combined()));
        }
        let started = Instant::now();
        let bytes = vm
            .download_file(&new_id(), "/tmp/ci-selftest.bin", Duration::from_secs(600))
            .await
            .map_err(|e| format!("download: {e}"))?;
        if bytes.len() as u64 != size {
            return Err(format!("downloaded {} bytes, wanted {size}", bytes.len()));
        }
        println!(
            "downloaded {size} bytes in {:?} ({} KiB/s of raw payload)",
            started.elapsed(),
            size / 1024 / started.elapsed().as_secs().max(1)
        );
        // A missing file is a named failure, not a hang or an empty artifact.
        match vm
            .download_file(
                &new_id(),
                "/tmp/ci-selftest-missing",
                Duration::from_secs(60),
            )
            .await
        {
            Err(VmError::DownloadFailed { of: 0, .. }) => {}
            other => return Err(format!("a missing file downloaded as {other:?}")),
        }

        Ok(())
    }
}
