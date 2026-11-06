//! The Incus boundary, for `driver: lxc` deployments.
//!
//! What [`crate::vm`] is to heyvmd, this is to Incus: everything that knows how
//! a container is created, listed, addressed and destroyed lives here.
//!
//! Three things are worth stating up front, because each is a trap:
//!
//! 1. **A `Running` container with no address yet is normal**, for the second or
//!    two it takes DHCP to settle. [`crate::vm::routable_addr`] treats a missing
//!    address as *terminal* — see the `Err(e)` arm of `promote_pending` — so
//!    reporting `Running` before an address exists would make the autoscaler
//!    kill healthy containers on boot. [`to_sandbox_info`] therefore reports
//!    [`SandboxStatus::Provisioning`] until an address is present, which keeps
//!    the autoscaler on its existing non-terminal branch.
//! 2. **Ownership lives in `user.app-lb.*`, not only in the name.** Incus names
//!    are DNS labels (1–63 chars, `[A-Za-z0-9-]`, no leading digit or dash, no
//!    trailing dash), and app-lb deployment ids are only checked for non-empty.
//!    `DeploymentSpec::validate` refuses an id that cannot make a legal name, so
//!    `vm::owner_of` still round-trips — but the config keys are what a human
//!    running `incus list` reads, and what a second app-lb on the same host uses
//!    to avoid adopting containers that are not its own.
//! 3. **The API is asynchronous.** A create answers `202` with an operation id
//!    and the instance appears later. That is the shape app-lb already wants:
//!    `scale_up` holds a fleet-wide permit across the create, so blocking until
//!    boot would serialize the pool behind the slowest image pull.

use crate::config::{Driver, LxcConfig, VmSpec};
use crate::vm::VmOwner;
use heyo_sdk::{SandboxInfo, SandboxStatus};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// How long an Incus call may take before it is abandoned. The same 30s
/// [`crate::vm`] gives heyvmd: a create that is pulling a large image is slow
/// for honest reasons, and the *reconcile* tick is protected by the create
/// running on its own task rather than by a short timeout here.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The instance-config prefix app-lb stamps its bookkeeping under. `user.*` is
/// Incus's documented free-form namespace, so nothing here collides with a key
/// Incus itself defines.
const OWNER_PREFIX: &str = "user.app-lb";

/// Longest legal Incus instance name. Names become DNS labels in the bridge's
/// dnsmasq, so this is the label limit rather than a filesystem one.
pub const MAX_NAME_LEN: usize = 63;

#[derive(Debug)]
pub enum IncusError {
    /// The socket is absent, or nothing is listening on it.
    Unreachable {
        socket: PathBuf,
        detail: String,
    },
    /// Reached Incus, but it does not trust this caller — almost always
    /// app-lb's user missing from the `incus` group.
    Untrusted {
        socket: PathBuf,
    },
    /// Incus answered, and said no.
    Api {
        status: u16,
        message: String,
    },
    /// A reply that did not parse as the API's envelope.
    Malformed(String),
    /// `vm.image` named a remote that is not configured.
    UnknownRemote {
        remote: String,
        known: Vec<String>,
    },
    Transport(String),
}

impl std::fmt::Display for IncusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { socket, detail } => write!(
                f,
                "no Incus at {}: {detail} — set APP_LB_LXC_SOCKET, or install Incus to run \
                 `driver: lxc` deployments on this host",
                socket.display()
            ),
            Self::Untrusted { socket } => write!(
                f,
                "Incus at {} does not trust this caller: add app-lb's user to the `incus` \
                 group (not `incus-admin`) and restart it",
                socket.display()
            ),
            Self::Api { status, message } => write!(f, "incus returned {status}: {message}"),
            Self::Malformed(what) => write!(f, "unrecognised reply from incus: {what}"),
            Self::UnknownRemote { remote, known } => write!(
                f,
                "image names remote {remote:?}, which is not configured; \
                 APP_LB_LXC_REMOTES holds {}",
                if known.is_empty() {
                    "nothing".to_string()
                } else {
                    known.join(", ")
                },
            ),
            Self::Transport(e) => write!(f, "incus transport: {e}"),
        }
    }
}

impl std::error::Error for IncusError {}

/// Incus wraps every reply in the same envelope, sync and async alike. The
/// `status_code` inside it is the one that matters: a `200` HTTP response can
/// still carry an error here.
#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    error_code: u16,
    #[serde(default)]
    error: String,
    #[serde(default)]
    metadata: Value,
    /// `/1.0/operations/<uuid>` when the reply is asynchronous. **Not optional
    /// to honour**: a mutating call answers `202` the moment it is *accepted*,
    /// so anything that depends on the change having happened has to wait on
    /// this. See [`Incus::request_awaited`].
    #[serde(default)]
    operation: String,
}

/// One instance as `GET /1.0/instances?recursion=2` reports it.
#[derive(Debug, Deserialize)]
struct Instance {
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    config: HashMap<String, String>,
    #[serde(default)]
    created_at: Option<String>,
    /// Epoch-zero until the instance has actually run. This is what
    /// distinguishes a container still on its way up from one that came up and
    /// died — see [`has_ever_run`].
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    state: Option<InstanceState>,
}

#[derive(Debug, Deserialize)]
struct InstanceState {
    #[serde(default)]
    network: Option<HashMap<String, NetworkInterface>>,
}

#[derive(Debug, Deserialize)]
struct NetworkInterface {
    #[serde(default)]
    addresses: Vec<NetworkAddress>,
}

#[derive(Debug, Deserialize)]
struct NetworkAddress {
    #[serde(default)]
    family: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    scope: String,
}

/// A pooled connection to the Incus socket.
///
/// Newtype because hyper-util only implements [`Connection`] for its own TCP
/// types — the same shape `heyo_sdk` uses for heyvmd's socket.
struct UnixConn(TokioIo<tokio::net::UnixStream>);

impl Connection for UnixConn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for UnixConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UnixConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Dials one socket path, ignoring the request URI's authority.
#[derive(Clone)]
struct UnixConnector(PathBuf);

impl tower_service::Service<hyper::Uri> for UnixConnector {
    type Response = UnixConn;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UnixConn, std::io::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: hyper::Uri) -> Self::Future {
        let path = self.0.clone();
        Box::pin(async move {
            Ok(UnixConn(TokioIo::new(
                tokio::net::UnixStream::connect(path).await?,
            )))
        })
    }
}

/// Talks to Incus over its unix socket.
#[derive(Clone)]
pub struct Incus {
    socket: PathBuf,
    cfg: LxcConfig,
    /// **Pooled, and that is load-bearing.** Incus runs a create inside an
    /// operation bound to the request's context, and Go cancels that context
    /// when the client disconnects. A connection closed the moment the `202`
    /// was read therefore cancelled roughly half of all creates: accepted, then
    /// silently abandoned, leaving a container that never appeared and a pool
    /// that waited out its boot timeout with nothing in the log to say why.
    /// Keeping the connection alive is what makes an accepted create happen.
    http: Client<UnixConnector, Full<Bytes>>,
}

/// `Client` is not `Debug`, and the socket is the half worth printing anyway.
impl std::fmt::Debug for Incus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Incus")
            .field("socket", &self.socket)
            .field("project", &self.cfg.project)
            .finish()
    }
}

impl Incus {
    /// Build the client. No I/O: `main` is synchronous (pingora's `Server`
    /// consumes it), and a constructor that had to be awaited would have to
    /// spin up a runtime just to decide whether a host has Incus on it.
    ///
    /// Whether Incus is actually *usable* is [`Self::probe`]'s question, asked
    /// once from the autoscaler's background service.
    pub fn new(cfg: LxcConfig) -> Self {
        let http = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(UnixConnector(cfg.socket.clone()));
        Self {
            socket: cfg.socket.clone(),
            cfg,
            http,
        }
    }

    /// Reach Incus and confirm it trusts us, returning its version.
    ///
    /// Called once at startup for the log. Not a gate: a failure here is
    /// reported and then every later call fails on its own with the same
    /// explanation, which is better than app-lb deciding at boot that a
    /// briefly-restarting Incus does not exist.
    pub async fn probe(&self) -> Result<String, IncusError> {
        let root = self.request(hyper::Method::GET, "/1.0", None).await?;
        // The whole point of the probe: reaching the socket without being
        // trusted fails every later call with a 403, and the fix is a group
        // membership rather than anything in app-lb's own config.
        if root.get("auth").and_then(Value::as_str) == Some("untrusted") {
            return Err(IncusError::Untrusted {
                socket: self.socket.clone(),
            });
        }
        Ok(root
            .get("environment")
            .and_then(|e| e.get("server_version"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string())
    }

    /// Every container app-lb owns, as the autoscaler's own vocabulary.
    ///
    /// One request per reconcile tick: `recursion=2` returns config *and* state
    /// for every instance, so the address and the ownership keys arrive with the
    /// listing rather than as a second call per container. Instances that are
    /// not ours — anything without our owner key — are dropped here rather than
    /// handed to the autoscaler to filter.
    pub async fn list(&self) -> Result<Vec<SandboxInfo>, IncusError> {
        let body = self
            .request(hyper::Method::GET, "/1.0/instances?recursion=2", None)
            .await?;
        let instances: Vec<Instance> = serde_json::from_value(body)
            .map_err(|e| IncusError::Malformed(format!("instance listing: {e}")))?;
        Ok(instances
            .iter()
            .filter(|i| self.is_ours(i))
            .map(|i| to_sandbox_info(i, self.cfg.network_nic.as_deref()))
            .collect())
    }

    /// Whether this container is one of ours, and worth reporting to the
    /// autoscaler at all.
    ///
    /// Two filters in one, because both answer "would reaping this be wrong?":
    ///
    /// - **Not app-lb's**: a container someone made by hand carries no
    ///   `deployment` key. The autoscaler reaps anything it cannot account for,
    ///   so letting one through would destroy a stranger's work.
    /// - **Another app-lb's**: names are per-deployment, not per-LB, so two
    ///   app-lb processes on one host would otherwise adopt each other's pools.
    ///   An instance stamped by a build that predates the key counts as ours,
    ///   so an in-place upgrade does not orphan what is already running.
    fn is_ours(&self, i: &Instance) -> bool {
        if !i.config.contains_key(&format!("{OWNER_PREFIX}.deployment")) {
            return false;
        }
        match i.config.get(&format!("{OWNER_PREFIX}.instance")) {
            Some(stamped) => stamped == &self.cfg.instance,
            None => true,
        }
    }

    /// Create a container and return its name without waiting for boot.
    ///
    /// Mirrors [`crate::vm::VmManager::create`]: the answer is a `202` naming an
    /// operation, and readiness is tracked across reconcile ticks. The name is
    /// the sandbox id everywhere else in app-lb.
    pub async fn create(
        &self,
        spec: &VmSpec,
        name: String,
        owner: &VmOwner,
        secret_env: HashMap<String, String>,
    ) -> Result<String, IncusError> {
        debug_assert!(spec.driver == Driver::Lxc, "validate must gate this");
        let body = self.create_body(spec, &name, owner, secret_env)?;
        let accepted = self
            .request_enveloped(hyper::Method::POST, "/1.0/instances", Some(body))
            .await?;
        self.watch_create(&name, accepted.operation);
        Ok(name)
    }

    /// Report a create that is accepted and then fails, without waiting for it.
    ///
    /// `POST /1.0/instances` answers `202` as soon as the request is *accepted*;
    /// the image pull and the start happen inside an operation that can still
    /// fail. Returning immediately is deliberate — `scale_up` holds a
    /// fleet-wide create permit across this call, so blocking on a cold image
    /// pull would serialize the whole fleet behind one deployment.
    ///
    /// But a failure there was previously *invisible*: the container simply
    /// never appeared, the autoscaler waited out `MISSING_GRACE` and gave up,
    /// and nothing anywhere said why. That is the same silent `ready: 0` the
    /// create-failure metric exists to explain. So the operation is watched on a
    /// detached task purely to turn it into a log line.
    ///
    /// Best-effort by construction: this cannot fail the create, because the
    /// create has already been accepted by the time it runs.
    fn watch_create(&self, name: &str, operation: String) {
        if operation.is_empty() {
            return;
        }
        let incus = self.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            let done = incus
                .request_enveloped(hyper::Method::GET, &format!("{operation}/wait"), None)
                .await;
            let err = match &done {
                Ok(envelope) => envelope
                    .metadata
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                Err(e) => e.to_string(),
            };
            if !err.is_empty() {
                tracing::error!(
                    container = %name,
                    error = %err,
                    "incus accepted the create and then failed it; the container will never \
                     appear and the pool will wait out its boot timeout",
                );
            }
        });
    }

    /// Destroy a container. One that Incus has already forgotten counts as
    /// destroyed, matching `VmManager::kill`.
    ///
    /// Force-stop first: Incus refuses to delete a running instance, and by the
    /// time app-lb is killing one it has already decided the workload is over.
    pub async fn kill(&self, name: &str) -> Result<(), IncusError> {
        // **The stop must complete before the delete is attempted.** Incus
        // refuses to delete a running instance, and a stop answers `202` the
        // moment it is accepted — so firing both without waiting fails with
        // `400 Instance is running` every time, and the container leaks.
        match self.stop(name, true).await {
            Ok(()) | Err(IncusError::Api { status: 404, .. }) => {}
            // Already stopped is the outcome we wanted.
            Err(IncusError::Api { message, .. }) if message.contains("already stopped") => {}
            Err(e) => return Err(e),
        }
        match self
            .request_awaited(
                hyper::Method::DELETE,
                &format!("/1.0/instances/{name}"),
                None,
            )
            .await
        {
            Ok(_) | Err(IncusError::Api { status: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Stop a container and keep it, for a sandbox this LB is not sure it
    /// owns (`Runtime::stop_unknown`). Missing or already stopped counts as
    /// stopped, as it does for `kill`.
    pub async fn stop_kept(&self, name: &str) -> Result<(), IncusError> {
        match self.stop(name, true).await {
            Ok(()) | Err(IncusError::Api { status: 404, .. }) => Ok(()),
            Err(IncusError::Api { message, .. }) if message.contains("already stopped") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn stop(&self, name: &str, force: bool) -> Result<(), IncusError> {
        let body = json!({"action": "stop", "timeout": 30, "force": force});
        self.request_awaited(
            hyper::Method::PUT,
            &format!("/1.0/instances/{name}/state"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    /// The create body. Split out and pure so it can be asserted without an
    /// Incus to talk to — this is where the interesting mistakes live.
    fn create_body(
        &self,
        spec: &VmSpec,
        name: &str,
        owner: &VmOwner,
        secret_env: HashMap<String, String>,
    ) -> Result<Value, IncusError> {
        let image = spec.image.as_deref().unwrap_or_default();
        let (server, alias) = self.resolve_image(image)?;

        let mut config = Map::new();
        // Never omitted. On heyvm an absent size class boots a 1 vCPU / 128 MB
        // guest; on a container it means no limit at all, which is worse — one
        // replica can take the host down. `validate` does not require the field,
        // so the default has to be applied here.
        let (cpu, memory) = limits_for(spec.size_class);
        config.insert("limits.cpu".into(), cpu.into());
        config.insert("limits.memory".into(), memory.into());

        // The image's ENTRYPOINT/CMD run unless the spec overrides them. An
        // `oci.entrypoint` is an argv rather than a shell string, so wrap it to
        // match the `sh -c` semantics every other app-lb driver has.
        if let Some(cmd) = spec
            .start_command
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            config.insert(
                "oci.entrypoint".into(),
                format!("/bin/sh -c {}", shell_quote(cmd)).into(),
            );
        }
        if let Some(cwd) = spec.working_directory.as_deref().filter(|c| !c.is_empty()) {
            config.insert("oci.cwd".into(), cwd.into());
        }

        // Literal env, then the resolved secrets over it — the same rule
        // `VmManager::create` follows, so a secret and a literal of the same
        // name resolve identically on both runtimes.
        for (k, v) in spec.env_vars.clone().unwrap_or_default() {
            config.insert(format!("environment.{k}"), v.into());
        }
        for (k, v) in secret_env {
            config.insert(format!("environment.{k}"), v.into());
        }

        // Which deployment owns this container. **Load-bearing**: `is_ours`
        // requires it, so a container created without it is invisible to the
        // very listing that has to watch it boot — it would run happily while
        // the pool that created it decided it had never appeared and gave up.
        // Derived from the name rather than passed in, for the same reason
        // `vm::owner_of` exists: the name is the one place the owner is already
        // recorded, and deriving it keeps the two from disagreeing.
        if let Some(deployment) = crate::vm::owner_of(name) {
            config.insert(format!("{OWNER_PREFIX}.deployment"), deployment.into());
        }
        config.insert(
            format!("{OWNER_PREFIX}.instance"),
            self.cfg.instance.clone().into(),
        );
        if let Some(account) = &owner.account_id {
            config.insert(format!("{OWNER_PREFIX}.account"), account.clone().into());
        }
        if let Some(user) = &owner.user_id {
            config.insert(format!("{OWNER_PREFIX}.user"), user.clone().into());
        }

        let mut body = json!({
            "name": name,
            "type": "container",
            "source": {
                "type": "image",
                "mode": "pull",
                "protocol": "oci",
                "server": server,
                "alias": alias,
            },
            "config": config,
            "start": true,
        });
        if !self.cfg.profiles.is_empty() {
            body["profiles"] = json!(self.cfg.profiles);
        }
        Ok(body)
    }

    /// Split `[<remote>:]<alias>` the way Incus's own client does: the prefix is
    /// a remote only if it names one we know, so `node:22` is the alias `node:22`
    /// on the default remote rather than the alias `22` on a remote called
    /// `node`.
    fn resolve_image(&self, image: &str) -> Result<(String, String), IncusError> {
        if let Some((prefix, rest)) = image.split_once(':')
            && let Some(server) = self.cfg.remotes.get(prefix)
        {
            return Ok((server.clone(), rest.to_string()));
        }
        let server = self
            .cfg
            .remotes
            .get(&self.cfg.default_remote)
            .ok_or_else(|| IncusError::UnknownRemote {
                remote: self.cfg.default_remote.clone(),
                known: self.cfg.remotes.keys().cloned().collect(),
            })?;
        Ok((server.clone(), image.to_string()))
    }

    /// One request, one connection.
    ///
    /// No pool and no connector: the listing is one call per reconcile tick and
    /// a create is rarer, so a connection per request is cheaper than the
    /// machinery that would avoid it. The URL's authority is a placeholder —
    /// the socket path is what decides where this goes.
    /// A request whose reply is the answer — the read paths, and the creates
    /// that deliberately do not wait for boot.
    async fn request(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, IncusError> {
        Ok(self.request_enveloped(method, path, body).await?.metadata)
    }

    async fn request_enveloped(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Envelope, IncusError> {
        let fut = self.request_inner(method, path, body);
        match tokio::time::timeout(TIMEOUT, fut).await {
            Ok(result) => result,
            Err(_) => Err(IncusError::Transport(format!(
                "{path} timed out after {TIMEOUT:?}"
            ))),
        }
    }

    async fn request_inner(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Envelope, IncusError> {
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        // The authority is a placeholder: the connector dials the socket path
        // regardless, and Incus's middleware only wants a Host header.
        let req = hyper::Request::builder()
            .method(method)
            .uri(format!("http://incus{}", self.with_project(path)))
            .header(hyper::header::HOST, "incus")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| IncusError::Transport(e.to_string()))?;

        let res = self.http.request(req).await.map_err(|e| {
            // A socket that is not there is the ordinary case on a host with no
            // Incus, and deserves the message naming the path rather than a
            // generic transport error.
            if e.is_connect() {
                IncusError::Unreachable {
                    socket: self.socket.clone(),
                    detail: e.to_string(),
                }
            } else {
                IncusError::Transport(e.to_string())
            }
        })?;

        let status = res.status().as_u16();
        let bytes = res
            .into_body()
            .collect()
            .await
            .map_err(|e| IncusError::Transport(e.to_string()))?
            .to_bytes();

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|e| {
            IncusError::Malformed(format!("{path}: {e}: {}", String::from_utf8_lossy(&bytes)))
        })?;
        // The envelope's error outranks the HTTP status: Incus reports a
        // not-found inside a 200 often enough that trusting the status alone
        // turns a missing container into a parse failure.
        if envelope.error_code != 0 {
            return Err(IncusError::Api {
                status: envelope.error_code,
                message: envelope.error,
            });
        }
        if !(200..300).contains(&status) {
            return Err(IncusError::Api {
                status,
                message: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(envelope)
    }

    /// A request whose effect must have *happened* before the next one is made.
    ///
    /// Incus answers a mutating call with `202` and an operation id as soon as
    /// it is accepted, not when it is done. Deleting an instance immediately
    /// after asking it to stop therefore races the stop and fails with
    /// `400 Instance is running` — which is exactly what it did before this
    /// existed, on every reap, drain and evict.
    ///
    /// A synchronous reply (no operation) is already complete and passes
    /// straight through.
    async fn request_awaited(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, IncusError> {
        let envelope = self.request_enveloped(method, path, body).await?;
        if envelope.operation.is_empty() {
            return Ok(envelope.metadata);
        }
        // `/wait` blocks server-side until the operation finishes, so this is
        // one request rather than a poll loop. The outer timeout still bounds it.
        let done = self
            .request_enveloped(
                hyper::Method::GET,
                &format!("{}/wait", envelope.operation),
                None,
            )
            .await?;
        // The operation's own failure is reported inside a successful envelope,
        // so it has to be read out rather than inferred from the status.
        let err = done
            .metadata
            .get("err")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !err.is_empty() {
            return Err(IncusError::Api {
                status: done
                    .metadata
                    .get("status_code")
                    .and_then(Value::as_u64)
                    .unwrap_or(500) as u16,
                message: err.to_string(),
            });
        }
        Ok(done.metadata)
    }

    /// Every call is scoped to app-lb's project. That is the security boundary,
    /// not a tenancy convenience: a confined project is what keeps an `incus`
    /// group membership from being `incus-admin`.
    fn with_project(&self, path: &str) -> String {
        let sep = if path.contains('?') { '&' } else { '?' };
        format!("{path}{sep}project={}", self.cfg.project)
    }
}

/// `limits.cpu` and `limits.memory` for a size class, matching what heyvmd
/// resolves the same class to host-side. `None` means `small`, never "no
/// limit" — see [`Incus::create_body`].
pub fn limits_for(size: Option<heyo_sdk::SandboxSize>) -> (String, String) {
    use heyo_sdk::SandboxSize::*;
    let (cpu, mem) = match size.unwrap_or(Small) {
        Micro => (1, "512MiB"),
        Mini => (1, "1GiB"),
        Small => (1, "2GiB"),
        Medium => (2, "4GiB"),
        Large => (4, "8GiB"),
        Xlarge => (8, "16GiB"),
    };
    (cpu.to_string(), mem.to_string())
}

/// The routable address of a container, or `None` while it still has none.
///
/// Prefers the configured interface when there is one, so a host with a second
/// bridge does not have app-lb routing to whichever interface Incus happened to
/// list first. Link-local and loopback are skipped: `scope: "global"` is the
/// only scope anything off-container can dial.
fn pick_address(state: &InstanceState, nic: Option<&str>) -> Option<String> {
    let network = state.network.as_ref()?;
    let mut names: Vec<&String> = network.keys().collect();
    names.sort();
    let candidates: Vec<&String> = match nic {
        Some(want) => names.into_iter().filter(|n| n.as_str() == want).collect(),
        None => names.into_iter().filter(|n| n.as_str() != "lo").collect(),
    };
    for name in candidates {
        let iface = &network[name];
        for addr in &iface.addresses {
            if addr.family == "inet" && addr.scope == "global" && !addr.address.is_empty() {
                return Some(addr.address.clone());
            }
        }
    }
    None
}

/// Incus's lifecycle vocabulary, as the autoscaler's.
///
/// The mapping is not quite mechanical, and the interesting arm is `Running`:
/// see [`to_sandbox_info`] for why a running container with no address is
/// reported as still provisioning.
/// Whether this instance has ever actually run.
///
/// Incus zeroes `last_used_at` until the first start (observed as
/// `1970-01-01T00:00:00Z`; the LXD lineage also uses `0001-01-01T00:00:00Z`), so
/// this separates "created, not started yet" from "ran and stopped" — two states
/// that are both reported as `Stopped` and mean opposite things to the
/// autoscaler. See [`map_status`].
fn has_ever_run(last_used_at: Option<&str>) -> bool {
    match last_used_at.map(str::trim).filter(|t| !t.is_empty()) {
        None => false,
        Some(t) => !t.starts_with("1970-01-01T00:00:00") && !t.starts_with("0001-01-01T00:00:00"),
    }
}

/// Incus's lifecycle vocabulary, as the autoscaler's.
///
/// Two arms are not mechanical, and both exist because a state that means
/// "still coming up" would otherwise be read as "will never serve" — which
/// makes `promote_pending` destroy a healthy container.
///
/// - **`Running` with no address** is the DHCP window, a second or two long.
/// - **`Stopped` before the first start** is the window between the instance
///   record appearing and the image finishing its pull. A `create` asks for
///   `start: true`, but the instance is visible as `Stopped` first — measured at
///   ~4s for `nginx:1.27` on a warm cache, and longer on a cold one. Reporting
///   the literal truth here killed every container mid-boot.
fn map_status(incus_status: &str, has_address: bool, ever_run: bool) -> SandboxStatus {
    match incus_status {
        "Running" if has_address => SandboxStatus::Running,
        // Running, but nothing can reach it yet.
        "Running" | "Starting" | "Ready" => SandboxStatus::Provisioning,
        // Created but never started: still on its way up, not dead.
        "Stopped" if !ever_run => SandboxStatus::Provisioning,
        "Stopped" | "Stopping" => SandboxStatus::Stopped,
        "Frozen" | "Freezing" => SandboxStatus::Paused,
        "Error" => SandboxStatus::Failed,
        _ => SandboxStatus::Unknown,
    }
}

/// One Incus instance as app-lb's own `SandboxInfo`.
///
/// Reusing the SDK's struct rather than defining a parallel one keeps every
/// consumer — `routable_addr`, `is_terminal`, `promote_pending`, `prune`, the
/// dashboard — working unchanged. The cost is constructing all of it by hand
/// here, which is the point: a field added to `SandboxInfo` upstream becomes a
/// compile error in exactly one place.
///
/// **`status` is load-bearing.** A `Running` container with no address is
/// reported as `Provisioning`, because `routable_addr`'s `NoGuestIp` is treated
/// as terminal by `promote_pending` — reporting the truth here would have the
/// autoscaler destroy healthy containers during the second it takes DHCP to
/// answer.
fn to_sandbox_info(i: &Instance, nic: Option<&str>) -> SandboxInfo {
    let guest_ip = i.state.as_ref().and_then(|s| pick_address(s, nic));
    SandboxInfo {
        // The Incus name *is* the sandbox id: app-lb addresses containers by
        // name everywhere, and `vm::owner_of` parses the deployment back out of
        // it.
        id: i.name.clone(),
        name: i.name.clone(),
        status: map_status(
            &i.status,
            guest_ip.is_some(),
            has_ever_run(i.last_used_at.as_deref()),
        ),
        image: i
            .config
            .get("image.description")
            .cloned()
            .unwrap_or_default(),
        guest_ip,
        port_mappings: Vec::new(),
        backend_type: Some(Driver::Lxc.as_str().to_string()),
        account_id: i.config.get(&format!("{OWNER_PREFIX}.account")).cloned(),
        created_at: i.created_at.clone(),
        // Everything below is either meaningless for a container or arrives in a
        // later stage; none of it is read on the Stage 1 path.
        region: None,
        start_command: None,
        working_directory: None,
        size_class: None,
        disk_size_gb: None,
        // Deliberately not populated. The values are in `config` under
        // `environment.*`, and `HostSandboxView` has no field for them — app-lb
        // does not re-expose what the runtime hands it, on either driver.
        env_vars: None,
        setup_hooks: None,
        uptime_secs: 0,
        ttl_seconds: None,
        is_deployed: true,
        error_message: None,
        status_changed_at: String::new(),
        urls: vec![],
        metadata: None,
        cpus: None,
        memory: None,
    }
}

/// Single-quote a string for `sh -c`, so a start command containing spaces or
/// quotes survives becoming one argv element of `oci.entrypoint`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Whether a string is a legal Incus instance name.
///
/// Names become DNS labels in the bridge's dnsmasq, hence the shape. Checked at
/// *registration* rather than at create time, so a deployment whose id could
/// never make one is refused while someone is still looking at the spec.
pub fn is_legal_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !name.starts_with(|c: char| c.is_ascii_digit() || c == '-')
        && !name.ends_with('-')
        // An all-numeric name is refused by Incus even though the rule above
        // already catches a leading digit; keep the check so the reason is
        // explicit rather than incidental.
        && !name.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Driver, LxcConfig};
    use heyo_sdk::SandboxSize;

    fn cfg() -> LxcConfig {
        LxcConfig {
            instance: "app-lb-test".into(),
            ..LxcConfig::default()
        }
    }

    fn incus() -> Incus {
        Incus::new(cfg())
    }

    fn spec(image: &str) -> VmSpec {
        let mut s: VmSpec = serde_json::from_value(serde_json::json!({
            "driver": "lxc",
            "image": image,
            "port": 8080,
        }))
        .unwrap();
        s.driver = Driver::Lxc;
        s
    }

    fn instance(name: &str, status: &str, addr: Option<&str>) -> Instance {
        let network = addr.map(|a| {
            HashMap::from([(
                "eth0".to_string(),
                NetworkInterface {
                    addresses: vec![NetworkAddress {
                        family: "inet".into(),
                        address: a.into(),
                        scope: "global".into(),
                    }],
                },
            )])
        });
        Instance {
            name: name.into(),
            status: status.into(),
            config: HashMap::from([(format!("{OWNER_PREFIX}.deployment"), "web".to_string())]),
            created_at: None,
            // Epoch-zero is "never started"; the helpers below override it.
            last_used_at: Some("1970-01-01T00:00:00Z".into()),
            state: Some(InstanceState { network }),
        }
    }

    /// The same instance, but one that has actually run.
    fn started(mut i: Instance) -> Instance {
        i.last_used_at = Some("2026-09-06T22:51:00Z".into());
        i
    }

    // -- the one that would have shipped a bug ------------------------------

    /// **A `Running` container with no address must not be reported as
    /// `Running`.**
    ///
    /// `routable_addr` returns `NoGuestIp` for a running sandbox with no
    /// address, and `promote_pending` treats *any* error other than a
    /// non-terminal `NotRunning` as fatal — its comment says "Terminal, or
    /// unroutable (no guest_ip). Either way it will never serve". A container
    /// takes a second or two to get a DHCP lease, so reporting the literal truth
    /// here would have the autoscaler destroy healthy containers moments after
    /// creating them, forever.
    #[test]
    fn a_running_container_with_no_address_yet_is_still_provisioning() {
        let booting = to_sandbox_info(&instance("applb-web-01", "Running", None), None);
        assert_eq!(booting.status, SandboxStatus::Provisioning);
        assert!(booting.guest_ip.is_none());
        // The property that matters, stated in the autoscaler's own terms.
        assert!(
            !crate::vm::is_terminal(&booting.status),
            "a container waiting on DHCP must not look reapable",
        );

        let ready = to_sandbox_info(&instance("applb-web-01", "Running", Some("10.1.2.3")), None);
        assert_eq!(ready.status, SandboxStatus::Running);
        assert_eq!(
            crate::vm::routable_addr(&ready, 8080).unwrap(),
            "10.1.2.3:8080".parse::<std::net::SocketAddr>().unwrap(),
        );
    }

    /// The rest of Incus's vocabulary, in the autoscaler's terms. `Stopped` has
    /// to be terminal — that is what makes a container app-lb asked to start and
    /// which then died get reaped rather than waited on.
    #[test]
    fn incus_statuses_map_onto_the_autoscalers_own() {
        for (incus, expected) in [
            ("Starting", SandboxStatus::Provisioning),
            ("Stopped", SandboxStatus::Stopped),
            ("Frozen", SandboxStatus::Paused),
            ("Error", SandboxStatus::Failed),
            ("Something New", SandboxStatus::Unknown),
        ] {
            assert_eq!(map_status(incus, false, true), expected, "{incus}");
        }
        assert!(crate::vm::is_terminal(&map_status("Stopped", false, true)));
        assert!(crate::vm::is_terminal(&map_status("Error", false, true)));
        assert!(!crate::vm::is_terminal(&map_status(
            "Starting", false, true
        )));
    }

    /// **`Stopped` before the first start is not death, it is the image still
    /// pulling.**
    ///
    /// `create` asks for `start: true`, but Incus makes the instance record
    /// visible before the start completes — measured at ~4s for `nginx:1.27` on
    /// a warm cache. Reading that as terminal made `promote_pending` give up on
    /// and destroy every container it had just created, then create another.
    /// Caught by running against a real daemon; no fixture would have shown it.
    #[test]
    fn a_container_that_has_not_started_yet_is_not_a_dead_one() {
        let pulling = to_sandbox_info(&instance("applb-web-01", "Stopped", None), None);
        assert_eq!(pulling.status, SandboxStatus::Provisioning);
        assert!(
            !crate::vm::is_terminal(&pulling.status),
            "a container whose image is still pulling must not look reapable",
        );

        // ...but one that ran and stopped really is stopped, or nothing would
        // ever reap a container that crashed after coming up.
        let died = to_sandbox_info(&started(instance("applb-web-01", "Stopped", None)), None);
        assert_eq!(died.status, SandboxStatus::Stopped);
        assert!(crate::vm::is_terminal(&died.status));
    }

    /// The signal itself, as Incus actually spells it. Both epoch conventions
    /// are accepted: Incus reports `1970-01-01`, its LXD lineage `0001-01-01`.
    #[test]
    fn a_zeroed_last_used_at_means_never_started() {
        assert!(!has_ever_run(None));
        assert!(!has_ever_run(Some("")));
        assert!(!has_ever_run(Some("1970-01-01T00:00:00Z")));
        assert!(!has_ever_run(Some("0001-01-01T00:00:00Z")));
        assert!(has_ever_run(Some("2026-09-06T22:51:00.511040199Z")));
    }

    // -- addressing ---------------------------------------------------------

    #[test]
    fn the_address_is_the_first_global_ipv4_and_never_loopback_or_link_local() {
        let state = |ifaces: Vec<(&str, Vec<(&str, &str, &str)>)>| InstanceState {
            network: Some(
                ifaces
                    .into_iter()
                    .map(|(name, addrs)| {
                        (
                            name.to_string(),
                            NetworkInterface {
                                addresses: addrs
                                    .into_iter()
                                    .map(|(family, address, scope)| NetworkAddress {
                                        family: family.into(),
                                        address: address.into(),
                                        scope: scope.into(),
                                    })
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
            ),
        };

        // Loopback is skipped even though it sorts first and has a global v4.
        let s = state(vec![
            ("lo", vec![("inet", "127.0.0.1", "local")]),
            ("eth0", vec![("inet", "10.1.2.3", "global")]),
        ]);
        assert_eq!(pick_address(&s, None).as_deref(), Some("10.1.2.3"));

        // IPv6-only is not routable by app-lb's upstream path, which builds a
        // v4 `SocketAddr` — better to keep waiting than to hand back something
        // that cannot be dialled.
        let s = state(vec![("eth0", vec![("inet6", "fd00::1", "global")])]);
        assert_eq!(pick_address(&s, None), None);

        // Link-local means DHCP has not answered yet.
        let s = state(vec![("eth0", vec![("inet", "169.254.1.1", "link")])]);
        assert_eq!(pick_address(&s, None), None);

        // With two bridges, the configured NIC decides — not whichever Incus
        // happened to list first.
        let s = state(vec![
            ("eth0", vec![("inet", "10.0.0.1", "global")]),
            ("eth1", vec![("inet", "192.168.5.5", "global")]),
        ]);
        assert_eq!(
            pick_address(&s, Some("eth1")).as_deref(),
            Some("192.168.5.5")
        );
        assert_eq!(pick_address(&s, Some("eth9")), None);
    }

    // -- the create body ----------------------------------------------------

    /// Limits are never omitted. On heyvm an absent size class boots a 1 vCPU /
    /// 128 MB guest; on a container it means *no limit*, so one replica could
    /// take the host down.
    #[test]
    fn every_size_class_maps_to_limits_and_none_means_small() {
        assert_eq!(
            limits_for(Some(SandboxSize::Micro)),
            ("1".into(), "512MiB".into())
        );
        assert_eq!(
            limits_for(Some(SandboxSize::Medium)),
            ("2".into(), "4GiB".into())
        );
        assert_eq!(
            limits_for(Some(SandboxSize::Xlarge)),
            ("8".into(), "16GiB".into())
        );
        assert_eq!(limits_for(None), limits_for(Some(SandboxSize::Small)));

        let body = incus()
            .create_body(
                &spec("nginx:1.27"),
                "applb-web-01",
                &VmOwner::default(),
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(body["config"]["limits.cpu"], "1");
        assert_eq!(body["config"]["limits.memory"], "2GiB");
    }

    /// The image's own ENTRYPOINT/CMD run unless the spec overrides them — the
    /// whole point of the driver, and the opposite of `firecracker_containerd`.
    #[test]
    fn the_image_entrypoint_runs_unless_the_spec_overrides_it() {
        let plain = incus()
            .create_body(
                &spec("nginx:1.27"),
                "applb-web-01",
                &VmOwner::default(),
                HashMap::new(),
            )
            .unwrap();
        assert!(
            plain["config"].get("oci.entrypoint").is_none(),
            "no start_command must leave the image's entrypoint alone: {plain}",
        );

        let mut s = spec("node:22");
        s.start_command = Some("npm start".into());
        s.working_directory = Some("/srv".into());
        let body = incus()
            .create_body(&s, "applb-web-01", &VmOwner::default(), HashMap::new())
            .unwrap();
        // Wrapped in a shell, because every other app-lb driver runs
        // `start_command` through `sh -c` and a bare argv would not.
        assert_eq!(body["config"]["oci.entrypoint"], "/bin/sh -c 'npm start'");
        assert_eq!(body["config"]["oci.cwd"], "/srv");

        // A command containing quotes still survives becoming one argv element.
        let mut s = spec("node:22");
        s.start_command = Some("sh -c 'echo hi'".into());
        let body = incus()
            .create_body(&s, "n", &VmOwner::default(), HashMap::new())
            .unwrap();
        assert_eq!(
            body["config"]["oci.entrypoint"],
            r"/bin/sh -c 'sh -c '\''echo hi'\'''"
        );
    }

    /// A secret beats a literal of the same name — the same rule
    /// `VmManager::create` follows, so the two runtimes resolve env identically.
    #[test]
    fn secrets_win_over_literals_of_the_same_name() {
        let mut s = spec("nginx:1.27");
        s.env_vars = Some(HashMap::from([
            ("PORT".to_string(), "8080".to_string()),
            ("TOKEN".to_string(), "placeholder".to_string()),
        ]));
        let body = incus()
            .create_body(
                &s,
                "applb-web-01",
                &VmOwner::default(),
                HashMap::from([("TOKEN".to_string(), "real".to_string())]),
            )
            .unwrap();
        assert_eq!(body["config"]["environment.PORT"], "8080");
        assert_eq!(body["config"]["environment.TOKEN"], "real");
    }

    /// Ownership is stamped in config, not only in the name — including the
    /// instance key that keeps two app-lb processes on one host from adopting
    /// each other's containers.
    #[test]
    fn the_create_body_stamps_who_owns_the_container() {
        let owner = VmOwner {
            account_id: Some("acc-1".into()),
            user_id: Some("u-1".into()),
        };
        let body = incus()
            .create_body(&spec("nginx:1.27"), "applb-web-01", &owner, HashMap::new())
            .unwrap();
        assert_eq!(body["config"]["user.app-lb.instance"], "app-lb-test");
        assert_eq!(body["config"]["user.app-lb.account"], "acc-1");
        assert_eq!(body["config"]["user.app-lb.user"], "u-1");
        assert_eq!(body["name"], "applb-web-01");
        assert_eq!(body["type"], "container");
        assert_eq!(body["start"], true);

        // A self-hosted app-lb stamps no owner and sends none.
        let plain = incus()
            .create_body(
                &spec("nginx:1.27"),
                "n",
                &VmOwner::default(),
                HashMap::new(),
            )
            .unwrap();
        assert!(plain["config"].get("user.app-lb.account").is_none());
    }

    /// **The round trip.** A container app-lb creates must be one app-lb
    /// recognises when it lists.
    ///
    /// The two halves were tested separately before this — `create_body` against
    /// its own expectations, `is_ours` against a hand-built fixture — and the
    /// gap between them was a missing `user.app-lb.deployment` that made every
    /// container app-lb created invisible to its own listing. The pool would
    /// have watched for a replica that was running the whole time, timed out,
    /// killed nothing it could see, and created another.
    ///
    /// So this test never builds a fixture: it feeds `create_body`'s own output
    /// back through the listing path.
    #[test]
    fn a_container_we_create_is_one_we_recognise() {
        let incus = incus();
        let name = crate::vm::replica_name("web", 42);
        let body = incus
            .create_body(
                &spec("nginx:1.27"),
                &name,
                &VmOwner::default(),
                HashMap::new(),
            )
            .unwrap();

        // Exactly what the daemon would hand back for what we just sent.
        let created = Instance {
            name: name.clone(),
            status: "Running".into(),
            config: serde_json::from_value(body["config"].clone()).unwrap(),
            created_at: None,
            last_used_at: Some("2026-09-06T22:51:00Z".into()),
            state: Some(InstanceState {
                network: Some(HashMap::from([(
                    "eth0".to_string(),
                    NetworkInterface {
                        addresses: vec![NetworkAddress {
                            family: "inet".into(),
                            address: "10.1.2.3".into(),
                            scope: "global".into(),
                        }],
                    },
                )])),
            }),
        };

        assert!(
            incus.is_ours(&created),
            "a container we created must survive our own listing filter; config was {:?}",
            created.config,
        );
        let info = to_sandbox_info(&created, None);
        assert_eq!(info.status, SandboxStatus::Running);
        // And the autoscaler can still tell which deployment it belongs to.
        assert_eq!(crate::vm::owner_of(&info.name), Some("web"));
    }

    /// Two app-lb processes on one host must not adopt each other's containers.
    /// An instance stamped by an older build carries no key and stays ours, so
    /// an in-place upgrade does not orphan a running pool.
    #[test]
    fn a_container_belonging_to_another_app_lb_is_not_ours() {
        let incus = incus();
        let mut theirs = instance("applb-web-01", "Running", None);
        theirs
            .config
            .insert(format!("{OWNER_PREFIX}.instance"), "app-lb-other".into());
        assert!(!incus.is_ours(&theirs));

        let mut ours = instance("applb-web-01", "Running", None);
        ours.config
            .insert(format!("{OWNER_PREFIX}.instance"), "app-lb-test".into());
        assert!(incus.is_ours(&ours));

        // Stamped by a build that predates the key.
        assert!(incus.is_ours(&instance("applb-web-01", "Running", None)));
    }

    // -- image references ---------------------------------------------------

    /// Incus's own rule: the prefix before the first `:` is a remote only if it
    /// names one we know. Otherwise `node:22` would become the alias `22` on a
    /// remote called `node`.
    #[test]
    fn an_image_prefix_is_a_remote_only_when_it_names_one() {
        let mut cfg = cfg();
        cfg.remotes.insert("ghcr".into(), "https://ghcr.io".into());
        let incus = Incus::new(cfg);

        assert_eq!(
            incus.resolve_image("node:22").unwrap(),
            ("https://docker.io".to_string(), "node:22".to_string()),
        );
        assert_eq!(
            incus.resolve_image("ghcr:org/app:v1").unwrap(),
            ("https://ghcr.io".to_string(), "org/app:v1".to_string()),
        );
        assert_eq!(
            incus.resolve_image("nginx").unwrap(),
            ("https://docker.io".to_string(), "nginx".to_string()),
        );
    }

    /// An unconfigured remote fails the *create*, not the spec — `validate` has
    /// no access to host config — and the message lists what this host will
    /// actually pull from.
    #[test]
    fn an_unconfigured_remote_names_what_is_configured() {
        let incus = Incus::new(LxcConfig {
            default_remote: "nope".into(),
            ..cfg()
        });
        let err = incus.resolve_image("whatever").unwrap_err();
        assert!(matches!(err, IncusError::UnknownRemote { .. }), "{err}");
        assert!(err.to_string().contains("docker"), "{err}");
    }

    // -- naming -------------------------------------------------------------

    /// Incus names are DNS labels. `vm::replica_name` produces the name, so
    /// these are the rules a deployment id has to survive.
    #[test]
    fn instance_names_follow_incuss_dns_label_rules() {
        assert!(is_legal_name("applb-web-0000000003e8"));
        assert!(is_legal_name(&crate::vm::replica_name("web", 42)));

        assert!(!is_legal_name(""), "empty");
        assert!(!is_legal_name(&"a".repeat(MAX_NAME_LEN + 1)), "too long");
        assert!(
            is_legal_name(&format!("a{}", "b".repeat(MAX_NAME_LEN - 1))),
            "exactly the limit"
        );
        assert!(!is_legal_name("web_1"), "underscore");
        assert!(!is_legal_name("web.1"), "dot");
        assert!(!is_legal_name("1web"), "leading digit");
        assert!(!is_legal_name("-web"), "leading dash");
        assert!(!is_legal_name("web-"), "trailing dash");
        assert!(!is_legal_name("12345"), "all numeric");
    }

    /// A container app-lb did not create is not app-lb's to reap.
    ///
    /// The autoscaler destroys anything in the fleet it cannot account for, so
    /// a hand-made container reaching the listing would be deleted out from
    /// under whoever made it.
    #[test]
    fn a_container_app_lb_did_not_create_is_never_in_the_fleet() {
        let incus = incus();
        let mut foreign = instance("someones-database", "Running", Some("10.0.0.9"));
        foreign.config.clear();
        assert!(
            !incus.is_ours(&foreign),
            "an unstamped container must not be ours"
        );

        // ...and one we did create still is.
        assert!(incus.is_ours(&instance("applb-web-01", "Running", None)));
    }

    /// Every request is scoped to app-lb's project — the security boundary, so
    /// a call that forgot it would be operating outside the confinement.
    #[test]
    fn every_request_is_scoped_to_the_project() {
        let incus = Incus::new(LxcConfig {
            project: "applb".into(),
            ..cfg()
        });
        assert_eq!(
            incus.with_project("/1.0/instances"),
            "/1.0/instances?project=applb"
        );
        assert_eq!(
            incus.with_project("/1.0/instances?recursion=2"),
            "/1.0/instances?recursion=2&project=applb",
        );
    }
}

/// Tests that need a real Incus on the host.
///
/// Ignored by default and gated on `APP_LB_TEST_INCUS=1`, so the ordinary
/// `cargo test` stays green on a machine that has never heard of Incus:
///
/// ```sh
/// APP_LB_TEST_INCUS=1 cargo test --offline -p app-lb -- --ignored live_
/// ```
///
/// The host needs a reachable socket (app-lb's user in the `incus` group), an
/// initialised storage pool and a bridge. Booting an image additionally needs
/// **Incus ≥ 6.3** with `skopeo` and `umoci`, because OCI support landed in 6.3
/// and was not backported to the 6.0 LTS line — a 6.0 host passes every test
/// here except [`live_boots_an_oci_image`], which reports the gap rather than
/// failing obscurely.
#[cfg(test)]
mod live {
    use super::*;
    use crate::config::LxcConfig;

    fn skip() -> bool {
        if std::env::var("APP_LB_TEST_INCUS").as_deref() != Ok("1") {
            eprintln!("skipping: set APP_LB_TEST_INCUS=1 to run against a real Incus");
            return true;
        }
        false
    }

    fn client() -> Incus {
        Incus::new(LxcConfig {
            instance: "app-lb-live-test".into(),
            ..LxcConfig::default()
        })
    }

    /// Whether this host can boot an OCI image at all. The API extension list is
    /// the authority — the version string alone would not tell us whether a
    /// distribution had backported it.
    async fn supports_oci(incus: &Incus) -> bool {
        let root = incus
            .request(hyper::Method::GET, "/1.0", None)
            .await
            .unwrap();
        root.get("api_extensions")
            .and_then(Value::as_array)
            .is_some_and(|exts| {
                exts.iter()
                    .filter_map(Value::as_str)
                    .any(|e| e.contains("oci"))
            })
    }

    /// The transport: a unix socket, hyper's `http1::handshake`, Incus's reply
    /// envelope, and the trust check that turns a missing group membership into
    /// a sentence rather than a 403 on every later call.
    #[tokio::test]
    #[ignore]
    async fn live_probes_the_daemon() {
        if skip() {
            return;
        }
        let version = client().probe().await.expect("probe");
        assert!(!version.is_empty(), "the server must report a version");
        eprintln!("incus {version}");
    }

    /// The listing app-lb runs once per reconcile tick, and the filter that
    /// keeps someone else's containers out of the fleet.
    #[tokio::test]
    #[ignore]
    async fn live_lists_only_our_own_containers() {
        if skip() {
            return;
        }
        let incus = client();
        let fleet = incus.list().await.expect("list");
        // Nothing on this host was created by a test instance of app-lb, so an
        // empty fleet is the correct answer even on a host full of containers.
        for info in &fleet {
            assert_eq!(info.backend_type.as_deref(), Some("lxc"));
            assert!(
                crate::vm::owner_of(&info.name).is_some(),
                "{} reached the fleet without an app-lb name",
                info.name,
            );
        }
        eprintln!("{} container(s) belong to this app-lb", fleet.len());
        for info in &fleet {
            eprintln!(
                "  {} status={:?} guest_ip={:?} routable={:?}",
                info.name,
                info.status,
                info.guest_ip,
                crate::vm::routable_addr(info, 8080).map(|a| a.to_string()),
            );
        }
    }

    /// Killing something that is not there is how every reap path ends when a
    /// container has already gone. It must be success, not a 404 the autoscaler
    /// logs forever.
    #[tokio::test]
    #[ignore]
    async fn live_killing_an_absent_container_is_success() {
        if skip() {
            return;
        }
        client()
            .kill("applb-nonexistent-000000000000")
            .await
            .expect("killing an absent container must succeed");
    }

    /// The whole Stage 1 path against a real daemon: create from an OCI image,
    /// watch it become addressable, confirm the address is reachable from this
    /// host, then destroy it.
    ///
    /// Skips with a clear message on a host whose Incus predates OCI support,
    /// rather than failing in a way that looks like an app-lb bug.
    ///
    /// **Cleans up on every path.** An earlier version used a fixed name and
    /// deleted only on success, so one failure left a container behind and every
    /// later run failed instantly on the name collision — which made the
    /// original failure impossible to diagnose. The name is unique per run and
    /// the teardown runs even when the body fails.
    #[tokio::test]
    #[ignore]
    async fn live_boots_an_oci_image() {
        if skip() {
            return;
        }
        let incus = client();
        if !supports_oci(&incus).await {
            eprintln!(
                "SKIPPED: this Incus has no OCI support (no `oci` API extension). It landed \
                 in 6.3 and was not backported to the 6.0 LTS line; the host also needs \
                 skopeo and umoci."
            );
            return;
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = crate::vm::replica_name("livetest", nonce);

        let outcome = boot_and_check(&incus, &name).await;
        // Teardown before the assertion, so a failure leaves nothing behind for
        // the next run to trip over.
        let cleaned = incus.kill(&name).await;
        if let Err(e) = outcome {
            panic!("{e}");
        }
        cleaned.expect("kill");

        let fleet = incus.list().await.expect("list after kill");
        assert!(
            !fleet.iter().any(|i| i.name == name),
            "{name} survived the kill",
        );
    }

    /// The body of [`live_boots_an_oci_image`], as a `Result` so the caller can
    /// clean up before reporting. Carries the last state it saw, because "never
    /// became Running" without saying what it *was* is not a diagnosis.
    async fn boot_and_check(incus: &Incus, name: &str) -> Result<(), String> {
        let mut spec: VmSpec = serde_json::from_value(serde_json::json!({
            "driver": "lxc", "image": "nginx:1.27", "port": 80,
        }))
        .unwrap();
        spec.driver = Driver::Lxc;

        incus
            .create(&spec, name.to_string(), &VmOwner::default(), HashMap::new())
            .await
            .map_err(|e| format!("create: {e}"))?;

        // Poll the way the autoscaler does: the same listing, the same
        // transitions. Generous, because a cold cache pulls the image first.
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        let mut last = String::from("never appeared in the listing");
        while std::time::Instant::now() < deadline {
            let fleet = incus.list().await.map_err(|e| format!("list: {e}"))?;
            if let Some(info) = fleet.iter().find(|i| i.name == name) {
                last = format!("{:?} guest_ip={:?}", info.status, info.guest_ip);
                if crate::vm::is_terminal(&info.status) {
                    return Err(format!("container died while booting: {last}"));
                }
                if info.status == SandboxStatus::Running {
                    let addr = crate::vm::routable_addr(info, spec.port)
                        .map_err(|e| format!("routable_addr: {e}"))?;
                    eprintln!("{name} is up at {addr}");
                    // The property the whole driver rests on: app-lb can reach it.
                    return tokio::net::TcpStream::connect(addr)
                        .await
                        .map(|_| ())
                        .map_err(|e| format!("app-lb cannot reach {addr}: {e}"));
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("{name} never became Running; last saw {last}"))
    }
}
