//! The tunnel plugin: a public Heyo Cloud hostname for an app-lb the internet
//! cannot reach.
//!
//! app-lb runs its own iroh endpoint and asks the daemon beside it (heyvmd,
//! which holds the cloud credential) to register a tunnel. The cloud then
//! serves `{subdomain}.heyo.computer` by dialing this endpoint and speaking
//! HTTP/1.1 over one QUIC stream per edge connection. Each stream is bridged
//! into pingora through an in-memory duplex and served by the same `LbProxy`
//! as the TCP listeners — routing, the sign-in gate, the guard and the access
//! log all apply unchanged — except that the visitor's address is taken from
//! the edge's `X-Heyo-Client-IP` (see [`LbProxy::for_tunnel_ingress`]).
//!
//! ## Trust
//!
//! Only the cloud edge may open streams. Registration returns the edge's
//! endpoint ids, and a connection from any other id is closed before a byte
//! is read — which is also what makes `X-Heyo-Client-IP` trustworthy here.
//!
//! ## Identity
//!
//! The endpoint's secret key is persisted beside the state file
//! (`app-lb-tunnel.key`, mode 0600), so the endpoint id — and with it the
//! cloud's record of where each hostname points — survives restarts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use heyo_sdk::{HeyoClient, HeyoError, RequestOptions};
use iroh::endpoint::presets::N0;
use iroh::{Endpoint, SecretKey};
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_proxy::HttpProxy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;

use super::{Plugin, PluginMeta};
use crate::proxy::LbProxy;

/// Must match the cloud's `services::tunnel_dialer::ALPN`.
pub const ALPN: &[u8] = b"heyo/applb-ingress/1";

/// How often registrations are refreshed. heyvmd re-registers on its own
/// heartbeat too; this is what brings a new edge id (after a cloud restart)
/// into the allow-list.
const REFRESH: Duration = Duration::from_secs(60);
/// How long to wait for the endpoint to reach a relay before registering
/// without one.
const ONLINE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long stopping the plugin waits for the streams it is serving.
const STOP_DRAIN: Duration = Duration::from_secs(10);
/// How long no stream must be open before a drain counts as done.
const DRAIN_QUIET: Duration = Duration::from_millis(300);

// ---- configuration --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub hostnames: Vec<HostnameConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostnameConfig {
    /// The subdomain to claim; omitted lets the cloud mint `lb-<random>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    /// Private hostnames require a Heyo sign-in for the owning account at
    /// the edge, before a request reaches this app-lb.
    #[serde(default = "yes")]
    pub public: bool,
}

fn yes() -> bool {
    true
}

/// Where this app-lb's tunnels are registered.
#[derive(Debug, Clone)]
pub enum Config {
    /// Heyo Cloud, through heyvmd: the cloud edge serves the hostname.
    Cloud(TunnelConfig),
    /// A namespace on a public app-lb, which serves the hostname itself
    /// (`docs/design/app-lb-namespace-tunnels.md`).
    Remote(RemoteConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// `"app-lb"`.
    pub provider: String,
    /// The public app-lb's admin API, e.g. `https://admin.us2.heyo.work`.
    pub remote: String,
    pub namespace: String,
    /// A tunnel token minted for this machine on the public app-lb, stored
    /// here as a secret.
    pub token: crate::secrets::SecretRef,
    pub tunnels: Vec<RemoteTunnel>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteTunnel {
    /// The tunnel's name there, which is its deployment id.
    pub name: String,
    pub hostnames: Vec<String>,
}

impl RemoteConfig {
    fn base(&self) -> &str {
        self.remote.trim_end_matches('/')
    }

    /// The public app-lb's hostname, as a proof names it.
    fn host(&self) -> String {
        url::Url::parse(&self.remote)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
            .unwrap_or_default()
    }
}

fn parse_remote(config: &Value) -> Result<RemoteConfig, String> {
    let cfg: RemoteConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    let url = url::Url::parse(&cfg.remote).map_err(|e| format!("remote {:?}: {e}", cfg.remote))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err("remote is the public app-lb's admin URL, like https://admin.us2.heyo.work".into());
    }
    if !crate::config::is_valid_namespace(&cfg.namespace) {
        return Err(format!("namespace {:?} is not a namespace name", cfg.namespace));
    }
    if cfg.tunnels.is_empty() || cfg.tunnels.len() > 10 {
        return Err("list 1 to 10 tunnels: {\"tunnels\": [{\"name\": \"desktop\", \"hostnames\": [\"desktop--<ns>.<domain>\"]}]}".into());
    }
    let mut seen = HashSet::new();
    for t in &cfg.tunnels {
        let label = (1..=63).contains(&t.name.len())
            && t.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !t.name.starts_with('-')
            && !t.name.ends_with('-');
        if !label {
            return Err(format!("tunnel name {:?}: one lowercase DNS label", t.name));
        }
        if !seen.insert(t.name.as_str()) {
            return Err(format!("tunnel {:?} is listed twice", t.name));
        }
        if t.hostnames.is_empty() || t.hostnames.len() > 10 {
            return Err(format!("tunnel {:?}: list 1 to 10 hostnames", t.name));
        }
    }
    Ok(cfg)
}

fn parse_config(config: &Value) -> Result<Config, String> {
    match config.get("provider").and_then(Value::as_str) {
        Some("app-lb") => parse_remote(config).map(Config::Remote),
        Some("cloud") => {
            let mut cloud = config.clone();
            cloud.as_object_mut().map(|o| o.remove("provider"));
            parse_cloud(&cloud).map(Config::Cloud)
        }
        Some(other) => Err(format!("provider {other:?}: use \"cloud\" or \"app-lb\"")),
        None => parse_cloud(config).map(Config::Cloud),
    }
}

fn parse_cloud(config: &Value) -> Result<TunnelConfig, String> {
    // Enabled with nothing configured: one public hostname the cloud picks,
    // which is what "put this app-lb on the internet" means.
    if config.is_null() {
        return Ok(TunnelConfig {
            hostnames: vec![HostnameConfig {
                subdomain: None,
                public: true,
            }],
        });
    }
    let cfg: TunnelConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    if cfg.hostnames.is_empty() {
        return Err("add at least one hostname: {\"hostnames\": [{\"public\": true}]}".into());
    }
    if cfg.hostnames.len() > 10 {
        return Err("at most 10 hostnames per app-lb".into());
    }
    // The cloud reuses a daemon's unnamed tunnel for the same endpoint, so two
    // unnamed entries would silently be one hostname.
    if cfg
        .hostnames
        .iter()
        .filter(|h| h.subdomain.is_none())
        .count()
        > 1
    {
        return Err("only one hostname may omit its subdomain; name the others".into());
    }
    let mut seen = HashSet::new();
    for h in &cfg.hostnames {
        if let Some(s) = &h.subdomain {
            let ok = (3..=63).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !s.starts_with('-')
                && !s.ends_with('-');
            if !ok {
                return Err(format!(
                    "subdomain {s:?}: use 3-63 lowercase letters, digits or inner hyphens"
                ));
            }
            if !seen.insert(s.as_str()) {
                return Err(format!("subdomain {s:?} is listed twice"));
            }
        }
    }
    Ok(cfg)
}

// ---- identity -------------------------------------------------------------

/// `app-lb-state.json` -> `app-lb-tunnel.key`, beside it.
pub fn key_path(state_path: &str) -> PathBuf {
    let path = Path::new(state_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app-lb-state");
    let name = match stem.strip_suffix("-state") {
        Some(prefix) => format!("{prefix}-tunnel.key"),
        None => format!("{stem}-tunnel.key"),
    };
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// Read the endpoint key, or create and persist one (0600).
pub(crate) fn load_or_create_key(path: &Path) -> Result<SecretKey, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse::<SecretKey>()
            .map_err(|e| format!("{} is not an iroh secret key: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("creating {}: {e}", dir.display()))?;
            }
            let tmp = path.with_extension("key.tmp");
            std::fs::write(
                &tmp,
                key.to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            )
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("securing {}: {e}", tmp.display()))?;
            }
            std::fs::rename(&tmp, path).map_err(|e| format!("writing {}: {e}", path.display()))?;
            tracing::info!(path = %path.display(), "created the tunnel endpoint key");
            Ok(key)
        }
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// `HEYO_IROH_RELAY_URL`, as every other Heyo iroh endpoint reads it.
pub(crate) fn relay_mode() -> iroh::RelayMode {
    match std::env::var("HEYO_IROH_RELAY_URL") {
        Ok(raw) if !raw.trim().is_empty() => match raw.trim().parse::<iroh::RelayUrl>() {
            Ok(url) => iroh::RelayMode::Custom(iroh::RelayMap::from(url)),
            Err(e) => {
                tracing::warn!(
                    "invalid HEYO_IROH_RELAY_URL {raw:?}: {e}; using the default relays"
                );
                iroh::RelayMode::Default
            }
        },
        _ => iroh::RelayMode::Default,
    }
}

// ---- state ----------------------------------------------------------------

/// Hostnames whose TLS the cloud edge terminates, shared with the ACME
/// manager so it never orders certificates for them.
pub type ExternalTlsHosts = Arc<RwLock<HashSet<String>>>;

/// What a public app-lb answers a registration with.
#[derive(Debug, Deserialize)]
struct RemoteRegistered {
    urls: Vec<String>,
    dialer_ids: Vec<String>,
}

/// For talking to a public app-lb's admin API.
fn remote_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("a reqwest client builds")
}

/// One hostname as heyvmd (and the cloud) registered it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Registered {
    pub subdomain: String,
    pub hostname: String,
    pub url: String,
    pub is_public: bool,
    #[serde(default)]
    pub edge_node_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct Status {
    node_id: Option<String>,
    online: bool,
    relay_url: Option<String>,
    tunnels: Vec<Registered>,
    /// Why the last registration pass failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    last_registered_at: u64,
}

struct Running {
    endpoint: Endpoint,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
}

pub struct TunnelPlugin {
    me: Weak<TunnelPlugin>,
    key_path: PathBuf,
    /// heyvmd, which holds the cloud credential. Attached with `app`: the
    /// daemon client is built after the plugin host.
    daemon: OnceLock<HeyoClient>,
    /// Where a remote provider's tunnel token is kept.
    secrets: Arc<crate::secrets::SecretStore>,
    /// The configuration last applied, which says where tunnels live.
    config: RwLock<Option<Config>>,
    external_tls: ExternalTlsHosts,
    /// The pingora app streams are served by. Attached by `main` once the
    /// proxy exists, which is after the plugin host is built.
    app: OnceLock<Arc<dyn StreamServer>>,
    running: tokio::sync::Mutex<Option<Running>>,
    status: RwLock<Status>,
    /// Endpoint ids allowed to open streams: the cloud edge's.
    allowed: RwLock<HashSet<String>>,
    streams_active: AtomicUsize,
    streams_total: AtomicU64,
    rejected: AtomicU64,
}

impl TunnelPlugin {
    pub fn new(
        key_path: PathBuf,
        external_tls: ExternalTlsHosts,
        secrets: Arc<crate::secrets::SecretStore>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            key_path,
            daemon: OnceLock::new(),
            secrets,
            config: RwLock::new(None),
            external_tls,
            app: OnceLock::new(),
            running: tokio::sync::Mutex::new(None),
            status: RwLock::new(Status::default()),
            allowed: RwLock::new(HashSet::new()),
            streams_active: AtomicUsize::new(0),
            streams_total: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        })
    }

    /// Hand the plugin the proxy to serve tunnel streams with, and the
    /// daemon to register them through.
    pub fn attach(&self, app: Arc<HttpProxy<LbProxy>>, daemon: HeyoClient) {
        let _ = self.app.set(Arc::new(Pingora(app)));
        let _ = self.daemon.set(daemon);
    }

    fn daemon(&self) -> Result<&HeyoClient, String> {
        self.daemon
            .get()
            .ok_or_else(|| "the tunnel plugin has no daemon client yet; this is a bug".into())
    }

    /// Accept connections on `endpoint` until it closes, serving each one
    /// that comes from an allowed edge.
    fn spawn_accept(
        &self,
        endpoint: Endpoint,
        shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let me = self.me.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Some(me) = me.upgrade() else { return };
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => me.serve_connection(conn, shutdown).await,
                        Err(e) => tracing::debug!("tunnel: incoming connection failed: {e}"),
                    }
                });
            }
        })
    }

    async fn stop(&self) {
        if let Some(r) = self.running.lock().await.take() {
            // No new connections and no more registrations; sessions finish
            // the request they are on instead of waiting for another.
            let _ = r.shutdown.send(true);
            for t in r.tasks {
                t.abort();
            }
            self.drain().await;
            r.endpoint.close().await;
        }
        let mut st = self.status.write().unwrap();
        st.online = false;
        st.tunnels.clear();
        st.error = None;
        self.allowed.write().unwrap().clear();
        self.external_tls.write().unwrap().clear();
    }

    /// Wait for the streams being served to finish — quiet for a moment, so
    /// one that a dialer opened just now is not cut — up to [`STOP_DRAIN`].
    async fn drain(&self) {
        let deadline = tokio::time::Instant::now() + STOP_DRAIN;
        let mut quiet_since = None;
        loop {
            let now = tokio::time::Instant::now();
            if self.streams_active.load(Ordering::Relaxed) == 0 {
                let since = *quiet_since.get_or_insert(now);
                if now - since >= DRAIN_QUIET {
                    return;
                }
            } else {
                quiet_since = None;
            }
            if now >= deadline {
                tracing::warn!(
                    active = self.streams_active.load(Ordering::Relaxed),
                    "tunnel: streams still open after the drain; closing them"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Register every configured hostname through heyvmd. Updates the status
    /// and the edge allow-list; returns the failures.
    async fn register_all(
        &self,
        cfg: &Config,
        key: &SecretKey,
        relay_url: Option<String>,
    ) -> Result<(), String> {
        let node_id = key.public().to_string();
        let (registered, errors) = match cfg {
            Config::Cloud(cfg) => self.register_cloud(cfg, &node_id, &relay_url).await,
            Config::Remote(cfg) => self.register_remote(cfg, key, &relay_url).await,
        };
        self.record(registered, &errors, relay_url);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// Register at a public app-lb's namespace, proving the node is ours.
    async fn register_remote(
        &self,
        cfg: &RemoteConfig,
        key: &SecretKey,
        relay_url: &Option<String>,
    ) -> (Vec<Registered>, Vec<String>) {
        let token = match self.secrets.resolve(&cfg.token) {
            Ok(t) => t,
            Err(e) => return (Vec::new(), vec![format!("the tunnel token secret: {e}")]),
        };
        let node_id = key.public().to_string();
        let host = cfg.host();
        let client = remote_client();
        let mut registered = Vec::new();
        let mut errors = Vec::new();
        for t in &cfg.tunnels {
            let ts = crate::deployment::now_secs();
            let msg = crate::tunnel_dialer::proof_message(&cfg.namespace, &t.name, &node_id, ts, &host);
            let body = json!({
                "node_id": node_id,
                "relay_url": relay_url,
                "hostnames": t.hostnames,
                "proof": {"ts": ts, "sig": crate::tunnel_dialer::sign_proof(key, &msg)},
            });
            let url = format!("{}/namespaces/{}/tunnels/{}", cfg.base(), cfg.namespace, t.name);
            match client.put(&url).bearer_auth(&token).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => match resp.json::<RemoteRegistered>().await {
                    Ok(r) => registered.extend(r.urls.iter().map(|u| Registered {
                        subdomain: t.name.clone(),
                        hostname: u.trim_start_matches("https://").trim_start_matches("http://").to_string(),
                        url: u.clone(),
                        is_public: true,
                        edge_node_ids: r.dialer_ids.clone(),
                    })),
                    Err(e) => errors.push(format!("{}: {} answered something else: {e}", t.name, cfg.base())),
                },
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    let why = if matches!(status.as_u16(), 401 | 403) {
                        format!("{} refused this app-lb's tunnel token ({status}): {}", cfg.base(), text.trim())
                    } else {
                        format!("{} refused the tunnel ({status}): {}", cfg.base(), text.trim())
                    };
                    errors.push(format!("{}: {why}", t.name));
                }
                Err(e) => errors.push(format!("{}: could not reach {}: {e}", t.name, cfg.base())),
            }
        }
        (registered, errors)
    }

    /// Register through heyvmd with Heyo Cloud.
    async fn register_cloud(
        &self,
        cfg: &TunnelConfig,
        node_id: &str,
        relay_url: &Option<String>,
    ) -> (Vec<Registered>, Vec<String>) {
        let mut registered = Vec::new();
        let mut errors = Vec::new();
        let daemon = match self.daemon() {
            Ok(d) => d,
            Err(e) => return (registered, vec![e]),
        };
        for h in &cfg.hostnames {
            let body = json!({
                "node_id": node_id,
                "relay_url": relay_url,
                "subdomain": h.subdomain,
                "is_public": h.public,
            });
            match daemon
                .request::<Registered>(
                    Method::POST,
                    "/tunnels",
                    Some(&body),
                    RequestOptions::default(),
                )
                .await
            {
                Ok(r) => registered.push(r),
                Err(e) => errors.push(format!(
                    "{}: {}",
                    h.subdomain.as_deref().unwrap_or("(minted)"),
                    describe(&e)
                )),
            }
        }
        (registered, errors)
    }

    /// Take in a registration pass: the status, the dialer allow-list, and
    /// the hostnames served here.
    fn record(&self, registered: Vec<Registered>, errors: &[String], relay_url: Option<String>) {
        {
            // Keep a hostname that failed to refresh this pass (a transient
            // cloud error) rather than dropping it from the page and the
            // allow-list; a successful pass replaces the whole set.
            let mut st = self.status.write().unwrap();
            if errors.is_empty() || !registered.is_empty() {
                let mut merged = registered.clone();
                for old in &st.tunnels {
                    if !merged.iter().any(|r| r.subdomain == old.subdomain) && !errors.is_empty() {
                        merged.push(old.clone());
                    }
                }
                st.tunnels = merged;
            }
            st.relay_url = relay_url;
            st.last_registered_at = crate::deployment::now_secs();
            st.error = (!errors.is_empty()).then(|| errors.join("; "));
            let mut allowed = self.allowed.write().unwrap();
            for t in &st.tunnels {
                allowed.extend(t.edge_node_ids.iter().cloned());
            }
            *self.external_tls.write().unwrap() =
                st.tunnels.iter().map(|t| t.hostname.to_ascii_lowercase()).collect();
        }
    }

    /// Serve one QUIC connection: refuse it unless it is the edge, then serve
    /// each stream it opens.
    async fn serve_connection(
        self: Arc<Self>,
        conn: iroh::endpoint::Connection,
        shutdown: watch::Receiver<bool>,
    ) {
        let remote = conn.remote_id().to_string();
        if !self.allowed.read().unwrap().contains(&remote) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(remote = %remote, "tunnel: refused a connection from an endpoint that is not the cloud edge");
            conn.close(1u32.into(), b"not an edge");
            return;
        }
        let Some(app) = self.app.get().cloned() else {
            conn.close(2u32.into(), b"not ready");
            return;
        };
        while let Ok((send, recv)) = conn.accept_bi().await {
            let me = self.clone();
            let app = app.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                me.streams_active.fetch_add(1, Ordering::Relaxed);
                me.streams_total.fetch_add(1, Ordering::Relaxed);
                app.serve(Box::new(tokio::io::join(recv, send)), shutdown)
                    .await;
                me.streams_active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }
}

/// A byte stream a tunnel carries: a QUIC bi-stream in production, a duplex
/// in tests.
pub(crate) trait TunnelIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TunnelIo for T {}

/// What serves a tunnel stream. pingora's `ServerApp` cannot be a trait
/// object (its receiver is `&Arc<Self>`), so this is the object-safe face of
/// one.
pub(crate) trait StreamServer: Send + Sync + 'static {
    fn serve(
        &self,
        io: Box<dyn TunnelIo>,
        shutdown: watch::Receiver<bool>,
    ) -> futures::future::BoxFuture<'static, ()>;
}

/// Any pingora app, as a [`StreamServer`].
pub(crate) struct Pingora<A>(pub Arc<A>);

impl<A: ServerApp + Send + Sync + 'static> StreamServer for Pingora<A> {
    fn serve(
        &self,
        io: Box<dyn TunnelIo>,
        shutdown: watch::Receiver<bool>,
    ) -> futures::future::BoxFuture<'static, ()> {
        Box::pin(serve_stream(self.0.clone(), io, shutdown))
    }
}

/// Bridge one byte stream into a pingora app and serve requests on it until
/// either side closes it. Generic so the tests can drive it without a full
/// `LbProxy`.
pub(crate) async fn serve_stream<A, S>(app: Arc<A>, io: S, shutdown: watch::Receiver<bool>)
where
    A: ServerApp + Send + Sync + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (mut io_read, mut io_write) = tokio::io::split(io);
    let (mut ours_read, mut ours_write) = tokio::io::split(ours);
    // The dialer's bytes in, pingora's answers out.
    let inbound = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut io_read, &mut ours_write).await;
        // The dialer hung up its side: pingora sees the end of the input.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut ours_write).await;
    });
    let outbound = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut ours_read, &mut io_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut io_write).await;
    });
    let mut stream: Option<Stream> = Some(Box::new(theirs));
    while let Some(s) = stream.take() {
        stream = app.process_new(s, &shutdown).await;
    }
    // Pingora is done with this stream and dropped its end: once what it
    // wrote has reached the dialer, the stream is over, whether or not the
    // dialer has hung up its side yet.
    let _ = outbound.await;
    inbound.abort();
}

/// Turn heyvmd's answer into something an operator can act on.
fn describe(e: &HeyoError) -> String {
    match e {
        HeyoError::Authentication => {
            "heyvmd refused the request: it is not logged in to Heyo Cloud \
             (run `heyvm login` on this machine), or app-lb's daemon key \
             (APP_LB_DAEMON_API_KEY) is wrong"
                .into()
        }
        HeyoError::NotFound(_) => "this heyvmd has no /tunnels route; upgrade heyvm".into(),
        other => other.to_string(),
    }
}

// ---- the plugin -----------------------------------------------------------

#[async_trait]
impl Plugin for TunnelPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "tunnel",
            name: "Tunnel",
            description: "Serve this app-lb at a public hostname without exposing the machine. \
                          Either Heyo Cloud's edge reaches it over iroh (needs heyvmd here, logged \
                          in with `heyvm login`), or a public app-lb does, through a namespace \
                          there (`\"provider\": \"app-lb\"`, with a tunnel token).",
            config_schema: json!({
                "type": "object",
                "properties": {
                    "provider": {"enum": ["cloud", "app-lb"], "default": "cloud"},
                    "remote": {"type": "string", "description": "app-lb provider: the public app-lb's admin URL"},
                    "namespace": {"type": "string", "description": "app-lb provider: the namespace there"},
                    "token": {"type": "object", "description": "app-lb provider: the secret holding a tunnel token",
                              "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}},
                    "tunnels": {"type": "array", "maxItems": 10, "description": "app-lb provider",
                                "items": {"type": "object", "required": ["name", "hostnames"],
                                          "properties": {"name": {"type": "string"},
                                                         "hostnames": {"type": "array", "items": {"type": "string"}}}}},
                    "hostnames": {
                        "type": "array",
                        "maxItems": 10,
                        "items": {
                            "type": "object",
                            "properties": {
                                "subdomain": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$",
                                              "description": "Omit to let the cloud mint one"},
                                "public": {"type": "boolean", "default": true,
                                           "description": "false requires a Heyo sign-in at the edge"}
                            }
                        }
                    }
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        self.stop().await;
        let Some(config) = config else { return Ok(()) };
        let cfg = parse_config(&config)?;
        if self.app.get().is_none() {
            return Err("the tunnel ingress is not wired to the proxy; this is a bug".into());
        }
        if matches!(cfg, Config::Cloud(_)) {
            self.daemon()?;
        }
        *self.config.write().unwrap() = Some(cfg.clone());
        let key = load_or_create_key(&self.key_path)?;
        let endpoint = Endpoint::builder(N0)
            .secret_key(key.clone())
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(relay_mode())
            .bind()
            .await
            .map_err(|e| format!("binding the tunnel endpoint: {e}"))?;
        let node_id = endpoint.id().to_string();
        let online = tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online())
            .await
            .is_ok();
        let relay_url = endpoint.addr().relay_urls().next().map(|u| u.to_string());
        {
            let mut st = self.status.write().unwrap();
            st.node_id = Some(node_id.clone());
            st.online = online;
        }
        tracing::info!(node = %node_id, online, relay = ?relay_url, "tunnel endpoint bound");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Register before accepting: registration is what fills the edge
        // allow-list, and `stop` emptied it. Accepting first refuses the edge
        // itself if it dials in that window — which it does right after a
        // restart. Connections that arrive meanwhile wait for `accept`.
        let first = self.register_all(&cfg, &key, relay_url).await;
        let accept = self.spawn_accept(endpoint.clone(), shutdown_rx.clone());
        let refresh = {
            let me = self.me.clone();
            let endpoint = endpoint.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(REFRESH);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let Some(me) = me.upgrade() else { return };
                    let relay = endpoint.addr().relay_urls().next().map(|u| u.to_string());
                    me.status.write().unwrap().online = relay.is_some();
                    if let Err(e) = me.register_all(&cfg, &key, relay).await {
                        tracing::warn!(error = %e, "tunnel: re-registration failed");
                    }
                }
            })
        };
        *self.running.lock().await = Some(Running {
            endpoint,
            tasks: vec![accept, refresh],
            shutdown: shutdown_tx,
        });
        // Serving continues either way: the refresh loop retries, and a
        // hostname that did register works now.
        first
    }

    async fn status(&self) -> Value {
        let st = self.status.read().unwrap().clone();
        let mut v = serde_json::to_value(&st).unwrap_or_default();
        v["streams_active"] = json!(self.streams_active.load(Ordering::Relaxed));
        v["streams_total"] = json!(self.streams_total.load(Ordering::Relaxed));
        v["rejected_connections"] = json!(self.rejected.load(Ordering::Relaxed));
        v
    }

    fn view_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/tunnels", get(list_tunnels))
            .with_state(self)
    }

    fn crud_routes(self: Arc<Self>) -> Router {
        Router::new()
            .route("/tunnels/:subdomain", delete(release_tunnel))
            .with_state(self)
    }
}

/// `GET …/tunnels` — what heyvmd has registered, including hostnames this
/// app-lb no longer configures (so they can be released).
fn gateway_error(e: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_GATEWAY, axum::Json(json!({ "error": e.to_string() }))).into_response()
}

impl TunnelPlugin {
    fn remote(&self) -> Option<RemoteConfig> {
        match self.config.read().unwrap().as_ref() {
            Some(Config::Remote(cfg)) => Some(cfg.clone()),
            _ => None,
        }
    }

    /// The public app-lb's answer to `method` on this namespace's tunnels.
    async fn remote_call(&self, cfg: &RemoteConfig, method: reqwest::Method, suffix: &str) -> Result<reqwest::Response, String> {
        let token = self.secrets.resolve(&cfg.token).map_err(|e| format!("the tunnel token secret: {e}"))?;
        let url = format!("{}/namespaces/{}/tunnels{suffix}", cfg.base(), cfg.namespace);
        remote_client()
            .request(method, &url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| format!("could not reach {}: {e}", cfg.base()))
    }
}

/// A public app-lb's tunnel rows, in the shape the panel shows the cloud's.
async fn list_remote(p: &TunnelPlugin, cfg: &RemoteConfig) -> Response {
    let resp = match p.remote_call(cfg, reqwest::Method::GET, "").await {
        Ok(r) => r,
        Err(e) => return gateway_error(e),
    };
    if !resp.status().is_success() {
        let status = resp.status();
        return gateway_error(format!("{} answered {status}: {}", cfg.base(), resp.text().await.unwrap_or_default().trim()));
    }
    let rows: Vec<Value> = match resp.json().await {
        Ok(rows) => rows,
        Err(e) => return gateway_error(format!("{} answered something else: {e}", cfg.base())),
    };
    let out: Vec<Value> = rows
        .iter()
        .flat_map(|row| {
            let hosts = row["hostnames"].as_array().cloned().unwrap_or_default();
            hosts.into_iter().filter_map(|h| h.as_str().map(str::to_string)).map(move |h| {
                json!({
                    "subdomain": row["name"], "hostname": h, "url": format!("https://{h}"),
                    "is_public": true, "node_id": row["node_id"], "live": row["live"], "healthy": row["healthy"],
                })
            })
        })
        .collect();
    axum::Json(out).into_response()
}

async fn list_tunnels(State(p): State<Arc<TunnelPlugin>>) -> Response {
    if let Some(cfg) = p.remote() {
        return list_remote(&p, &cfg).await;
    }
    let daemon = match p.daemon() {
        Ok(d) => d,
        Err(e) => {
            return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({ "error": e })))
                .into_response()
        }
    };
    match daemon
        .request::<Vec<Value>>(
            Method::GET,
            "/tunnels",
            None::<&()>,
            RequestOptions::default(),
        )
        .await
    {
        Ok(all) => axum::Json(all).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({ "error": describe(&e) })),
        )
            .into_response(),
    }
}

/// `DELETE …/tunnels/:subdomain` — release a hostname at the cloud. Remove
/// it from the plugin's configuration too, or the next refresh claims it
/// again.
async fn release_tunnel(
    State(p): State<Arc<TunnelPlugin>>,
    UrlPath(subdomain): UrlPath<String>,
) -> Response {
    if let Some(cfg) = p.remote() {
        let suffix = format!("/{}", urlencoding_segment(&subdomain));
        return match p.remote_call(&cfg, reqwest::Method::DELETE, &suffix).await {
            Ok(r) if r.status().is_success() => {
                p.status.write().unwrap().tunnels.retain(|t| t.subdomain != subdomain);
                StatusCode::NO_CONTENT.into_response()
            }
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": format!("no tunnel named {subdomain:?}") })),
            )
                .into_response(),
            Ok(r) => {
                let status = r.status();
                gateway_error(format!("{} answered {status}: {}", cfg.base(), r.text().await.unwrap_or_default().trim()))
            }
            Err(e) => gateway_error(e),
        };
    }
    let daemon = match p.daemon() {
        Ok(d) => d,
        Err(e) => {
            return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({ "error": e })))
                .into_response()
        }
    };
    let path = format!("/tunnels/{}", urlencoding_segment(&subdomain));
    match daemon
        .request::<Value>(
            Method::DELETE,
            &path,
            None::<&()>,
            RequestOptions::default(),
        )
        .await
    {
        Ok(_) => {
            p.status
                .write()
                .unwrap()
                .tunnels
                .retain(|t| t.subdomain != subdomain);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(HeyoError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": format!("no tunnel named {subdomain:?}") })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(json!({ "error": describe(&e) })),
        )
            .into_response(),
    }
}

/// Subdomains are `[a-z0-9-]` by validation, but a path segment from a URL
/// is whatever the caller sent.
fn urlencoding_segment(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_config_names_the_app_lb_namespace_and_tunnels() {
        let ok = json!({"provider": "app-lb", "remote": "https://Admin.us2.heyo.work/", "namespace": "sam",
                        "token": {"secret": "tunnel-us2", "key": "token"},
                        "tunnels": [{"name": "desktop", "hostnames": ["desktop--sam.us2.heyo.work"]}]});
        let Config::Remote(cfg) = parse_config(&ok).unwrap() else { panic!("remote") };
        assert_eq!(cfg.host(), "admin.us2.heyo.work");
        assert_eq!(cfg.base(), "https://Admin.us2.heyo.work");
        assert!(matches!(parse_config(&json!({"provider": "cloud", "hostnames": [{}]})), Ok(Config::Cloud(_))));
        let with = |k: &str, v: Value| { let mut c = ok.clone(); c[k] = v; c };
        for bad in [
            with("remote", json!("admin.us2.heyo.work")),
            with("namespace", json!("no spaces")),
            with("tunnels", json!([])),
            with("tunnels", json!([{"name": "Desktop", "hostnames": ["a.b"]}])),
            with("tunnels", json!([{"name": "a", "hostnames": []}])),
            with("tunnels", json!([{"name": "a", "hostnames": ["x.y"]}, {"name": "a", "hostnames": ["x.y"]}])),
            with("provider", json!("ngrok")),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&json!({"hostnames": [{"public": true}]})).is_ok());
        let Config::Cloud(default) = parse_config(&Value::Null).expect("enabling with no configuration works") else {
            panic!("no configuration is the cloud provider");
        };
        assert_eq!(default.hostnames.len(), 1);
        assert!(default.hostnames[0].subdomain.is_none() && default.hostnames[0].public);
        assert!(parse_config(&json!({"hostnames": [{"subdomain": "my-shop"}, {}]})).is_ok());
        for bad in [
            json!({"hostnames": []}),
            json!({"hostnames": [{}, {}]}),
            json!({"hostnames": [{"subdomain": "Shop"}]}),
            json!({"hostnames": [{"subdomain": "ab"}]}),
            json!({"hostnames": [{"subdomain": "a-b"}, {"subdomain": "a-b"}]}),
            json!({"hostnames": [{"subdomin": "x"}]}),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn the_key_is_created_once_and_kept_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-lb-tunnel.key");
        let a = load_or_create_key(&path).unwrap();
        let b = load_or_create_key(&path).unwrap();
        assert_eq!(a.public(), b.public(), "the endpoint id survives a restart");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            key_path("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-tunnel.key")
        );
    }

    /// A pingora app that answers every request with its path, so the test
    /// sees a real HTTP exchange through the duplex bridge.
    struct Echo;

    #[async_trait]
    impl pingora_core::apps::HttpServerApp for Echo {
        async fn process_new_http(
            self: &Arc<Self>,
            mut session: pingora_core::protocols::http::ServerSession,
            _shutdown: &pingora_core::server::ShutdownWatch,
        ) -> Option<pingora_core::apps::ReusedHttpStream> {
            if !session.read_request().await.ok()? {
                return None;
            }
            let path = session.req_header().uri.path().to_string();
            let host = session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = format!("{host}{path}");
            let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
            resp.insert_header("content-length", body.len().to_string())
                .unwrap();
            session.write_response_header(Box::new(resp)).await.ok()?;
            session.write_response_body(body.into(), true).await.ok()?;
            let stream = session.finish().await.ok()??;
            let (stream, _) = stream.into_parts();
            Some(pingora_core::apps::ReusedHttpStream::new(stream, None))
        }
    }

    /// The whole ingress path over real (loopback, relay-less) iroh: the edge's
    /// request reaches pingora and its answer comes back on the stream; an
    /// endpoint that is not the edge is refused before a byte is served.
    #[tokio::test]
    async fn only_the_edge_may_open_streams_and_its_requests_are_served() {
        use iroh::endpoint::presets::Minimal;

        let dir = tempfile::tempdir().unwrap();
        let daemon = HeyoClient::new(heyo_sdk::HeyoClientOptions {
            base_url: Some("http://127.0.0.1:9".into()),
            api_key: None,
            timeout: None,
        })
        .unwrap();
        let plugin = TunnelPlugin::new(
            dir.path().join("k"),
            Default::default(),
            Arc::new(crate::secrets::SecretStore::new(dir.path().join("s.json"), None)),
        );
        let _ = plugin.app.set(Arc::new(Pingora(Arc::new(Echo))));
        let _ = plugin.daemon.set(daemon);

        let bind = |alpn: bool| async move {
            let mut b = Endpoint::builder(Minimal).relay_mode(iroh::RelayMode::Disabled);
            if alpn {
                b = b.alpns(vec![ALPN.to_vec()]);
            }
            b.bind().await.unwrap()
        };
        let server = bind(true).await;
        let edge = bind(false).await;
        let stranger = bind(false).await;
        let (_tx, rx) = watch::channel(false);
        let _accept = plugin.spawn_accept(server.clone(), rx);
        plugin
            .allowed
            .write()
            .unwrap()
            .insert(edge.id().to_string());

        let exchange = |ep: Endpoint, addr: iroh::EndpointAddr| async move {
            let conn = ep.connect(addr, ALPN).await.map_err(|e| e.to_string())?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
            send.write_all(b"GET /hello HTTP/1.1\r\nHost: shop.heyo.test\r\n\r\n")
                .await
                .map_err(|e| e.to_string())?;
            let mut got = String::new();
            let mut buf = [0u8; 1024];
            while !got.contains("shop.heyo.test/hello") {
                let n = recv
                    .read(&mut buf)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("stream closed")?;
                got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
            }
            Ok::<String, String>(got)
        };
        let within = Duration::from_secs(10);

        let got = tokio::time::timeout(within, exchange(edge.clone(), server.addr()))
            .await
            .expect("the edge's request is answered in time")
            .expect("the edge's request is served");
        assert!(got.starts_with("HTTP/1.1 200"), "{got}");

        let refused = tokio::time::timeout(within, exchange(stranger.clone(), server.addr()))
            .await
            .expect("a stranger is refused promptly, not left hanging");
        assert!(
            refused.is_err(),
            "a non-edge endpoint was served: {refused:?}"
        );
        assert_eq!(plugin.rejected.load(Ordering::Relaxed), 1);
        assert_eq!(plugin.streams_total.load(Ordering::Relaxed), 1);
    }

    /// Answers after a pause, like a slow upstream.
    struct SlowEcho;

    #[async_trait]
    impl pingora_core::apps::HttpServerApp for SlowEcho {
        async fn process_new_http(
            self: &Arc<Self>,
            mut session: pingora_core::protocols::http::ServerSession,
            _shutdown: &pingora_core::server::ShutdownWatch,
        ) -> Option<pingora_core::apps::ReusedHttpStream> {
            if !session.read_request().await.ok()? {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
            let body = "slow and whole";
            let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
            resp.insert_header("content-length", body.len().to_string()).unwrap();
            session.write_response_header(Box::new(resp)).await.ok()?;
            session.write_response_body(body.into(), true).await.ok()?;
            let _ = session.finish().await;
            None
        }
    }

    /// Stopping the plugin (a reconfigure, or disabling it) lets a request it
    /// is serving finish instead of cutting it off.
    #[tokio::test]
    async fn stopping_drains_the_streams_being_served() {
        use iroh::endpoint::presets::Minimal;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let plugin = TunnelPlugin::new(
            dir.path().join("k"),
            Default::default(),
            Arc::new(crate::secrets::SecretStore::new(dir.path().join("s.json"), None)),
        );
        let _ = plugin.app.set(Arc::new(Pingora(Arc::new(SlowEcho))));
        let bind = |alpn: bool| async move {
            let mut b = Endpoint::builder(Minimal).relay_mode(iroh::RelayMode::Disabled);
            if alpn {
                b = b.alpns(vec![ALPN.to_vec()]);
            }
            b.bind().await.unwrap()
        };
        let server = bind(true).await;
        let edge = bind(false).await;
        plugin.allowed.write().unwrap().insert(edge.id().to_string());
        let (tx, rx) = watch::channel(false);
        let accept = plugin.spawn_accept(server.clone(), rx);
        *plugin.running.lock().await = Some(Running { endpoint: server.clone(), tasks: vec![accept], shutdown: tx });

        let conn = edge.connect(server.addr(), ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"GET /slow HTTP/1.1\r\nHost: shop.heyo.test\r\n\r\n").await.unwrap();
        let answer = tokio::spawn(async move {
            let mut got = String::new();
            let mut buf = [0u8; 1024];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
                if got.ends_with("slow and whole") {
                    break;
                }
            }
            got
        });
        // Stop once the request is being served.
        while plugin.streams_active.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::timeout(Duration::from_secs(5), plugin.stop()).await.expect("the drain is bounded");
        let got = tokio::time::timeout(Duration::from_secs(5), answer).await.unwrap().unwrap();
        assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("slow and whole"), "cut off: {got:?}");
    }

    #[tokio::test]
    async fn tunnel_ingress_serves_only_registered_hostnames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let hosts: ExternalTlsHosts = Default::default();
        hosts.write().unwrap().insert("mine.heyo.test".into());
        // No manager answers this socket: a request that passes the gate gets
        // the 503 a restarting app-lb gives, which proves it was let through.
        let control = crate::worker_rpc::Client::with_wait(dir.path().join("requests"), Duration::ZERO);
        let conf = Arc::new(pingora_core::server::configuration::ServerConf::default());
        let app = Arc::new(pingora_proxy::http_proxy(
            &conf,
            crate::proxy::LbProxy::for_tunnel_ingress(control, hosts),
        ));
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (_tx, rx) = watch::channel(false);
        let served = tokio::spawn(serve_stream(app, server, rx));

        for (host, path, status) in [
            ("someone-else.heyo.test", "/", "421"),
            ("anything", crate::proxy::TUNNEL_HEALTH_PATH, "200"),
            ("MINE.heyo.test:443", "/", "503"),
        ] {
            client
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let mut got = String::new();
            while !got.contains("\r\n\r\n") || !got.ends_with('\n') {
                let n = client.read(&mut buf).await.unwrap();
                assert!(n > 0, "stream closed early; got {got:?}");
                got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
            }
            assert!(got.starts_with(&format!("HTTP/1.1 {status}")), "{host}{path}: {got}");
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_stream_is_served_by_pingora_with_keep_alive() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (_tx, rx) = watch::channel(false);
        let served = tokio::spawn(serve_stream(Arc::new(Echo), server, rx));

        // Two requests on one stream: the edge keeps a stream alive the way
        // a browser keeps a connection alive.
        for path in ["/one", "/two"] {
            client
                .write_all(
                    format!("GET {path} HTTP/1.1\r\nHost: shop.heyo.test\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let mut got = String::new();
            while !got.ends_with(&format!("shop.heyo.test{path}")) {
                let n = client.read(&mut buf).await.unwrap();
                assert!(n > 0, "stream closed early; got {got:?}");
                got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
            }
            assert!(got.starts_with("HTTP/1.1 200"), "{got}");
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .unwrap()
            .unwrap();
    }
}
