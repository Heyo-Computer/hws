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

fn parse_config(config: &Value) -> Result<TunnelConfig, String> {
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
fn load_or_create_key(path: &Path) -> Result<SecretKey, String> {
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
fn relay_mode() -> iroh::RelayMode {
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
    pub fn new(key_path: PathBuf, external_tls: ExternalTlsHosts) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            key_path,
            daemon: OnceLock::new(),
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
            let _ = r.shutdown.send(true);
            for t in r.tasks {
                t.abort();
            }
            r.endpoint.close().await;
        }
        let mut st = self.status.write().unwrap();
        st.online = false;
        st.tunnels.clear();
        st.error = None;
        self.allowed.write().unwrap().clear();
        self.external_tls.write().unwrap().clear();
    }

    /// Register every configured hostname through heyvmd. Updates the status
    /// and the edge allow-list; returns the failures.
    async fn register_all(
        &self,
        cfg: &TunnelConfig,
        node_id: &str,
        relay_url: Option<String>,
    ) -> Result<(), String> {
        let mut registered = Vec::new();
        let mut errors = Vec::new();
        for h in &cfg.hostnames {
            let body = json!({
                "node_id": node_id,
                "relay_url": relay_url,
                "subdomain": h.subdomain,
                "is_public": h.public,
            });
            match self
                .daemon()?
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
                st.tunnels.iter().map(|t| t.hostname.clone()).collect();
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
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
pub(crate) async fn serve_stream<A, S>(app: Arc<A>, mut io: S, shutdown: watch::Receiver<bool>)
where
    A: ServerApp + Send + Sync + 'static,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let bridge = tokio::spawn(async move {
        let _ = tokio::io::copy_bidirectional(&mut io, &mut ours).await;
    });
    let mut stream: Option<Stream> = Some(Box::new(theirs));
    while let Some(s) = stream.take() {
        stream = app.process_new(s, &shutdown).await;
    }
    // The duplex end pingora held is dropped with its last session, which
    // ends the copy above.
    let _ = bridge.await;
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
            name: "Heyo Cloud tunnel",
            description: "Serve this app-lb at a public Heyo Cloud hostname without exposing the \
                          machine: the cloud edge reaches it over iroh. Needs heyvmd on this host, \
                          logged in with `heyvm login`.",
            config_schema: json!({
                "type": "object",
                "required": ["hostnames"],
                "properties": {
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
        self.daemon()?;
        let key = load_or_create_key(&self.key_path)?;
        let endpoint = Endpoint::builder(N0)
            .secret_key(key)
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
        let accept = self.spawn_accept(endpoint.clone(), shutdown_rx.clone());
        let first = self.register_all(&cfg, &node_id, relay_url).await;
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
                    let id = endpoint.id().to_string();
                    if let Err(e) = me.register_all(&cfg, &id, relay).await {
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
async fn list_tunnels(State(p): State<Arc<TunnelPlugin>>) -> Response {
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
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&json!({"hostnames": [{"public": true}]})).is_ok());
        let default = parse_config(&Value::Null).expect("enabling with no configuration works");
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let daemon = HeyoClient::new(heyo_sdk::HeyoClientOptions {
            base_url: Some("http://127.0.0.1:9".into()),
            api_key: None,
            timeout: None,
        })
        .unwrap();
        let plugin = TunnelPlugin::new(dir.path().join("k"), Default::default());
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
