//! One admin API across the fleet (`docs/design/fleet-shared-state.md`,
//! "One admin API"): any member's admin listener answers any admin call.
//!
//! **What moves.** A call that acts where a deployment runs — anything under
//! `/deployments/:id/` for a deployment this host does not run, an operation,
//! transfer or job another host minted, a VM another host holds, a plugin
//! another host is home to — is forwarded **once** to the host that owns it,
//! and its answer is streamed back (WebSocket upgrades included). Fleet state
//! (namespaces, secrets, tokens, …) is written wherever the call lands, as
//! before. Listing calls (`GET /deployments`, `GET /metrics`, one `spread`
//! deployment) ask every live member in parallel and merge what they say.
//!
//! **How a hop reaches a peer's admin API.** The same way a tenant hop
//! reaches a peer (`fleet_hop`): HTTPS to the peer's `APP_LB_FLEET_ADDRESS`
//! on 443, carrying `x-heyo-fleet-hop` and the sealed peer token. Its `Host`
//! (and SNI) is a name the peer routes to *its own* admin deployment — the
//! shared admin name the client used when the peer routes it, else a route of
//! the peer's admin deployment as the fleet's registry shows it, else
//! `APP_LB_FLEET_ADMIN_HOST`. So the admin port is never exposed: the peer's
//! ingress admits the hop by its token, runs its edge checks, and passes the
//! hop headers through to its admin listener only (`request_control`), which
//! checks the token again in constant time.
//!
//! **Trust.** The token says only "a fleet member sent this". The home host
//! re-authorizes the caller's own credential (`Authorization`, cookies —
//! tokens are fleet state), so a token without reach is refused there. A
//! forwarded call is never forwarded again: a hop that would need another
//! answers 503.

use crate::fleet_hop::{FleetHop, HOP, Inbound, TOKEN};
use crate::fleet_pg::{HostFacts, HostRow};
use crate::fleet_sync::Fleet;
use crate::registry::Registry;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Which host answered a forwarded call.
pub const SERVED_BY: &str = "x-heyo-fleet-served-by";
/// A merged answer missing some member's part: `1`.
pub const PARTIAL: &str = "x-heyo-fleet-partial";
/// The members a merged answer is missing, comma separated.
pub const UNREACHABLE: &str = "x-heyo-fleet-unreachable";
/// The client, as this host's ingress saw it, on a request it passes to the
/// admin listener. Set by the ingress only (it removes any a client sent).
pub const CLIENT: &str = "x-heyo-fleet-client";
pub const ADMIN_HOST_ENV: &str = "APP_LB_FLEET_ADMIN_HOST";
pub const DRIVERS_ENV: &str = "APP_LB_FLEET_DRIVERS";
pub const FANOUT_TIMEOUT_ENV: &str = "APP_LB_FLEET_FANOUT_TIMEOUT_MS";
const DEFAULT_FANOUT_TIMEOUT: Duration = Duration::from_millis(3000);
/// The driver a spec that names none boots with.
const DEFAULT_DRIVER: &str = "firecracker";
/// The largest body read to place a deployment or find the VM it names.
const MAX_PEEK: usize = 16 << 20;
/// The largest answer merged from one member.
const MAX_MERGE: usize = 64 << 20;

// ---- host-scoped ids ------------------------------------------------------

static ID_HOST: OnceLock<String> = OnceLock::new();

/// Between a minting host's name and the id it minted. Never in a fleet host
/// name, an id app-lb mints, or base64url.
pub const ID_SEP: char = '~';

/// In fleet mode: prefix the ids this host mints (operations, transfers,
/// jobs) with its name, so another member can send a call naming one here.
pub fn set_id_host(host: &str) {
    let _ = ID_HOST.set(host.to_string());
}

/// `id`, scoped to this host in fleet mode; unchanged on a single server.
pub fn scoped(id: String) -> String {
    match ID_HOST.get() {
        Some(host) => format!("{host}{ID_SEP}{id}"),
        None => id,
    }
}

/// The host that minted `id`, if it is host-scoped. An id from before ids
/// were scoped names none, and is this host's.
pub fn owner_of(id: &str) -> Option<&str> {
    let (host, rest) = id.split_once(ID_SEP)?;
    (!rest.is_empty() && crate::config::is_valid_fleet_host(host)).then_some(host)
}

// ---- routing --------------------------------------------------------------

/// What an admin call is about, as far as where it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Fleet state, or a host-local surface: answered here.
    Local,
    /// Acts where deployment `id` runs.
    Deployment {
        id: String,
        /// A VM it names in its path or query.
        vm: Option<String>,
        /// The host that minted an operation or transfer id it names.
        owner: Option<String>,
        /// It may name a VM in its JSON body (`sandbox_id`).
        body_vm: bool,
    },
    /// An id a host minted, outside a deployment: `/jobs/:id`, `/transfers/:token`.
    Owned(Option<String>),
    /// Acts where plugin `id` runs.
    Plugin(String),
    /// `POST /deployments`: a new deployment is placed.
    Register,
    /// `GET /deployments`.
    List,
    /// `GET /metrics`.
    Metrics,
}

pub fn classify(method: &Method, path: &str, query: Option<&str>) -> Route {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    let query_vm = || {
        query.and_then(|q| {
            form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "sandbox_id")
                .map(|(_, v)| v.into_owned())
                .filter(|v| !v.is_empty())
        })
    };
    match segs.as_slice() {
        ["deployments"] if method == Method::GET => Route::List,
        ["deployments"] if method == Method::POST => Route::Register,
        ["metrics"] if method == Method::GET => Route::Metrics,
        ["deployments", id] => Route::Deployment { id: id.to_string(), vm: None, owner: None, body_vm: false },
        ["deployments", id, rest @ ..] => {
            let vm = match rest {
                ["vms" | "adoptions", sandbox, ..] => Some(sandbox.to_string()),
                _ => query_vm(),
            };
            let owner = match rest {
                ["operations" | "transfers", op, ..] => owner_of(op).map(str::to_string),
                _ => None,
            };
            let body_vm = method == Method::POST && matches!(rest, ["exec"] | ["operations"] | ["transfers"]);
            Route::Deployment { id: id.to_string(), vm, owner, body_vm }
        }
        ["jobs", job, ..] | ["transfers", job, ..] => Route::Owned(owner_of(job).map(str::to_string)),
        ["api", "plugins", id, ..] => Route::Plugin(id.to_string()),
        ["namespaces", _, "plugins", id] if method != Method::GET => Route::Plugin(id.to_string()),
        ["namespaces", _, "plugins", id, _, ..] => Route::Plugin(id.to_string()),
        _ => Route::Local,
    }
}

// ---- the forwarder --------------------------------------------------------

/// How a peer's admin API is reached.
#[derive(Debug, Clone)]
enum Peers {
    /// Production: its ingress, by a name it routes to its admin listener.
    Ingress { admin_host: Option<String> },
    /// Tests: straight to each host's admin listener at a base URL.
    #[cfg(test)]
    Direct(HashMap<String, String>),
}

/// One fleet member's admin API, ready to call.
struct Target {
    base: String,
    host_header: Option<String>,
    client: reqwest::Client,
}

pub struct FleetAdmin {
    host: String,
    hop: Arc<FleetHop>,
    fleet: Arc<Fleet>,
    registry: Arc<Registry>,
    plugins: Arc<crate::plugins::PluginHost>,
    admin_addr: String,
    fanout_timeout: Duration,
    peers: Peers,
    clients: Mutex<HashMap<(String, SocketAddr), reqwest::Client>>,
    /// This host's facts as last computed, for placing on itself without
    /// waiting for its own heartbeat to come back.
    local_facts: Mutex<Option<HostFacts>>,
}

impl std::fmt::Debug for FleetAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetAdmin").field("host", &self.host).finish_non_exhaustive()
    }
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (status, axum::Json(json!({ "error": message.into(), "code": code }))).into_response()
}

const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade", "host",
];

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.get(header::UPGRADE).is_some()
        && headers
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

impl FleetAdmin {
    pub fn new(
        host: &str,
        hop: Arc<FleetHop>,
        fleet: Arc<Fleet>,
        registry: Arc<Registry>,
        plugins: Arc<crate::plugins::PluginHost>,
        admin_addr: &str,
    ) -> Self {
        let fanout_timeout = std::env::var(FANOUT_TIMEOUT_ENV)
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .map_or(DEFAULT_FANOUT_TIMEOUT, Duration::from_millis);
        let admin_host = std::env::var(ADMIN_HOST_ENV)
            .ok()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty());
        Self {
            host: host.to_string(),
            hop,
            fleet,
            registry,
            plugins,
            admin_addr: admin_addr.to_string(),
            fanout_timeout,
            peers: Peers::Ingress { admin_host },
            clients: Mutex::new(HashMap::new()),
            local_facts: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn direct(mut self, peers: HashMap<String, String>) -> Self {
        self.peers = Peers::Direct(peers);
        self.fanout_timeout = Duration::from_millis(1500);
        self
    }

    pub fn set_local_facts(&self, facts: HostFacts) {
        *self.local_facts.lock().unwrap() = Some(facts);
    }

    /// What a request's hop headers say.
    pub fn inbound(&self, headers: &HeaderMap) -> Inbound {
        self.hop.inbound(headers)
    }

    // -- where things are --

    /// The host that runs a deployment this host does not.
    fn home_of(&self, spec: &crate::config::DeploymentSpec) -> Result<String, String> {
        let placement = spec.placement.as_ref();
        if let Some(home) = placement.and_then(|p| p.home.clone()) {
            return Ok(home);
        }
        // A spread deployment that excludes this host: a member it runs on.
        if let Some(p) = crate::fleet_placement::placer()
            && let Some(h) = p.peer_ready(&spec.id).or_else(|| p.peer_targeted(&spec.id))
        {
            return Ok(h);
        }
        self.fleet
            .live_members()
            .into_iter()
            .map(|m| m.host)
            .find(|h| h != &self.host && placement.is_none_or(|p| p.includes(h)))
            .ok_or_else(|| format!("no live fleet host runs {}", spec.id))
    }

    /// The host that holds VM `sandbox`, as members last published it.
    pub fn vm_host(&self, sandbox: &str) -> Option<String> {
        if self.local_facts.lock().unwrap().as_ref().is_some_and(|f| f.vms.contains_key(sandbox)) {
            return Some(self.host.clone());
        }
        self.fleet
            .live_members()
            .into_iter()
            .find(|m| m.facts.as_ref().is_some_and(|f| f.vms.contains_key(sandbox)))
            .map(|m| m.host)
    }

    /// Where a deployment-scoped call runs: `None` here.
    #[allow(clippy::result_large_err)]
    fn deployment_target(&self, id: &str, vm: Option<&str>, owner: Option<&str>) -> Result<Option<String>, Response> {
        let elsewhere = |h: &str| (h != self.host).then(|| h.to_string());
        if let Some(d) = self.registry.get(id) {
            if let Some(owner) = owner {
                return Ok(elsewhere(owner));
            }
            // Only a spread deployment has VMs on other hosts.
            if crate::fleet_placement::spreads(&d.spec)
                && let Some(host) = vm.and_then(|v| self.vm_host(v))
            {
                return Ok(elsewhere(&host));
            }
            return Ok(None);
        }
        let Some(spec) = self.registry.foreign().get(id).cloned() else {
            // Unknown anywhere: answered here, 404 as ever.
            return Ok(None);
        };
        if let Some(owner) = owner {
            return Ok(elsewhere(owner));
        }
        if let Some(host) = vm.and_then(|v| self.vm_host(v)) {
            return Ok(elsewhere(&host));
        }
        match self.home_of(&spec) {
            Ok(home) => Ok(elsewhere(&home)),
            Err(e) => Err(error(StatusCode::SERVICE_UNAVAILABLE, "fleet_home_unreachable", e)),
        }
    }

    fn plugin_target(&self, id: &str) -> Option<String> {
        self.plugins.home_of(id).filter(|h| h != &self.host)
    }

    // -- the middleware --

    /// Answer one admin call: here, by forwarding it once, or by asking
    /// every member.
    pub async fn handle(self: &Arc<Self>, req: Request<Body>, next: axum::middleware::Next) -> Response {
        match self.inbound(req.headers()) {
            Inbound::Refused => {
                tracing::warn!("refused an admin fleet hop without the fleet's token");
                return error(StatusCode::FORBIDDEN, "fleet_hop_refused", "fleet hop refused");
            }
            Inbound::Valid { origin, .. } => return self.hop_in(&origin, req, next).await,
            Inbound::None => {}
        }
        // Forwarding is the tenant hop's switch too (`APP_LB_FLEET_FORWARD`).
        if !self.hop.forwards() {
            return next.run(req).await;
        }
        let route = classify(req.method(), req.uri().path(), req.uri().query());
        match route {
            Route::Local => next.run(req).await,
            Route::List => self.fan_out(req, next, Merge::List).await,
            Route::Metrics => self.fan_out(req, next, Merge::Metrics).await,
            Route::Owned(owner) => match owner.filter(|h| h != &self.host) {
                Some(host) => self.forward(&host, req).await,
                None => next.run(req).await,
            },
            Route::Plugin(id) => match self.plugin_target(&id) {
                Some(host) => self.forward(&host, req).await,
                None => next.run(req).await,
            },
            Route::Register => self.place(None, req, next).await,
            Route::Deployment { id, vm, owner, body_vm } => {
                let known = self.registry.get(&id).is_some() || self.registry.foreign().contains_key(&id);
                if req.method() == Method::PUT && !known && req.uri().path().trim_matches('/').split('/').count() == 2 {
                    // A PUT that creates: placed like a register.
                    return self.place(Some(id), req, next).await;
                }
                let (req, vm) = if body_vm && vm.is_none() && self.registry.get(&id).is_some_and(|d| crate::fleet_placement::spreads(&d.spec)) {
                    match peek_sandbox(req).await {
                        Ok(peeked) => peeked,
                        Err(r) => return r,
                    }
                } else {
                    (req, vm)
                };
                match self.deployment_target(&id, vm.as_deref(), owner.as_deref()) {
                    Err(r) => r,
                    Ok(Some(host)) => self.forward(&host, req).await,
                    Ok(None) => {
                        let one = req.method() == Method::GET
                            && req.uri().path().trim_matches('/').split('/').count() == 2
                            && self.registry.get(&id).is_some_and(|d| crate::fleet_placement::spreads(&d.spec));
                        if one { self.fan_out(req, next, Merge::One).await } else { next.run(req).await }
                    }
                }
            }
        }
    }

    /// A call another member forwarded: answered here and nowhere else.
    async fn hop_in(&self, origin: &str, req: Request<Body>, next: axum::middleware::Next) -> Response {
        let route = classify(req.method(), req.uri().path(), req.uri().query());
        let onward = match &route {
            Route::Deployment { id, vm, owner, .. } => self.deployment_target(id, vm.as_deref(), owner.as_deref()).ok().flatten(),
            Route::Owned(owner) => owner.clone().filter(|h| h != &self.host),
            Route::Plugin(id) => self.plugin_target(id),
            _ => None,
        };
        if let Some(host) = onward {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet_hop_loop",
                format!("forwarded here by {origin}, but this runs on {host}; a fleet hop is never forwarded again"),
            );
        }
        next.run(req).await
    }

    // -- placement --

    /// Place a new deployment (`POST /deployments`, or a `PUT` that creates).
    async fn place(self: &Arc<Self>, put_id: Option<String>, req: Request<Body>, next: axum::middleware::Next) -> Response {
        let (mut parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_PEEK).await {
            Ok(b) => b,
            Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "deployment spec too large"),
        };
        let rebuilt = |parts: axum::http::request::Parts, bytes: bytes::Bytes| Request::from_parts(parts, Body::from(bytes));
        // Whatever does not parse is the handler's to refuse.
        let Ok(mut spec) = serde_json::from_slice::<Value>(&bytes) else {
            return next.run(rebuilt(parts, bytes)).await;
        };
        let id = put_id.or_else(|| spec.get("id").and_then(Value::as_str).map(str::to_string));
        if let Some(id) = &id {
            if self.registry.get(id).is_some() {
                return next.run(rebuilt(parts, bytes)).await;
            }
            if let Some(theirs) = self.registry.foreign().get(id).cloned() {
                // A replace goes to the host that runs it.
                return match self.home_of(&theirs) {
                    Ok(home) if home != self.host => self.forward(&home, rebuilt(parts, bytes)).await,
                    Ok(_) => next.run(rebuilt(parts, bytes)).await,
                    Err(e) => error(StatusCode::SERVICE_UNAVAILABLE, "fleet_home_unreachable", e),
                };
            }
        }
        let Some(driver) = spec_driver(&spec) else {
            // Not a VM pool (static upstreams, a site, a tunnel): its upstreams
            // and files are this host's, so it stays here.
            return next.run(rebuilt(parts, bytes)).await;
        };
        let members = self.members_with_me();
        let decision = match spec.get("placement").filter(|p| !p.is_null()) {
            None => match choose_home(&self.host, &members, &driver) {
                Ok(home) => {
                    spec["placement"] = json!({ "mode": "pinned", "home": home });
                    tracing::info!(deployment = ?id, %home, %driver, "placed a new deployment by driver and capacity");
                    Ok(home)
                }
                Err(e) => Err(error(StatusCode::CONFLICT, "no_capable_host", e)),
            },
            Some(placement) => check_explicit(&self.host, &members, placement, &driver)
                .map_err(|e| error(StatusCode::CONFLICT, "driver_unsupported", e)),
        };
        let home = match decision {
            Ok(home) => home,
            Err(r) => return r,
        };
        let bytes = bytes::Bytes::from(serde_json::to_vec(&spec).expect("a parsed spec serializes"));
        parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
        if home == self.host {
            next.run(rebuilt(parts, bytes)).await
        } else {
            self.forward(&home, rebuilt(parts, bytes)).await
        }
    }

    /// Every member's row, with this host's own facts as freshly computed.
    fn members_with_me(&self) -> Vec<HostRow> {
        let mut members = self.fleet.live_members();
        let mine = self.local_facts.lock().unwrap().clone();
        match members.iter_mut().find(|m| m.host == self.host) {
            Some(me) => {
                if mine.is_some() {
                    me.facts = mine;
                }
            }
            None => members.push(HostRow {
                host: self.host.clone(),
                address: None,
                state: self
                    .fleet
                    .member(&self.host)
                    .map(|m| m.state)
                    .unwrap_or_else(|| crate::fleet_placement::ACTIVE.to_string()),
                boot_id: String::new(),
                age_secs: 0.0,
                facts: mine,
            }),
        }
        members
    }

    // -- the hop --

    /// How to reach `host`'s admin API.
    async fn target(&self, host: &str, original_host: Option<&str>) -> Result<Target, String> {
        match &self.peers {
            #[cfg(test)]
            Peers::Direct(map) => {
                if self.fleet.live_member(host).is_none() {
                    return Err(format!("home host {host} unreachable: the deployment's home host is not a live fleet member"));
                }
                let base = map.get(host).ok_or_else(|| format!("home host {host} unreachable: not a fleet member"))?;
                let client = self.client(host, "127.0.0.1:1".parse().unwrap(), None)?;
                Ok(Target { base: base.clone(), host_header: None, client })
            }
            Peers::Ingress { admin_host } => {
                let address = self.hop.address_of(host).await.map_err(|e| format!("home host {host} unreachable: {e}"))?;
                let name = self.admin_name(host, original_host, admin_host.as_deref()).ok_or_else(|| {
                    format!(
                        "home host {host} has no admin route this host knows: give its host-scoped admin \
                         deployment the shared admin name, or set {ADMIN_HOST_ENV}"
                    )
                })?;
                let client = self.client(&name, address, Some(address))?;
                Ok(Target { base: format!("https://{name}"), host_header: Some(name), client })
            }
        }
    }

    /// The name `peer` routes to its own admin listener: the one the client
    /// used, if `peer`'s admin deployment has it, else that deployment's
    /// first exact route, else the configured shared admin name.
    fn admin_name(&self, peer: &str, original_host: Option<&str>, configured: Option<&str>) -> Option<String> {
        let foreign = self.registry.foreign();
        let mut names: Vec<String> = foreign
            .values()
            .filter(|s| s.placement.as_ref().and_then(|p| p.home.as_deref()) == Some(peer))
            .filter(|s| s.upstreams.iter().any(|u| crate::auth::same_listener(&self.admin_addr, u)))
            .flat_map(|s| s.routes.iter().filter_map(|r| r.host.clone()))
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        names.sort();
        let original = original_host.map(|h| h.split(':').next().unwrap_or(h).trim().to_ascii_lowercase());
        if let Some(o) = original.filter(|o| names.contains(o)) {
            return Some(o);
        }
        names.into_iter().next().or_else(|| configured.map(str::to_string))
    }

    fn client(&self, name: &str, addr: SocketAddr, resolve: Option<SocketAddr>) -> Result<reqwest::Client, String> {
        let mut clients = self.clients.lock().unwrap();
        if let Some(c) = clients.get(&(name.to_string(), addr)) {
            return Ok(c.clone());
        }
        let mut builder = reqwest::Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(30));
        if let Some(a) = resolve {
            builder = builder.resolve(name, a);
        }
        let client = builder.build().map_err(|e| format!("fleet admin client: {e}"))?;
        if clients.len() > 64 {
            clients.clear();
        }
        clients.insert((name.to_string(), addr), client.clone());
        Ok(client)
    }

    /// The request as it goes to `target`: the caller's method, path, query,
    /// body and credentials, plus this host's hop headers.
    fn outbound(&self, target: &Target, parts: &Head, upgrade: bool) -> Result<reqwest::RequestBuilder, String> {
        let token = self.hop.token().ok_or("this host has no fleet peer token yet")?;
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        let mut rb = target.client.request(parts.method.clone(), format!("{}{path}", target.base));
        let mut headers = HeaderMap::new();
        for (name, value) in &parts.headers {
            let n = name.as_str();
            if HOP_BY_HOP.contains(&n) || n == HOP || n == TOKEN || n == CLIENT || n == "x-forwarded-for" {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        if upgrade {
            headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            if let Some(u) = parts.headers.get(header::UPGRADE) {
                headers.insert(header::UPGRADE, u.clone());
            }
        }
        if let Some(h) = &target.host_header {
            headers.insert(header::HOST, HeaderValue::from_str(h).map_err(|e| e.to_string())?);
        }
        headers.insert(HeaderName::from_static(HOP), HeaderValue::from_str(&self.host).map_err(|e| e.to_string())?);
        headers.insert(HeaderName::from_static(TOKEN), HeaderValue::from_str(&token).map_err(|e| e.to_string())?);
        // Only a client this host's own ingress vouched for; never one the
        // caller claimed. The peer's ingress otherwise judges this host.
        if let Some(client) = parts.headers.get(CLIENT) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), client.clone());
        }
        rb = rb.headers(headers);
        Ok(rb)
    }

    /// Forward one call to `host` and stream its answer back.
    pub async fn forward(&self, host: &str, req: Request<Body>) -> Response {
        let original_host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_string);
        let target = match self.target(host, original_host.as_deref()).await {
            Ok(t) => t,
            Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, "fleet_home_unreachable", e),
        };
        let (mut parts, body) = req.into_parts();
        let upgrade = is_upgrade(&parts.headers);
        let on_upgrade = if upgrade { parts.extensions.remove::<hyper::upgrade::OnUpgrade>() } else { None };
        let rb = match self.outbound(&target, &Head { method: parts.method.clone(), uri: parts.uri.clone(), headers: parts.headers.clone() }, upgrade) {
            Ok(rb) => rb,
            Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, "fleet_hop_unavailable", e),
        };
        let rb = if upgrade { rb } else { rb.body(reqwest::Body::wrap_stream(body.into_data_stream())) };
        tracing::debug!(%host, method = %parts.method, path = %parts.uri.path(), "forwarding an admin call to its home host");
        let resp = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "fleet_home_unreachable",
                    format!("home host {host} unreachable: {e}"),
                );
            }
        };
        let status = resp.status();
        let mut out = Response::builder().status(status.as_u16());
        for (name, value) in resp.headers() {
            if HOP_BY_HOP.contains(&name.as_str()) && !(status == StatusCode::SWITCHING_PROTOCOLS && (name == header::UPGRADE || name == header::CONNECTION)) {
                continue;
            }
            out = out.header(name, value);
        }
        if let Ok(v) = HeaderValue::from_str(host) {
            out = out.header(SERVED_BY, v);
        }
        if status == StatusCode::SWITCHING_PROTOCOLS {
            let Some(on_upgrade) = on_upgrade else {
                return error(StatusCode::BAD_GATEWAY, "fleet_hop_upgrade", "the home host upgraded a call that asked for none");
            };
            let host = host.to_string();
            tokio::spawn(async move {
                let peer = match resp.upgrade().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(%host, error = %e, "fleet admin hop: the home host's upgrade failed");
                        return;
                    }
                };
                let client = match on_upgrade.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!(error = %e, "fleet admin hop: the client's upgrade failed");
                        return;
                    }
                };
                let mut client = hyper_util::rt::TokioIo::new(client);
                let mut peer = peer;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut peer).await;
            });
            return out.body(Body::empty()).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
        }
        out.body(Body::from_stream(resp.bytes_stream()))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
    }

    // -- fan-out --

    /// The members asked for a merged answer.
    fn peers(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .fleet
            .live_members()
            .into_iter()
            .filter(|m| m.host != self.host)
            .map(|m| m.host)
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    async fn fetch(&self, host: &str, parts: &Head) -> Result<(StatusCode, Value), String> {
        let original_host = parts.headers.get(header::HOST).and_then(|v| v.to_str().ok());
        let target = self.target(host, original_host).await?;
        let rb = self.outbound(&target, parts, false)?.timeout(self.fanout_timeout);
        let resp = rb.send().await.map_err(|e| format!("{host}: {e}"))?;
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let bytes = resp.bytes().await.map_err(|e| format!("{host}: {e}"))?;
        if bytes.len() > MAX_MERGE {
            return Err(format!("{host}: answer too large to merge"));
        }
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, value))
    }

    /// Answer here, ask every other live member the same, and merge. A
    /// member that does not answer in time is named, never dropped silently.
    async fn fan_out(&self, req: Request<Body>, next: axum::middleware::Next, merge: Merge) -> Response {
        let head = Head::of(&req);
        let parts = &head;
        let local = req;
        let peers = self.peers();
        let asks = futures::future::join_all(peers.iter().map(|h| self.fetch(h, parts)));
        let (response, answers) = tokio::join!(next.run(local), asks);
        if peers.is_empty() || !response.status().is_success() {
            return response;
        }
        let (rparts, rbody) = response.into_parts();
        let Ok(bytes) = axum::body::to_bytes(rbody, MAX_MERGE).await else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "merge_failed", "this host's answer could not be read");
        };
        let Ok(mine) = serde_json::from_slice::<Value>(&bytes) else {
            return Response::from_parts(rparts, Body::from(bytes));
        };
        let mut theirs = Vec::new();
        let mut unreachable = Vec::new();
        for (host, answer) in peers.iter().zip(answers) {
            match answer {
                Ok((status, value)) if status.is_success() => theirs.push((host.clone(), value)),
                // A member that does not run a spread deployment says so.
                Ok((StatusCode::NOT_FOUND, _)) if merge == Merge::One => {}
                Ok((status, _)) => unreachable.push(format!("{host} ({status})")),
                Err(e) => {
                    tracing::debug!(%host, error = %e, "fleet member did not answer a merged read");
                    unreachable.push(host.clone());
                }
            }
        }
        let merged = match merge {
            Merge::List => merge_lists(&self.host, mine, theirs),
            Merge::One => merge_one(&self.host, mine, theirs),
            Merge::Metrics => merge_metrics(&self.host, mine, theirs, &unreachable),
        };
        let mut out = Response::from_parts(rparts, Body::from(serde_json::to_vec(&merged).expect("json serializes")));
        out.headers_mut().remove(header::CONTENT_LENGTH);
        if !unreachable.is_empty() {
            out.headers_mut().insert(PARTIAL, HeaderValue::from_static("1"));
            if let Ok(v) = HeaderValue::from_str(&unreachable.join(", ")) {
                out.headers_mut().insert(UNREACHABLE, v);
            }
        }
        out
    }
}

/// What is sent on of a request: everything but its body and extensions.
struct Head {
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
}

impl Head {
    fn of(req: &Request<Body>) -> Self {
        Self { method: req.method().clone(), uri: req.uri().clone(), headers: req.headers().clone() }
    }
}

/// Read a JSON body for the `sandbox_id` it names, and put it back.
async fn peek_sandbox(req: Request<Body>) -> Result<(Request<Body>, Option<String>), Response> {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_PEEK)
        .await
        .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "request body too large"))?;
    let vm = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("sandbox_id").and_then(Value::as_str).map(str::to_string))
        .filter(|v| !v.is_empty());
    Ok((Request::from_parts(parts, Body::from(bytes)), vm))
}

/// The driver a spec's VM pool boots with; `None` when it has no VM pool.
fn spec_driver(spec: &Value) -> Option<String> {
    let vm = spec.get("vm").filter(|v| v.is_object())?;
    Some(vm.get("driver").and_then(Value::as_str).unwrap_or(DEFAULT_DRIVER).to_string())
}

/// Where a new VM pool that names no placement runs: the live, `active`
/// member that says it boots `driver` and has the most free memory (then
/// vCPUs, then the first name). Members that publish no facts — an older
/// binary, a daemon that would not say — are not chosen automatically; with
/// none known capable, the receiving host keeps it, as before, unless it
/// knows it cannot boot `driver`.
pub fn choose_home(me: &str, members: &[HostRow], driver: &str) -> Result<String, String> {
    let mut capable: Vec<&HostRow> = members
        .iter()
        .filter(|m| m.state == crate::fleet_placement::ACTIVE)
        .filter(|m| m.host == me || m.address.is_some())
        .filter(|m| m.facts.as_ref().and_then(|f| f.supports(driver)) == Some(true))
        .collect();
    capable.sort_by(|a, b| {
        let free = |m: &HostRow| m.facts.as_ref().and_then(|f| f.memory_free_bytes).unwrap_or(0);
        let cpu = |m: &HostRow| m.facts.as_ref().and_then(|f| f.vcpus_free).unwrap_or(0.0);
        free(b)
            .cmp(&free(a))
            .then(cpu(b).partial_cmp(&cpu(a)).unwrap_or(std::cmp::Ordering::Equal))
            .then(a.host.cmp(&b.host))
    });
    if let Some(best) = capable.first() {
        return Ok(best.host.clone());
    }
    let me_row = members.iter().find(|m| m.host == me);
    if me_row.and_then(|m| m.facts.as_ref()).and_then(|f| f.supports(driver)) == Some(false) {
        return Err(format!(
            "no live, active fleet host says it can boot driver {driver:?}; name one with placement.home"
        ));
    }
    Ok(me.to_string())
}

/// Check a spec's own placement against what members can boot. A pinned
/// home that says it cannot boot `driver` is refused, as is a spread whose
/// listed (or, listing none, live) members include one that says it cannot:
/// the placer splits a spread across every such member, so a subset that
/// could not boot is a pool that never fills. Returns the host the
/// registration is made on.
pub fn check_explicit(me: &str, members: &[HostRow], placement: &Value, driver: &str) -> Result<String, String> {
    let mode = placement.get("mode").and_then(Value::as_str).unwrap_or("");
    let says_no = |host: &str| {
        members
            .iter()
            .find(|m| m.host == host)
            .and_then(|m| m.facts.as_ref())
            .and_then(|f| f.supports(driver))
            == Some(false)
    };
    match mode {
        "pinned" => {
            let home = placement.get("home").and_then(Value::as_str).unwrap_or(me);
            if says_no(home) {
                return Err(format!("fleet host {home} cannot boot driver {driver:?}"));
            }
            Ok(home.to_string())
        }
        "spread" => {
            let listed: Vec<String> = placement
                .get("hosts")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|h| h.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let mut refusing: Vec<&str> = members
                .iter()
                .filter(|m| listed.is_empty() || listed.contains(&m.host))
                .filter(|m| m.state != crate::fleet_placement::MAINTENANCE)
                .map(|m| m.host.as_str())
                .filter(|h| says_no(h))
                .collect();
            refusing.sort();
            if !refusing.is_empty() {
                return Err(format!(
                    "a spread deployment runs on every listed live host, and {} cannot boot driver {driver:?}; \
                     list only capable hosts in placement.hosts",
                    refusing.join(", ")
                ));
            }
            Ok(me.to_string())
        }
        // Malformed: the handler's validation says why.
        _ => Ok(me.to_string()),
    }
}

// ---- merging --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Merge {
    List,
    One,
    Metrics,
}

fn deployment_id(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str).or_else(|| v.pointer("/spec/id").and_then(Value::as_str))
}

fn tag(v: &mut Value, key: &str, host: &str) {
    if let Some(o) = v.as_object_mut() {
        o.entry(key).or_insert_with(|| Value::from(host));
    }
}

/// Fold another host's status for the same (spread) deployment into `into`:
/// its VMs join, tagged with the host, and the counts add.
fn fold_status(into: &mut Value, from: Value, host: &str) {
    let Some(o) = into.as_object_mut() else { return };
    let hosts = o.entry("hosts").or_insert_with(|| json!([]));
    if let Some(a) = hosts.as_array_mut()
        && !a.iter().any(|h| h == host)
    {
        a.push(Value::from(host));
    }
    for key in ["ready", "pending", "total_in_flight", "desired_replicas"] {
        if let (Some(a), Some(b)) = (o.get(key).and_then(Value::as_u64), from.get(key).and_then(Value::as_u64)) {
            o.insert(key.into(), Value::from(a + b));
        }
    }
    for key in ["vms", "pending_vms"] {
        if let Some(theirs) = from.get(key).and_then(Value::as_array) {
            let mine = o.entry(key).or_insert_with(|| json!([]));
            if let Some(m) = mine.as_array_mut() {
                for vm in theirs {
                    let mut vm = vm.clone();
                    tag(&mut vm, "host", host);
                    m.push(vm);
                }
            }
        }
    }
}

fn start_status(v: &mut Value, host: &str) {
    let spread = v.pointer("/spec/placement/mode").and_then(Value::as_str) == Some("spread");
    tag(v, "host", host);
    if spread {
        if let Some(o) = v.as_object_mut() {
            o.insert("hosts".into(), json!([host]));
        }
        for key in ["vms", "pending_vms"] {
            if let Some(a) = v.get_mut(key).and_then(Value::as_array_mut) {
                for vm in a {
                    tag(vm, "host", host);
                }
            }
        }
    }
}

/// `GET /deployments` across members: each deployment once, tagged with the
/// host that answered for it; a spread one carries every host's VMs.
pub fn merge_lists(me: &str, mine: Value, theirs: Vec<(String, Value)>) -> Value {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut anonymous = Vec::new();
    for (host, list) in std::iter::once((me.to_string(), mine)).chain(theirs) {
        let Value::Array(items) = list else { continue };
        for mut item in items {
            let Some(id) = deployment_id(&item).map(str::to_string) else {
                anonymous.push(item);
                continue;
            };
            match out.get_mut(&id) {
                Some(existing) => fold_status(existing, item, &host),
                None => {
                    start_status(&mut item, &host);
                    out.insert(id, item);
                }
            }
        }
    }
    Value::Array(out.into_values().chain(anonymous).collect())
}

/// `GET /deployments/:id` for a spread deployment: this host's status, with
/// every other host's VMs folded in.
pub fn merge_one(me: &str, mut mine: Value, theirs: Vec<(String, Value)>) -> Value {
    start_status(&mut mine, me);
    for (host, v) in theirs {
        fold_status(&mut mine, v, &host);
    }
    mine
}

/// `GET /metrics` across members: every member's deployments and unowned
/// sandboxes, tagged with their host; pool counts summed; each member's host
/// and daemon readings under `members`. `limit`/`offset` page each member's
/// list, so a paged answer holds up to one page per member.
pub fn merge_metrics(me: &str, mut mine: Value, theirs: Vec<(String, Value)>, unreachable: &[String]) -> Value {
    let member = |host: &str, v: &Value| {
        json!({
            "host": host,
            "usage": v.get("host").cloned().unwrap_or(Value::Null),
            "daemon": v.get("daemon").cloned().unwrap_or(Value::Null),
            "uptime_secs": v.get("uptime_secs").cloned().unwrap_or(Value::Null),
        })
    };
    let mut members = vec![member(me, &mine)];
    let Some(o) = mine.as_object_mut() else { return mine };
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(a) = o.get_mut("deployments").and_then(Value::as_array_mut) {
        for d in a.iter_mut() {
            tag(d, "host", me);
            if let Some(id) = deployment_id(d) {
                seen.insert(id.to_string());
            }
        }
    }
    if let Some(a) = o.get_mut("host_sandboxes").and_then(Value::as_array_mut) {
        for s in a.iter_mut() {
            tag(s, "host", me);
        }
    }
    for (host, v) in theirs {
        members.push(member(&host, &v));
        if let Some(theirs) = v.get("deployments").and_then(Value::as_array) {
            let mut added = 0u64;
            let list = o.entry("deployments").or_insert_with(|| json!([]));
            if let Some(list) = list.as_array_mut() {
                for d in theirs {
                    let id = deployment_id(d).map(str::to_string);
                    if let Some(id) = &id
                        && !seen.insert(id.clone())
                    {
                        // A spread deployment: listed once, by its first host.
                        if let Some(existing) = list.iter_mut().find(|x| deployment_id(x) == Some(id)) {
                            let hosts = existing.as_object_mut().map(|e| e.entry("hosts").or_insert_with(|| json!([me])));
                            if let Some(Value::Array(h)) = hosts {
                                h.push(Value::from(host.as_str()));
                            }
                        }
                        continue;
                    }
                    let mut d = d.clone();
                    tag(&mut d, "host", &host);
                    list.push(d);
                    added += 1;
                }
            }
            if let Some(m) = o.get("matched").and_then(Value::as_u64) {
                o.insert("matched".into(), Value::from(m + added));
            }
        }
        if let Some(theirs) = v.get("host_sandboxes").and_then(Value::as_array) {
            let list = o.entry("host_sandboxes").or_insert_with(|| json!([]));
            if let Some(list) = list.as_array_mut() {
                for s in theirs {
                    let mut s = s.clone();
                    tag(&mut s, "host", &host);
                    list.push(s);
                }
            }
        }
        if let (Some(Value::Object(fleet)), Some(Value::Object(their))) = (o.get_mut("fleet"), v.get("fleet")) {
            for (k, n) in their {
                if let (Some(a), Some(b)) = (fleet.get(k).and_then(Value::as_u64), n.as_u64()) {
                    fleet.insert(k.clone(), Value::from(a + b));
                }
            }
        }
        if let (Some(a), Some(b)) = (o.get("tracked_deployments").and_then(Value::as_u64), v.get("tracked_deployments").and_then(Value::as_u64)) {
            o.insert("tracked_deployments".into(), Value::from(a + b));
        }
    }
    o.insert("members".into(), Value::Array(members));
    o.insert("partial".into(), Value::Bool(!unreachable.is_empty()));
    o.insert("hosts_unreachable".into(), json!(unreachable));
    mine
}

// ---- facts ----------------------------------------------------------------

/// The drivers an app-lb can boot, of those the daemon says it supports.
const APP_LB_DRIVERS: &[&str] = &["firecracker", "kvm", "libvirt"];

/// `APP_LB_FLEET_DRIVERS`, when set: the operator's word on what this host
/// boots. heyvmd's `/capabilities` lists every driver it was built with on
/// Linux, whether or not the host has KVM or libvirt, so a host that cannot
/// boot one of them should say so here.
pub fn drivers_from_env() -> Option<Vec<String>> {
    let raw = std::env::var(DRIVERS_ENV).ok()?;
    let list: Vec<String> = raw
        .split(',')
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    Some(list)
}

/// Ask the daemon which drivers it boots (`GET /capabilities`).
async fn probe_drivers(daemon: &str) -> Option<Vec<String>> {
    if !daemon.starts_with("http") {
        return None;
    }
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().ok()?;
    let resp = client.get(format!("{}/capabilities", daemon.trim_end_matches('/'))).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: Value = resp.json().await.ok()?;
    let list = v.get("supportedDrivers")?.as_array()?;
    Some(
        list.iter()
            .filter_map(Value::as_str)
            .filter(|d| APP_LB_DRIVERS.contains(d))
            .map(str::to_string)
            .collect(),
    )
}

/// This host's facts, from what it already knows.
pub fn facts(registry: &Registry, usage: &crate::metrics::HostUsageSnapshot, drivers: Option<Vec<String>>) -> HostFacts {
    let mut vms = BTreeMap::new();
    for d in registry.deployments().values() {
        if !crate::fleet_placement::spreads(&d.spec) {
            continue;
        }
        for b in d.backends().iter() {
            vms.insert(b.sandbox_id.clone(), d.spec.id.clone());
        }
        for s in &d.state().suspended {
            vms.insert(s.clone(), d.spec.id.clone());
        }
    }
    let known = usage.available && usage.memory_total_bytes > 0;
    HostFacts {
        drivers,
        memory_free_bytes: known.then(|| usage.memory_total_bytes.saturating_sub(usage.memory_used_bytes)),
        memory_total_bytes: known.then_some(usage.memory_total_bytes),
        vcpus: (usage.cpu_count > 0).then_some(usage.cpu_count),
        vcpus_free: (usage.available && usage.cpu_count > 0)
            .then(|| usage.cpu_count as f64 * (1.0 - (usage.cpu_percent / 100.0).clamp(0.0, 1.0))),
        vms,
    }
}

/// Publishes this host's facts with its heartbeat, every few seconds.
pub struct FactsService {
    pub admin: Arc<FleetAdmin>,
    pub fleet: Arc<Fleet>,
    pub registry: Arc<Registry>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub daemon_url: Option<String>,
}

#[async_trait::async_trait]
impl pingora_core::services::background::BackgroundService for FactsService {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        let configured = drivers_from_env();
        let mut drivers = configured.clone();
        let mut probed_at: Option<std::time::Instant> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = shutdown.changed() => break,
            }
            if configured.is_none() && probed_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                probed_at = Some(std::time::Instant::now());
                if let Some(url) = &self.daemon_url
                    && let Some(found) = probe_drivers(url).await
                {
                    drivers = Some(found);
                }
            }
            let facts = facts(&self.registry, &self.metrics.host_snapshot(), drivers.clone());
            self.fleet.set_facts(&facts);
            self.admin.set_local_facts(facts);
        }
    }
}

#[cfg(test)]
mod tests;
