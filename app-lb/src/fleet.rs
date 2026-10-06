//! Read-only, explicitly configured gateway observations. Never a placement or
//! rollout authority, and never a proxy for arbitrary browser-supplied URLs.
use crate::secrets::{SecretRef, SecretStore};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::{Arc, Mutex}, time::Duration, path::{Path, PathBuf}};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    id: String,
    region: String,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    use_caller_auth: bool,
}

pub struct Fleet {
    gateways: Vec<Gateway>,
    client: reqwest::Client,
    secrets: Arc<SecretStore>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewConfig {
    pub gateways: Vec<Gateway>,
    pub control_plane: Vec<Gateway>,
    /// The control-plane app-lb whose fleet tokens this server accepts. Set on
    /// each member server; the control plane itself needs no entry, because it
    /// holds its fleet tokens in its own store. Service credential only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_authority: Option<Gateway>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureViews {
    pub expected_revision: u64,
    pub config: ViewConfig,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedViews { revision: u64, config: ViewConfig }

#[derive(Serialize)]
pub struct ViewSnapshot {
    pub revision: u64,
    config: ViewConfig,
    pub externally_managed: bool,
    #[serde(skip)]
    pub fleet: Option<Arc<Fleet>>,
    #[serde(skip)]
    pub control_plane: Option<Arc<Fleet>>,
    #[serde(skip)]
    pub token_authority: Option<Arc<Fleet>>,
}

/// Gateway-local bindings, never application or rollout authority. Persist
/// before publishing; readers keep one immutable snapshot across a request.
pub struct ViewStore {
    path: PathBuf,
    current: arc_swap::ArcSwap<ViewSnapshot>,
    writer: Mutex<()>,
    secrets: Arc<SecretStore>,
}

impl ViewStore {
    pub fn open(path: PathBuf, secrets: Arc<SecretStore>, overrides: [Option<PathBuf>; 2]) -> Result<Self, String> {
        let saved = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<SavedViews>(&bytes).map_err(|_| "invalid persisted view configuration")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SavedViews { revision: 0, config: ViewConfig::default() },
            Err(_) => return Err("cannot read persisted view configuration".into()),
        };
        let mut config = saved.config;
        for (target, file) in [&mut config.gateways, &mut config.control_plane].into_iter().zip(&overrides) {
            if let Some(file) = file {
                *target = parse(&std::fs::read_to_string(file).map_err(|_| "cannot read configured view file")?)?;
            }
        }
        let snapshot = Self::prepare(saved.revision, config, overrides.iter().any(Option::is_some), secrets.clone())?;
        Ok(Self { path, current: arc_swap::ArcSwap::from_pointee(snapshot), writer: Mutex::new(()), secrets })
    }

    fn prepare(revision: u64, mut config: ViewConfig, externally_managed: bool, secrets: Arc<SecretStore>) -> Result<ViewSnapshot, String> {
        if config.control_plane.iter().any(|g| g.use_caller_auth) {
            return Err("Orchestrator bindings require service credentials".into());
        }
        // Pulled in the background with no caller to forward, so it can only
        // ever use a service credential.
        let token_authority = match config.token_authority.take() {
            None => None,
            Some(authority) if authority.use_caller_auth => {
                return Err("the token authority requires a service credential".into());
            }
            Some(authority) => {
                let authority = parse(&serde_json::to_string(&[authority]).map_err(|_| "invalid view configuration")?)?
                    .remove(0);
                config.token_authority = Some(authority.clone());
                Some(Arc::new(Fleet::new(vec![authority], secrets.clone())?))
            }
        };
        let mut clients = Vec::new();
        for targets in [&mut config.gateways, &mut config.control_plane] {
            if targets.is_empty() { clients.push(None); continue; }
            *targets = parse(&serde_json::to_string(targets).map_err(|_| "invalid view configuration")?)?;
            clients.push(Some(Arc::new(Fleet::new(targets.clone(), secrets.clone())?)));
        }
        Ok(ViewSnapshot { revision, config, externally_managed, fleet: clients.remove(0), control_plane: clients.remove(0), token_authority })
    }

    pub fn snapshot(&self) -> Arc<ViewSnapshot> { self.current.load_full() }

    pub fn configure(&self, request: ConfigureViews) -> Result<Arc<ViewSnapshot>, (http::StatusCode, String)> {
        use http::StatusCode;
        use std::{fs::{File, OpenOptions}, io::Write, os::unix::fs::OpenOptionsExt};
        let _lock = self.writer.lock().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "view writer unavailable".into()))?;
        let current = self.snapshot();
        if current.externally_managed { return Err((StatusCode::CONFLICT, "view configuration is managed by startup files".into())); }
        if request.expected_revision != current.revision { return Err((StatusCode::CONFLICT, "view configuration revision changed; read it again".into())); }
        let revision = current.revision.checked_add(1).ok_or((StatusCode::CONFLICT, "view revision exhausted".into()))?;
        let next = Self::prepare(revision, request.config, false, self.secrets.clone())
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        // Reject unresolved credentials before acknowledging activation. Values
        // stay in SecretStore; neither persistence nor the response contains them.
        for gateway in next.config.gateways.iter().chain(&next.config.control_plane).chain(&next.config.token_authority) {
            if gateway.auth.as_ref().is_some_and(|auth| self.secrets.resolve(auth).map_or(true, |value| value.trim().is_empty())) {
                return Err((StatusCode::BAD_REQUEST, "view credential unavailable".into()));
            }
        }
        let bytes = serde_json::to_vec(&SavedViews { revision, config: next.config.clone() })
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cannot encode view configuration".into()))?;
        let next = Arc::new(next);
        let persist = || -> std::io::Result<()> {
            let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            std::fs::create_dir_all(parent)?;
            let mut nonce = [0u8; 16];
            openssl::rand::rand_bytes(&mut nonce).map_err(std::io::Error::other)?;
            let temp = self.path.with_extension(format!("{:032x}.writing", u128::from_be_bytes(nonce)));
            let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&temp)?;
            let result = (|| {
                file.write_all(&bytes)?;
                file.sync_all()?;
                let directory = File::open(parent)?;
                std::fs::rename(&temp, &self.path)?;
                // Rename is the commit point. If the directory flush fails,
                // return an error but never allow a stale CAS to overwrite it.
                self.current.store(next.clone());
                directory.sync_all()
            })();
            if result.is_err() { let _ = std::fs::remove_file(&temp); }
            result
        };
        persist().map_err(|e| {
            tracing::error!(error = %e, "view configuration persistence failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "cannot persist view configuration".into())
        })?;
        Ok(next)
    }
}

#[derive(Serialize)]
pub struct Observation {
    id: String,
    region: String,
    dashboard_url: String,
    observed_at: u64,
    metrics: Option<GatewayMetrics>,
    error: Option<&'static str>,
}

// Allowlist fields: remote responses must not accidentally expose deployment
// specs, credentials, or new privileged API fields through this view.
#[derive(Deserialize, Serialize)]
struct GatewayMetrics {
    generated_at: u64,
    uptime_secs: u64,
    fleet: Pools,
}

#[derive(Deserialize, Serialize)]
struct Pools {
    deployments: usize,
    ready: usize,
    draining: usize,
    pending: usize,
    total_in_flight: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    services: Vec<Service>,
    next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Service {
    service_id: String,
    desired_replicas: Option<u32>,
    replica_regions: Option<Vec<String>>,
    discovery_version: Option<u64>,
    endpoints: Option<Vec<Endpoint>>,
    rollout: Option<Rollout>,
    external: Option<ExternalService>,
    update: Option<ApplicationUpdate>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationUpdate {
    operation_id: String,
    status: String,
    target_revision: String,
    run_id: String,
    phase: Option<String>,
    observed_at: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalService {
    externally_managed: bool,
    lifecycle_owner: String,
    deployment_id: String,
    region: String,
    observed_at: String,
    capabilities: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint {
    region: Option<String>,
    revision: Option<String>,
    health_status: String,
    draining: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Rollout {
    operation_id: String,
    status: String,
    phase: String,
    target_revision: String,
}

fn parse(text: &str) -> Result<Vec<Gateway>, String> {
    let mut gateways: Vec<Gateway> = serde_json::from_str(text)
        .map_err(|_| "fleet file must be an array of gateway definitions".to_string())?;
    if gateways.is_empty() || gateways.len() > 32 {
        return Err("fleet must contain 1–32 gateways".into());
    }
    let mut ids = HashSet::new();
    let mut urls = HashSet::new();
    for gateway in &mut gateways {
        for value in [&gateway.id, &gateway.region] {
            if value.is_empty() || value.len() > 128
                || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                return Err("gateway id and region must be bounded identifiers".into());
            }
        }
        let url = reqwest::Url::parse(&gateway.url).map_err(|_| "invalid gateway URL")?;
        if url.scheme() != "https" || url.host_str().is_none()
            || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            return Err("gateway URL must be a credential-free HTTPS origin".into());
        }
        gateway.url = url.to_string();
        if !ids.insert(gateway.id.clone()) || !urls.insert(url) {
            return Err("duplicate gateway id or origin".into());
        }
        if gateway.use_caller_auth == gateway.auth.is_some() {
            return Err("choose exactly one gateway credential: auth or use_caller_auth".into());
        }
        if let Some(auth) = &gateway.auth {
            auth.validate().map_err(|_| "invalid fleet secret reference")?;
        }
    }
    Ok(gateways)
}

impl Fleet {
    fn new(gateways: Vec<Gateway>, secrets: Arc<SecretStore>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build().map_err(|_| "cannot build fleet HTTP client")?;
        Ok(Self { gateways, client, secrets })
    }

    async fn fetch<T: serde::de::DeserializeOwned>(&self, gateway: &Gateway, path: &str, caller: Option<&str>) -> Result<T, &'static str> {
        let request = self.client.get(format!("{}{path}", gateway.url.trim_end_matches('/')));
        let request = if gateway.use_caller_auth {
            request.bearer_auth(caller.filter(|s| !s.is_empty()).ok_or("Heyo sign-in required for regional observations")?)
        } else {
            let auth = gateway.auth.as_ref().ok_or("credential unavailable")?;
            let credential = self.secrets.resolve(auth).map_err(|_| "credential unavailable")?;
            if credential.trim().is_empty() { return Err("credential unavailable") }
            match &auth.username {
                Some(user) => request.basic_auth(user, Some(credential)),
                None => request.bearer_auth(credential),
            }
        };
        let mut response = request.send().await.map_err(|_| "gateway unreachable")?;
        if response.status().is_server_error() { return Err("gateway unavailable") }
        if !response.status().is_success() { return Err("gateway rejected observation") }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "gateway response interrupted")? {
            if body.len() + chunk.len() > 1024 * 1024 { return Err("gateway response too large") }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| "invalid gateway metrics")
    }

    /// Only read-only requests fail over. Never replay mutations or merge
    /// inventories from different sources. Operators must bind these endpoints
    /// to the same authoritative database, not independent regional copies.
    pub async fn inventory(&self, after: Option<&str>) -> Result<Inventory, &'static str> {
        let mut path = "/orchestration/services".to_string();
        if let Some(after) = after {
            path.push('?');
            path.push_str(&form_urlencoded::Serializer::new(String::new()).append_pair("after", after).finish());
        }
        let mut last = "control plane unavailable";
        for gateway in &self.gateways {
            match self.fetch(gateway, &path, None).await {
                Ok(inventory) => return Ok(inventory),
                Err(error @ ("gateway unreachable" | "gateway unavailable" | "gateway response interrupted")) => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    /// Pull the control plane's fleet tokens. Only ever called on a
    /// single-gateway `token_authority` binding; returns its id with the export.
    pub async fn fleet_tokens(&self) -> Result<(String, crate::tokens::FleetExport), &'static str> {
        let authority = self.gateways.first().ok_or("token authority not configured")?;
        let export = self.fetch(authority, "/fleet/tokens", None).await?;
        Ok((authority.id.clone(), export))
    }

    pub async fn observe(&self, caller: Option<&str>) -> Vec<Observation> {
        futures::future::join_all(self.gateways.iter().map(|gateway| async move {
            let result = self.fetch(gateway, "/metrics?summary=true&limit=0", caller).await;
            Observation {
                id: gateway.id.clone(), region: gateway.region.clone(),
                dashboard_url: format!("{}/dashboard?view=local", gateway.url.trim_end_matches('/')),
                observed_at: crate::deployment::now_secs(),
                error: result.as_ref().err().copied(), metrics: result.ok(),
            }
        })).await
    }
}

// ---- workload rollup, gateway drill-down and network view -------------------
//
// Still observations, never authority: every row below is what one gateway said
// about its own pools at `observed_at`. Nothing here places, scales or routes.
// Each remote document is deserialized into an allowlist, so a gateway that
// grows a new field (or a spec, env var, credential-bearing URL) cannot leak it
// through the control-plane origin. Unknown fields are dropped, not forwarded.

/// Rows per remote `/metrics` page. Summary rows are ~2.5 KiB, so a page stays
/// far below the 1 MiB response cap even with a large `host_sandboxes` list.
const ROLLUP_PAGE: usize = 100;
/// Pages per gateway for the rollup before it reports `truncated`.
const ROLLUP_MAX_PAGES: usize = 20;
/// Rows per page when VM rows are included (drill-down and network view).
const DETAIL_PAGE: usize = 50;
/// Pages per gateway for the network view before it reports `truncated`.
const NETWORK_MAX_PAGES: usize = 10;
/// One slow gateway must not hold the whole response hostage.
const GATEWAY_DEADLINE: Duration = Duration::from_secs(15);

/// Why a gateway is left out for a caller without fleet coverage. Service
/// credentials are never spent on a namespace caller's behalf.
pub const SERVICE_CREDENTIAL_REFUSED: &str = "fleet-wide view required for this gateway";

fn default_namespace() -> String { crate::config::DEFAULT_NAMESPACE.to_string() }

#[derive(Deserialize)]
struct RemotePage {
    generated_at: u64,
    uptime_secs: u64,
    fleet: Pools,
    #[serde(default)]
    host: Option<RemoteHost>,
    #[serde(default)]
    matched: usize,
    #[serde(default)]
    deployments: Vec<RemoteDeployment>,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemoteHost {
    available: bool,
    cpu_count: u64,
    cpu_percent: Option<f64>,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemoteDeployment {
    id: String,
    #[serde(default = "default_namespace")]
    namespace: String,
    kind: String,
    #[serde(default)]
    routed: bool,
    /// Exact routed hostnames only. `urls`, `upstreams`, `site_root`,
    /// `account_id` and everything spec-shaped are deliberately absent.
    #[serde(default)]
    hosts: Vec<String>,
    pool: RemotePool,
    #[serde(default)]
    vms: Vec<RemoteVm>,
    #[serde(default)]
    pending_vms: Vec<RemotePendingVm>,
    #[serde(default)]
    metrics: Option<RemoteDeploymentMetrics>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct RemotePool {
    desired_replicas: u32,
    ready: usize,
    draining: usize,
    pending: usize,
    total_in_flight: usize,
    #[serde(default)]
    min_replicas: u32,
    #[serde(default)]
    max_replicas: u32,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemoteVm {
    sandbox_id: String,
    /// Guest address. Kept only for fleet-wide callers; cleared otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    addr: Option<String>,
    #[serde(default)]
    in_flight: usize,
    #[serde(default)]
    healthy: bool,
    #[serde(default)]
    draining: bool,
    #[serde(default)]
    uptime_secs: u64,
    #[serde(default)]
    cpu_percent: Option<f64>,
    #[serde(default)]
    memory_bytes: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemotePendingVm {
    sandbox_id: String,
    #[serde(default)]
    age_secs: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemoteDeploymentMetrics {
    #[serde(default)]
    requests: RemoteRequests,
    #[serde(default)]
    latency_ms: RemoteLatency,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct RemoteRequests {
    #[serde(default)] total: u64,
    #[serde(default)] c2xx: u64,
    #[serde(default)] c4xx: u64,
    #[serde(default)] c5xx: u64,
    #[serde(default)] errors: u64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct RemoteLatency {
    #[serde(default)] count: u64,
    #[serde(default)] p50: Option<f64>,
    #[serde(default)] p99: Option<f64>,
}

#[derive(Clone, Deserialize, Serialize)]
struct RemoteIngress {
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    ipv6: Vec<String>,
}

impl RemoteIngress {
    /// Addresses only: anything that is not an IP literal is dropped.
    fn sanitized(self) -> Self {
        let keep = |list: Vec<String>| list.into_iter()
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok()).take(64).collect();
        Self { ipv4: keep(self.ipv4), ipv6: keep(self.ipv6) }
    }
}

/// Serving health derived from pool gauges alone, never from a probe.
fn pool_health(kind: &str, pool: &RemotePool) -> &'static str {
    if kind == "site" { return "healthy" }
    let serving = pool.ready.saturating_sub(pool.draining);
    let desired = pool.desired_replicas as usize;
    if desired == 0 && serving == 0 {
        return if pool.pending > 0 { "starting" } else { "idle" };
    }
    if serving >= desired { "healthy" }
    else if serving > 0 { "degraded" }
    else if pool.pending > 0 { "starting" }
    else if pool.draining > 0 { "draining" }
    else { "down" }
}

/// Sums across servers. Each app-lb drives its own colocated daemon, so VMs
/// counted here are distinct machines' VMs, not the same capacity seen twice.
#[derive(Clone, Copy, Default, Serialize)]
pub struct Totals {
    ready: usize,
    pending: usize,
    draining: usize,
    desired: u64,
    in_flight: usize,
}

impl Totals {
    fn add(&mut self, pool: &RemotePool) {
        self.ready += pool.ready;
        self.pending += pool.pending;
        self.draining += pool.draining;
        self.desired += u64::from(pool.desired_replicas);
        self.in_flight += pool.total_in_flight;
    }
    fn as_pool(&self) -> RemotePool {
        RemotePool { desired_replicas: u32::try_from(self.desired).unwrap_or(u32::MAX), ready: self.ready,
            draining: self.draining, pending: self.pending, total_in_flight: self.in_flight,
            min_replicas: 0, max_replicas: 0 }
    }
}

#[derive(Serialize)]
pub struct Workloads {
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    gateways: Vec<GatewayRollup>,
    rows: Vec<WorkloadRow>,
    totals: Totals,
}

#[derive(Serialize)]
struct GatewayRollup {
    id: String,
    region: String,
    dashboard_url: String,
    observed_at: u64,
    generated_at: Option<u64>,
    deployments: usize,
    truncated: bool,
    totals: Totals,
    error: Option<&'static str>,
}

#[derive(Serialize)]
struct WorkloadRow {
    namespace: String,
    id: String,
    kind: String,
    routed: bool,
    hosts: Vec<String>,
    health: &'static str,
    totals: Totals,
    cells: Vec<Cell>,
}

#[derive(Serialize)]
struct Cell {
    gateway: String,
    region: String,
    ready: Option<usize>,
    pending: Option<usize>,
    draining: Option<usize>,
    desired: Option<u32>,
    in_flight: Option<usize>,
    health: Option<&'static str>,
    error: Option<&'static str>,
}

#[derive(Serialize)]
pub struct GatewayDetail {
    id: String,
    region: String,
    dashboard_url: String,
    observed_at: u64,
    generated_at: u64,
    uptime_secs: u64,
    fleet: Pools,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<RemoteHost>,
    matched: usize,
    offset: usize,
    limit: usize,
    deployments: Vec<DeploymentDetail>,
}

#[derive(Serialize)]
struct DeploymentDetail {
    namespace: String,
    id: String,
    kind: String,
    routed: bool,
    hosts: Vec<String>,
    health: &'static str,
    pool: RemotePool,
    vms: Vec<RemoteVm>,
    pending_vms: Vec<RemotePendingVm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<RemoteDeploymentMetrics>,
}

impl DeploymentDetail {
    fn from_remote(d: RemoteDeployment, reveal_addrs: bool) -> Self {
        let health = pool_health(&d.kind, &d.pool);
        let vms = d.vms.into_iter()
            .map(|vm| RemoteVm { addr: if reveal_addrs { vm.addr } else { None }, ..vm })
            .collect();
        Self { namespace: d.namespace, id: d.id, kind: d.kind, routed: d.routed, hosts: d.hosts,
            health, pool: d.pool, vms, pending_vms: d.pending_vms, metrics: d.metrics }
    }
}

#[derive(Serialize)]
pub struct NetworkView {
    regions: Vec<NetworkRegion>,
}

#[derive(Serialize)]
struct NetworkRegion {
    region: String,
    gateways: Vec<NetworkGateway>,
}

#[derive(Serialize)]
struct NetworkGateway {
    id: String,
    dashboard_url: String,
    observed_at: u64,
    generated_at: Option<u64>,
    ingress: Option<RemoteIngress>,
    ingress_error: Option<&'static str>,
    deployments: Vec<DeploymentDetail>,
    truncated: bool,
    error: Option<&'static str>,
}

/// Whether a fleet read may use a gateway on this caller's behalf.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Covers the fleet: service credentials and caller identity both usable.
    Fleet,
    /// Namespace caller: only gateways that take the caller's own identity.
    CallerOnly,
}

/// Build a `/metrics` request path. The namespace is encoded, never spliced.
fn metrics_path(summary: bool, limit: usize, offset: usize, namespace: Option<&str>) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("summary", if summary { "true" } else { "false" })
        .append_pair("limit", &limit.to_string())
        .append_pair("offset", &offset.to_string());
    if let Some(ns) = namespace { query.append_pair("namespace", ns); }
    format!("/metrics?{}", query.finish())
}

impl Fleet {
    fn dashboard_url(gateway: &Gateway) -> String {
        format!("{}/dashboard?view=local", gateway.url.trim_end_matches('/'))
    }

    fn usable(gateway: &Gateway, reach: Reach) -> Result<(), &'static str> {
        if reach == Reach::CallerOnly && !gateway.use_caller_auth { Err(SERVICE_CREDENTIAL_REFUSED) } else { Ok(()) }
    }

    /// Page through one gateway's `/metrics` until it runs out or `max_pages`
    /// is reached. Returns the first page's header fields, all rows, and
    /// whether rows were left behind.
    async fn collect(&self, gateway: &Gateway, summary: bool, namespace: Option<&str>, page: usize,
        max_pages: usize, caller: Option<&str>) -> Result<(RemotePage, bool), &'static str> {
        let run = async {
            let mut first: Option<RemotePage> = None;
            let mut offset = 0;
            for _ in 0..max_pages {
                let mut next: RemotePage = self.fetch(gateway, &metrics_path(summary, page, offset, namespace), caller).await?;
                let got = next.deployments.len();
                offset += got;
                let done = got < page || offset >= next.matched;
                match &mut first {
                    None => first = Some(next),
                    Some(acc) => {
                        acc.matched = next.matched;
                        acc.deployments.append(&mut next.deployments);
                    }
                }
                if done { return Ok((first.expect("first page recorded"), false)) }
            }
            Ok((first.ok_or("invalid gateway metrics")?, true))
        };
        tokio::time::timeout(GATEWAY_DEADLINE, run).await.map_err(|_| "gateway observation timed out")?
    }

    /// Global workload rollup: namespace × deployment rows with one cell per
    /// gateway. A failing gateway contributes an error cell, never zeros.
    pub async fn workloads(&self, namespace: Option<&str>, reach: Reach, caller: Option<&str>) -> Workloads {
        self.workloads_capped(namespace, reach, caller, ROLLUP_PAGE, ROLLUP_MAX_PAGES).await
    }

    async fn workloads_capped(&self, namespace: Option<&str>, reach: Reach, caller: Option<&str>,
        page: usize, max_pages: usize) -> Workloads {
        let results = futures::future::join_all(self.gateways.iter().map(|gateway| async move {
            let result = match Self::usable(gateway, reach) {
                Ok(()) => self.collect(gateway, true, namespace, page, max_pages, caller).await,
                Err(e) => Err(e),
            };
            (gateway, crate::deployment::now_secs(), result)
        })).await;
        let mut rows: std::collections::BTreeMap<(String, String), WorkloadRow> = Default::default();
        let mut gateways = Vec::new();
        let mut failed = Vec::new();
        let mut totals = Totals::default();
        for (gateway, observed_at, result) in results {
            let mut rollup = GatewayRollup {
                id: gateway.id.clone(), region: gateway.region.clone(), dashboard_url: Self::dashboard_url(gateway),
                observed_at, generated_at: None, deployments: 0, truncated: false, totals: Totals::default(), error: None,
            };
            match result {
                Ok((page, truncated)) => {
                    rollup.generated_at = Some(page.generated_at);
                    rollup.truncated = truncated;
                    for d in page.deployments {
                        // The remote narrows too; this is the second wall.
                        if namespace.is_some_and(|ns| ns != d.namespace) { continue }
                        rollup.deployments += 1;
                        rollup.totals.add(&d.pool);
                        totals.add(&d.pool);
                        let row = rows.entry((d.namespace.clone(), d.id.clone())).or_insert_with(|| WorkloadRow {
                            namespace: d.namespace.clone(), id: d.id.clone(), kind: d.kind.clone(), routed: false,
                            hosts: Vec::new(), health: "idle", totals: Totals::default(), cells: Vec::new(),
                        });
                        row.routed |= d.routed;
                        for host in &d.hosts { if !row.hosts.contains(host) { row.hosts.push(host.clone()) } }
                        row.totals.add(&d.pool);
                        row.cells.push(Cell {
                            gateway: gateway.id.clone(), region: gateway.region.clone(),
                            ready: Some(d.pool.ready), pending: Some(d.pool.pending), draining: Some(d.pool.draining),
                            desired: Some(d.pool.desired_replicas), in_flight: Some(d.pool.total_in_flight),
                            health: Some(pool_health(&d.kind, &d.pool)), error: None,
                        });
                    }
                }
                Err(error) => { rollup.error = Some(error); failed.push((gateway, error)); }
            }
            gateways.push(rollup);
        }
        let order: Vec<&str> = self.gateways.iter().map(|g| g.id.as_str()).collect();
        let rows = rows.into_values().map(|mut row| {
            row.health = pool_health(&row.kind, &row.totals.as_pool());
            for (gateway, error) in &failed {
                row.cells.push(Cell { gateway: gateway.id.clone(), region: gateway.region.clone(), ready: None,
                    pending: None, draining: None, desired: None, in_flight: None, health: None, error: Some(error) });
            }
            row.cells.sort_by_key(|c| order.iter().position(|id| *id == c.gateway));
            row
        }).collect();
        Workloads { namespace: namespace.map(str::to_owned), gateways, rows, totals }
    }

    /// One page of one gateway's deployments with VM rows, allowlisted. `None`
    /// when no gateway has that id.
    pub async fn gateway_detail(&self, id: &str, namespace: Option<&str>, offset: usize, reach: Reach,
        caller: Option<&str>) -> Option<Result<GatewayDetail, &'static str>> {
        let gateway = self.gateways.iter().find(|g| g.id == id)?;
        if let Err(e) = Self::usable(gateway, reach) { return Some(Err(e)) }
        let result = self.fetch::<RemotePage>(gateway, &metrics_path(false, DETAIL_PAGE, offset, namespace), caller).await;
        Some(result.map(|page| GatewayDetail {
            id: gateway.id.clone(), region: gateway.region.clone(), dashboard_url: Self::dashboard_url(gateway),
            observed_at: crate::deployment::now_secs(), generated_at: page.generated_at, uptime_secs: page.uptime_secs,
            fleet: page.fleet, host: page.host, matched: page.matched, offset, limit: DETAIL_PAGE,
            deployments: page.deployments.into_iter()
                .filter(|d| namespace.is_none_or(|ns| ns == d.namespace))
                .map(|d| DeploymentDetail::from_remote(d, reach == Reach::Fleet)).collect(),
        }))
    }

    /// Region → gateway → deployments → VMs, with each gateway's ingress
    /// addresses. Fleet-wide callers only (enforced by the handler).
    pub async fn network(&self, caller: Option<&str>) -> NetworkView {
        let observed = futures::future::join_all(self.gateways.iter().map(|gateway| async move {
            let (ingress, metrics) = futures::future::join(
                self.fetch::<RemoteIngress>(gateway, "/ingress", caller),
                self.collect(gateway, false, None, DETAIL_PAGE, NETWORK_MAX_PAGES, caller),
            ).await;
            let (deployments, truncated, generated_at, error) = match metrics {
                Ok((page, truncated)) => (page.deployments.into_iter()
                    .map(|d| DeploymentDetail::from_remote(d, true)).collect(), truncated, Some(page.generated_at), None),
                Err(e) => (Vec::new(), false, None, Some(e)),
            };
            NetworkGateway {
                id: gateway.id.clone(), dashboard_url: Self::dashboard_url(gateway),
                observed_at: crate::deployment::now_secs(), generated_at,
                ingress_error: ingress.as_ref().err().copied(), ingress: ingress.ok().map(RemoteIngress::sanitized),
                deployments, truncated, error,
            }
        })).await;
        let mut regions: Vec<NetworkRegion> = Vec::new();
        for (gateway, view) in self.gateways.iter().zip(observed) {
            match regions.iter_mut().find(|r| r.region == gateway.region) {
                Some(region) => region.gateways.push(view),
                None => regions.push(NetworkRegion { region: gateway.region.clone(), gateways: vec![view] }),
            }
        }
        NetworkView { regions }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(url: &str) -> serde_json::Value {
        serde_json::json!({"id":"us3-edge","region":"US","url":url,
            "auth":{"secret":"fleet-observer","key":"token"}})
    }

    #[test]
    fn the_token_authority_takes_a_service_credential_https_origin_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.json");
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
        secrets.put(crate::secrets::SecretSpec { id:"fleet-observer".into(),namespace:"default".into(),
            description:None,updated_at:0,data:std::collections::BTreeMap::from([("token".into(),"member-pull".into())]) });
        let store = ViewStore::open(path.clone(), secrets.clone(), [None,None]).unwrap();
        let config = |authority: serde_json::Value| -> ViewConfig {
            serde_json::from_value(serde_json::json!({"gateways":[],"control_plane":[],"token_authority":authority})).unwrap()
        };

        let caller = serde_json::json!({"id":"us2","region":"US2","url":"https://admin.us2.example","use_caller_auth":true});
        assert_eq!(store.configure(ConfigureViews { expected_revision:0, config:config(caller) }).err().unwrap().0, http::StatusCode::BAD_REQUEST);
        let plain = serde_json::json!({"id":"us2","region":"US2","url":"http://admin.us2.example","auth":{"secret":"fleet-observer","key":"token"}});
        assert_eq!(store.configure(ConfigureViews { expected_revision:0, config:config(plain) }).err().unwrap().0, http::StatusCode::BAD_REQUEST);
        let missing = serde_json::json!({"id":"us2","region":"US2","url":"https://admin.us2.example","auth":{"secret":"absent","key":"token"}});
        assert_eq!(store.configure(ConfigureViews { expected_revision:0, config:config(missing) }).err().unwrap().0, http::StatusCode::BAD_REQUEST);

        let good = serde_json::json!({"id":"us2","region":"US2","url":"https://admin.us2.example","auth":{"secret":"fleet-observer","key":"token"}});
        let updated = store.configure(ConfigureViews { expected_revision:0, config:config(good) }).unwrap();
        assert!(updated.token_authority.is_some());
        assert!(updated.fleet.is_none(), "a member is not a control plane");
        let restarted = ViewStore::open(path, secrets, [None,None]).unwrap();
        assert!(restarted.snapshot().token_authority.is_some());
        assert_eq!(serde_json::to_value(&*restarted.snapshot()).unwrap()["config"]["token_authority"]["url"], "https://admin.us2.example/");
    }

    #[test]
    fn view_configuration_is_durable_conditional_and_keeps_old_readers_pinned() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.json");
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"), None));
        secrets.put(crate::secrets::SecretSpec { id:"fleet-observer".into(),namespace:"default".into(),
            description:None,updated_at:0,data:std::collections::BTreeMap::from([("token".into(),"never-persist-this-value".into())]) });
        let store = ViewStore::open(path.clone(), secrets.clone(), [None,None]).unwrap();
        let before = store.snapshot();
        let config: ViewConfig = serde_json::from_value(serde_json::json!({"gateways":[gateway("https://edge.example")],
            "control_plane":[gateway("https://authority.example")]})).unwrap();
        let updated = store.configure(ConfigureViews { expected_revision:0,config:config.clone() }).unwrap();
        assert_eq!(updated.revision,1);
        assert_eq!(updated.fleet.as_ref().unwrap().gateways[0].url,"https://edge.example/");
        assert_eq!(updated.control_plane.as_ref().unwrap().gateways[0].url,"https://authority.example/");
        assert!(before.fleet.is_none());
        assert_eq!(before.revision,0);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,0o600);
        assert!(!std::fs::read_to_string(&path).unwrap().contains("never-persist-this-value"));
        assert!(!serde_json::to_string(&*updated).unwrap().contains("never-persist-this-value"));
        assert_eq!(store.configure(ConfigureViews { expected_revision:0,config:ViewConfig::default() }).err().unwrap().0,http::StatusCode::CONFLICT);
        let restarted = ViewStore::open(path.clone(), secrets.clone(), [None,None]).unwrap();
        assert_eq!(restarted.snapshot().revision,1);
        let mut invalid = config.clone();
        invalid.control_plane[0].url = "http://untrusted.example".into();
        assert_eq!(restarted.configure(ConfigureViews { expected_revision:1,config:invalid }).err().unwrap().0,http::StatusCode::BAD_REQUEST);
        let mut missing = config;
        missing.gateways[0].auth.as_mut().unwrap().key = "missing".into();
        assert_eq!(restarted.configure(ConfigureViews { expected_revision:1,config:missing }).err().unwrap().0,http::StatusCode::BAD_REQUEST);
        assert_eq!(restarted.snapshot().revision,1);
        let override_path = dir.path().join("override.json");
        std::fs::write(&override_path,serde_json::json!([gateway("https://operator.example")]).to_string()).unwrap();
        let managed = ViewStore::open(path, secrets, [Some(override_path),None]).unwrap();
        assert_eq!(managed.snapshot().fleet.as_ref().unwrap().gateways[0].url,"https://operator.example/");
        assert_eq!(managed.configure(ConfigureViews { expected_revision:1,config:ViewConfig::default() }).err().unwrap().0,http::StatusCode::CONFLICT);
    }

    #[test]
    fn failed_view_persistence_does_not_publish_and_corruption_fails_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.json");
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"),None));
        let store = ViewStore::open(path.clone(), secrets.clone(),[None,None]).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(store.configure(ConfigureViews { expected_revision:0,config:ViewConfig::default() }).err().unwrap().0,http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(store.snapshot().revision,0);
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path,b"not-json").unwrap();
        assert!(ViewStore::open(path,secrets,[None,None]).is_err());
    }

    #[test]
    fn simultaneous_view_writers_cannot_both_replace_the_same_revision() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets.json"),None));
        let store = Arc::new(ViewStore::open(dir.path().join("views.json"),secrets,[None,None]).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2).map(|_| {
            let store = store.clone(); let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.configure(ConfigureViews { expected_revision:0,config:ViewConfig::default() }).map(|s| s.revision).map_err(|e| e.0)
            })
        }).collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| **r == Ok(1)).count(),1);
        assert_eq!(results.iter().filter(|r| **r == Err(http::StatusCode::CONFLICT)).count(),1);
    }

    #[test]
    fn targets_are_explicit_https_origins_without_credentials_or_ambiguity() {
        assert!(parse(&serde_json::json!([gateway("https://admin.example")]).to_string()).is_ok());
        for url in ["http://admin.example", "https://user:pass@admin.example", "https://admin.example/metrics",
            "https://admin.example?token=x", "https://admin.example#fragment"] {
            assert!(parse(&serde_json::json!([gateway(url)]).to_string()).is_err(), "{url}");
        }
        let a = gateway("https://admin.example");
        let mut b = gateway("https://admin.example:443/");
        b["id"] = "eu1-edge".into();
        assert!(parse(&serde_json::json!([a,b]).to_string()).is_err());
        assert!(parse("[]").is_err());
    }

    #[test]
    fn caller_auth_is_explicit_and_cannot_replace_control_plane_credentials() {
        let mut g = gateway("https://admin.example");
        let legacy = parse(&serde_json::json!([g.clone()]).to_string()).unwrap();
        assert!(serde_json::to_value(&legacy).unwrap()[0].get("use_caller_auth").is_none());
        g["use_caller_auth"] = true.into();
        assert!(parse(&serde_json::json!([g.clone()]).to_string()).is_err());
        g.as_object_mut().unwrap().remove("auth");
        let gateways = parse(&serde_json::json!([g.clone()]).to_string()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(SecretStore::new(dir.path().join("secrets"), None));
        let store = ViewStore::open(dir.path().join("views"), secrets, [None,None]).unwrap();
        let config = ViewConfig { gateways:gateways.clone(), control_plane:vec![], token_authority:None };
        assert_eq!(store.configure(ConfigureViews {expected_revision:0,config}).unwrap().revision,1);
        let config = ViewConfig { gateways:vec![], control_plane:gateways, token_authority:None };
        assert_eq!(store.configure(ConfigureViews {expected_revision:1,config}).err().unwrap().0,http::StatusCode::BAD_REQUEST);
        assert_eq!(store.snapshot().revision,1);
        g["use_caller_auth"] = false.into();
        assert!(parse(&serde_json::json!([g]).to_string()).is_err());
    }

    #[test]
    fn remote_fields_are_allowlisted() {
        let metrics: GatewayMetrics = serde_json::from_value(serde_json::json!({
            "generated_at":42,"uptime_secs":7,"secret":"never-forward",
            "fleet":{"deployments":9,"ready":3,"draining":2,"pending":1,"total_in_flight":17}
        })).unwrap();
        let encoded = serde_json::to_value(metrics).unwrap();
        assert_eq!(encoded["fleet"]["total_in_flight"],17);
        assert!(encoded.get("secret").is_none());
        assert!(serde_json::from_value::<GatewayMetrics>(serde_json::json!({"fleet":{}})).is_err());
    }

    #[tokio::test]
    async fn observations_keep_success_when_a_peer_redirects_or_lacks_credentials() {
        use axum::{Router, routing::get, response::IntoResponse};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(|headers: http::HeaderMap| async move {
            match headers.get(http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
                Some("Bearer test-observer") => axum::Json(serde_json::json!({
                    "generated_at":42,"uptime_secs":7,
                    "fleet":{"deployments":9,"ready":3,"draining":2,"pending":1,"total_in_flight":17}
                })).into_response(),
                Some("Bearer redirect-observer") => axum::response::Redirect::temporary("/metrics").into_response(),
                _ => http::StatusCode::UNAUTHORIZED.into_response(),
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let secrets = Arc::new(SecretStore::new("unused-fleet-test.json", None));
        secrets.put(crate::secrets::SecretSpec {
            id: "fleet-observer".into(), namespace: "default".into(), description: None,
            data: std::collections::BTreeMap::from([
                ("token".into(), "test-observer".into()),
                ("redirect".into(), "redirect-observer".into()),
            ]), updated_at: 0,
        });
        // HTTP is only used by this loopback transport test. Config parsing
        // independently requires HTTPS for installed gateways.
        let mut gateways: Vec<Gateway> = (0..3).map(|index| {
            let mut value = gateway(&format!("http://{address}"));
            value["id"] = format!("edge-{index}").into();
            value["auth"]["key"] = ["token", "redirect", "missing"][index].into();
            serde_json::from_value(value).unwrap()
        }).collect();
        gateways[1].region = "eu1".into();
        gateways.push(serde_json::from_value(serde_json::json!({
            "id":"signed-in","region":"eu1","url":format!("http://{address}"),"use_caller_auth":true
        })).unwrap());
        let fleet = Fleet { gateways, secrets, client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5)).redirect(reqwest::redirect::Policy::none()).build().unwrap() };
        let observed = fleet.observe(None).await;
        assert_eq!(observed[0].metrics.as_ref().unwrap().fleet.total_in_flight, 17);
        assert_eq!(observed[1].region, "eu1");
        assert!(observed[1].metrics.is_none());
        assert_eq!(observed[1].error, Some("gateway rejected observation"));
        assert!(observed[2].metrics.is_none());
        assert_eq!(observed[2].error, Some("credential unavailable"));
        assert!(!serde_json::to_string(&observed).unwrap().contains("test-observer"));
        assert_eq!(observed[3].error,Some("Heyo sign-in required for regional observations"));
        let signed_in = fleet.observe(Some("test-observer")).await;
        assert_eq!(signed_in[3].metrics.as_ref().unwrap().fleet.total_in_flight,17);
        assert!(signed_in[3].dashboard_url.ends_with("/dashboard?view=local"));
        assert_eq!(signed_in[1].error,Some("gateway rejected observation"));
        assert_eq!(signed_in[2].error,Some("credential unavailable"));
        assert!(!serde_json::to_string(&signed_in).unwrap().contains("test-observer"));
        server.abort();
    }

    fn test_fleet(gateways: Vec<Gateway>, secrets: Arc<SecretStore>) -> Fleet {
        Fleet { gateways, secrets, client: reqwest::Client::builder()
            .timeout(Duration::from_secs(5)).redirect(reqwest::redirect::Policy::none()).build().unwrap() }
    }

    fn observer_secrets(pairs: &[(&str, &str)]) -> Arc<SecretStore> {
        let secrets = Arc::new(SecretStore::new("unused-rollup-test.json", None));
        secrets.put(crate::secrets::SecretSpec {
            id: "fleet-observer".into(), namespace: "default".into(), description: None, updated_at: 0,
            data: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        });
        secrets
    }

    fn remote_deployment(id: &str, namespace: Option<&str>, ready: usize, desired: u32) -> serde_json::Value {
        let mut d = serde_json::json!({"id":id,"kind":"vm","upstreams":["10.0.0.9:80"],"routed":true,
            "hosts":[format!("{id}.example.com")],"urls":["https://user:pw@leak.example.com"],
            "account_id":"acct-secret","site_root":"/srv/secret","spec":{"env":{"TOKEN":"never-forward"}},
            "pool":{"desired_replicas":desired,"ready":ready,"draining":0,"pending":0,"total_in_flight":1,
                "target_concurrency":1,"min_replicas":0,"max_replicas":3,"warm_pool":0,"utilization":null,
                "cpu_percent":null,"memory_bytes":null,"boot_timeout_secs":300,"cold_start_timeout_secs":120},
            "vms":[{"sandbox_id":format!("{id}-vm"),"addr":"172.16.0.4:8080","in_flight":1,"healthy":true,
                "draining":false,"uptime_secs":5,"cpu_percent":1.5,"memory_bytes":10,"subdomain":"x.heyo","env":"never-forward"}],
            "pending_vms":[],"metrics":{"requests":{"total":7,"c2xx":6,"c3xx":0,"c4xx":0,"c5xx":1,"errors":0},
                "latency_ms":{"count":7,"sum":9,"mean":1.0,"p50":1.0,"p90":2.0,"p99":3.0,"buckets":[]},
                "secret":"never-forward"}});
        if let Some(ns) = namespace { d["namespace"] = ns.into(); }
        d
    }

    fn metrics_page(deployments: Vec<serde_json::Value>, matched: usize) -> serde_json::Value {
        serde_json::json!({"generated_at":42,"uptime_secs":7,"secret":"never-forward",
            "host":{"available":true,"cpu_count":4,"cpu_percent":12.5,"memory_total_bytes":100,"memory_used_bytes":50,"sampled_at_ms":1},
            "fleet":{"deployments":matched,"ready":1,"draining":0,"pending":0,"total_in_flight":1},
            "deployments":deployments,"matched":matched})
    }

    #[test]
    fn rollup_rows_are_allowlisted_and_guest_addresses_are_fleet_only() {
        let remote: RemoteDeployment = serde_json::from_value(remote_deployment("web", Some("team-a"), 1, 1)).unwrap();
        let wire = serde_json::to_string(&DeploymentDetail::from_remote(remote.clone(), true)).unwrap();
        for leaked in ["never-forward", "user:pw", "acct-secret", "/srv/secret", "10.0.0.9", "subdomain", "urls", "upstreams"] {
            assert!(!wire.contains(leaked), "{leaked} leaked: {wire}");
        }
        assert!(wire.contains("172.16.0.4"));
        assert!(wire.contains("\"health\":\"healthy\""));
        let narrowed = serde_json::to_string(&DeploymentDetail::from_remote(remote, false)).unwrap();
        assert!(!narrowed.contains("172.16.0.4") && !narrowed.contains("addr"));
        // The default namespace is omitted remotely and restored here.
        let default: RemoteDeployment = serde_json::from_value(remote_deployment("api", None, 0, 2)).unwrap();
        assert_eq!(default.namespace, "default");
        assert_eq!(pool_health(&default.kind, &default.pool), "down");
        let ingress: RemoteIngress = serde_json::from_value(serde_json::json!({
            "ipv4":["203.0.113.1","not-an-ip"],"ipv6":["2001:db8::1"],"extra":"never-forward"})).unwrap();
        let ingress = serde_json::to_string(&ingress.sanitized()).unwrap();
        assert_eq!(ingress, r#"{"ipv4":["203.0.113.1"],"ipv6":["2001:db8::1"]}"#);
    }

    #[test]
    fn health_is_derived_from_pool_gauges() {
        let pool = |desired, ready, draining, pending| RemotePool { desired_replicas: desired, ready, draining,
            pending, total_in_flight: 0, min_replicas: 0, max_replicas: 0 };
        assert_eq!(pool_health("vm", &pool(2, 2, 0, 0)), "healthy");
        assert_eq!(pool_health("vm", &pool(2, 2, 1, 0)), "degraded");
        assert_eq!(pool_health("vm", &pool(2, 0, 0, 1)), "starting");
        assert_eq!(pool_health("vm", &pool(2, 1, 1, 0)), "draining");
        assert_eq!(pool_health("vm", &pool(2, 0, 0, 0)), "down");
        assert_eq!(pool_health("vm", &pool(0, 0, 0, 0)), "idle");
        assert_eq!(pool_health("site", &pool(0, 0, 0, 0)), "healthy");
    }

    #[tokio::test]
    async fn rollup_survives_a_failing_gateway_and_merges_rows_per_server() {
        use axum::{Router, routing::get, response::IntoResponse};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(|headers: http::HeaderMap| async move {
            match headers.get(http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
                Some("Bearer us2") => axum::Json(metrics_page(vec![
                    remote_deployment("web", Some("team-a"), 2, 2), remote_deployment("api", None, 1, 1)], 2)).into_response(),
                Some("Bearer us4") => axum::Json(metrics_page(vec![remote_deployment("web", Some("team-a"), 0, 2)], 1)).into_response(),
                Some("Bearer broken") => http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                _ => http::StatusCode::UNAUTHORIZED.into_response(),
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let secrets = observer_secrets(&[("us2", "us2"), ("us4", "us4"), ("us5", "broken")]);
        let gateways: Vec<Gateway> = ["us2", "us4", "us5"].iter().enumerate().map(|(index, id)| {
            let mut value = gateway(&format!("http://{address}"));
            value["id"] = (*id).into();
            value["region"] = id.to_uppercase().into();
            value["auth"]["key"] = (*id).into();
            // Distinct origins are only a parse-time rule; reuse the loopback.
            let _ = index;
            serde_json::from_value(value).unwrap()
        }).collect();
        let fleet = test_fleet(gateways, secrets);
        let rollup = serde_json::to_value(fleet.workloads(None, Reach::Fleet, None).await).unwrap();
        assert_eq!(rollup["gateways"][0]["deployments"], 2);
        assert_eq!(rollup["gateways"][1]["deployments"], 1);
        assert_eq!(rollup["gateways"][2]["error"], "gateway unavailable");
        assert!(rollup["gateways"][2]["generated_at"].is_null());
        let rows = rollup["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0]["namespace"].as_str(), rows[0]["id"].as_str()), (Some("default"), Some("api")));
        let web = &rows[1];
        assert_eq!((web["namespace"].as_str(), web["id"].as_str()), (Some("team-a"), Some("web")));
        let cells = web["cells"].as_array().unwrap();
        assert_eq!(cells.len(), 3);
        assert_eq!((cells[0]["gateway"].as_str(), cells[0]["ready"].as_u64(), cells[0]["health"].as_str()), (Some("us2"), Some(2), Some("healthy")));
        assert_eq!((cells[1]["gateway"].as_str(), cells[1]["ready"].as_u64(), cells[1]["health"].as_str()), (Some("us4"), Some(0), Some("down")));
        assert_eq!((cells[2]["gateway"].as_str(), cells[2]["error"].as_str()), (Some("us5"), Some("gateway unavailable")));
        assert!(cells[2]["ready"].is_null());
        assert_eq!((web["totals"]["ready"].as_u64(), web["totals"]["desired"].as_u64()), (Some(2), Some(4)));
        assert_eq!(web["health"], "degraded");
        assert_eq!(rollup["totals"]["ready"], 3);
        let wire = rollup.to_string();
        assert!(!wire.contains("never-forward") && !wire.contains("user:pw") && !wire.contains("172.16.0.4"));
        // Namespace narrowing also filters locally.
        let narrowed = serde_json::to_value(fleet.workloads(Some("team-a"), Reach::Fleet, None).await).unwrap();
        assert_eq!(narrowed["rows"].as_array().unwrap().len(), 1);
        assert_eq!(narrowed["namespace"], "team-a");
        server.abort();
    }

    #[tokio::test]
    async fn namespace_callers_never_spend_service_credentials() {
        use axum::{Router, routing::get, extract::Query};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
        let (count, record) = (hits.clone(), seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/metrics", get(move |headers: http::HeaderMap,
            Query(query): Query<std::collections::HashMap<String, String>>| {
            let (count, record) = (count.clone(), record.clone());
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let auth = headers.get(http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or_default().to_string();
                record.lock().unwrap().push((auth, query.get("namespace").cloned().unwrap_or_default()));
                axum::Json(metrics_page(vec![remote_deployment("web", Some("team-a"), 1, 1),
                    remote_deployment("other", Some("team-b"), 1, 1)], 2))
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let service: Gateway = serde_json::from_value(gateway(&format!("http://{address}"))).unwrap();
        let caller: Gateway = serde_json::from_value(serde_json::json!({
            "id":"signed-in","region":"US4","url":format!("http://{address}"),"use_caller_auth":true})).unwrap();
        let fleet = test_fleet(vec![service, caller], observer_secrets(&[("token", "service-secret")]));

        let rollup = serde_json::to_value(fleet.workloads(Some("team-a"), Reach::CallerOnly, Some("user-jwt")).await).unwrap();
        assert_eq!(rollup["gateways"][0]["error"], SERVICE_CREDENTIAL_REFUSED);
        assert!(rollup["gateways"][1]["error"].is_null());
        assert_eq!(rollup["rows"].as_array().unwrap().len(), 1, "the other namespace is dropped locally too");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "only the caller-auth gateway is contacted");
        assert_eq!(seen.lock().unwrap()[0], ("Bearer user-jwt".to_string(), "team-a".to_string()));

        assert!(matches!(fleet.gateway_detail("us3-edge", Some("team-a"), 0, Reach::CallerOnly, Some("user-jwt")).await,
            Some(Err(SERVICE_CREDENTIAL_REFUSED))));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let detail = serde_json::to_value(fleet.gateway_detail("signed-in", Some("team-a"), 0, Reach::CallerOnly, Some("user-jwt"))
            .await.unwrap().unwrap()).unwrap();
        assert_eq!(detail["deployments"].as_array().unwrap().len(), 1);
        assert!(detail["deployments"][0]["vms"][0].get("addr").is_none(), "guest addresses are fleet-only");
        assert!(fleet.gateway_detail("nope", None, 0, Reach::Fleet, None).await.is_none());
        // Without a Heyo identity, the caller gateway reports sign-in instead.
        let anonymous = serde_json::to_value(fleet.workloads(Some("team-a"), Reach::CallerOnly, None).await).unwrap();
        assert_eq!(anonymous["gateways"][1]["error"], "Heyo sign-in required for regional observations");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        // A fleet caller reaches both, the service one with the service key.
        let full = serde_json::to_value(fleet.workloads(None, Reach::Fleet, Some("user-jwt")).await).unwrap();
        assert!(full["gateways"][0]["error"].is_null());
        assert!(seen.lock().unwrap().iter().any(|(auth, _)| auth == "Bearer service-secret"));
        server.abort();
    }

    #[tokio::test]
    async fn rollup_pagination_stops_when_done_or_at_the_cap() {
        use axum::{Router, routing::get, extract::Query};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // `matched` is taken from the `total` query knob so one server can
        // play both a small and an endless gateway.
        let app = Router::new().route("/metrics", get(move |headers: http::HeaderMap,
            Query(query): Query<std::collections::HashMap<String, String>>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let total: usize = if headers[http::header::AUTHORIZATION] == "Bearer small" { 3 } else { 1_000_000 };
                let offset: usize = query["offset"].parse().unwrap();
                let limit: usize = query["limit"].parse().unwrap();
                assert_eq!(query["summary"], "true");
                let rows = (offset..total.min(offset + limit))
                    .map(|i| remote_deployment(&format!("d{i:07}"), None, 1, 1)).collect();
                axum::Json(metrics_page(rows, total))
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let make = |key: &str| {
            let mut value = gateway(&format!("http://{address}"));
            value["auth"]["key"] = key.into();
            serde_json::from_value::<Gateway>(value).unwrap()
        };
        let small = test_fleet(vec![make("small")], observer_secrets(&[("small", "small"), ("endless", "endless")]));
        let rollup = serde_json::to_value(small.workloads_capped(None, Reach::Fleet, None, 2, 3).await).unwrap();
        assert_eq!(rollup["rows"].as_array().unwrap().len(), 3);
        assert_eq!(rollup["gateways"][0]["truncated"], false);
        assert_eq!(hits.swap(0, Ordering::SeqCst), 2);

        let endless = test_fleet(vec![make("endless")], observer_secrets(&[("endless", "endless")]));
        let rollup = serde_json::to_value(endless.workloads_capped(None, Reach::Fleet, None, 2, 3).await).unwrap();
        assert_eq!(rollup["rows"].as_array().unwrap().len(), 6);
        assert_eq!(rollup["gateways"][0]["truncated"], true);
        assert_eq!(hits.load(Ordering::SeqCst), 3, "stops at the page cap");
        server.abort();
    }

    /// The checked-in example for the us2 control plane must stay loadable.
    #[test]
    fn the_example_fleet_file_parses() {
        let gateways = parse(include_str!("../../.heyo/fleet/fleet.json")).unwrap();
        let ids: Vec<_> = gateways.iter().map(|g| (g.id.as_str(), g.region.as_str())).collect();
        assert_eq!(ids, [("us2", "US2"), ("us4", "US4"), ("us5", "US5")]);
        assert!(gateways.iter().all(|g| g.auth.as_ref().is_some_and(|a| a.secret == format!("fleet-observer-{}", g.id) && a.key == "token")));
    }

    #[test]
    fn metrics_paths_encode_the_namespace() {
        assert_eq!(metrics_path(true, 100, 0, None), "/metrics?summary=true&limit=100&offset=0");
        assert_eq!(metrics_path(false, 50, 50, Some("a&b=c")), "/metrics?summary=false&limit=50&offset=50&namespace=a%26b%3Dc");
    }

    #[tokio::test]
    async fn network_groups_gateways_by_region_with_ingress() {
        use axum::{Router, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/metrics", get(|| async { axum::Json(metrics_page(vec![remote_deployment("web", None, 1, 1)], 1)) }))
            .route("/ingress", get(|| async { axum::Json(serde_json::json!({"ipv4":["203.0.113.7"],"ipv6":[]})) }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateways: Vec<Gateway> = [("us2", "US"), ("us4", "US"), ("eu1", "EU")].iter().map(|(id, region)| {
            let mut value = gateway(&format!("http://{address}"));
            value["id"] = (*id).into();
            value["region"] = (*region).into();
            if *id == "eu1" { value["auth"]["key"] = "missing".into(); }
            serde_json::from_value(value).unwrap()
        }).collect();
        let fleet = test_fleet(gateways, observer_secrets(&[("token", "t")]));
        let view = serde_json::to_value(fleet.network(None).await).unwrap();
        assert_eq!(view["regions"].as_array().unwrap().len(), 2);
        assert_eq!(view["regions"][0]["region"], "US");
        assert_eq!(view["regions"][0]["gateways"].as_array().unwrap().len(), 2);
        let us2 = &view["regions"][0]["gateways"][0];
        assert_eq!(us2["ingress"]["ipv4"][0], "203.0.113.7");
        assert_eq!(us2["deployments"][0]["vms"][0]["addr"], "172.16.0.4:8080");
        let eu1 = &view["regions"][1]["gateways"][0];
        assert_eq!(eu1["error"], "credential unavailable");
        assert_eq!(eu1["ingress_error"], "credential unavailable");
        assert!(!view.to_string().contains("never-forward"));
        server.abort();
    }

    #[tokio::test]
    async fn inventory_fails_over_on_unavailable_region_but_not_denied_credentials() {
        use axum::{Router, routing::get, extract::Query};
        use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
        let status = Arc::new(AtomicU16::new(503));
        let flag = status.clone();
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_url = format!("http://{}",first.local_addr().unwrap());
        let a = tokio::spawn(async move {
            axum::serve(first, Router::new().route("/orchestration/services", get(move || {
                let flag = flag.clone();
                async move { http::StatusCode::from_u16(flag.load(Ordering::SeqCst)).unwrap() }
            }))).await.unwrap();
        });
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_url = format!("http://{}",second.local_addr().unwrap());
        let b = tokio::spawn(async move {
            axum::serve(second, Router::new().route("/orchestration/services", get(move |headers: http::HeaderMap,
                Query(query): Query<std::collections::HashMap<String,String>>| {
                let count = count.clone();
                async move {
                    assert_eq!(headers["authorization"],"Bearer shared-credential");
                    assert_eq!(query.get("after").unwrap(),"a&b");
                    count.fetch_add(1,Ordering::SeqCst);
                    axum::Json(serde_json::json!({"services":[{"serviceId":"global-app","desiredReplicas":2,
                        "replicaRegions":["US","eu1"],"discoveryVersion":8,"endpoints":[],"rollout":null},
                        {"serviceId":"ci","update":{"operationId":"op-1","status":"running","targetRevision":"revision-2","runId":"run-3",
                        "phase":"draining","observedAt":null,"error":null,"unexpectedSecret":"must-not-forward"},
                        "external":{"externallyManaged":false,"lifecycleOwner":"orchestrator",
                        "deploymentId":"ci-eu1","region":"eu1","observedAt":"2026-09-24T17:24:48Z",
                        "capabilities":["release-update"],"unexpectedSecret":"must-not-forward"}}],"nextCursor":null}))
                }
            }))).await.unwrap();
        });
        let secrets = Arc::new(SecretStore::new("unused-inventory-test.json",None));
        secrets.put(crate::secrets::SecretSpec {
            id:"fleet-observer".into(),namespace:"default".into(),description:None,updated_at:0,
            data:std::collections::BTreeMap::from([("token".into(),"shared-credential".into())]),
        });
        let fleet = Fleet { gateways:vec![serde_json::from_value(gateway(&first_url)).unwrap(),
            serde_json::from_value(gateway(&second_url)).unwrap()], secrets,
            client:reqwest::Client::builder().timeout(Duration::from_secs(1)).build().unwrap() };
        let inventory = fleet.inventory(Some("a&b")).await.unwrap();
        assert_eq!(inventory.services[0].service_id,"global-app");
        assert_eq!(inventory.services[1].external.as_ref().unwrap().deployment_id,"ci-eu1");
        let wire = serde_json::to_value(&inventory).unwrap();
        assert_eq!(wire["services"][1]["external"]["lifecycleOwner"],"orchestrator");
        assert_eq!(wire["services"][1]["external"]["capabilities"],serde_json::json!(["release-update"]));
        assert_eq!(wire["services"][1]["update"]["phase"],"draining");
        assert!(wire["services"][1]["update"].get("unexpectedSecret").is_none());
        assert!(wire["services"][1]["external"].get("unexpectedSecret").is_none());
        assert_eq!(hits.load(Ordering::SeqCst),1);
        status.store(401,Ordering::SeqCst);
        assert_eq!(fleet.inventory(Some("a&b")).await.err(),Some("gateway rejected observation"));
        assert_eq!(hits.load(Ordering::SeqCst),1);
        a.abort();
        let _ = a.await;
        // Existing keep-alive connections can outlive the listener task; use a
        // fresh client to exercise an actual refused regional connection.
        let fleet = Fleet { client: reqwest::Client::new(), ..fleet };
        assert_eq!(fleet.inventory(Some("a&b")).await.unwrap().services[0].desired_replicas,Some(2));
        b.abort();
    }
}
