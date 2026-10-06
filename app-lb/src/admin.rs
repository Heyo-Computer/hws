//! The control plane.
//!
//! Runs as a pingora `BackgroundService` so it shares the server's lifecycle and
//! graceful shutdown. It binds its own listener rather than using a pingora
//! listening service, which trades away zero-downtime socket handoff for that
//! port in exchange for real routing — an acceptable deal for an admin API.

use crate::autoscale::{Autoscaler, EvictOutcome};
use crate::config::DeploymentSpec;
use crate::jobs::{Jobs, StartError};
use crate::deployment::{Deployment, UpstreamDrain, now_secs};
use crate::metrics::{DeploymentMetricsSnapshot, HostSandboxView, HostUsageSnapshot, Metrics};
use crate::registry::Registry;
use crate::secrets::{SecretSpec, SecretStore};
use crate::siem::AuthAction;
use crate::tls::CertStore;
use async_trait::async_trait;
use axum::extract::{ConnectInfo, MatchedPath, Path, Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use base64::Engine;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;

#[path = "admin_login.rs"]
mod browser_login;

#[path = "release_console.rs"]
mod release_console;

/// The live dashboard page. Self-contained (no external fetches beyond the
/// same-origin `/metrics` poll) so it works over an SSH tunnel with no assets.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// The server-rendered landing page at `/`. Self-contained for the same reason
/// the dashboard is: it has to work over an SSH tunnel with no route out.
const DIRECTORY_HTML: &str = include_str!("directory.html");

/// The security console at `GET /siem`.
const SIEM_HTML: &str = include_str!("siem.html");

/// The network topology console at `GET /network`.
const NETWORK_HTML: &str = include_str!("network.html");

/// The disk console at `GET /storage`.
const DISKS_HTML: &str = include_str!("disks.html");

/// The plugin console at `GET /plugins`.
const PLUGINS_HTML: &str = include_str!("plugins.html");

/// How to turn a deployment's hostname into a URL somebody can click.
///
/// The dashboard runs on the *admin* listener, so it cannot infer the data
/// plane's scheme or port from its own location — an app-lb serving HTTPS on
/// 6189 would otherwise be linked as `http://host`, which connects to nothing.
#[derive(Debug, Clone)]
pub struct PublicUrl {
    scheme: &'static str,
    /// Appended as `:port`, unless it is the default for the scheme.
    port: Option<u16>,
}

impl PublicUrl {
    /// Derived from the listener config: the HTTPS listener when TLS is on
    /// (that is where a browser should land), the plaintext one otherwise.
    pub fn from_config(tls_enabled: bool, proxy_addr: &str, tls_addr: &str) -> Self {
        let (scheme, addr, default) = if tls_enabled {
            ("https", tls_addr, 443)
        } else {
            ("http", proxy_addr, 80)
        };
        Self {
            scheme,
            port: port_of(addr).filter(|p| *p != default),
        }
    }

    /// The URL for one route rule, or `None` if it names no host.
    ///
    /// A rule with only a `path_prefix` or a `host_suffix` is deliberately not
    /// linkable: neither names a single hostname a browser could be sent to.
    fn of(&self, rule: &crate::config::RouteRule) -> Option<String> {
        let host = rule.host.as_deref()?.trim();
        if host.is_empty() {
            return None;
        }
        let mut url = format!("{}://{host}", self.scheme);
        if let Some(port) = self.port {
            url.push_str(&format!(":{port}"));
        }
        // A host+path rule only matches under that prefix, so linking the bare
        // host would land on a 404 from this very deployment.
        if let Some(path) = &rule.path_prefix {
            url.push_str(path);
        }
        Some(url)
    }
}

/// The port from a `host:port` listen address, including `[::]:port`.
fn port_of(addr: &str) -> Option<u16> {
    let tail = match addr.rfind(']') {
        Some(end) => addr.get(end + 1..)?.strip_prefix(':')?,
        None => addr.rsplit_once(':')?.1,
    };
    tail.parse().ok()
}

/// The optional Basic-auth gate over the dashboard and `/metrics`.
///
/// Credentials are collapsed to the exact `Authorization` header they must
/// produce, computed once at startup, so verifying a request is a single
/// constant-time byte comparison — no per-request base64 decode, and no branch
/// on where the first mismatch is.
struct DashboardAuth {
    expected_header: String,
}

impl DashboardAuth {
    fn new(user: &str, password: &str) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Self {
            expected_header: format!("Basic {token}"),
        }
    }

    fn accepts(&self, header_value: Option<&str>) -> bool {
        header_value.is_some_and(|got| ct_eq(got.as_bytes(), self.expected_header.as_bytes()))
    }
}

/// Length-then-content comparison that doesn't short-circuit on the first
/// differing byte, so a matching prefix can't be timed out of the credential.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HTML-escape a value bound for element text / a `<title>` — the display name
/// comes from an env var, so escape it rather than trusting it into markup.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Clone)]
struct AdminState {
    views: Option<Arc<crate::fleet::ViewStore>>,
    /// The last pull of the token authority's fleet tokens, if one is bound.
    token_sync: Arc<std::sync::Mutex<TokenSyncStatus>>,
    rollouts: Arc<crate::rollout::Rollouts>,
    registry: Arc<Registry>,
    autoscaler: Arc<Autoscaler>,
    metrics: Arc<Metrics>,
    /// The dashboard page with the display name substituted in, rendered once at
    /// startup. `Arc<str>` so cloning `AdminState` per request is a refcount bump.
    dashboard_html: Arc<str>,
    /// The directory shell, with the display name already substituted. Only
    /// `{{LEDE}}` and `{{CARDS}}` are left, and those are filled per request
    /// because the registry moves.
    directory_html: Arc<str>,
    /// `None` disables the gate — the dashboard and `/metrics` are then open.
    auth: Option<Arc<DashboardAuth>>,
    /// Whether `auth` actually gates the view tier. False when the operator
    /// runs their own sign-in (e.g. Google auth) in front of the dashboard:
    /// the browser-facing pages open up while the credential keeps guarding
    /// the CRUD tier and minting tokens. Meaningless when `auth` is `None`.
    gate_view: bool,
    /// When true, the gate also covers the deployment CRUD routes (reflected in
    /// `router`), so mutations and spec reads require the same credentials.
    gate_admin: bool,
    /// Process start (LB clock), so the dashboard can show how long the numbers
    /// have been accumulating.
    started_at: u64,
    /// Issued certificates, for `GET /certs`.
    certs: Arc<CertStore>,
    /// Where the theme cookie is written and under what name — from
    /// `APP_LB_UI_COOKIE_*`, else the fleet-wide `HEYO_UI_*`.
    ///
    /// Set it to the same realm as an `auth.cookie_domain` in the deployment
    /// specs and one choice of light or dark covers every app in the fleet,
    /// exactly as one sign-in does.
    ui_cookies: Arc<crate::heyo_ui::CookieConfig>,
    /// Stored secrets. Values enter through this API and never leave it.
    secrets: Arc<SecretStore>,
    /// This LB's public addresses, for `GET /ingress`.
    ingress: Arc<Ingress>,
    /// CI workflow objects. app-lb stores and serves them; the `ci`
    /// orchestrator polls them and does the building.
    workflows: Arc<crate::workflows::WorkflowStore>,
    /// Namespaces somebody declared on purpose. The ones deployments merely
    /// mention are not in here — `GET /namespaces` reports the union, and
    /// `declared` on each row is what tells them apart.
    namespaces: Arc<crate::namespaces::NamespaceStore>,
    /// Reusable, namespace-scoped auth providers. A deployment inherits one with
    /// `auth.provider_ref`; the proxy resolves it live. Managed through this API,
    /// walled by namespace exactly as `secrets` is.
    auth_providers: Arc<crate::auth_providers::AuthProviderStore>,
    /// App-tokens. Verified on every gated request, so reads are lock-free.
    tokens: Arc<crate::tokens::TokenStore>,
    /// Resolves bearers the Heyo auth service issued. `None` when
    /// `APP_LB_AUTH_URL` is unset, in which case a foreign bearer is simply
    /// an unknown credential.
    federated: Option<Arc<crate::federated::FederatedAuth>>,
    /// Runs image builds and host updates, and remembers what they did.
    jobs: Arc<Jobs>,
    /// Nudges the ACME manager to issue for a newly-registered hostname instead
    /// of waiting out its sweep interval. `None` when ACME is disabled.
    acme: Option<Arc<Notify>>,
    /// Counters for the app-obs log shipper. `None` when log shipping is off.
    obs: Option<Arc<crate::obs::Stats>>,
    /// Queues rejected credentials for analysis. `None` when `APP_LB_SIEM=0`.
    security: Option<crate::siem::SecuritySink>,
    /// Findings, for `GET /security`. `None` when `APP_LB_SIEM=0`.
    alerts: Option<Arc<crate::siem::AlertRing>>,
    /// Counters for the detection engine, reported beside `obs` on `/metrics`.
    siem: Option<Arc<crate::siem::SiemStats>>,
    /// The block rules the data plane enforces. Always present, unlike the SIEM:
    /// a rule an operator created must keep working whether or not detection is
    /// switched on.
    guard: Arc<crate::guard::Guard>,
    /// The SIEM console, with the display name already substituted.
    siem_html: Arc<str>,
    /// Per-sandbox disk inventory and reclamation. `None` when the daemon's data
    /// directory could not be resolved, which is the only way it is off.
    disks: Option<Arc<crate::disks::DiskStore>>,
    /// The disk console, with the display name already substituted.
    disks_html: Arc<str>,
    /// The built-in plugins and their records. Always present: the set is
    /// compiled in, and an empty set is a page that says so.
    plugins: Arc<crate::plugins::PluginHost>,
    /// The plugin console, with the display name already substituted.
    plugins_html: Arc<str>,
    /// The network topology console, with the display name already substituted.
    network_html: Arc<str>,
    /// How to turn a deployment's hostname into a link, given where the data
    /// plane actually listens.
    public_url: PublicUrl,
    /// The per-namespace event feed, read by `GET /feeds/:namespace` and
    /// written by the deployment lifecycle handlers.
    feed: Arc<crate::feed::Feed>,
    /// Base domain a hostless deployment's `<id>.<base>` route is built under,
    /// already resolved from config (explicit, else the first wildcard). `None`
    /// disables host synthesis. See [`assume_host`].
    deploy_base_domain: Option<Arc<str>>,
    /// `APP_LB_HOME_URL`: the Heyo front end a namespace user opens this
    /// dashboard from, linked when their session is refused or runs out. They
    /// cannot sign in here directly — see [`browser_login::handoff`].
    home_url: Option<Arc<str>>,
    /// What the dashboard's "Get started" card shows a namespace user, and the
    /// cap on the tokens such a user may mint. See `onboarding.rs`.
    onboarding: Arc<crate::onboarding::Onboarding>,
}

/// `APP_LB_HOME_URL`, when it is an absolute http(s) URL.
fn home_url_from_env() -> Option<Arc<str>> {
    let raw = std::env::var("APP_LB_HOME_URL").ok()?;
    let raw = raw.trim();
    if raw.is_empty() { return None; }
    match reqwest::Url::parse(raw) {
        // The parsed form, not the raw one: serialising percent-encodes
        // anything that could break out of the attribute or script string the
        // templates put it in.
        Ok(u) if matches!(u.scheme(), "https" | "http") => Some(Arc::from(u.as_str())),
        _ => {
            tracing::warn!(value = %raw, "ignoring APP_LB_HOME_URL: not an absolute http(s) URL");
            None
        }
    }
}

impl AdminState {
    /// Ask for an immediate ACME sweep. Issuance is asynchronous — the request
    /// that triggered this returns without waiting for a certificate.
    fn nudge_acme(&self) {
        if let Some(acme) = &self.acme {
            acme.notify_one();
        }
    }
}

pub struct AdminApi {
    addr: String,
    state: AdminState,
}

impl AdminApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: String,
        registry: Arc<Registry>,
        autoscaler: Arc<Autoscaler>,
        metrics: Arc<Metrics>,
        name: String,
        dashboard_user: Option<String>,
        dashboard_password: Option<String>,
        gate_view: bool,
        gate_admin: bool,
        federated: Option<Arc<crate::federated::FederatedAuth>>,
        certs: Arc<CertStore>,
        acme: Option<Arc<Notify>>,
        secrets: Arc<SecretStore>,
        workflows: Arc<crate::workflows::WorkflowStore>,
        namespaces: Arc<crate::namespaces::NamespaceStore>,
        auth_providers: Arc<crate::auth_providers::AuthProviderStore>,
        tokens: Arc<crate::tokens::TokenStore>,
        jobs: Arc<Jobs>,
        obs: Option<Arc<crate::obs::Stats>>,
        siem: Option<&crate::siem::Siem>,
        guard: Arc<crate::guard::Guard>,
        disks: Option<Arc<crate::disks::DiskStore>>,
        public_url: PublicUrl,
        feed: Arc<crate::feed::Feed>,
        public_ips: &[std::net::IpAddr],
        deploy_base_domain: Option<String>,
        plugins: Arc<crate::plugins::PluginHost>,
    ) -> Self {
        let ingress = Arc::new(Ingress::from_ips(public_ips));
        // Render the display name into the page once; the placeholder appears in
        // both the <title> and the <h1>.
        let dashboard_html: Arc<str> =
            Arc::from(DASHBOARD_HTML.replace("{{APP_NAME}}", &html_escape(&name)));
        let directory_html: Arc<str> =
            Arc::from(DIRECTORY_HTML.replace("{{APP_NAME}}", &html_escape(&name)));
        let siem_html: Arc<str> = Arc::from(SIEM_HTML.replace("{{APP_NAME}}", &html_escape(&name)));
        let disks_html: Arc<str> =
            Arc::from(DISKS_HTML.replace("{{APP_NAME}}", &html_escape(&name)));
        let plugins_html: Arc<str> =
            Arc::from(PLUGINS_HTML.replace("{{APP_NAME}}", &html_escape(&name)));
        let network_html: Arc<str> =
            Arc::from(NETWORK_HTML.replace("{{APP_NAME}}", &html_escape(&name)));

        // The gate turns on as soon as a password is set; the username is
        // optional and defaults to "admin", so one env var is enough to secure
        // it and there is no "half-configured, silently open" state.
        let auth = dashboard_password.map(|password| {
            let user = dashboard_user.unwrap_or_else(|| "admin".to_string());
            tracing::info!(
                user = %user,
                dashboard = gate_view,
                admin_api = gate_admin,
                "dashboard credentials configured"
            );
            Arc::new(DashboardAuth::new(&user, &password))
        });
        if auth.is_none() {
            tracing::info!("dashboard auth disabled (set APP_LB_DASHBOARD_PASSWORD to enable)");
        }
        // main() rejects gate_admin without a password, so this can't be a
        // silently-open state; assert the invariant in case that check moves.
        debug_assert!(!gate_admin || auth.is_some(), "admin gate needs credentials");

        Self {
            addr,
            state: AdminState {
                views: None,
                token_sync: Default::default(),
                rollouts: Arc::new(crate::rollout::Rollouts::new(registry.clone(), autoscaler.clone(), jobs.clone())),
                registry,
                autoscaler,
                metrics,
                dashboard_html,
                directory_html,
                auth,
                gate_view,
                gate_admin,
                federated,
                started_at: now_secs(),
                certs,
                acme,
                secrets,
                ingress,
                workflows,
                namespaces,
                auth_providers,
                tokens,
                jobs,
                obs,
                security: siem.map(|s| s.sink.clone()),
                alerts: siem.map(|s| s.ring.clone()),
                siem: siem.map(|s| s.stats.clone()),
                guard,
                siem_html,
                ui_cookies: Arc::new(crate::heyo_ui::CookieConfig::from_env("APP_LB")),
                disks,
                disks_html,
                plugins,
                plugins_html,
                network_html,
                public_url,
                feed,
                deploy_base_domain: deploy_base_domain
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .map(Arc::from),
                home_url: home_url_from_env(),
                onboarding: Arc::new(crate::onboarding::Onboarding::from_env()),
            },
        }
    }

    pub fn with_views(mut self, views: Arc<crate::fleet::ViewStore>) -> Self {
        self.state.views = Some(views);
        self
    }
}

/// How a request was identified, and what that permits.
///
/// Placed in the request's extensions by the gate, so a handler that needs to
/// know who is asking can say so in its signature. Most do not: the gate itself
/// enforces both the tier and the deployment scope (see [`authorize`]), which
/// keeps the policy in one auditable place rather than in fifteen handlers where
/// exactly one would eventually be forgotten.
#[derive(Clone, Debug)]
pub(crate) enum Caller {
    /// No gate is configured. This build is not checking credentials at all.
    Ungated,
    /// The configured Basic credential. Unscoped by definition — it is the
    /// credential that *mints* tokens, so it necessarily outranks every token it
    /// could produce.
    Operator,
    /// An app-token, carrying its own scope.
    Token(Arc<crate::tokens::AppToken>),
    /// A bearer the Heyo auth service vouched for, carrying the namespaces it
    /// may reach and a tier per namespace. Confined unless the grant says
    /// `fleet:admin`. See `federated.rs`.
    Federated(Arc<crate::federated::Grant>),
}

impl Caller {
    /// Tier check with no particular target. A confined grant passes when
    /// *any* of its namespaces reaches `want`; the per-namespace answer is
    /// [`satisfies_in`](Self::satisfies_in), used once the target is known.
    fn satisfies(&self, want: crate::tokens::AdminScope) -> bool {
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) => t.admin.satisfies(want),
            Self::Federated(g) => g.fleet || g.namespaces.values().any(|s| s.satisfies(want)),
        }
    }

    /// Tier check against the namespace the route acts on, when the gate
    /// knows it. A token's tier is uniform across its reach, so only a
    /// federated grant — which may be admin in one namespace and view in
    /// another — answers differently here.
    fn satisfies_in(&self, want: crate::tokens::AdminScope, ns: Option<&str>) -> bool {
        match (self, ns) {
            (Self::Federated(g), Some(ns)) if !g.fleet => {
                g.namespaces.get(ns).is_some_and(|s| s.satisfies(want))
            }
            _ => self.satisfies(want),
        }
    }

    /// Whether this caller may act on a deployment, given the namespace the
    /// registry says it lives in — `None` when the deployment does not exist.
    fn may_touch(&self, deployment: &str, namespace: Option<&str>) -> bool {
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) => match (&t.namespace, namespace) {
                (None, _) => t.allows(deployment),
                (Some(_), Some(ns)) => t.admits(deployment, ns),
                // No such deployment, so no namespace to check against. A
                // namespace token cannot be shown to own it, so it does not —
                // the 403 costs nothing (the handler would 404) and never
                // confirms or denies that the id exists.
                (Some(_), None) => false,
            },
            Self::Federated(g) => {
                g.fleet || namespace.is_some_and(|ns| g.namespaces.contains_key(ns))
            }
        }
    }

    /// Whether this caller is behind a namespace wall — one namespace for a
    /// token, any number for a federated grant. The routes that are about the
    /// whole fleet are closed to a confined caller; `/deployments` narrows
    /// itself instead.
    fn confined(&self) -> bool {
        match self {
            Self::Ungated | Self::Operator => false,
            Self::Token(t) => t.namespace.is_some(),
            Self::Federated(g) => !g.fleet,
        }
    }

    /// Whether this caller may read a namespace-wide surface — the event feed.
    /// An unconfined token needs fleet scope: "which namespaces exist and what
    /// happens in them" is fleet information.
    fn reaches_namespace(&self, ns: &str) -> bool {
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) => match &t.namespace {
                Some(own) => own == ns,
                None => t.covers_fleet(),
            },
            Self::Federated(g) => g.fleet || g.namespaces.contains_key(ns),
        }
    }

    /// Whether this caller may *see* a deployment on the views that narrow
    /// themselves (the directory, `/metrics`, `/security`) rather than refuse.
    fn may_view(&self, deployment: &str, namespace: &str) -> bool {
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) => t.admits(deployment, namespace),
            Self::Federated(_) => self.reaches_namespace(namespace),
        }
    }

    /// Whether this caller may use a route that is not about any one deployment
    /// — creating one, listing them all, reading the secret store.
    fn covers_fleet(&self) -> bool {
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) => t.covers_fleet(),
            Self::Federated(g) => g.fleet,
        }
    }

    /// The deployments this caller may see, or `None` for all of them. Used to
    /// narrow `/metrics` rather than to refuse it: a token scoped to one sandbox
    /// should be able to watch that sandbox.
    fn visible(&self) -> Option<&[String]> {
        match self {
            Self::Ungated | Self::Operator => None,
            Self::Token(t) if t.covers_fleet() => None,
            Self::Token(t) => Some(&t.deployments),
            // A grant names namespaces, never ids; `visible_ids` resolves it
            // against the registry the way a namespace token is resolved.
            Self::Federated(_) => None,
        }
    }

    /// Whether this caller administers *all* of `ns` — the bar for handling
    /// that namespace's tokens. A namespace token narrowed to a few
    /// deployments does not clear it: anything it minted would reach the rest
    /// of the room, and a credential must never mint one wider than itself.
    fn administers_namespace(&self, ns: &str) -> bool {
        use crate::tokens::AdminScope;
        match self {
            Self::Ungated | Self::Operator => true,
            Self::Token(t) if t.covers_fleet() => t.admin == AdminScope::Admin,
            Self::Token(t) => {
                t.namespace.as_deref() == Some(ns)
                    && t.admin == AdminScope::Admin
                    && (t.deployments.is_empty() || t.deployments.iter().any(|d| d == "*"))
            }
            Self::Federated(g) => {
                g.fleet || g.namespaces.get(ns).is_some_and(|s| *s == AdminScope::Admin)
            }
        }
    }

    /// Who this caller is, for the record a token it mints keeps. `None` for
    /// the operator, whose tokens have always gone unattributed.
    fn principal(&self) -> Option<String> {
        match self {
            Self::Ungated | Self::Operator => None,
            Self::Token(t) => Some(format!("token:{}", t.id)),
            Self::Federated(g) => Some(format!("user:{}", g.subject.user_id)),
        }
    }

    /// The single namespace this caller is confined to, when it reaches exactly
    /// one — the namespace a deployment spec may omit and have filled in. A
    /// namespace token always has exactly one; a federated grant may name
    /// several, so it qualifies only when it names one. An unconfined or
    /// fleet caller has no single namespace to assume, so it gets `None` and the
    /// spec keeps whatever it said (`default` when it said nothing).
    fn sole_namespace(&self) -> Option<&str> {
        match self {
            Self::Ungated | Self::Operator => None,
            Self::Token(t) => t.namespace.as_deref(),
            Self::Federated(g) if !g.fleet && g.namespaces.len() == 1 => {
                g.namespaces.keys().next().map(String::as_str)
            }
            Self::Federated(_) => None,
        }
    }
}

/// The deployment ids `caller` may see, or `None` for all of them.
///
/// [`Caller::visible`] resolved against the registry: a namespace wall names no
/// ids of its own, so the ids behind it have to be looked up at the moment of
/// asking. Every self-narrowing view goes through here so a namespace token and
/// a deployment-list token narrow the same way.
fn visible_ids(state: &AdminState, caller: Option<&Caller>) -> Option<Vec<String>> {
    let caller = caller?;
    if caller.confined() {
        return Some(
            state
                .registry
                .deployments()
                .values()
                .filter(|d| caller.may_view(&d.spec.id, &d.spec.namespace))
                .map(|d| d.spec.id.clone())
                .collect(),
        );
    }
    caller.visible().map(<[String]>::to_vec)
}

/// Routes that are not about a single deployment but that a deployment-scoped
/// token may still reach, because the handler narrows the answer to that token's
/// scope instead of refusing it.
fn narrows_itself(matched: &str) -> bool {
    // `/siem` is here for the same reason `/dashboard` is: it is a static page
    // that narrows itself from `/security`, so a deployment-scoped token should
    // get the console rather than a 403. `/security/rules` is deliberately
    // absent — a scoped token has no business arming a fleet-wide block.
    // `/ingress` narrows nothing, but it holds nothing to narrow: the LB's
    // public addresses are what every hostname it routes already resolves to.
    // `/namespaces` narrows through `may_view`, exactly as `/metrics` does — it
    // is the deployment directory regrouped, so refusing a scoped token here
    // while handing it the directory would be a wall with a door beside it.
    // `/whoami` is the extreme case of narrowing: it answers only about the
    // credential presented, so there is nothing there for a scoped token to
    // reach past. Refusing it as "fleet-wide" would deny a caller the one fact
    // it already holds, which is how a token's own scope became undiscoverable
    // without a *second*, wider credential to list tokens with.
    matches!(
        matched,
        "/" | "/metrics"
            | "/dashboard"
            | "/security"
            | "/siem"
            | "/ingress"
            | "/network"
            | "/namespaces"
            | "/auth-providers"
            | "/whoami"
            | "/onboarding"
    )
}

/// The secret store's routes, which are walled by namespace in their handlers.
fn is_secret_route(matched: &str) -> bool {
    matches!(matched, "/secrets" | "/secrets/:id")
}

/// The auth-provider routes, walled by namespace in their handlers for the same
/// reason the secret ones are: for `POST /auth-providers` the namespace is in
/// the body, and for the item routes it is a path parameter the gate does not
/// read, so the handler checks reach rather than the gate. `GET /auth-providers`
/// is handled by `narrows_itself` instead, like `/secrets` on `GET`.
fn is_auth_provider_route(matched: &str) -> bool {
    matches!(matched, "/auth-providers" | "/auth-providers/:namespace/:name")
}

/// The app-token routes, walled by namespace in their handlers: a confined
/// caller may mint, list, re-scope and revoke only tokens confined to a
/// namespace it administers. See [`confine_new_token`].
fn is_token_route(matched: &str) -> bool {
    matches!(matched, "/tokens" | "/tokens/:id")
}

/// Fleet reads a namespace-confined caller may reach with `?namespace=`. The
/// handler checks the namespace against the caller's reach and restricts the
/// fan-out to gateways that take the caller's own identity. `/fleet`,
/// `/fleet/network` and `/services` stay fleet-wide only.
fn is_fleet_namespace_route(matched: &str) -> bool {
    matches!(matched, "/fleet/deployments" | "/fleet/gateways/:id/metrics")
}

/// The deployment a matched route acts on, if it acts on one.
///
/// Read off the *matched* path rather than the raw URI so this cannot be fooled
/// by a path that merely looks like a deployment route, and the id is then taken
/// positionally from the real path — every such route is `/deployments/:id/…`,
/// so the id is always the second segment.
fn deployment_of<'a>(matched: &str, path: &'a str) -> Option<&'a str> {
    if matched != "/deployments/:id" && !matched.starts_with("/deployments/:id/") {
        return None;
    }
    path.split('/').nth(2).filter(|s| !s.is_empty())
}

/// The one refusal for "this credential has no business with that deployment".
///
/// Shared between the gate and the handlers that decide the same thing later
/// with more context, so every route answers a caller identically whether the id
/// exists, belongs to another namespace, or was never registered at all. Naming
/// only the id the caller supplied is the point: anything drawn from the
/// registry would describe a resource they cannot see.
fn out_of_scope(id: &str) -> String {
    format!("this token is not scoped to deployment \"{id}\"")
}

/// `Bearer <token>`, if that is what was presented.
fn bearer(header: Option<&str>) -> Option<&str> {
    let raw = header?.strip_prefix("Bearer ")?.trim();
    (!raw.is_empty()).then_some(raw)
}

/// `?app_token=…`, accepted on the shell route and nowhere else.
///
/// A credential in a URL is worse than one in a header — it lands in access
/// logs, proxy logs and browser history — so this exists for exactly one reason:
/// a browser's `WebSocket` constructor cannot set headers, and a query parameter
/// is the only thing it *can* carry. Every other route can use a header, so
/// every other route must.
fn ws_query_token(matched: &str, query: Option<&str>) -> Option<String> {
    if matched != "/deployments/:id/shell" {
        return None;
    }
    form_urlencoded::parse(query?.as_bytes())
        .find(|(k, _)| k == "app_token")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        // Two schemes, one header line each. Both are advertised, but they must
        // be separate `WWW-Authenticate` lines rather than one comma-joined
        // value: the combined form (`Basic …, Bearer`) is legal per RFC 7235 but
        // ambiguous to parse, and Chrome chokes on the trailing bare `Bearer`
        // token and suppresses its native Basic login prompt entirely — the user
        // lands on the raw 401 body instead of a sign-in dialog. Firefox parses
        // the combined line leniently, which is why it only broke on Chrome.
        //
        // `AppendHeaders` is load-bearing: a plain array of tuples *inserts*
        // into the header map, so the second `WWW-Authenticate` would replace
        // the first and the response would advertise only `Bearer` — no Basic
        // challenge, no browser prompt, same raw-401 symptom as the bug above.
        AppendHeaders([
            (
                header::WWW_AUTHENTICATE,
                "Basic realm=\"app-lb dashboard\", charset=\"UTF-8\"",
            ),
            (header::WWW_AUTHENTICATE, "Bearer"),
        ]),
        "authentication required\n",
    )
        .into_response()
}

/// A 403 rather than a 401: the credential was good, the scope was not, and
/// re-presenting it will not help. The message names the missing scope, because
/// the alternative is somebody rotating a working token trying to fix a
/// permission problem.
fn forbidden(detail: impl Into<String>) -> Response {
    err(StatusCode::FORBIDDEN, detail).into_response()
}

/// What the gate decided about one request.
#[derive(Debug)]
enum Verdict {
    Allow(Caller),
    /// No usable credential. Answered with a challenge.
    Unauthorized,
    /// The credential was good and the scope was not.
    Forbidden(String),
}

/// Everything the gate needs to know about a request, as plain data.
///
/// A struct rather than a borrowed `Request` so the decision is a pure function
/// — the same shape `auth.rs` uses for the data-plane gate, and for the same
/// reason: authorization logic that can only be exercised through a live socket
/// is authorization logic that does not get exercised.
struct Presented<'a> {
    /// The `Authorization` header, verbatim.
    header: Option<&'a str>,
    /// The route pattern axum matched, e.g. `/deployments/:id/exec`.
    matched: Option<&'a str>,
    /// The concrete request path.
    path: &'a str,
    query: Option<&'a str>,
    /// The namespace of the deployment the path names, when it names one that
    /// exists. Resolved by [`authorize`] from the registry, so the decision
    /// itself stays a pure function.
    target_namespace: Option<&'a str>,
    /// What the auth service said about a foreign bearer, when federation is
    /// configured and the bearer is not a local token. Resolved by
    /// [`authorize`] for the same reason `target_namespace` is: the lookup
    /// is async and remote, and the decision should be neither.
    federated: Option<Arc<crate::federated::Grant>>,
}

/// Decide whether a request gets through, and as whom.
///
/// Three credentials are accepted, in this order of precedence:
///
/// - the configured Basic username/password, which is unscoped,
/// - an app-token as `Authorization: Bearer applb_…` (or `?app_token=` on the
///   shell route only), which carries its own scope, and
/// - a bearer the Heyo auth service has already resolved to a grant
///   (`req.federated`), which is confined to the namespaces it names.
///
/// `auth: None` means no gate is configured and everything is permitted.
fn decide_access(
    auth: Option<&DashboardAuth>,
    tokens: &crate::tokens::TokenStore,
    req: &Presented<'_>,
    want: crate::tokens::AdminScope,
    now: u64,
) -> Verdict {
    let Some(auth) = auth else {
        return Verdict::Allow(Caller::Ungated);
    };

    let caller = if auth.accepts(req.header) {
        Some(Caller::Operator)
    } else {
        bearer(req.header)
            .map(str::to_owned)
            .or_else(|| ws_query_token(req.matched.unwrap_or_default(), req.query))
            .and_then(|raw| tokens.verify(&raw, now))
            .map(Caller::Token)
            .or_else(|| req.federated.clone().map(Caller::Federated))
    };

    let Some(caller) = caller else {
        return Verdict::Unauthorized;
    };

    if !caller.satisfies_in(want, req.target_namespace) {
        return Verdict::Forbidden(
            match want {
                crate::tokens::AdminScope::Admin => {
                    "this token's admin scope is not `admin`, which this route requires"
                }
                _ => "this token has no admin scope, so it cannot read the admin API",
            }
            .into(),
        );
    }

    // Deployment scope. Every route is one of four things: about a named
    // deployment, about a namespace, able to narrow itself, or fleet-wide.
    if let Some(matched) = req.matched {
        match deployment_of(matched, req.path) {
            Some(id) if !caller.may_touch(id, req.target_namespace) => {
                return Verdict::Forbidden(out_of_scope(id));
            }
            None if namespace_plugin_target(matched, req.path).is_some() => {
                // Walled by the namespace in the path, like the feed below: a
                // namespace token reaches its own namespace's plugins and no
                // other, and a deployment-list token reaches none.
                let ns = namespace_plugin_target(matched, req.path).unwrap_or_default();
                if !caller.reaches_namespace(ns) {
                    return Verdict::Forbidden(format!(
                        "this token cannot reach the \"{ns}\" namespace's plugins"
                    ));
                }
            }
            None if matched == "/feeds/:namespace" => {
                // Namespace-scoped rather than fleet-scoped: the handler knows
                // which namespace from the path, and the check lives here so a
                // feed can never be read past a token's namespace wall.
                let ns = req.path.split('/').nth(2).unwrap_or_default();
                let ns = ns.strip_suffix(".xml").unwrap_or(ns);
                if !caller.reaches_namespace(ns) {
                    return Verdict::Forbidden(format!(
                        "this token cannot read the \"{ns}\" namespace feed"
                    ));
                }
            }
            // A namespace token may list and create deployments; the handlers
            // narrow the answer to its namespace (list) or refuse a spec that
            // names another one (create).
            None if matched == "/deployments" && caller.confined() => {}
            // Secrets live behind the same wall as deployments. The handlers
            // check the namespace each request names against the caller's
            // reach — the gate cannot, because for `/secrets` the namespace is
            // in the body or the query, not the path.
            None if is_secret_route(matched) && caller.confined() => {}
            // Auth providers, walled the same way: the `:namespace` is a path
            // parameter the gate does not read (and the body names it on
            // `POST`), so the handler measures the caller's reach against it.
            None if is_auth_provider_route(matched) && caller.confined() => {}
            // The workload rollup and gateway drill-down narrow to a namespace
            // the handler measures against the caller's reach, and then only
            // through gateways that take the caller's own identity.
            None if is_fleet_namespace_route(matched) && caller.confined() => {}
            // A namespace administrator mints and revokes that namespace's
            // tokens; the handlers keep every token they touch inside it.
            None if is_token_route(matched) && caller.confined() => {}
            // A job a namespace caller started (a pull, a build) is one it must
            // be able to watch. The handler answers 404 for a job whose
            // deployment the caller cannot touch, exactly as for one that
            // never existed; the job list stays fleet-wide.
            None if matched == "/jobs/:job_id" && caller.confined() => {}
            None if !narrows_itself(matched) && !caller.covers_fleet() => {
                return Verdict::Forbidden(
                    "this token is scoped to specific deployments, so it cannot use a \
                     fleet-wide route — mint one scoped to \"*\" if that is what you want"
                        .into(),
                );
            }
            _ => {}
        }
    }

    Verdict::Allow(caller)
}

/// Gate the protected routes when a credential is configured.
///
/// A `401` carries the `WWW-Authenticate` challenge so a browser shows its
/// native login prompt and caches the credentials for same-origin requests. A
/// bad *scope* is a `403` and says so.
async fn authorize(
    state: AdminState,
    mut req: Request,
    next: Next,
    want: crate::tokens::AdminScope,
) -> Response {
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let browser_auth = if state.gate_admin && state.federated.is_some() && state.auth.is_some() {
        match browser_login::session(req.headers(), req.method()) {
            Ok(value) => value,
            Err(()) => return forbidden("invalid session or cross-origin session request"),
        }
    } else { None };
    let browser_navigation = req.method() == axum::http::Method::GET
        && !req.headers().contains_key(header::AUTHORIZATION)
        && req.headers().get(header::ACCEPT).and_then(|h| h.to_str().ok()).is_some_and(|h| h.contains("text/html"));
    // A page's own `fetch` (Fetch Metadata says `dest: empty`). With browser
    // sessions on, its 401 must not advertise Basic: Chrome would answer with
    // a native password prompt over the page, where the page itself should be
    // saying the session ran out.
    let script_fetch = req.headers().get("sec-fetch-dest").and_then(|h| h.to_str().ok()) == Some("empty");
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned).or(browser_auth);
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_owned);
    // Requires `into_make_service_with_connect_info` on the listener; without it
    // this is always `None` and every alert raised here loses its source.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());

    // Resolved here rather than in `decide_access` so the decision stays pure.
    // Only consulted for a namespace-confined token, but cheap enough (one
    // lock-free registry read) to do unconditionally.
    let target_namespace = matched
        .as_deref()
        .and_then(|m| deployment_of(m, &path))
        .and_then(|id| state.registry.get(id))
        .map(|d| d.spec.namespace.clone())
        // A namespace's plugin routes act on the namespace in their path, so
        // a federated grant's tier is measured there — view in one namespace
        // must not post alerts in it because it is admin in another.
        .or_else(|| {
            matched
                .as_deref()
                .and_then(|m| namespace_plugin_target(m, &path))
                .map(str::to_owned)
        });

    // A foreign bearer is asked about only when federation is on, the gate is
    // on, and the local store does not already know the token — so a local
    // token never costs a round trip and a local token is always preferred.
    // Header only: the `?app_token=` query is for app-lb's own tokens.
    let now = now_secs();
    let federated = match (state.federated.as_ref(), state.auth.as_ref(), bearer(header.as_deref())) {
        (Some(f), Some(_), Some(raw))
            if !raw.starts_with(crate::federated::LOCAL_TOKEN_PREFIX)
                && state.tokens.verify(raw, now).is_none() =>
        {
            f.resolve(raw).await
        }
        _ => None,
    };

    let verdict = decide_access(
        state.auth.as_deref(),
        &state.tokens,
        &Presented {
            header: header.as_deref(),
            matched: matched.as_deref(),
            path: &path,
            query: query.as_deref(),
            target_namespace: target_namespace.as_deref(),
            federated,
        },
        want,
        now,
    );

    // A rejected credential was invisible before this: the gate answered 401 or
    // 403 and logged nothing, so a password spray against the dashboard left no
    // trace anywhere. The `tracing::warn!` earns its place independently of the
    // SIEM — it works with `APP_LB_SIEM=0`, and `obs::EventLayer` already ships
    // it to app-obs.
    let scheme = crate::siem::AuthScheme::of(header.as_deref());
    match verdict {
        Verdict::Allow(caller) => {
            // A federated caller is somebody else's user acting here; the
            // access log should say who, the way it says which token.
            if let Caller::Federated(g) = &caller {
                tracing::debug!(
                    path = %path,
                    user = %g.subject.user_id,
                    email = ?g.subject.email,
                    account = ?g.subject.account_id,
                    platform_role = ?g.subject.platform_role,
                    fleet = g.fleet,
                    namespaces = g.namespaces.len(),
                    "admin API request admitted for a federated caller",
                );
            }
            req.extensions_mut().insert(caller);
            next.run(req).await
        }
        Verdict::Unauthorized => {
            tracing::warn!(
                path = %path,
                scheme = scheme.as_str(),
                client = ?peer,
                "admin API request rejected: no usable credential",
            );
            observe_auth_failure(&state, peer, &path, AuthAction::AdminRejected, scheme);
            if browser_navigation && state.gate_admin && state.federated.is_some() {
                return axum::response::Redirect::to("/login").into_response();
            }
            if script_fetch && state.gate_admin && state.federated.is_some() {
                return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")], "unauthorized\n")
                    .into_response();
            }
            unauthorized()
        }
        Verdict::Forbidden(detail) => {
            tracing::warn!(
                path = %path,
                scheme = scheme.as_str(),
                client = ?peer,
                detail = %detail,
                "admin API request rejected: credential is out of scope",
            );
            observe_auth_failure(&state, peer, &path, AuthAction::AdminScope, scheme);
            forbidden(detail)
        }
    }
}

/// Queue one rejected credential for analysis, if the SIEM is running.
///
/// Never carries the credential — not the password, not the token, not a prefix
/// of either. Only the *scheme*, which is what separates token guessing from an
/// unauthenticated probe.
fn observe_auth_failure(
    state: &AdminState,
    peer: Option<std::net::IpAddr>,
    path: &str,
    action: AuthAction,
    scheme: crate::siem::AuthScheme,
) {
    if let Some(siem) = &state.security {
        siem.observe_auth(crate::siem::AuthObs {
            ts: crate::obs::now_millis(),
            client: peer,
            deployment: None,
            path: Box::from(path),
            action,
            scheme,
            subject: None,
        });
    }
}

async fn require_view_auth(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    // `gate_view` off means the view tier behaves exactly as if no password
    // were set: the layer still runs (handlers keep their `Caller` extension,
    // now `Ungated`), the challenge never fires. Done by dropping `auth` here
    // rather than by skipping the layer so the two paths cannot drift.
    let state = if state.gate_view {
        state
    } else {
        AdminState { auth: None, ..state }
    };
    authorize(state, req, next, crate::tokens::AdminScope::View).await
}

async fn require_crud_auth(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    authorize(state, req, next, crate::tokens::AdminScope::Admin).await
}

/// The lowest bar there is: a credential this server recognises, and no tier.
///
/// Only `/whoami` uses it, and the tier is `None` rather than `View` on
/// purpose. A token minted with `admin: none` — the shape an application is
/// handed to get past its own deployment's gate — is precisely the one whose
/// holder cannot work out why the admin API refuses them, so it is the one that
/// most needs to be able to ask. Requiring `view` here would leave exactly that
/// caller unable to discover the thing that would explain their 403s.
async fn require_any_credential(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Response {
    authorize(state, req, next, crate::tokens::AdminScope::None).await
}

#[derive(Serialize)]
struct VmStatus {
    sandbox_id: String,
    addr: String,
    in_flight: usize,
    healthy: bool,
    draining: bool,
}

#[derive(Serialize)]
struct DeploymentStatus {
    rollout_revision: String,
    spec: DeploymentSpec,
    /// `"vm"` (managed pool) or `"static"` (fixed proxy_pass upstreams).
    kind: &'static str,
    desired_replicas: u32,
    ready: usize,
    pending: usize,
    total_in_flight: usize,
    vms: Vec<VmStatus>,
    /// The deployment's workspace, when the spec declares one: which snapshot
    /// the pool runs from, whether the store has it, and what — if anything —
    /// is holding the pool at zero. See [`crate::workspace`].
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<crate::workspace::WorkspaceStatus>,
    /// For a site: whether its root on this host can serve anything, and if
    /// not, why. Reported on register and update too, so a spec pointing at a
    /// path that only exists on the caller's machine is noticed at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<crate::site::RootStatus>,
}

fn is_default_namespace_str(ns: &String) -> bool {
    ns == crate::config::DEFAULT_NAMESPACE
}

/// The backend kind of a deployment, as a stable string for the API/dashboard.
fn deployment_kind(d: &crate::deployment::Deployment) -> &'static str {
    match d.spec.backend() {
        crate::config::Backend::Site => "site",
        crate::config::Backend::Upstreams => "static",
        crate::config::Backend::Vm => "vm",
    }
}

/// Which `POST` a deployment's code is redeployed with, if any.
///
/// At most one is ever configured, because validation refuses the combinations:
/// a `proxy_pass` upstream has no image to build, a microVM has no host
/// directory to run commands in, and a site takes one of `update`, `artifact`
/// or `build`. So this is one answer rather than three flags.
fn job_kind_of(spec: &DeploymentSpec) -> Option<&'static str> {
    if spec.build.is_some() {
        Some("build")
    } else if spec.artifact.is_some() {
        Some("pull")
    } else if spec.update.is_some() {
        Some("update")
    } else {
        None
    }
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn err(code: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        code,
        Json(ApiError {
            error: message.into(),
        }),
    )
}

/// Start a mount pull if this deployment could not create a VM without one.
///
/// Registration and edits both call it, because a mount whose tree is not on
/// this host is not a degraded pool — it is *no* pool: the autoscaler refuses
/// the create rather than booting a guest without its data. Leaving that to an
/// operator to notice would make "register a deployment with mounts" a two-call
/// sequence whose second call is only discoverable from an error line.
///
/// Best-effort, and quiet when it does nothing. `AlreadyRunning` is the ordinary
/// outcome of editing a deployment twice while its first pull is still going,
/// and the pull already in flight is fetching the same trees; a real failure to
/// start is logged and shows up as an empty pool with the autoscaler saying
/// exactly why.
fn pull_mounts_if_needed(state: &AdminState, spec: &DeploymentSpec) {
    if !state.jobs.mounts_need_pulling(spec) {
        return;
    }
    match state.jobs.start_mount_pull(&spec.id, false) {
        Ok(record) => tracing::info!(
            deployment = %spec.id,
            job = %record.id,
            "mount pull started: this deployment declares mounts with no tree on this host",
        ),
        // One job per deployment at a time. If that job is itself the mount pull
        // this edit would have started, there is nothing to do; if it is a build,
        // nothing retries afterwards — the autoscaler's refusal to create says so
        // and names the endpoint that fixes it.
        Err(crate::jobs::StartError::AlreadyRunning(_)) => tracing::debug!(
            deployment = %spec.id,
            "another job holds this deployment's slot, so its mounts were not pulled",
        ),
        Err(e) => tracing::warn!(
            deployment = %spec.id,
            error = %e,
            "could not start the mount pull this deployment needs; its pool will stay empty \
             until one runs",
        ),
    }
}

fn status_of(state: &AdminState, d: &Arc<crate::deployment::Deployment>) -> DeploymentStatus {
    let backends = d.backends();
    DeploymentStatus {
        rollout_revision: d.state().rollout_revision.clone(),
        workspace: state.autoscaler.workspaces().status(d),
        site: d.spec.site.as_ref().map(crate::site::root_status),
        spec: d.spec.clone(),
        kind: deployment_kind(d),
        desired_replicas: d.desired_replicas(),
        ready: backends.len(),
        pending: d.pending().len(),
        total_in_flight: d.total_in_flight(),
        vms: backends
            .iter()
            .map(|b| VmStatus {
                sandbox_id: b.sandbox_id.clone(),
                addr: b.peer.clone(),
                in_flight: b.in_flight(),
                healthy: b.is_healthy(),
                draining: b.is_draining(),
            })
            .collect(),
    }
}

/// Live pool state for one deployment, as the dashboard shows it. Distinct from
/// the daemon's view: these are the LB's own gauges (in-flight, draining), not
/// anything the daemon reports.
#[derive(Serialize)]
struct PoolStatus {
    desired_replicas: u32,
    /// Total backends in the pool, draining ones included.
    ready: usize,
    /// Backends marked draining (still serving, taking nothing new).
    draining: usize,
    /// Booting VMs not yet routable.
    pending: usize,
    total_in_flight: usize,
    target_concurrency: u32,
    min_replicas: u32,
    max_replicas: u32,
    warm_pool: u32,
    /// Load against capacity: in-flight / (available VMs × target). `None` when
    /// there is no available capacity to divide by (an empty or all-draining
    /// pool), which the dashboard renders as "—" rather than a fake 0%.
    utilization: Option<f64>,
    /// Summed CPU% (percent-of-a-core) and RSS across the pool's VMs, `None`
    /// until the daemon reports usage for at least one of them.
    cpu_percent: Option<f64>,
    memory_bytes: Option<u64>,
    /// How long a booting VM gets before the autoscaler kills it; `0` means it
    /// waits indefinitely. Shown so a pending VM's age can be read against the
    /// deadline it is heading for rather than as a bare number.
    boot_timeout_secs: u64,
    /// How long a request waits on a cold start. The dashboard reads a pending
    /// VM's age against this: past it, the boot has already cost somebody a 503.
    cold_start_timeout_secs: u64,
}

/// A VM that has been created but has not joined the pool.
///
/// Reported because a booting VM is otherwise a *count* only, and a count cannot
/// distinguish "a VM is 3 seconds into a normal boot" from "a VM has been failing
/// its health check for six minutes" — which is the difference between waiting and
/// having a broken guest.
#[derive(Serialize)]
struct PendingVmView {
    sandbox_id: String,
    /// Seconds since the daemon accepted the create call.
    age_secs: u64,
    /// The daemon's last reported status, absent before the first observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<heyo_sdk::SandboxStatus>,
}

#[derive(Serialize)]
struct VmView {
    sandbox_id: String,
    addr: String,
    in_flight: usize,
    healthy: bool,
    draining: bool,
    uptime_secs: u64,
    /// Latest per-VM sample from the daemon, `None` if not yet reported.
    cpu_percent: Option<f64>,
    memory_bytes: Option<u64>,
    /// The daemon-side proxy bind of this VM's port, when the deployment has
    /// `ingress.cloud` and the bind is in place: the subdomain the cloud's
    /// deployment URL fans out to. Absent otherwise, so the payload is
    /// unchanged for a deployment with no cloud URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    subdomain: Option<String>,
}

#[derive(Serialize)]
struct DeploymentView {
    id: String,
    /// The namespace the deployment belongs to. Omitted for `"default"`, so
    /// the payload is unchanged for a fleet that never uses namespaces.
    #[serde(skip_serializing_if = "is_default_namespace_str")]
    namespace: String,
    /// The heyo account this deployment's VMs are metered to, when app-lb
    /// knows it (see `DeploymentSpec::account_id`). Absent on a self-hosted
    /// app-lb, so the payload is unchanged there.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    /// `"vm"` (managed pool) or `"static"` (proxy_pass). The dashboard renders
    /// the two differently — a static deployment hides scaling controls.
    kind: &'static str,
    /// For a static deployment, the configured upstream addresses; empty for a
    /// managed one.
    upstreams: Vec<String>,
    /// Whether any data-plane route points at this deployment. Agent sandboxes
    /// may be intentionally registered without a route and must not count as
    /// unavailable serving capacity in fleet status.
    routed: bool,
    /// Exact hostnames this deployment is routed on — `host` rules only, since a
    /// `host_suffix` names no single certificate subject and a `path_prefix` names
    /// no hostname at all. Reported so the dashboard can say which routed names
    /// have no certificate yet, which is otherwise a join nobody can make from
    /// `/certs` alone.
    hosts: Vec<String>,
    /// The same routes as URLs a browser can be sent to, scheme and non-default
    /// port included. Built here rather than in the page because the dashboard
    /// is served from the *admin* listener and knows nothing about the data
    /// plane's scheme or port — it would guess `http://host` for an app-lb
    /// serving HTTPS on 6189.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    urls: Vec<String>,
    /// For a site, the directory it serves and whether unmatched paths fall back
    /// to the index. Absent for every other kind, so the dashboard can tell the
    /// three apart from the payload alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    site_root: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    site_spa: bool,
    /// The deploy job this deployment accepts — `"build"` for a managed one with a
    /// `build` block, `"update"` for a static one with an `update` block, `None`
    /// when neither is configured and there is nothing to trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    job_kind: Option<&'static str>,
    pool: PoolStatus,
    vms: Vec<VmView>,
    /// Booting VMs, oldest first — the ones holding a cold start open.
    pending_vms: Vec<PendingVmView>,
    metrics: DeploymentMetricsSnapshot,
}

/// A rollup of pool gauges across every deployment, for the top-of-dashboard
/// totals.
#[derive(Serialize)]
struct FleetPool {
    deployments: usize,
    ready: usize,
    draining: usize,
    pending: usize,
    total_in_flight: usize,
}

#[derive(Serialize)]
struct MetricsResponse {
    generated_at: u64,
    uptime_secs: u64,
    /// Whole-host CPU/memory from the daemon.
    host: HostUsageSnapshot,
    fleet: FleetPool,
    /// All deployments' metrics merged. Includes history from deregistered
    /// deployments, so totals don't drop when one is removed.
    global: DeploymentMetricsSnapshot,
    /// Log-shipping counters, absent when it is off. Here because the pipeline
    /// drops rather than blocks by design, and a drop is only visible if
    /// somebody counts it — asking app-obs "are my logs arriving?" cannot
    /// distinguish a quiet deployment from a full queue.
    #[serde(skip_serializing_if = "Option::is_none")]
    obs: Option<crate::obs::ObsSnapshot>,
    /// Detection-engine counters and a live alert tally, absent when
    /// `APP_LB_SIEM=0`. On the *fast* poll rather than only on `/security` so an
    /// alert reaches the dashboard's stat tiles within two seconds, and so a
    /// dropping queue is visible next to `obs.dropped`, which fails the same way.
    #[serde(skip_serializing_if = "Option::is_none")]
    security: Option<SecuritySummary>,
    /// Whether app-lb can reach the VM daemon, and what it said if not.
    ///
    /// Fleet-wide and unconditional, unlike `obs`/`security`, because this one
    /// gates everything: `Autoscaler::reconcile` abandons the tick when the
    /// sandbox listing fails, so an unreachable daemon stops the entire control
    /// plane while every per-deployment number stays exactly where it was.
    daemon: crate::metrics::DaemonSnapshot,
    /// The slice of deployments this response carries. Scoped by the query
    /// parameters on `MetricsQuery` — at fleet scale the full list is megabytes,
    /// and the dashboard polls it every few seconds.
    deployments: Vec<DeploymentView>,
    /// How many deployments matched before `limit`/`offset`, so a client can
    /// page without guessing.
    matched: usize,
    /// How many deployments currently hold their own counters. Normally equal
    /// to the number registered; a number that climbs past it means retirement
    /// is not keeping up, which is the leak this used to have.
    tracked_deployments: usize,
    /// Sandboxes on the daemon's host that no deployment owns — created
    /// through the heyvm CLI, the cloud API or the desktop rather than by
    /// app-lb. They share the host's CPU and memory with every pool above, so
    /// a host that reads loaded against a half-empty pool table is explained
    /// here. Scoped like `deployments` (a namespace caller sees the ones
    /// billed to its own accounts), emptied by `summary=true` like the per-VM
    /// rows, and never paged: a host holds at most a few hundred.
    host_sandboxes: Vec<HostSandboxView>,
}

/// The three numbers the dashboard's alert tile needs, without the alert list.
///
/// Separate from [`SecurityResponse`] so the two-second metrics poll does not
/// carry a few hundred alerts it is not going to render.
#[derive(Serialize)]
struct SecuritySummary {
    /// Alerts currently held in the ring.
    open: usize,
    /// How many of those are high or critical — what the tile colours on.
    urgent: u64,
    /// Observations refused because the queue was full. Non-zero means detection
    /// is sampling rather than complete.
    dropped: u64,
    /// Whether the per-client table is full, which means the same thing for
    /// sources rather than for events.
    clients_at_capacity: bool,
    /// Block rules in force, and how many requests they have refused. On the
    /// summary because "we are blocking traffic" belongs next to "we are seeing
    /// attacks" — an operator who forgot a rule exists should trip over it here.
    rules: usize,
    blocked: u64,
}

/// `GET /security`.
///
/// Behind the same gate as `/metrics`, and deliberately: it enumerates attacker
/// addresses and the exact probes that reached the fleet.
#[derive(Serialize)]
struct SecurityResponse {
    generated_at: u64,
    /// `false` with an empty list when `APP_LB_SIEM=0`, rather than a 404. The
    /// dashboard has to be able to render "off"; a 404 is indistinguishable from
    /// an app-lb too old to have this route.
    enabled: bool,
    window_secs: u64,
    /// Newest first, which is the order the dashboard renders. Each carries its
    /// own `response` — the runbook and the ready-to-post rules — so the console
    /// never has to derive "and now what?" from the rule name in JavaScript.
    alerts: Vec<crate::siem::AlertView>,
    totals: crate::siem::SeverityTotals,
    /// The block rules in force. Served here rather than from a route of their
    /// own so the console renders findings and interventions from one fetch, and
    /// cannot show a stale rule list beside fresh alerts.
    rules: Vec<crate::guard::RuleView>,
    guard: crate::guard::GuardStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<crate::siem::SiemSnapshot>,
}

/// Query parameters for `GET /security`.
#[derive(Debug, Default, Deserialize)]
struct SecurityQuery {
    /// Only alerts at or above this severity.
    severity: Option<String>,
    /// Only this rule, e.g. `auth.brute-force`.
    rule: Option<String>,
    /// Only alerts attributed to this deployment.
    deployment: Option<String>,
    /// Only alerts attributed to a deployment *in* this namespace.
    ///
    /// Resolved against the registry rather than read off the alert, because an
    /// alert records the deployment it was attributed to and nothing else — a
    /// namespace stamped at detection time would be a copy that goes stale the
    /// moment a deployment moves. This is a filter, never a widening: it can
    /// only narrow what the caller's own scope already admits.
    namespace: Option<String>,
    limit: Option<usize>,
}

/// Query parameters for `GET /metrics`.
///
/// The unfiltered response used to be the only response. That is fine for a few
/// dozen services and untenable for thousands of sandboxes, where every poll
/// serialises every VM and every histogram. All fields are optional and the
/// defaults reproduce the old behaviour for small fleets.
#[derive(Debug, Default, Deserialize)]
struct MetricsQuery {
    /// Restrict to one deployment by id. The cheap path for "how is this one
    /// sandbox doing", which is the common question about a fleet.
    deployment: Option<String>,
    /// Restrict to deployments whose id starts with this. Sandbox ids are
    /// generated with a common prefix, so this is how a tenant is scoped.
    prefix: Option<String>,
    /// Restrict to one namespace. The customer-shaped filter: `prefix` is a
    /// convention, this is the wall.
    namespace: Option<String>,
    /// Drop the per-VM detail, keeping pool counts and metrics. The largest
    /// single saving: VM rows dominate the payload for a fleet at rest.
    #[serde(default)]
    summary: bool,
    /// Page size. Absent means no limit, which is what the dashboard sends for
    /// a small fleet.
    limit: Option<usize>,
    #[serde(default)]
    offset: usize,
}

fn pool_status_of(d: &Arc<crate::deployment::Deployment>) -> PoolStatus {
    let backends = d.backends();
    let draining = backends.iter().filter(|b| b.is_draining()).count();
    let available = backends.iter().filter(|b| b.is_available()).count();
    let total_in_flight = d.total_in_flight();
    let target = d.spec.scaling.target_concurrency.max(1) as usize;
    let capacity = available * target;
    let utilization = (capacity > 0).then(|| total_in_flight as f64 / capacity as f64);

    // Aggregate resource usage over the VMs the daemon has reported. `None` if
    // none have a sample yet, so the dashboard can distinguish "no data" from 0.
    let samples: Vec<(f64, u64)> = backends.iter().filter_map(|b| b.usage()).collect();
    let (cpu_percent, memory_bytes) = if samples.is_empty() {
        (None, None)
    } else {
        (
            Some(samples.iter().map(|(c, _)| c).sum()),
            Some(samples.iter().map(|(_, m)| m).sum()),
        )
    };

    PoolStatus {
        desired_replicas: d.desired_replicas(),
        ready: backends.len(),
        draining,
        pending: d.pending().len(),
        total_in_flight,
        target_concurrency: d.spec.scaling.target_concurrency,
        min_replicas: d.spec.scaling.min_replicas,
        max_replicas: d.spec.scaling.max_replicas,
        warm_pool: d.spec.scaling.warm_pool,
        utilization,
        cpu_percent,
        memory_bytes,
        boot_timeout_secs: d.spec.scaling.boot_timeout_secs,
        cold_start_timeout_secs: d.spec.scaling.cold_start_timeout_secs,
    }
}

/// The booting VMs of a deployment, oldest first.
fn pending_vms_of(d: &Arc<crate::deployment::Deployment>) -> Vec<PendingVmView> {
    let mut views: Vec<PendingVmView> = d
        .pending()
        .iter()
        .map(|p| PendingVmView {
            sandbox_id: p.sandbox_id.clone(),
            age_secs: p.age_secs(),
            status: p.status.clone(),
        })
        .collect();
    // Oldest first: the one closest to its boot timeout is the one to look at.
    views.sort_by(|a, b| b.age_secs.cmp(&a.age_secs));
    views
}

/// The dashboard's data source: live pool gauges joined with accumulated
/// metrics, per deployment plus a global rollup.
async fn metrics_snapshot(
    State(state): State<AdminState>,
    Query(q): Query<MetricsQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let deployments = state.registry.deployments();

    // A deployment-scoped token gets a *narrowed* answer rather than a 403: a
    // token minted to drive one sandbox should be able to watch that sandbox.
    // `None` means unscoped, which is the operator credential and the ungated
    // case both.
    let scope = visible_ids(&state, caller.as_ref().map(|c| &c.0));
    let scope = scope.as_deref();
    let in_scope = |id: &str| scope.is_none_or(|s| s.iter().any(|d| d == id));

    // The fleet rollup covers the whole registry, never the filter or the page.
    // It sits under "Host & fleet" alongside the global metrics, and a number
    // there that moved when somebody typed in the table's search box would be
    // describing the query rather than the system.
    //
    // "The whole registry" still means the whole *visible* registry: a scoped
    // token must not learn the size of the fleet from a total it can't itemise.
    let mut fleet = FleetPool {
        deployments: 0,
        ready: 0,
        draining: 0,
        pending: 0,
        total_in_flight: 0,
    };
    for d in deployments.values().filter(|d| in_scope(&d.spec.id)) {
        let pool = pool_status_of(d);
        fleet.deployments += 1;
        fleet.ready += pool.ready;
        fleet.draining += pool.draining;
        fleet.pending += pool.pending;
        fleet.total_in_flight += pool.total_in_flight;
    }

    // Filter and page *before* building views: a view snapshots every VM and
    // every histogram, so the work skipped here is the work that made this
    // endpoint expensive.
    let mut selected: Vec<_> = deployments
        .values()
        .filter(|d| in_scope(&d.spec.id))
        .filter(|d| q.deployment.as_ref().is_none_or(|id| &d.spec.id == id))
        .filter(|d| q.prefix.as_ref().is_none_or(|p| d.spec.id.starts_with(p)))
        .filter(|d| q.namespace.as_ref().is_none_or(|ns| &d.spec.namespace == ns))
        .collect();
    selected.sort_by(|a, b| a.spec.id.cmp(&b.spec.id));

    let matched = selected.len();
    let page = selected
        .into_iter()
        .skip(q.offset)
        .take(q.limit.unwrap_or(usize::MAX));

    let views: Vec<DeploymentView> = page
        .map(|d| {
            let backends = d.backends();
            DeploymentView {
                id: d.spec.id.clone(),
                namespace: d.spec.namespace.clone(),
                account_id: d.spec.account_id.clone(),
                kind: deployment_kind(d),
                upstreams: d.spec.upstreams.clone(),
                routed: !d.spec.routes.is_empty(),
                hosts: d
                    .spec
                    .routes
                    .iter()
                    .filter_map(|r| r.host.clone())
                    .collect(),
                urls: d
                    .spec
                    .routes
                    .iter()
                    .filter_map(|r| state.public_url.of(r))
                    .collect(),
                site_root: d.spec.site.as_ref().map(|s| s.root.clone()),
                site_spa: d.spec.site.as_ref().is_some_and(|s| s.spa),
                job_kind: job_kind_of(&d.spec),
                pool: pool_status_of(d),
                // Skipped under `summary`: one row per VM is what makes this
                // response large, and the pool counts above already say how
                // many there are.
                vms: if q.summary {
                    Vec::new()
                } else {
                    backends
                        .iter()
                        .map(|b| {
                            let usage = b.usage();
                            VmView {
                                sandbox_id: b.sandbox_id.clone(),
                                addr: b.peer.clone(),
                                in_flight: b.in_flight(),
                                healthy: b.is_healthy(),
                                draining: b.is_draining(),
                                uptime_secs: b.uptime_secs(),
                                cpu_percent: usage.map(|(c, _)| c),
                                memory_bytes: usage.map(|(_, m)| m),
                                subdomain: b.bind(),
                            }
                        })
                        .collect()
                },
                pending_vms: if q.summary { Vec::new() } else { pending_vms_of(d) },
                metrics: state.metrics.deployment_snapshot(&d.spec.id),
            }
        })
        .collect();

    let now = now_secs();
    // For a scoped token the rollup is over what it can see, not over the fleet.
    // `global_snapshot` also folds in *retired* deployments' counters, which a
    // scoped caller has no business receiving.
    //
    // `host` is left alone deliberately: whole-machine CPU and memory is not an
    // inventory of deployments, and a sandbox operator watching the load on the
    // box their VM sits on is reasonable.
    let (global, tracked) = match scope {
        None => (
            state.metrics.global_snapshot(),
            state.metrics.tracked_deployments(),
        ),
        Some(ids) => {
            let mut merged = crate::metrics::DeploymentMetricsSnapshot::empty();
            for id in ids {
                merged.merge(&state.metrics.deployment_snapshot(id));
            }
            (merged, ids.len())
        }
    };
    Json(MetricsResponse {
        generated_at: now,
        uptime_secs: now.saturating_sub(state.started_at),
        host: state.metrics.host_snapshot(),
        fleet,
        global,
        obs: state.obs.as_ref().map(|o| o.snapshot()),
        security: security_summary(&state),
        daemon: state.metrics.daemon_snapshot(),
        deployments: views,
        matched,
        tracked_deployments: tracked,
        host_sandboxes: if q.summary {
            Vec::new()
        } else {
            visible_host_sandboxes(
                &state.metrics.host_sandboxes(),
                caller.as_ref().map(|c| &c.0),
                q.namespace.as_deref(),
            )
        },
    })
}

/// The unowned sandboxes on the host that `caller` may see.
///
/// A host sandbox lives in no namespace, so the wall that scopes deployments
/// has nothing to place it by. What it has is an *account* — the one the
/// daemon bills it to — and that is what a federated caller is narrowed by:
/// the accounts behind the namespaces they hold, or behind the one namespace
/// a `namespace=` query names (which is how every request through the cloud
/// door arrives). A deployment- or namespace-scoped app-token sees none: a
/// key minted to drive one deployment has no claim on the host's other
/// tenants. Everyone unconfined sees the whole host, which is the operator's
/// dashboard.
fn visible_host_sandboxes(
    all: &[HostSandboxView],
    caller: Option<&Caller>,
    namespace: Option<&str>,
) -> Vec<HostSandboxView> {
    // `None` is "no narrowing"; `Some(set)` keeps sandboxes billed to a
    // listed account and drops the unattributed rest.
    let accounts: Option<std::collections::BTreeSet<&str>> = match caller {
        None | Some(Caller::Ungated) | Some(Caller::Operator) => None,
        Some(Caller::Token(t)) if t.covers_fleet() => None,
        Some(Caller::Token(_)) => return Vec::new(),
        Some(Caller::Federated(g)) => match namespace {
            // A fleet grant is not confined; the query narrows it only when
            // the auth service said who owns that namespace.
            Some(ns) if g.fleet => g.accounts.get(ns).map(|a| [a.as_str()].into()),
            Some(ns) if g.namespaces.contains_key(ns) => {
                Some(g.account_for(ns).into_iter().collect())
            }
            // A namespace they do not hold: nothing, not everything.
            Some(_) => return Vec::new(),
            None if g.fleet => None,
            None => Some(
                g.accounts
                    .values()
                    .map(String::as_str)
                    .chain(g.subject.account_id.as_deref())
                    .collect(),
            ),
        },
    };
    all.iter()
        .filter(|s| {
            accounts.as_ref().is_none_or(|allowed| {
                s.account_id.as_deref().is_some_and(|a| allowed.contains(a))
            })
        })
        .cloned()
        .collect()
}

/// The alert tile's numbers. Fleet-wide regardless of any deployment filter, as
/// `host`/`fleet`/`global` are — a filter narrows the table, not the system.
fn security_summary(state: &AdminState) -> Option<SecuritySummary> {
    let (ring, stats) = (state.alerts.as_ref()?, state.siem.as_ref()?);
    let totals = ring.totals();
    let s = stats.snapshot();
    let g = state.guard.stats(now_secs());
    Some(SecuritySummary {
        open: ring.len(),
        urgent: totals.high + totals.critical,
        dropped: s.dropped,
        clients_at_capacity: s.clients_at_capacity,
        rules: g.rules,
        blocked: g.blocked,
    })
}

/// The rules a caller may see.
///
/// Narrowed the same way alerts are: a deployment-scoped token sees the rules
/// that name its own deployment and nothing else. A fleet-wide block is fleet
/// information — it says which addresses are considered hostile, which is the
/// same disclosure the alert list is gated for.
fn visible_rules(
    state: &AdminState,
    scope: Option<&[String]>,
    now: u64,
) -> Vec<crate::guard::RuleView> {
    let enforcing = state.guard.enforcing();
    state
        .guard
        .list()
        .into_iter()
        .filter(|r| match scope {
            None => true,
            Some(ids) => r
                .deployment()
                .is_some_and(|d| ids.iter().any(|id| id == d)),
        })
        // `report`, not `view`: the console charts each rule's recent hits, and
        // that series is what answers "is this rule still doing anything, or am
        // I paying for a branch on every request for nothing?".
        .map(|r| r.report(enforcing, now))
        .collect()
}

/// `GET /security` — the findings, newest first.
///
/// Narrowed for a deployment-scoped token exactly as `/metrics` is, with one
/// extra rule: alerts carrying no deployment are dropped for such a caller.
/// Those are the admin-plane and unrouted-traffic findings, and the set of
/// addresses attacking the LB itself is fleet information a sandbox-scoped token
/// has no business reading.
async fn security_snapshot(
    State(state): State<AdminState>,
    Query(q): Query<SecurityQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let now = now_secs();
    let scope = visible_ids(&state, caller.as_ref().map(|c| &c.0));
    let scope = scope.as_deref();

    // Drop rules that have run out on the way past. Expiry is already enforced
    // in `Guard::decide`, so this is tidying rather than correctness — but a
    // console listing rules that stopped doing anything yesterday is a console
    // nobody trusts. Not persisted here: a `GET` that writes to disk is a
    // surprise, and the next mutation or restart rewrites the file anyway.
    state.guard.sweep(now);

    let Some(ring) = state.alerts.as_ref() else {
        // Enabled:false rather than 404 — see `SecurityResponse::enabled`. The
        // rules still come back: enforcement does not depend on detection, and a
        // console that hid the active blocks whenever `APP_LB_SIEM=0` would hide
        // the one thing still affecting traffic.
        return Json(SecurityResponse {
            generated_at: now,
            enabled: false,
            window_secs: 0,
            alerts: Vec::new(),
            totals: crate::siem::SeverityTotals {
                info: 0,
                low: 0,
                medium: 0,
                high: 0,
                critical: 0,
            },
            rules: visible_rules(&state, scope, now),
            guard: state.guard.stats(now),
            stats: None,
        });
    };

    let min = q.severity.as_deref().and_then(crate::siem::Severity::parse);
    let limit = q.limit.unwrap_or(200).min(1000);

    // Resolve the namespace to the ids in it once, rather than asking the
    // registry per alert: the ring holds a few hundred entries and this is one
    // pass over the registry either way.
    let ns_ids: Option<Vec<String>> = q.namespace.as_deref().map(|ns| {
        state
            .registry
            .deployments()
            .values()
            .filter(|d| d.spec.namespace == ns)
            .map(|d| d.spec.id.clone())
            .collect()
    });

    // Read the whole ring and filter, rather than filtering inside it: the ring
    // is a few hundred entries and this keeps the lock hold to one clone.
    let alerts = ring
        .recent(usize::MAX)
        .into_iter()
        .filter(|a| match scope {
            None => true,
            Some(ids) => a
                .deployment
                .as_deref()
                .is_some_and(|d| ids.iter().any(|id| id == d)),
        })
        .filter(|a| match ns_ids.as_deref() {
            None => true,
            // An alert app-lb could not attribute to a deployment has no
            // namespace either, so it is not in the one being asked about.
            // Dropping it is what makes "namespace: sam" mean sam's events
            // rather than sam's events plus everything unattributed.
            Some(ids) => a
                .deployment
                .as_deref()
                .is_some_and(|d| ids.iter().any(|id| id == d)),
        })
        .filter(|a| min.is_none_or(|m| a.severity >= m))
        .filter(|a| q.rule.as_deref().is_none_or(|r| a.rule == r))
        .filter(|a| {
            q.deployment
                .as_deref()
                .is_none_or(|d| a.deployment.as_deref() == Some(d))
        })
        .take(limit)
        .map(crate::siem::AlertView::from)
        .collect();

    Json(SecurityResponse {
        generated_at: now,
        enabled: true,
        window_secs: ring.window_secs(),
        alerts,
        totals: ring.totals(),
        rules: visible_rules(&state, scope, now),
        guard: state.guard.stats(now),
        // Fleet-wide counters: withheld from a scoped caller, for whom they
        // would describe traffic they cannot see.
        stats: scope
            .is_none()
            .then(|| state.siem.as_ref().map(|s| s.snapshot()))
            .flatten(),
    })
}

// ---- guard rules ----------------------------------------------------------

/// Map a guard rejection onto a status. Everything a caller can get wrong is a
/// 400 except the cap, which is a 409 — that one is about the server's state
/// rather than about the request, and retrying the identical body after
/// deleting a rule is the correct next move.
fn guard_error(e: crate::guard::GuardError) -> Response {
    use crate::guard::GuardError as E;
    let code = match &e {
        E::EmptyMatch | E::BadClient(_) | E::TooLong(_) => StatusCode::BAD_REQUEST,
        E::Full => StatusCode::CONFLICT,
        E::NoRule(_) => StatusCode::NOT_FOUND,
        E::Io(_) | E::Json(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(code, e.to_string()).into_response()
}

/// `POST /security/rules` — start refusing something.
///
/// CRUD tier, not view. This is the only route on the admin API that can stop
/// traffic reaching a deployment, so it sits behind the same credentials as
/// editing the spec — a dashboard-only token may read the console and may not
/// arm it.
async fn create_rule(
    State(state): State<AdminState>,
    Json(spec): Json<crate::guard::RuleSpec>,
) -> Response {
    let now = now_secs();
    let rule = match state.guard.insert(spec, now) {
        Ok(r) => r,
        Err(e) => return guard_error(e),
    };
    // Persist before answering. A 200 for a rule that a crash would lose is the
    // wrong way round for a control somebody just used to stop an attack.
    if let Err(e) = state.guard.persist() {
        // The rule is live in memory either way, so undoing it here would be
        // worse than saying what happened: report the failure and leave the
        // block in force.
        tracing::error!(error = %e, path = %state.guard.path().display(), "guard rules not saved");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "the rule is in force but could not be written to {}: {e} — it will not \
                 survive a restart",
                state.guard.path().display()
            ),
        )
        .into_response();
    }
    tracing::warn!(
        rule = %rule.id,
        action = ?rule.action,
        matched = %rule.describe(),
        expires_at = ?rule.expires_at,
        "guard rule created",
    );
    (StatusCode::CREATED, Json(rule.view(state.guard.enforcing()))).into_response()
}

#[derive(Debug, Deserialize)]
struct RuleExpiryBody {
    /// Seconds from now, or `null` for a rule that never expires. Required —
    /// absent is refused rather than read as "forever", because making a block
    /// permanent by omission is exactly the accident this field exists to
    /// prevent.
    #[serde(default, deserialize_with = "double_option")]
    expires_in_secs: Option<Option<u64>>,
}

/// `PATCH /security/rules/:id` — change when a rule expires, including never.
///
/// The counterpart to the bounded lifetime every suggested action carries. That
/// default is right for a rule authored mid-incident, and wrong once an operator
/// has decided an address is simply not welcome; re-posting the rule to make it
/// permanent would work but would reset its hit history, which is the evidence
/// the decision rests on.
async fn patch_rule(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(body): Json<RuleExpiryBody>,
) -> Response {
    let Some(expires_in_secs) = body.expires_in_secs else {
        return err(
            StatusCode::BAD_REQUEST,
            "expires_in_secs is required: a number of seconds, or null to keep the rule \
             indefinitely",
        )
        .into_response();
    };
    let now = now_secs();
    match state.guard.set_expiry(&id, expires_in_secs, now) {
        Ok(view) => {
            if let Err(e) = state.guard.persist() {
                tracing::error!(error = %e, "guard rules not saved after expiry change");
            }
            match expires_in_secs {
                None => tracing::warn!(
                    rule = %id,
                    summary = %view.summary,
                    "guard rule made permanent; it will now outlive the incident that created it",
                ),
                Some(secs) => tracing::info!(rule = %id, secs, "guard rule expiry extended"),
            }
            Json(view).into_response()
        }
        Err(e) => guard_error(e),
    }
}

/// `DELETE /security/rules/:id` — stop refusing it.
async fn delete_rule(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    let now = now_secs();
    if let Err(e) = state.guard.remove(&id, now) {
        return guard_error(e);
    }
    if let Err(e) = state.guard.persist() {
        tracing::error!(error = %e, "guard rules not saved after delete");
    }
    tracing::warn!(rule = %id, "guard rule removed");
    StatusCode::NO_CONTENT.into_response()
}

// ---- the SIEM console -----------------------------------------------------

/// `GET /siem` — the security console.
///
/// Its own page rather than a bigger card on `/dashboard`, because the two are
/// read at different moments and at different depths. The dashboard answers "is
/// the fleet healthy" in a glance and must stay glanceable; this answers "what
/// is attacking us and what do I do about it", which needs the full alert list,
/// the ECS fields behind each one, and the buttons that change what the data
/// plane does. The dashboard card links here and keeps its summary.
async fn siem_console(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    Html(render_page(&state, &state.siem_html, &headers))
}

// ---- disks ----------------------------------------------------------------

/// The store, or the 503 that explains why there isn't one.
///
/// Disk management is the one subsystem that can be *absent* rather than merely
/// idle: without a resolvable daemon data directory there is nothing to
/// inventory. Saying so with the fix in it beats a 404 on a route the page is
/// hard-coded to call.
fn disks_off() -> Response {
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "disk management is off: app-lb could not work out where heyvmd keeps its \
         per-sandbox disks. Set APP_LB_VM_DATA_DIR to the daemon's data directory \
         (MVM_DATA_DIR, or ~/.heyo) and restart",
    )
    .into_response()
}

fn disk_error(e: crate::disks::DiskError) -> Response {
    use crate::disks::DiskError as E;
    let code = match &e {
        E::BadId(_) => StatusCode::BAD_REQUEST,
        E::NotFound(_) => StatusCode::NOT_FOUND,
        // 409, not 403: the request was permitted, the disk's state refuses it,
        // and the caller can change that state.
        E::Held { .. } | E::AlreadyArchiving(_) | E::NothingToArchive(_) => StatusCode::CONFLICT,
        E::NoArchiveTarget => StatusCode::NOT_IMPLEMENTED,
        // 500, not 409: nothing about the disk's state refuses this and no
        // `force=1` gets past it. Something on the host — almost always the
        // ownership of the daemon's data directory — stopped app-lb deleting
        // files it was told to delete, and that is the server's problem to fix.
        E::PurgeFailed { .. } | E::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(code, e.to_string()).into_response()
}

/// `GET /disks` — every per-sandbox disk on this host.
///
/// View tier, like `/metrics` and `/security`: the console renders it, so the
/// browser's cached view credentials have to work. Fleet-wide, so a
/// deployment-scoped token is refused — a disk inventory spans deployments and
/// includes sandboxes no deployment owns any more.
async fn disks(State(state): State<AdminState>) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    Json(store.inventory().await).into_response()
}

/// `GET /storage` — the disk console.
async fn storage_console(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    Html(render_page(&state, &state.disks_html, &headers))
}

// ---- plugins --------------------------------------------------------------

/// `GET /plugins` — the plugin console.
async fn plugins_console(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    Html(render_page(&state, &state.plugins_html, &headers))
}

/// `GET /api/plugins` — every built-in plugin, its record and its live status.
///
/// View tier: the console renders it. A plugin's configuration never holds a
/// credential (those are secret references), so there is nothing here the
/// view tier should not read.
async fn list_plugins(State(state): State<AdminState>) -> Response {
    Json(state.plugins.list().await).into_response()
}

/// `GET /api/plugins/:id`
async fn get_plugin(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    match state.plugins.get(&id).await {
        Some(view) => Json(view).into_response(),
        None => err(StatusCode::NOT_FOUND, format!("no plugin named {id:?}")).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct PutPlugin {
    enabled: bool,
    /// Omitted keeps the stored configuration.
    #[serde(default)]
    config: Option<serde_json::Value>,
}

/// `PUT /api/plugins/:id` — `{enabled, config?}`.
async fn put_plugin(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(body): Json<PutPlugin>,
) -> Response {
    set_plugin(&state, &id, body.enabled, body.config).await
}

/// `POST /api/plugins/:id/enable`
async fn enable_plugin(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    set_plugin(&state, &id, true, None).await
}

/// `POST /api/plugins/:id/disable`
async fn disable_plugin(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    set_plugin(&state, &id, false, None).await
}

async fn set_plugin(
    state: &AdminState,
    id: &str,
    enabled: bool,
    config: Option<serde_json::Value>,
) -> Response {
    match state.plugins.set(id, enabled, config).await {
        Ok(view) => Json(view).into_response(),
        Err(e) => plugin_set_error(e),
    }
}

fn plugin_set_error(e: crate::plugins::SetError) -> Response {
    use crate::plugins::SetError;
    match e {
        e @ SetError::NotFound => err(StatusCode::NOT_FOUND, e.to_string()).into_response(),
        e @ SetError::Invalid(_) => err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        e @ SetError::Io(_) => {
            err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        e @ SetError::Disabled(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": e.to_string(), "code": "plugin_disabled" })),
        )
            .into_response(),
    }
}

/// `GET /api/plugins/:id/installs` — the namespaces that installed a
/// per-namespace plugin. Fleet-wide: it is what app-obs reads, with the
/// operator credential, to learn what to collect.
async fn plugin_installs(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    match state.plugins.installs(&id) {
        Some(view) => Json(view).into_response(),
        None => err(
            StatusCode::NOT_FOUND,
            format!("no plugin named {id:?} can be installed in a namespace"),
        )
        .into_response(),
    }
}

/// The namespace a `/namespaces/:name/plugins…` route acts on, read
/// positionally off the real path the way [`deployment_of`] reads an id.
fn namespace_plugin_target<'a>(matched: &str, path: &'a str) -> Option<&'a str> {
    if !matched.starts_with("/namespaces/:name/plugins") {
        return None;
    }
    path.split('/').nth(2).filter(|s| !s.is_empty())
}

fn bad_namespace(ns: &str) -> Option<Response> {
    (!crate::config::is_valid_namespace(ns)).then(|| {
        err(StatusCode::BAD_REQUEST, format!("{ns:?} is not a valid namespace name")).into_response()
    })
}

/// `GET /namespaces/:name/plugins` — what this namespace may install and
/// whether it has. The gate has checked the caller reaches the namespace.
async fn namespace_plugins(State(state): State<AdminState>, Path(ns): Path<String>) -> Response {
    if let Some(r) = bad_namespace(&ns) {
        return r;
    }
    Json(state.plugins.namespace_plugins(&ns)).into_response()
}

/// `GET /namespaces/:name/plugins/:id`
async fn namespace_plugin(
    State(state): State<AdminState>,
    Path((ns, id)): Path<(String, String)>,
) -> Response {
    if let Some(r) = bad_namespace(&ns) {
        return r;
    }
    match state.plugins.namespace_plugins(&ns).into_iter().find(|p| p.id == id) {
        Some(view) => Json(view).into_response(),
        None => err(
            StatusCode::NOT_FOUND,
            format!("no plugin named {id:?} can be installed in a namespace"),
        )
        .into_response(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct InstallPlugin {
    #[serde(default)]
    config: Option<serde_json::Value>,
}

/// Installing changes what the namespace's apps send to a shared collector,
/// so it is the namespace administrator's call: a token narrowed to a few of
/// the namespace's deployments does not get to decide it for the rest.
fn refuse_unless_administers(caller: Option<&Caller>, ns: &str) -> Option<Response> {
    match caller {
        Some(c) if !c.administers_namespace(ns) => Some(
            err(
                StatusCode::FORBIDDEN,
                format!(
                    "installing a plugin needs an admin credential for all of namespace \"{ns}\""
                ),
            )
            .into_response(),
        ),
        _ => None,
    }
}

/// `PUT /namespaces/:name/plugins/:id` — `{config?}`.
async fn install_namespace_plugin(
    State(state): State<AdminState>,
    Path((ns, id)): Path<(String, String)>,
    caller: Option<axum::Extension<Caller>>,
    body: Option<Json<InstallPlugin>>,
) -> Response {
    let caller = caller.as_deref();
    if let Some(r) = bad_namespace(&ns).or_else(|| refuse_unless_administers(caller, &ns)) {
        return r;
    }
    let config = body
        .and_then(|Json(b)| b.config)
        .unwrap_or_else(|| serde_json::json!({}));
    let by = caller.and_then(Caller::principal);
    match state.plugins.install(&id, &ns, config, by).await {
        Ok(view) => Json(view).into_response(),
        Err(e) => plugin_set_error(e),
    }
}

/// `DELETE /namespaces/:name/plugins/:id`
async fn uninstall_namespace_plugin(
    State(state): State<AdminState>,
    Path((ns, id)): Path<(String, String)>,
    caller: Option<axum::Extension<Caller>>,
) -> Response {
    if let Some(r) = bad_namespace(&ns).or_else(|| refuse_unless_administers(caller.as_deref(), &ns)) {
        return r;
    }
    match state.plugins.uninstall(&id, &ns).await {
        Ok(view) => Json(view).into_response(),
        Err(e) => plugin_set_error(e),
    }
}

/// `/namespaces/:name/plugins/:id/*rest` — a plugin's namespace surface. A
/// `GET` arrives here through the view tier and anything else through the
/// CRUD tier; the plugin sees the request relative to its own prefix.
async fn namespace_plugin_surface(
    State(state): State<AdminState>,
    Path((ns, id, _rest)): Path<(String, String, String)>,
    mut req: Request,
) -> Response {
    if let Some(r) = bad_namespace(&ns) {
        return r;
    }
    let prefix = format!("/namespaces/{ns}/plugins/{id}");
    let rest = req
        .uri()
        .path()
        .strip_prefix(&prefix)
        .unwrap_or("/")
        .to_string();
    let rest = if rest.is_empty() { "/".to_string() } else { rest };
    let rewritten = match req.uri().query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest,
    };
    match rewritten.parse() {
        Ok(uri) => *req.uri_mut() = uri,
        Err(_) => return err(StatusCode::BAD_REQUEST, "unparseable plugin path").into_response(),
    }
    state.plugins.dispatch_namespace(&id, &ns, req).await
}

/// `GET /network` — the network topology console.
///
/// A 2D-canvas visualiser of the request path: ingress → hostnames →
/// deployments → VMs, with traffic-flow animation. Reads the same
/// `/metrics?summary=false` and `/ingress` endpoints the dashboard does and
/// polls at the same 2s cadence, so the two never disagree about the fleet.
/// View tier for the same reason the dashboard is: it renders `/metrics`, so
/// it must work with whatever credentials the browser already has.
async fn network_console(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    Html(render_page(&state, &state.network_html, &headers))
}

// ---- the event feed -------------------------------------------------------

#[derive(Serialize)]
struct FeedIndexEntry {
    namespace: String,
    events: usize,
}

/// `GET /feeds` — the namespaces that have events, narrowed to what the caller
/// may read. A discovery aid for the dashboard and `heyctl`, not the feed
/// itself.
async fn feeds_index(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let out: Vec<FeedIndexEntry> = state
        .feed
        .namespaces()
        .into_iter()
        .filter(|ns| caller.as_ref().is_none_or(|c| c.0.reaches_namespace(ns)))
        .map(|ns| {
            let events = state.feed.recent(&ns, usize::MAX).len();
            FeedIndexEntry { namespace: ns, events }
        })
        .collect();
    Json(out)
}

/// One row of `GET /namespaces`.
#[derive(Serialize)]
struct NamespaceEntry {
    namespace: String,
    /// Deployments in it that *this caller* may see. A count rather than a list
    /// because the list is `GET /deployments?namespace=…`, which narrows itself
    /// the same way.
    deployments: usize,
    /// Whether a namespace *object* exists, as opposed to the name being one a
    /// deployment happens to mention. Both are real namespaces and behave
    /// identically for scoping; the difference is only whether anything can be
    /// deleted, and whether there is anywhere to hang a description.
    declared: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
}

/// The namespaces a caller carries a key to, whether or not anything is in them.
///
/// Only a *confined* caller has any: an operator, an ungated build and a
/// fleet-scoped token are not walled into a room, so naming one for them would
/// be inventing a confinement that does not exist. A deployment-scoped token is
/// not confined either — its wall is a list of ids, and the namespaces those
/// happen to sit in are discovered from the registry rather than carried.
///
/// Split out from the handler because it is the half worth asserting on: it
/// decides what a namespace token sees when its room is empty, which is the one
/// case the registry cannot answer.
fn own_namespaces(caller: Option<&Caller>) -> Vec<String> {
    match caller {
        Some(Caller::Token(t)) => t.namespace.iter().cloned().collect(),
        Some(Caller::Federated(g)) if !g.fleet => g.namespaces.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

/// `GET /namespaces` — the namespaces this caller can see, and how much is in
/// each.
///
/// Derived from [`Caller::may_view`] over the registry rather than from
/// [`Caller::reaches_namespace`], and the difference matters. `reaches_namespace`
/// guards the *event feed*, where "which namespaces exist and what happens in
/// them" is genuinely fleet information an unconfined token should need fleet
/// scope for. This route discloses strictly less: every namespace it names is
/// one the caller can already see a deployment in through `GET /deployments`,
/// so it adds no reach — and a deployment-scoped token gets a picker that works
/// instead of an empty one.
///
/// A confined caller also gets its own namespace back when nothing is in it
/// yet. An empty room whose name the token already carries is not information,
/// and a namespace that vanishes from the picker until its first deployment
/// exists is a worse answer than one that reads zero.
#[derive(Debug, Deserialize)]
struct OnboardingQuery {
    #[serde(default)]
    namespace: Option<String>,
}

/// `GET /onboarding[?namespace=]` — everything the "Get started" card shows a
/// namespace user: whether the namespace is still empty, the MCP endpoint to
/// install, the lifetime cap on a token they mint for it, and a fastcar spec
/// built for this namespace on this fleet. See `onboarding.rs`.
///
/// The namespace defaults to the caller's only one. Everything returned is
/// about a namespace the caller already reaches, and none of it is secret.
async fn onboarding(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Query(q): Query<OnboardingQuery>,
) -> Response {
    use crate::onboarding::{HEYO_PROVIDER, ImageLookup, fastcar_id, fastcar_spec};

    let caller = caller.as_deref();
    let ns = q
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|ns| !ns.is_empty())
        .or_else(|| caller.and_then(Caller::sole_namespace))
        .map(str::to_string);
    let Some(ns) = ns else {
        return err(StatusCode::BAD_REQUEST, "name the namespace: ?namespace=<name>").into_response();
    };
    if !crate::config::is_valid_namespace(&ns) {
        return err(StatusCode::BAD_REQUEST, format!("\"{ns}\" is not a namespace")).into_response();
    }
    if caller.is_some_and(|c| !c.reaches_namespace(&ns)) {
        return err(
            StatusCode::FORBIDDEN,
            format!("this credential cannot reach the \"{ns}\" namespace"),
        )
        .into_response();
    }

    let deployments = state
        .registry
        .deployments()
        .values()
        .filter(|d| d.spec.namespace == ns)
        .count();
    let gated = state.auth_providers.get(&ns, HEYO_PROVIDER).is_some();
    let id = fastcar_id(&ns);
    let host = state.deploy_base_domain.as_deref().map(|base| format!("{id}.{base}"));
    let url = host.as_ref().and_then(|h| {
        state.public_url.of(&crate::config::RouteRule {
            host: Some(h.clone()),
            ..Default::default()
        })
    });

    // The hub, when one is configured, is the source; the catalog otherwise.
    let ob = &state.onboarding;
    let hub_store = ob.hub_store();
    let (source, image_status, image_note, lookup) = match &hub_store {
        Some(_) => {
            let (status, note) = ob.hub_fastcar().await.status(&ob.fastcar_ref);
            ("hub", status, note, None)
        }
        None => {
            let lookup = ob.fastcar_image().await;
            let (status, note) = lookup.status();
            ("catalog", status, note, Some(lookup))
        }
    };
    let image = match &lookup {
        Some(ImageLookup::Found(i)) => Some(i),
        _ => None,
    };
    let hub = hub_store.as_deref().map(|store| (store, ob.fastcar_ref.as_str()));
    let spec = fastcar_spec(&ns, &ob.fastcar_image, image, hub, host.as_deref(), gated);

    Json(serde_json::json!({
        "namespace": ns,
        "deployments": deployments,
        "can_mint": caller.is_none_or(|c| c.administers_namespace(&ns)),
        "mcp": {
            "name": state.onboarding.mcp_name,
            "url": state.onboarding.mcp_url,
        },
        "token": {
            "max_ttl_secs": state.onboarding.tenant_token_max_ttl_secs,
        },
        "hub": {
            "url": state.onboarding.hub_page(),
        },
        "fastcar": {
            "id": id,
            "url": url,
            "gated": gated,
            "source": source,
            "ref": hub_store.as_ref().map(|_| state.onboarding.fastcar_ref.clone()),
            "image": image_status,
            "note": image_note,
            "spec": spec,
        },
    }))
    .into_response()
}

async fn namespaces(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let caller = caller.as_ref().map(|c| &c.0);

    // BTreeMap so the order is the namespace order and not the registry's.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for d in state.registry.deployments().values() {
        let ns = &d.spec.namespace;
        if caller.is_none_or(|c| c.may_view(&d.spec.id, ns)) {
            *counts.entry(ns.clone()).or_insert(0) += 1;
        }
    }

    for ns in own_namespaces(caller) {
        counts.entry(ns).or_insert(0);
    }

    // Declared namespaces, whether or not anything is in them — that is the
    // point of declaring one.
    //
    // A *stronger* predicate than the counts above, and deliberately: a
    // namespace holding a deployment the caller can see is already implied by
    // `GET /deployments`, so listing it discloses nothing new. An empty declared
    // one is not implied by anything, so it takes `reaches_namespace` — the same
    // bar the event feed uses for "which namespaces exist is fleet information".
    for ns in state.namespaces.list() {
        if caller.is_none_or(|c| c.reaches_namespace(&ns.name)) {
            counts.entry(ns.name.clone()).or_insert(0);
        }
    }

    Json(
        counts
            .into_iter()
            .map(|(namespace, deployments)| {
                let declared = state.namespaces.get(&namespace);
                NamespaceEntry {
                    deployments,
                    declared: declared.is_some(),
                    description: declared.as_ref().and_then(|d| d.description.clone()),
                    created_at: declared.as_ref().map(|d| d.created_at),
                    namespace,
                }
            })
            .collect::<Vec<_>>(),
    )
}

/// `POST /namespaces` — declare one.
///
/// Fleet-scoped and `admin`, deliberately: a namespace is the wall other scopes
/// are defined against, so minting rooms is not something a credential confined
/// to one room may do. `covers_fleet` is checked here rather than at the gate
/// because `/namespaces` is a route that *narrows itself* on `GET` — the gate
/// cannot tell the two methods apart, so the write side states its own rule.
async fn create_namespace(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Json(mut spec): Json<crate::config::NamespaceSpec>,
) -> Response {
    if let Some(c) = caller.as_ref().map(|c| &c.0)
        && !c.covers_fleet()
    {
        return err(
            StatusCode::FORBIDDEN,
            "declaring a namespace is a fleet-wide act, so it needs a fleet-scoped admin \
             credential — a token confined to a namespace cannot create another",
        )
        .into_response();
    }
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    // Stamped here, never taken from the body: a client-supplied creation time
    // is a client-supplied claim. Re-declaring keeps the original, so `apply`
    // is idempotent and does not reset the clock on every run.
    spec.created_at = match state.namespaces.get(&spec.name) {
        Some(existing) => existing.created_at,
        None => now_secs(),
    };
    let existed = state.namespaces.contains(&spec.name);
    match state.namespaces.upsert(spec) {
        Ok(ns) => (
            if existed { StatusCode::OK } else { StatusCode::CREATED },
            Json(ns),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "namespace write failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "could not persist the namespace").into_response()
        }
    }
}

/// `DELETE /namespaces/:name` — undeclare one.
///
/// Refuses while deployments are still in it. Removing the object would
/// otherwise "succeed" and change nothing observable — the namespace would stay
/// alive as an undeclared one, still scoping every token pointed at it — which
/// is the kind of success that gets read as "it is gone".
async fn delete_namespace(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    caller: Option<axum::Extension<Caller>>,
) -> Response {
    if let Some(c) = caller.as_ref().map(|c| &c.0)
        && !c.covers_fleet()
    {
        return err(
            StatusCode::FORBIDDEN,
            "removing a namespace is a fleet-wide act, so it needs a fleet-scoped admin \
             credential",
        )
        .into_response();
    }
    let occupied = state
        .registry
        .deployments()
        .values()
        .filter(|d| d.spec.namespace == name)
        .count();
    if occupied > 0 {
        return err(
            StatusCode::CONFLICT,
            format!(
                "namespace {name:?} still holds {occupied} deployment(s); move or delete them \
                 first — undeclaring it would leave them exactly where they are"
            ),
        )
        .into_response();
    }
    match state.namespaces.remove(&name) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, format!("no declared namespace {name:?}"))
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "namespace delete failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "could not remove the namespace").into_response()
        }
    }
}

// ---- auth providers -----------------------------------------------------

/// Whether `caller` may read (`admin == false`) or change (`admin == true`) the
/// auth providers of `ns`. Walled exactly as secrets are: an ungated or operator
/// caller may do anything; a confined credential is measured against its reach.
fn may_use_auth_providers(caller: Option<&Caller>, ns: &str, admin: bool) -> Result<(), Response> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if !caller.reaches_namespace(ns) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!("this credential cannot reach the \"{ns}\" namespace's auth providers"),
        )
        .into_response());
    }
    if admin && !caller.satisfies_in(crate::tokens::AdminScope::Admin, Some(ns)) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!(
                "this credential may only view the \"{ns}\" namespace, not change its auth providers"
            ),
        )
        .into_response());
    }
    Ok(())
}

/// Deployments in `ns` whose sign-in gate inherits the provider `name`. Used to
/// keep a delete from pulling a provider out from under a live gate — which,
/// because resolution fails closed, would take those deployments offline.
fn auth_provider_users(state: &AdminState, ns: &str, name: &str) -> Vec<String> {
    let mut users: Vec<String> = state
        .registry
        .deployments()
        .values()
        .filter(|d| {
            d.spec.namespace == ns
                && d.spec.auth.as_ref().and_then(|g| g.provider_ref.as_deref()) == Some(name)
        })
        .map(|d| d.spec.id.clone())
        .collect();
    users.sort();
    users
}

/// The body of `POST /auth-providers`: an [`AuthProviderSpec`] plus three
/// request-only conveniences that never reach the store.
///
/// `preset` expands a known template, so "gate this on Heyo sign-in" is one
/// POST rather than a dozen fields nobody should have to know:
///
/// | preset | verifies | needs |
/// | --- | --- | --- |
/// | `heyo-jwks` | gate tokens, `RS256`, against the published key set | nothing, or `jwks_url` |
/// | `heyo` | access tokens, `HS256` | `secret` |
///
/// Prefer `heyo-jwks`. `heyo` needs the auth service's *signing* key, so the
/// fleet that holds it can mint identities as well as check them — acceptable
/// where we run everything, and not something to put behind a wall somebody
/// else administers.
#[derive(Deserialize)]
struct CreateProviderBody {
    #[serde(flatten)]
    spec: crate::config::AuthProviderSpec,
    /// Expand a provider template before validation. Request-only.
    #[serde(default)]
    preset: Option<String>,
    /// The signing secret the `heyo` preset needs. Request-only.
    #[serde(default)]
    secret: Option<crate::secrets::SecretRef>,
    /// Where the issuer publishes its key set, for `heyo-jwks`. Request-only,
    /// and optional: with federated auth configured app-lb already knows the
    /// auth service's address and derives it.
    #[serde(default)]
    jwks_url: Option<String>,
    /// Request-only tweaks laid over the resulting `jwt` policy — above all
    /// over a preset's, which is otherwise replaced wholesale. They make
    /// "Heyo sign-in, for this account only, with a browser redirect" one POST
    /// instead of a preset followed by an edit.
    #[serde(default)]
    require: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    cookie: Option<String>,
    #[serde(default)]
    login_url: Option<String>,
    #[serde(default)]
    login_redirect_param: Option<String>,
    /// Scoped sign-in endpoints, laid over the policy like the fields above.
    /// See [`crate::config::JwtSpec::authorize_url`].
    #[serde(default)]
    authorize_url: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
}

impl CreateProviderBody {
    fn has_jwt_tweaks(&self) -> bool {
        self.require.is_some()
            || self.cookie.is_some()
            || self.login_url.is_some()
            || self.login_redirect_param.is_some()
            || self.authorize_url.is_some()
            || self.token_url.is_some()
    }
}

/// The request-only fields [`apply_jwt_tweaks`] lays over a JWT policy.
struct JwtTweaks {
    require: Option<BTreeMap<String, serde_json::Value>>,
    cookie: Option<String>,
    login_url: Option<String>,
    login_redirect_param: Option<String>,
    authorize_url: Option<String>,
    token_url: Option<String>,
}

/// Lay the request-only tweaks over a materialised JWT policy. `require` is
/// merged claim by claim, so a preset's `role` check survives an added
/// `accountId`.
fn apply_jwt_tweaks(jwt: &mut crate::config::JwtSpec, tweaks: JwtTweaks) {
    let JwtTweaks { require, cookie, login_url, login_redirect_param, authorize_url, token_url } = tweaks;
    if let Some(require) = require {
        jwt.require.extend(require);
    }
    if cookie.is_some() {
        jwt.cookie = cookie;
    }
    if login_url.is_some() {
        jwt.login_url = login_url;
    }
    if login_redirect_param.is_some() {
        jwt.login_redirect_param = login_redirect_param;
    }
    if authorize_url.is_some() {
        jwt.authorize_url = authorize_url;
    }
    if token_url.is_some() {
        jwt.token_url = token_url;
    }
}

/// `GET /auth-providers[?namespace=]` — the providers this caller may see.
///
/// View tier, and it narrows itself: with a namespace it answers only that one
/// (refusing a caller that cannot reach it), and without, only the namespaces
/// the caller reaches — the same shape as `list_secrets`.
async fn list_auth_providers(
    State(state): State<AdminState>,
    Query(q): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let caller = caller.as_deref();
    if let Some(ns) = q.namespace.as_deref().map(str::trim).filter(|ns| !ns.is_empty()) {
        if let Err(refused) = may_use_auth_providers(caller, ns, false) {
            return refused;
        }
        return Json(state.auth_providers.list(ns)).into_response();
    }
    let visible: Vec<_> = state
        .auth_providers
        .list_all()
        .into_iter()
        .filter(|p| caller.is_none_or(|c| c.reaches_namespace(&p.namespace)))
        .collect();
    Json(visible).into_response()
}

/// `POST /auth-providers` — declare or replace one in the namespace the body
/// names (`default` when it names none). A confined caller must reach that
/// namespace as an admin, exactly as it must to write a secret there.
async fn create_auth_provider(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Json(body): Json<CreateProviderBody>,
) -> Response {
    let has_tweaks = body.has_jwt_tweaks();
    let tweaks = JwtTweaks {
        require: body.require,
        cookie: body.cookie,
        login_url: body.login_url,
        login_redirect_param: body.login_redirect_param,
        authorize_url: body.authorize_url,
        token_url: body.token_url,
    };
    let mut spec = body.spec;

    // Apply the preset before validation, so what is stored and what is checked
    // are the fully materialised provider — no preset expansion lives on the hot
    // path or in the state file.
    if let Some(preset) = body.preset.as_deref() {
        match preset {
            "heyo-jwks" => {
                // Either the caller named the key set, or app-lb derives it from
                // the auth service it already federates to — which is the whole
                // provisioning story: declaring a customer's provider takes a
                // namespace and a name, and nothing else.
                let jwks_url = match body.jwks_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
                    Some(url) => url.to_string(),
                    None => {
                        let Some(base) = state.federated.as_ref().map(|f| f.base_url().to_string())
                        else {
                            return err(
                                StatusCode::BAD_REQUEST,
                                "the \"heyo-jwks\" preset needs `jwks_url`, because this app-lb \
                                 has no auth service configured to derive it from (set \
                                 APP_LB_AUTH_URL, or send \
                                 {\"jwks_url\": \"https://auth.example.com/.well-known/jwks.json\"})",
                            )
                            .into_response();
                        };
                        format!("{}/.well-known/jwks.json", base.trim_end_matches('/'))
                    }
                };
                spec.provider = crate::config::Providers::one(crate::config::AuthProvider::Jwt);
                spec.jwt = Some(crate::config::JwtSpec::heyo_jwks(jwks_url));
            }
            "heyo" => {
                let Some(secret) = body.secret else {
                    return err(
                        StatusCode::BAD_REQUEST,
                        "the \"heyo\" preset needs a `secret` reference to the JWT signing key, \
                         e.g. {\"secret\": \"heyo-auth\", \"key\": \"jwt_secret\"} — or use the \
                         \"heyo-jwks\" preset, which verifies against the auth service's \
                         published key set and needs no secret at all",
                    )
                    .into_response();
                };
                spec.provider = crate::config::Providers::one(crate::config::AuthProvider::Jwt);
                spec.jwt = Some(crate::config::JwtSpec::heyo(secret));
            }
            other => {
                return err(
                    StatusCode::BAD_REQUEST,
                    crate::config::SpecError::UnknownAuthPreset(other.to_string()).to_string(),
                )
                .into_response();
            }
        }
    }

    if has_tweaks {
        let Some(jwt) = spec.jwt.as_mut() else {
            return err(
                StatusCode::BAD_REQUEST,
                "`require`, `cookie`, `login_url`, `login_redirect_param`, `authorize_url` and \
                 `token_url` tune a JWT policy, and this provider has none — name a `preset` or \
                 send a `jwt` block",
            )
            .into_response();
        };
        apply_jwt_tweaks(jwt, tweaks);
    }

    // Bind the secret references to this provider's own namespace before
    // anything validates or stores them — the wall a deployment gets from
    // `DeploymentSpec::normalize`, which no other path was giving a provider.
    spec.normalize();

    let ns = spec.namespace.clone();
    if let Err(refused) = may_use_auth_providers(caller.as_deref(), &ns, true) {
        return refused;
    }
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    // Stamped here, never from the body; re-declaring keeps the original clock so
    // `apply` is idempotent.
    let existing = state.auth_providers.get(&ns, &spec.name);
    spec.created_at = match &existing {
        Some(p) => p.created_at,
        None => now_secs(),
    };
    let existed = existing.is_some();
    match state.auth_providers.upsert(spec) {
        Ok(p) => (
            if existed { StatusCode::OK } else { StatusCode::CREATED },
            Json(p),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "auth provider write failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not persist the auth provider",
            )
            .into_response()
        }
    }
}

/// `GET /auth-providers/:namespace/:name`. The client secret is a reference,
/// never a value, so the object is safe to echo — the same reason a deployment
/// spec is.
async fn get_auth_provider(
    State(state): State<AdminState>,
    Path((namespace, name)): Path<(String, String)>,
    caller: Option<axum::Extension<Caller>>,
) -> Response {
    if let Err(refused) = may_use_auth_providers(caller.as_deref(), &namespace, false) {
        return refused;
    }
    match state.auth_providers.get(&namespace, &name) {
        Some(p) => Json(p).into_response(),
        None => err(
            StatusCode::NOT_FOUND,
            format!("no auth provider {name:?} in namespace {namespace:?}"),
        )
        .into_response(),
    }
}

/// `DELETE /auth-providers/:namespace/:name`.
///
/// Refused while a deployment's gate still inherits it: resolution fails closed,
/// so removing a referenced provider would take those deployments offline. The
/// message names them, exactly as deleting a still-referenced secret does.
async fn delete_auth_provider(
    State(state): State<AdminState>,
    Path((namespace, name)): Path<(String, String)>,
    caller: Option<axum::Extension<Caller>>,
) -> Response {
    if let Err(refused) = may_use_auth_providers(caller.as_deref(), &namespace, true) {
        return refused;
    }
    if state.auth_providers.get(&namespace, &name).is_none() {
        return err(
            StatusCode::NOT_FOUND,
            format!("no auth provider {name:?} in namespace {namespace:?}"),
        )
        .into_response();
    }
    let users = auth_provider_users(&state, &namespace, &name);
    if !users.is_empty() {
        return err(
            StatusCode::CONFLICT,
            format!(
                "auth provider {name:?} is inherited by deployment(s) {}; their sign-in gates \
                 would fail closed. Repoint or remove them first",
                users.join(", ")
            ),
        )
        .into_response();
    }
    match state.auth_providers.remove(&namespace, &name) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(
            StatusCode::NOT_FOUND,
            format!("no auth provider {name:?} in namespace {namespace:?}"),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "auth provider delete failed");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not remove the auth provider",
            )
            .into_response()
        }
    }
}

/// If `spec`'s gate inherits an auth provider, resolve it against the store now
/// and validate the merged deployment — so a reference to a missing or
/// incompatible provider is refused at registration (400) with the provider
/// named, rather than surfacing as a 500 on the first gated request.
fn check_provider_ref(state: &AdminState, spec: &DeploymentSpec) -> Result<(), Response> {
    let Some(name) = spec.auth.as_ref().and_then(|g| g.provider_ref.as_deref()) else {
        return Ok(());
    };
    let Some(provider) = state.auth_providers.get(&spec.namespace, name) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            crate::config::SpecError::UnknownAuthProvider {
                namespace: spec.namespace.clone(),
                name: name.to_string(),
            }
            .to_string(),
        )
        .into_response());
    };
    // Validate the deployment as though the inherited identity had been written
    // inline: the resolved gate goes through the same `DeploymentSpec::validate`,
    // so an incompatible provider is caught here with the gate error named.
    let mut resolved = spec.clone();
    resolved.auth = Some(provider.resolve(spec.auth.as_ref().expect("gate present")));
    resolved.validate().map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("auth.provider_ref {name:?} resolves to a provider this deployment cannot use: {e}"),
        )
        .into_response()
    })
}

#[derive(Deserialize)]
struct FeedQuery {
    /// `json` returns the events as structured data instead of RSS — what
    /// `heyctl feed` and the dashboard read; a feed reader takes the
    /// default.
    #[serde(default)]
    format: Option<String>,
}

/// `GET /feeds/:namespace` — the namespace's feed as RSS. `:namespace` may
/// carry a `.xml` suffix, because half the feed readers ever written assume
/// one. Access was already decided by the gate (see `decide_access`), which
/// checks the same spelling.
async fn feed_rss(
    State(state): State<AdminState>,
    Path(namespace): Path<String>,
    Query(q): Query<FeedQuery>,
) -> Response {
    let ns = namespace.strip_suffix(".xml").unwrap_or(&namespace);
    let events = state.feed.recent(ns, crate::proxy::FEED_PAGE);
    if q.format.as_deref() == Some("json") {
        return Json(events).into_response();
    }
    let doc = crate::feed::rss(ns, &format!("/feeds/{ns}"), &events);
    (
        [(header::CONTENT_TYPE, "application/rss+xml; charset=utf-8")],
        doc,
    )
        .into_response()
}

/// What a lifecycle feed entry says about the deployment: where it serves, so
/// a subscriber can go look at it. Falls back to the backend kind for the
/// unrouted (exec-only) shape.
fn lifecycle_detail(state: &AdminState, spec: &DeploymentSpec) -> String {
    let urls: Vec<String> = spec.routes.iter().filter_map(|r| state.public_url.of(r)).collect();
    if urls.is_empty() {
        let kind = match spec.backend() {
            crate::config::Backend::Vm => "vm",
            crate::config::Backend::Upstreams => "static",
            crate::config::Backend::Site => "site",
        };
        format!("a {kind} deployment with no public routes")
    } else {
        format!("serving at {}", urls.join(", "))
    }
}

#[derive(Debug, Deserialize)]
struct DiskPolicyBody {
    /// Absent leaves the flag alone, so a note can be edited without touching
    /// retention and vice versa.
    #[serde(default)]
    retain: Option<bool>,
    /// `null` clears the note; absent leaves it.
    #[serde(default, deserialize_with = "double_option")]
    note: Option<Option<String>>,
}

/// Distinguish "absent" from "present and null" in a JSON body.
fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// `PATCH /disks/:id` — pin a disk against expiry, or annotate it.
async fn patch_disk(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(body): Json<DiskPolicyBody>,
) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    let _retention = state.autoscaler.workspaces().lifecycle_guard().await;
    if let Err(e) = store.set_policy(&id, body.retain, body.note) {
        return disk_error(e);
    }
    if let Some(retain) = body.retain {
        tracing::info!(sandbox = %id, retain, "disk retention changed");
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, Default, Deserialize)]
struct ForceQuery {
    #[serde(default)]
    force: Option<String>,
}

impl ForceQuery {
    fn on(&self) -> bool {
        matches!(
            self.force.as_deref().map(str::trim),
            Some("1" | "true" | "yes" | "on")
        )
    }
}

/// `DELETE /disks/:id` — reclaim a sandbox's disks.
///
/// CRUD tier, and the most destructive route app-lb has: it deletes gigabytes
/// with no undo. `?force=1` overrides the "a deployment expects to resume it"
/// and "the daemon is unreachable" guards; it does *not* override the running
/// check, which has no legitimate override.
async fn purge_disk(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(q): Query<ForceQuery>,
) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    match store.purge(&id, q.on()).await {
        Ok(outcome) => Json(outcome).into_response(),
        Err(e) => disk_error(e),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ArchiveBody {
    /// Reclaim the disks once the upload succeeds. Never on failure.
    #[serde(default)]
    purge: bool,
}

/// `POST /disks/:id/archive` — stream a sandbox's disks to S3.
///
/// Answers as soon as the upload starts; progress arrives on `GET /disks`
/// alongside the inventory, which is what the console polls anyway.
async fn archive_disk(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<ArchiveBody>>,
) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    let purge = body.map(|Json(b)| b.purge).unwrap_or(false);
    match store.archive(&id, purge).await {
        Ok(view) => (StatusCode::ACCEPTED, Json(view)).into_response(),
        Err(e) => disk_error(e),
    }
}

/// `POST /disks/sweep` — run the expiry sweep now instead of at the next tick.
async fn sweep_disks(State(state): State<AdminState>) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    Json(store.sweep().await).into_response()
}

/// `POST /disks/purge-orphans` — reclaim every orphaned disk, at any age.
///
/// The sweep's TTL does not apply here; the holds do. A claimed or retained
/// orphan is skipped and counted, and the outcome says so.
async fn purge_orphan_disks(State(state): State<AdminState>) -> Response {
    let Some(store) = state.disks.as_ref() else {
        return disks_off();
    };
    Json(store.purge_orphans().await).into_response()
}

// ---- the directory page -------------------------------------------------

/// One clickable destination.
///
/// A card per *URL* rather than per deployment: a deployment with three
/// hostnames genuinely offers three places to go, and this page exists to be
/// clicked.
struct DirectoryEntry {
    url: String,
    deployment: String,
    kind: &'static str,
    state: EntryState,
    /// What is behind it, in a few words — "2 of 3 VMs ready", "serving /srv/www".
    detail: String,
    /// Behind a sign-in gate. Worth saying before the click rather than after:
    /// following one of these can bounce through the provider, and knowing which
    /// cards will do that is the difference between "slow" and "broken".
    gated: bool,
}

/// Whether following the link right now would reach anything.
#[derive(PartialEq)]
enum EntryState {
    Ready,
    /// Nothing available yet, but a VM is booting — a cold start, not an outage.
    Starting,
    /// Registered and routable with nothing healthy behind it.
    Down,
    /// A site: files on this host, so there is no backend to be up or down.
    Files,
}

impl EntryState {
    fn dot(&self) -> &'static str {
        match self {
            Self::Ready | Self::Files => "ready",
            Self::Starting => "starting",
            Self::Down => "down",
        }
    }
}

/// Collect what the directory shows, narrowed to what this caller may see.
///
/// Returns the linkable entries and, separately, the ids of deployments that are
/// registered but have no URL a browser could be sent to. Those are reported
/// rather than silently omitted: a directory that quietly drops things is worse
/// than one that explains the gap, and "why isn't my deployment listed" has
/// exactly one cause here.
fn directory_entries(
    state: &AdminState,
    scope: Option<&[String]>,
) -> (Vec<DirectoryEntry>, Vec<String>) {
    let deployments = state.registry.deployments();
    let mut entries = Vec::new();
    let mut unlinkable = Vec::new();

    for d in deployments.values() {
        // Both operands are pure reads, so collapsing these is safe.
        if let Some(ids) = scope
            && !ids.iter().any(|id| id.as_str() == d.spec.id.as_str())
        {
            continue;
        }

        let urls: Vec<String> = d
            .spec
            .routes
            .iter()
            .filter_map(|r| state.public_url.of(r))
            .collect();
        if urls.is_empty() {
            unlinkable.push(d.spec.id.clone());
            continue;
        }

        let kind = deployment_kind(d);
        let (entry_state, detail) = match d.spec.backend() {
            // No backend by construction — app-lb answers these itself, so there
            // is nothing that can be down.
            crate::config::Backend::Site => (
                EntryState::Files,
                match d.spec.site.as_ref() {
                    Some(s) => format!("serving {}", s.root),
                    None => "static files".to_string(),
                },
            ),
            crate::config::Backend::Upstreams => {
                let backends = d.backends();
                let up = backends.iter().filter(|b| b.is_available()).count();
                let total = backends.len().max(d.spec.upstreams.len());
                (
                    if up > 0 { EntryState::Ready } else { EntryState::Down },
                    format!("{up} of {total} {} up", plural(total, "upstream")),
                )
            }
            crate::config::Backend::Vm => {
                let backends = d.backends();
                let up = backends.iter().filter(|b| b.is_available()).count();
                let pending = d.pending().len();
                if up > 0 {
                    (
                        EntryState::Ready,
                        format!("{up} {} ready", plural(up, "VM")),
                    )
                } else if pending > 0 {
                    (
                        EntryState::Starting,
                        format!("{pending} {} booting", plural(pending, "VM")),
                    )
                } else if d.spec.scaling.min_replicas == 0 {
                    // Scale-to-zero is the configured state, not a fault: the
                    // first request boots a VM. Saying "down" here would send
                    // somebody debugging a system that is working.
                    (EntryState::Starting, "idle — starts on first request".into())
                } else {
                    (EntryState::Down, "no healthy VMs".into())
                }
            }
        };

        let gated = d.spec.auth.is_some();
        for url in urls {
            entries.push(DirectoryEntry {
                url,
                deployment: d.spec.id.clone(),
                kind,
                state: match entry_state {
                    EntryState::Ready => EntryState::Ready,
                    EntryState::Starting => EntryState::Starting,
                    EntryState::Down => EntryState::Down,
                    EntryState::Files => EntryState::Files,
                },
                detail: detail.clone(),
                gated,
            });
        }
    }

    // Stable order, so a reload does not reshuffle the page under a cursor.
    entries.sort_by(|a, b| a.deployment.cmp(&b.deployment).then(a.url.cmp(&b.url)));
    unlinkable.sort();
    (entries, unlinkable)
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// The cards, as HTML.
///
/// Pure, so the escaping and the empty states are testable without a listener.
/// Every interpolation goes through [`html_escape`] — a deployment id and a
/// hostname are operator-supplied rather than attacker-supplied, but they reach
/// this page from a JSON body over the admin API, which is close enough to
/// untrusted that the distinction is not worth relying on.
fn render_directory_cards(entries: &[DirectoryEntry], unlinkable: &[String]) -> String {
    let note = if unlinkable.is_empty() {
        String::new()
    } else {
        let ids = unlinkable
            .iter()
            .map(|id| format!("<code>{}</code>", html_escape(id)))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "<div class=\"note\">Not shown: {ids} — a route with only a \
             <code>host_suffix</code> or a <code>path_prefix</code> names no single \
             hostname to link to.</div>"
        )
    };

    if entries.is_empty() {
        let body = if unlinkable.is_empty() {
            "Nothing is registered yet. <code>POST /deployments</code>, or \
             <code>heyctl apply</code>, and it appears here."
        } else {
            "No deployment has a linkable hostname."
        };
        return format!("<div class=\"empty\">{body}</div>{note}");
    }

    let cards = entries
        .iter()
        .map(|e| {
            format!(
                "<a class=\"card\" href=\"{url}\">\
                   <div class=\"card-head\">\
                     <span class=\"id\">{id}</span>\
                     {gate}\
                     <span class=\"tag {kind}\">{kind}</span>\
                   </div>\
                   <div class=\"url\">{url}</div>\
                   <div class=\"meta\"><span class=\"dot {dot}\"></span>{detail}</div>\
                 </a>",
                url = html_escape(&e.url),
                id = html_escape(&e.deployment),
                kind = e.kind,
                dot = e.state.dot(),
                detail = html_escape(&e.detail),
                gate = if e.gated {
                    "<span class=\"tag gated\" title=\"Google sign-in required\">sign-in</span>"
                } else {
                    ""
                },
            )
        })
        .collect::<String>();

    format!("<div class=\"grid\">{cards}</div>{note}")
}

/// One line under the title: what this page is showing.
fn directory_lede(entries: &[DirectoryEntry]) -> String {
    if entries.is_empty() {
        return "No deployments are routable yet.".into();
    }
    // Only the deployments these URLs actually came from. Counting the
    // unlinkable ones here would claim URLs across deployments that contributed
    // none; they get their own line under the cards instead.
    let deployments = {
        let mut ids: Vec<&str> = entries.iter().map(|e| e.deployment.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    };
    let down = entries.iter().filter(|e| e.state == EntryState::Down).count();
    let mut s = format!(
        "{} {} across {} {}.",
        entries.len(),
        plural(entries.len(), "URL"),
        deployments,
        plural(deployments, "deployment"),
    );
    if down > 0 {
        s.push_str(&format!(" {down} with nothing healthy behind {}.",
            if down == 1 { "it" } else { "them" }));
    }
    s
}

/// `GET /` — a directory of everything this app-lb routes.
///
/// Server-rendered, unlike `/dashboard`: it is a landing page that should be
/// complete in its first response, work without JavaScript, and not hold a
/// polling connection open. The cards are built per request because the
/// underlying registry changes; the app name is substituted once at startup.
async fn directory(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let scope = visible_ids(&state, caller.as_ref().map(|c| &c.0));
    let (entries, unlinkable) = directory_entries(&state, scope.as_deref());
    let html = render_page(&state, &state.directory_html, &headers)
        .replace("{{LEDE}}", &html_escape(&directory_lede(&entries)))
        .replace("{{CARDS}}", &render_directory_cards(&entries, &unlinkable));
    Html(html)
}

async fn dashboard(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let page = if let Some(axum::Extension(Caller::Federated(grant))) = caller {
        let name = crate::heyo_ui::escape(grant.subject.email.as_deref().unwrap_or(&grant.subject.user_id));
        render_page(&state, &state.dashboard_html.replace("{{WHO}}", &name), &headers)
    } else { render_page(&state, &state.dashboard_html, &headers) };
    let sign_out = if browser_login::session(&headers, &axum::http::Method::GET).ok().flatten().is_some() {
        "<form method=\"post\" action=\"/logout\"><button class=\"btn btn-sm\">Sign out</button></form>"
    } else { "" };
    ([(header::CACHE_CONTROL, "no-store")], Html(page.replace("{{SESSION_ACTION}}", sign_out)))
}

/// Fill the per-request half of a page: the theme, and who is signed in.
///
/// `{{APP_NAME}}` was substituted once at startup — it cannot change — but the
/// theme is a property of the *caller*, and it has to be on the `<html>` tag in
/// the first response or every navigation flashes the wrong palette before
/// script can correct it. One `String` per page render, which is a rounding
/// error next to the JSON these pages then fetch.
fn render_page(state: &AdminState, page: &str, headers: &axum::http::HeaderMap) -> String {
    let cookies = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    // Shown, never trusted. app-lb strips these three before setting them, so
    // behind its own gate they are this process's word — but the admin listener
    // can also be reached directly, so nothing is authorized on them: the
    // dashboard's own gate still decides that.
    let who = crate::heyo_ui::identity_from(|n| headers.get(n).and_then(|v| v.to_str().ok()))
        .map(|i| crate::heyo_ui::escape(i.display()))
        .unwrap_or_default();
    page.replace("{{HTML_ATTRS}}", &state.ui_cookies.attrs(cookies))
        .replace("{{WHO}}", &who)
        .replace("{{HOME_URL}}", &state.home_url.as_deref().map(html_escape).unwrap_or_default())
}

/// `GET /__ui/*path` — the platform stylesheet, theme script and fonts.
///
/// Compiled into the binary and served from the same origin as the page: these
/// dashboards are read over SSH tunnels and from networks with no route out,
/// where a CDN would leave them unstyled.
async fn ui_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match crate::heyo_ui::asset(&path) {
        Some(a) => (
            [
                (axum::http::header::CONTENT_TYPE, a.content_type),
                (
                    axum::http::header::CACHE_CONTROL,
                    crate::heyo_ui::cache_control(&a),
                ),
            ],
            a.bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

/// Log the things a spec is allowed to say but probably didn't mean.
///
/// Not `validate`, because none of these make the spec unservable — refusing
/// them would be app-lb deciding it knows better. Logged at the moment the
/// author can still act on it.
fn warn_about(spec: &DeploymentSpec) {
    let Some(vm) = &spec.vm else { return };
    if spec.scaling.idle_action == crate::config::IdleAction::Retain
        && vm.disk_size_gb.unwrap_or(0) == 0
    {
        tracing::warn!(
            deployment = %spec.id,
            "idle_action is `retain` but the VM has no data disk: the daemon recopies the \
             rootfs from the base image on every boot, so a suspended VM keeps nothing. \
             Set `vm.disk_size_gb` and keep state under /workspace, or this only saves \
             boot time",
        );
    }
}

/// Who pays for `spec`'s VMs, decided by the credential rather than the body.
///
/// A federated caller is a heyo customer, and its deployment is metered to the
/// account that owns the namespace it lands in — the grant says which, and the
/// body is overridden so a client cannot bill its namespace to somebody else.
/// An operator, a local token or an ungated caller keeps what the body said:
/// on a self-hosted app-lb there is no meter, and on the managed one those are
/// the platform's own hands.
/// Fill in the namespace a confined caller could have named but didn't.
///
/// A credential that reaches exactly one namespace should not have to repeat it
/// in every spec: an unnamed spec (which serde parses as the `default`
/// namespace) is taken to mean "my namespace". This never widens what a token
/// can reach — it writes only the one namespace the caller could already have
/// named — and it deliberately leaves an *explicit* namespace alone, so a token
/// confined to `team-a` that writes `team-b` is still refused by the scope check
/// downstream rather than silently rewritten. The one case it cannot serve is a
/// confined token that genuinely wants the literal `default` namespace, which is
/// only reachable by a token actually confined to `default` (a no-op here) —
/// every other confined token is walled out of `default` regardless.
///
/// Runs before `normalize`, so secret refs bind to the assumed namespace, and
/// before `stamp_owner`, so a federated grant meters to the right account.
fn assume_namespace(spec: &mut DeploymentSpec, caller: Option<&Caller>) {
    if spec.namespace == crate::config::DEFAULT_NAMESPACE
        && let Some(sole) = caller.and_then(Caller::sole_namespace)
    {
        spec.namespace = sole.to_string();
    }
}

/// Give a deployment that names no host one of its own: `<id>.<base>`.
///
/// So a deployment need not restate the fleet's domain to be reachable: with a
/// base domain configured (an explicit one, else the wildcard zone that already
/// has a certificate and DNS pointing here — see
/// [`LbConfig::deploy_host_base`]), a spec that pins no hostname gets a route to
/// `<id>.<base>`. Ids are globally unique, so the name is too.
///
/// Two shapes are left exactly as written:
/// - one that already pins a `host` or `host_suffix` — there is nothing to
///   assume; and
/// - a *routeless VM*, the intentional headless-sandbox shape reached only
///   through `exec`/`shell`. A VM earns a host only once it exposes a port with
///   a route (even a path-only one); every other backend is unreachable without
///   a route, so a routeless site or static deployment does get one rather than
///   being dead weight.
///
/// Runs before `validate`, so the generated route is checked like any other and
/// an auth callback resolves against it. Off entirely when no base is
/// configured, leaving a hostless deployment to be handled exactly as before.
///
/// [`LbConfig::deploy_host_base`]: crate::config::LbConfig::deploy_host_base
fn assume_host(spec: &mut DeploymentSpec, base: Option<&str>) {
    let Some(base) = base else { return };
    // A pinned hostname is respected; an empty id is left for `validate` to
    // reject rather than baked into a nonsense `.base` name.
    if spec.has_host_route() || spec.id.trim().is_empty() {
        return;
    }
    // A routeless VM is private on purpose. Any other backend, or a VM that has
    // exposed a port with a route, is reached through the proxy and gets a name.
    if spec.routes.is_empty() && spec.vm.is_some() {
        return;
    }
    spec.routes.push(crate::config::RouteRule {
        host: Some(format!("{}.{}", spec.id.trim(), base)),
        ..Default::default()
    });
}

/// A site that names no `root` gets one app-lb manages:
/// `<APP_LB_SITES_DIR>/<namespace>/<id>`. The caller cannot know this host's
/// filesystem, and a root guessed from somewhere else is the mistake that
/// registers and then 404s every request. With no sites dir configured the
/// empty root is left for `validate` to refuse.
fn assume_site_root(spec: &mut DeploymentSpec, sites_dir: Option<&std::path::Path>) {
    let (Some(dir), Some(site)) = (sites_dir, spec.site.as_mut()) else { return };
    if !site.root.trim().is_empty() || spec.id.trim().is_empty() {
        return;
    }
    let ns = if spec.namespace.trim().is_empty() { crate::config::DEFAULT_NAMESPACE } else { spec.namespace.trim() };
    site.root = dir.join(ns).join(spec.id.trim()).display().to_string();
}

pub(crate) fn stamp_owner(spec: &mut DeploymentSpec, caller: Option<&Caller>) {
    if let Some(Caller::Federated(g)) = caller {
        spec.account_id = g.account_for(&spec.namespace).map(str::to_string);
        spec.user_id = Some(g.subject.user_id.clone());
    }
}

/// A strong validator for the complete, normalized spec as represented on the
/// wire. Explicitly sort every object: serde_json's `preserve_order` feature
/// can be enabled transitively and must not change the validator protocol.
fn deployment_etag(spec: &DeploymentSpec) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(spec)?;
    value.sort_all_objects();
    let bytes = serde_json::to_vec(&value)?;
    Ok(format!("\"{:x}\"", Sha256::digest(bytes)))
}

/// Accept only the one conditional-update form app-lb implements: one exact,
/// strong tag emitted by `GET`. Lists, wildcards and weak validators have
/// semantics this endpoint does not promise and are rejected rather than
/// approximated.
fn if_match(headers: &axum::http::HeaderMap) -> Result<Option<&str>, Response> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err(err(StatusCode::BAD_REQUEST, "If-Match must contain exactly one strong ETag").into_response());
    }
    let value = value.to_str().map_err(|_| {
        err(StatusCode::BAD_REQUEST, "If-Match is not a valid HTTP header value").into_response()
    })?;
    let valid = value.len() == 66
        && value.starts_with('"')
        && value.ends_with('"')
        && value[1..65].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "If-Match must be one quoted lowercase SHA256 ETag from GET /deployments/:id",
        ).into_response());
    }
    Ok(Some(value))
}

fn check_etag_precondition(expected: Option<&str>, current: &DeploymentSpec) -> Result<(), StatusCode> {
    let Some(expected) = expected else { return Ok(()) };
    let current = deployment_etag(current).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if expected == current {
        Ok(())
    } else {
        Err(StatusCode::PRECONDITION_FAILED)
    }
}

fn discovery_route_conflicts(registry: &Registry, spec: &DeploymentSpec) -> bool {
    spec.routes.iter().any(|new| {
        let Some(host) = new.host.as_deref() else { return true };
        let prefix = new.path_prefix.as_deref().unwrap_or("/");
        registry.deployments().values().any(|d| d.spec.routes.iter().any(|old| {
            let old_prefix = old.path_prefix.as_deref().unwrap_or("/");
            old.matches(Some(host), old_prefix)
                && (prefix.starts_with(old_prefix) || old_prefix.starts_with(prefix))
        }))
    })
}

async fn register(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    headers: axum::http::HeaderMap,
    Json(mut spec): Json<DeploymentSpec>,
) -> impl IntoResponse {
    let create_only = match headers.get(axum::http::header::IF_NONE_MATCH) {
        None => false,
        Some(value) if value == "*" => true,
        Some(_) => return err(StatusCode::BAD_REQUEST, "If-None-Match must be *").into_response(),
    };
    // A namespace token may omit the namespace and have its own filled in.
    // Runs first, so the assumed namespace is what secret refs bind to.
    assume_namespace(&mut spec, caller.as_ref().map(|c| &c.0));
    // A spec that pins no hostname gets `<id>.<base>`, so a route is checked
    // and an auth callback resolves against it below.
    assume_host(&mut spec, state.deploy_base_domain.as_deref());
    assume_site_root(&mut spec, state.jobs.sites_dir());
    // Bind secret references to the spec's namespace before anything reads
    // them; see `DeploymentSpec::normalize`.
    spec.normalize();
    // Validation is the gate that keeps unroutable VMs (e.g. libvirt, which has
    // no guest_ip) from ever being booted.
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(refused) = check_provider_ref(&state, &spec) {
        return refused;
    }
    warn_about(&spec);

    let id = spec.id.clone();

    // A namespace token creates inside its own wall or not at all. Checked
    // against the *replaced* deployment too: `POST` with an existing id is a
    // replace, and without that check a namespace token could capture another
    // namespace's deployment by re-registering its id.
    //
    // The two refusals answer identically, and deliberately so — but note what
    // that does and does not buy, because an earlier version of this comment
    // claimed more than was true.
    //
    // `taken_elsewhere` is decided by a deployment the caller cannot see, so its
    // refusal must not describe the caller's *own* namespace: saying "cannot
    // register in sam" to a token confined to sam is both false and a signal
    // that something invisible was consulted. Instead both cases answer with the
    // same 403 the gate gives for any deployment outside the caller's scope
    // (`decide_access`), so `POST`, `PUT`, `GET` and `DELETE` on an id owned by
    // another namespace are byte-for-byte identical, and no route's body says
    // more than the others.
    //
    // What that does NOT close is the status code: a create that is refused is
    // 403 and one that succeeds is 201, so a confined caller can still learn
    // whether a guessed id is taken somewhere in the fleet. That bit is
    // irreducible while deployment ids are globally unique — the same reason a
    // signup form reveals which usernames exist — and closing it means scoping
    // the id space per namespace, not rewording an error. Everything the body
    // could leak is closed here; the rest is a data-model decision.
    if let Some(c) = caller.as_ref().map(|c| &c.0).filter(|c| c.confined()) {
        let taken_elsewhere = state
            .registry
            .get(&id)
            .is_some_and(|old| !c.reaches_namespace(&old.spec.namespace));
        if !c.reaches_namespace(&spec.namespace)
            || !c.satisfies_in(crate::tokens::AdminScope::Admin, Some(&spec.namespace))
            || taken_elsewhere
        {
            return err(StatusCode::FORBIDDEN, out_of_scope(&id)).into_response();
        }
    }
    stamp_owner(&mut spec, caller.as_ref().map(|c| &c.0));
    // Replacing a deployment abandons its old pool; tear it down explicitly so
    // the VMs don't linger until their TTL.
    //
    // For a workspace, first drain the autoscaler's create slots and persist a
    // stale-seed fence. The registry swap still precedes teardown, so the old
    // object cannot create orphan VMs; the fence keeps the newly exposed object
    // from booting until teardown's final old-state capture has published.
    let change = state.registry.change_guard().await;
    let old = state.registry.get(&id);
    if state.registry.retirement_frozen(&id) {
        return err(StatusCode::CONFLICT,"deployment permanently frozen for retirement").into_response();
    }
    if create_only && old.is_some() {
        return err(StatusCode::PRECONDITION_FAILED, "deployment already exists").into_response();
    }
    if create_only && spec.discovery.is_some() && discovery_route_conflicts(&state.registry, &spec) {
        return err(StatusCode::CONFLICT, "discovery bootstrap needs an unclaimed exact-host route").into_response();
    }
    if old.as_ref().is_some_and(|d| crate::rollout::reserved(d)) {
        return err(StatusCode::CONFLICT, "candidate rollout reserves this deployment").into_response();
    }
    if state.autoscaler.workspaces().recovery_active(&id) {
        return err(StatusCode::CONFLICT, "workspace recovery reserves this deployment").into_response();
    }
    let replaced = old.is_some();
    let workspace_replacement = match &old {
        Some(old) => match state.autoscaler.fence_workspace_replacement(old).await {
            Ok(fence) => fence,
            Err(message) => return err(StatusCode::SERVICE_UNAVAILABLE, message).into_response(),
        },
        None => None,
    };
    let deployment = state.registry.upsert(spec);
    if let Err(e) = state.registry.persist_one(&id) {
        tracing::error!(deployment = %id, error = %e, "failed to persist state");
        if create_only {
            state.registry.remove(&id);
            return err(StatusCode::INTERNAL_SERVER_ERROR, "failed to persist new deployment").into_response();
        }
    }
    drop(change);
    if let Some(old) = old {
        state.autoscaler.teardown(&old).await;
    }
    if let Some(fence) = workspace_replacement {
        fence.finish();
    }
    tracing::info!(deployment = %id, "registered");
    state.feed.announce(
        &deployment.spec,
        if replaced { crate::feed::FeedEventKind::Updated } else { crate::feed::FeedEventKind::Deployed },
        lifecycle_detail(&state, &deployment.spec),
        now_secs(),
    );

    // Let the autoscaler build the warm pool without waiting for the next tick.
    deployment.scale_signal.notify_one();
    // ...and let ACME start issuing for any new hostname. Asynchronous: this
    // response does not wait for a certificate.
    state.nudge_acme();
    // A deployment with unpulled mounts has nothing to boot until they are on
    // this host, so the job that puts them there starts with the registration.
    pull_mounts_if_needed(&state, &deployment.spec);

    (StatusCode::CREATED, Json(status_of(&state, &deployment))).into_response()
}

/// Edit a deployment in place: `PUT /deployments/:id`.
///
/// The whole spec is replaced (the path id wins, so the body's id can't retarget
/// another deployment). The pool is preserved when the VM *template* is
/// unchanged — a scaling/route/health edit never disturbs running VMs; only a
/// change to the `vm` block reboots them, because the existing VMs were built
/// from the old template.
async fn update(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    caller: Option<axum::Extension<Caller>>,
    headers: axum::http::HeaderMap,
    Json(mut spec): Json<DeploymentSpec>,
) -> impl IntoResponse {
    let expected_etag = match if_match(&headers) {
        Ok(value) => value.map(str::to_owned),
        Err(response) => return response,
    };
    spec.id = id.clone();
    // A namespace token may omit the namespace and have its own filled in,
    // rather than trip the cross-namespace refusal below with an unnamed spec.
    assume_namespace(&mut spec, caller.as_ref().map(|c| &c.0));
    // A spec that pins no hostname gets `<id>.<base>`, as at registration.
    assume_host(&mut spec, state.deploy_base_domain.as_deref());
    assume_site_root(&mut spec, state.jobs.sites_dir());
    spec.normalize();
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(refused) = check_provider_ref(&state, &spec) {
        return refused;
    }
    warn_about(&spec);

    // The gate already established the caller may touch this deployment; what
    // it cannot see is the body. A namespace token must not *move* a
    // deployment: writing another namespace into the spec would walk it out
    // through the wall the token is behind.
    if let Some(c) = caller.as_ref().map(|c| &c.0).filter(|c| c.confined())
        && !c.reaches_namespace(&spec.namespace)
    {
        return err(
            StatusCode::FORBIDDEN,
            format!(
                "this credential is confined to its namespaces and cannot move a deployment to \
                 \"{}\"",
                spec.namespace
            ),
        )
        .into_response();
    }

    stamp_owner(&mut spec, caller.as_ref().map(|c| &c.0));
    let response_etag = match deployment_etag(&spec) {
        Ok(etag) => etag,
        Err(e) => {
            tracing::error!(deployment = %id, error = %e, "failed to serialize deployment ETag");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "failed to serialize deployment ETag").into_response();
        }
    };
    let change = state.registry.change_guard().await;
    let Some(old) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if crate::rollout::reserved(&old) {
        return err(StatusCode::CONFLICT, "candidate rollout reserves this deployment").into_response();
    }
    // Compare while holding the same writer guard that covers fencing, the
    // registry swap, persistence and teardown scheduling. A stale request must
    // leave all of those untouched.
    if state.autoscaler.workspaces().recovery_active(&id) {
        return err(StatusCode::CONFLICT, "workspace recovery reserves this deployment").into_response();
    }
    if let Err(status) = check_etag_precondition(expected_etag.as_deref(), &old.spec) {
        let message = if status == StatusCode::PRECONDITION_FAILED {
            "If-Match does not match the current deployment spec"
        } else {
            "failed to serialize deployment ETag"
        };
        return err(status, message).into_response();
    }

    // The owner is not part of the template, so a stamp never recycles a pool.
    let rebuild = old.spec.vm != spec.vm || old.spec.upstreams != spec.upstreams;
    let workspace_replacement = if rebuild {
        match state.autoscaler.fence_workspace_replacement(&old).await {
            Ok(fence) => fence,
            Err(message) => return err(StatusCode::SERVICE_UNAVAILABLE, message).into_response(),
        }
    } else {
        None
    };
    let deployment = if rebuild {
        // The backend set changed — a managed VM *template*, or a static
        // deployment's upstream list (or a switch between the two kinds). The
        // running backends no longer match the spec, so rebuild from scratch
        // (`teardown` is a no-op-that-clears-routing for the static kind).
        //
        // Fence, swap, then tear down: see the note in `register`.
        tracing::info!(deployment = %id, "updating deployment (backends changed; rebuilding)");
        state.registry.upsert(spec)
    } else {
        // Scaling/routes/health only: keep the pool live.
        tracing::info!(deployment = %id, "updating deployment (pool preserved)");
        match state.registry.update(spec) {
            Some(d) => d,
            None => return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response(),
        }
    };

    if let Err(e) = state.registry.persist_one(&id) {
        tracing::error!(deployment = %id, error = %e, "failed to persist state");
    }
    drop(change);
    if rebuild {
        state.autoscaler.teardown(&old).await;
    }
    if let Some(fence) = workspace_replacement {
        fence.finish();
    }
    // Reconcile to the new policy immediately (scale up/down, warm pool).
    deployment.scale_signal.notify_one();
    // An edit can introduce a hostname, so this needs the same nudge as
    // registration.
    state.nudge_acme();
    // An edit can also introduce a mount, or move one to a ref this host has
    // never pulled.
    pull_mounts_if_needed(&state, &deployment.spec);
    state.feed.announce(
        &deployment.spec,
        crate::feed::FeedEventKind::Updated,
        lifecycle_detail(&state, &deployment.spec),
        now_secs(),
    );

    ([(header::ETAG, response_etag)], Json(status_of(&state, &deployment))).into_response()
}

/// Manually scale a deployment: `PATCH /deployments/:id/scaling`.
///
/// The body is a partial `ScalingPolicy` — only the fields present are changed,
/// the rest are kept — so the dashboard can send just `{min_replicas, ...}`
/// without resetting the timeouts it doesn't show. Never touches the VM
/// template, so the pool is always preserved; the autoscaler grows or drains it
/// to match the new policy on the nudge.
async fn scale(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(patch): Json<serde_json::Value>,
) -> impl IntoResponse {
    let _change = state.registry.change_guard().await;
    let Some(old) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if crate::rollout::reserved(&old) {
        return err(StatusCode::CONFLICT, "candidate rollout reserves this deployment").into_response();
    }

    // Only a managed deployment is autoscaled; for the others the scaling policy
    // is inert, so a scale request is a mistake rather than a no-op.
    if state.autoscaler.workspaces().recovery_active(&id) {
        return err(StatusCode::CONFLICT, "workspace recovery reserves this deployment").into_response();
    }
    if !old.spec.is_managed() {
        let fix = if old.spec.is_site() {
            "a site serves files off disk and has nothing to scale"
        } else {
            "edit its `upstreams` via PUT instead"
        };
        return err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} has no VM pool and cannot be scaled; {fix}"),
        )
        .into_response();
    }

    let Some(patch) = patch.as_object() else {
        return err(StatusCode::BAD_REQUEST, "scaling patch must be a JSON object").into_response();
    };

    // Merge the patch onto the current policy, then re-parse so unknown/typed
    // fields are validated by serde.
    let mut merged = match serde_json::to_value(&old.spec.scaling) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not read scaling policy").into_response(),
    };
    for (k, v) in patch {
        merged.insert(k.clone(), v.clone());
    }
    let scaling: crate::config::ScalingPolicy = match serde_json::from_value(serde_json::Value::Object(merged)) {
        Ok(s) => s,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid scaling policy: {e}")).into_response(),
    };

    let mut spec = old.spec.clone();
    spec.scaling = scaling;
    // Catches min > max, zero target_concurrency, etc.
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let Some(deployment) = state.registry.update(spec) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if let Err(e) = state.registry.persist_one(&id) {
        tracing::error!(deployment = %id, error = %e, "failed to persist state");
    }
    tracing::info!(deployment = %id, "scaled");
    deployment.scale_signal.notify_one();

    Json(status_of(&state, &deployment)).into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    /// Keep only deployments in this namespace. A filter, not authorization —
    /// the caller's own narrowing has already happened by the time it applies.
    #[serde(default)]
    namespace: Option<String>,
}

async fn list(
    State(state): State<AdminState>,
    Query(q): Query<ListQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    // Only a namespace token reaches here scoped (the gate refuses
    // deployment-list tokens on this route), and it gets the narrowed answer.
    let scope = visible_ids(&state, caller.as_ref().map(|c| &c.0));
    let deployments = state.registry.deployments();
    let mut out: Vec<_> = deployments
        .values()
        .filter(|d| {
            scope
                .as_deref()
                .is_none_or(|s| s.iter().any(|id| id == &d.spec.id))
        })
        .filter(|d| q.namespace.as_ref().is_none_or(|ns| &d.spec.namespace == ns))
        .map(|d| status_of(&state, d))
        .collect();
    out.sort_by(|a, b| a.spec.id.cmp(&b.spec.id));
    ([("x-app-lb-create-only", "1"), ("x-app-lb-discovery-source", "1"),
        ("x-app-lb-discovery-region", "1"), ("x-app-lb-gateway", "1"),
        ("x-app-lb-regional-admission", "1")], Json(out))
}

async fn get_one(State(state): State<AdminState>, Path(id): Path<String>) -> impl IntoResponse {
    let _change = state.registry.change_guard().await;
    if let Some(d) = state.registry.get(&id) {
        if d.state().rollout_revision.is_empty() { d.mutate_state(|s| s.rollout_revision = crate::rollout::revision()); }
    }
    if state.registry.get(&id).is_some() && !state.registry.get(&id).is_some_and(|d| crate::rollout::reserved(&d)) {
        if state.registry.persist_one(&id).is_err() {
            return err(StatusCode::SERVICE_UNAVAILABLE, "could not persist rollout revision").into_response();
        }
    }
    match state.registry.get(&id) {
        Some(d) => match deployment_etag(&d.spec) {
            Ok(etag) => ([(header::ETAG, etag)], Json(status_of(&state, &d))).into_response(),
            Err(e) => {
                tracing::error!(deployment = %id, error = %e, "failed to serialize deployment ETag");
                err(StatusCode::INTERNAL_SERVER_ERROR, "failed to serialize deployment ETag").into_response()
            }
        },
        None => err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response(),
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DiscoveryStatusResponse {
    service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_url: Option<String>,
    version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regional: Option<serde_json::Value>,
    upstreams: Vec<DiscoveryUpstreamStatus>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DiscoveryUpstreamStatus {
    peer: String,
    draining: bool,
    in_flight: usize,
}

fn discovery_status_locked(
    registry: &Registry,
    id: &str,
) -> Result<DiscoveryStatusResponse, Response> {
    discovery_target_status_locked(registry, id, false)
}

fn discovery_target_status_locked(
    registry: &Registry,
    id: &str,
    staged: bool,
) -> Result<DiscoveryStatusResponse, Response> {
    let Some(deployment) = (if staged { registry.staged(id) } else { registry.get(id) }) else {
        return Err(
            err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response(),
        );
    };
    let Some(discovery) = deployment.spec.discovery.as_ref() else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} is not discovery-backed"),
        )
        .into_response());
    };
    let mut upstreams: BTreeMap<String, (bool, usize)> = BTreeMap::new();
    let backends = if staged { deployment.backends().iter().cloned().collect() } else { registry.discovery_backends(id) };
    for backend in backends {
        let value = upstreams.entry(backend.peer.clone()).or_insert((true, 0));
        value.0 &= backend.is_draining();
        value.1 += backend.in_flight();
    }
    Ok(DiscoveryStatusResponse {
        service_id: discovery.service_id.clone(),
        source_url: deployment.state().discovery_source_url.clone(),
        version: deployment.state().discovery_version,
        regional: deployment.regional.as_ref().zip(discovery.regional.as_ref())
            .map(|(router, spec)| {
                let mut status = router.status(spec, !deployment.spec.maintenance);
                let host = deployment.spec.routes.first().and_then(|r| r.host.as_deref()).unwrap_or("");
                let conflict = registry.deployments().values().any(|other| other.spec.id != id
                    && other.spec.routes.iter().any(|r| r.matches(Some(host), r.path_prefix.as_deref().unwrap_or("/"))));
                status["admission"] = serde_json::json!({"protocolVersion":1,"environment":spec.environment,
                    "region":discovery.region,"backendServerId":spec.backend_server_id,"namespace":deployment.spec.namespace,
                    "routes":deployment.spec.routes,"sourceUrl":discovery.source.as_ref().map(|s| &s.url),
                    "routeConflict":conflict,"maintenance":deployment.spec.maintenance,"credentialsReady":false});
                status
            }),
        upstreams: upstreams
            .into_iter()
            .map(|(peer, (draining, in_flight))| DiscoveryUpstreamStatus {
                peer,
                draining,
                in_flight,
            })
            .collect(),
    })
}

/// Observed discovery state. The registry mutation gate makes the durable
/// version and all live/retired generation counters one coherent observation.
#[derive(Default, Deserialize)]
struct DiscoveryTarget {
    #[serde(default)]
    staged: bool,
}

async fn discovery_status(State(state): State<AdminState>, Path(id): Path<String>, Query(target): Query<DiscoveryTarget>) -> Response {
    let _change = state.registry.change_guard().await;
    let status = if target.staged { discovery_target_status_locked(&state.registry, &id, true) }
        else { discovery_status_locked(&state.registry, &id) };
    match status {
        Ok(mut status) => {
            if let Some(deployment) = (if target.staged { state.registry.staged(&id) } else { state.registry.get(&id) }) {
                if let Some(spec) = deployment.spec.discovery.as_ref().and_then(|d| d.regional.as_ref()) {
                    let ready = state.secrets.resolve(&spec.auth).is_ok_and(|token|
                        !token.is_empty() && http::HeaderValue::from_str(&token).is_ok())
                        && deployment.spec.discovery.as_ref().and_then(|d| d.source.as_ref()).is_some_and(|source|
                            state.secrets.resolve(&source.auth).is_ok_and(|token| !token.trim().is_empty()
                                && http::HeaderValue::from_str(&token).is_ok()));
                    if let Some(regional) = &mut status.regional {
                        regional["admission"]["credentialsReady"] = serde_json::json!(ready);
                    }
                    if !ready {
                        if let Some(report) = status.regional.as_mut().and_then(|r| r.get_mut("report")).filter(|r| r.is_object()) {
                            report["prepared"] = serde_json::json!(false);
                        }
                    }
                }
            }
            ([(header::CACHE_CONTROL, "no-store")], Json(status)).into_response()
        }
        Err(response) => response,
    }
}

/// An authenticated control-plane request makes this gateway exercise the
/// destination's HTTPS peer path. Peer credentials never leave the gateway.
async fn regional_probe(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>, Json(request): Json<crate::regional::ProbeRequest>) -> Response {
    let Some(deployment) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND,"deployment not found").into_response();
    };
    if !recovery_authorized(&caller,&deployment.spec) {
        return forbidden("authenticated namespace admin required");
    }
    if deployment.spec.maintenance { return err(StatusCode::CONFLICT,"gateway is in maintenance").into_response(); }
    let (Some(router),Some(discovery)) = (&deployment.regional,&deployment.spec.discovery) else {
        return err(StatusCode::CONFLICT,"regional gateway required").into_response();
    };
    let host = deployment.spec.routes.first().and_then(|r| r.host.as_deref()).unwrap_or("");
    match router.probe_remote(discovery.regional.as_ref().unwrap(),&discovery.service_id,&request,
        host,&deployment.spec.health,&state.secrets).await {
        Ok(()) => ([(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"request":request,"sourceBootId":router.boot_id}))).into_response(),
        Err(code) => err(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),"candidate probe refused or unhealthy").into_response(),
    }
}

/// Read-only readiness of currently eligible capacity, independent of a pending
/// proposal's owner. Namespace admin authorization does not authorize a rollout.
async fn regional_active_probe(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>, Json(request): Json<crate::regional::ActiveProbeRequest>) -> Response {
    let Some(deployment) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND,"deployment not found").into_response();
    };
    if !recovery_authorized(&caller,&deployment.spec) {return forbidden("authenticated namespace admin required");}
    if deployment.spec.maintenance {return err(StatusCode::CONFLICT,"gateway is in maintenance").into_response();}
    let (Some(router),Some(discovery)) = (&deployment.regional,&deployment.spec.discovery) else {
        return err(StatusCode::CONFLICT,"regional gateway required").into_response();
    };
    let spec = discovery.regional.as_ref().unwrap();
    let host = deployment.spec.routes.first().and_then(|r| r.host.as_deref()).unwrap_or("");
    match router.active_probe_remote(spec,&discovery.service_id,&request,host,&deployment.spec.health,&state.secrets).await {
        Ok(receipt) => ([(header::CACHE_CONTROL,"no-store")],Json(serde_json::json!({"request":request,
            "sourceGatewayId":spec.gateway_id,"sourceBootId":router.boot_id,"destination":receipt}))).into_response(),
        Err(code) => err(StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),"active capacity probe refused or unhealthy").into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrepareRouteHandoff {
    operation_id: String,
    expected_predecessor_fingerprint: String,
    staged_spec: DeploymentSpec,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitRouteHandoff { operation_id: String }

fn handoff_response(result: Result<crate::registry::RouteHandoffRecord, crate::registry::HandoffError>) -> Response {
    match result {
        Ok(receipt) => ([(header::CACHE_CONTROL,"no-store")], Json(receipt)).into_response(),
        Err(crate::registry::HandoffError::NotFound) => err(StatusCode::NOT_FOUND,"deployment not found").into_response(),
        Err(crate::registry::HandoffError::Conflict(message)) => err(StatusCode::CONFLICT,message).into_response(),
        Err(crate::registry::HandoffError::Io(error)) => {
            tracing::error!(%error,"failed to persist route handoff");
            err(StatusCode::SERVICE_UNAVAILABLE,"could not durably record route handoff").into_response()
        }
    }
}

fn fleet_handoff_authorized(caller: &Caller) -> bool {
    !matches!(caller, Caller::Ungated) && caller.covers_fleet()
        && caller.satisfies_in(crate::tokens::AdminScope::Admin, None)
}

async fn prepare_route_handoff(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>, Json(mut request): Json<PrepareRouteHandoff>) -> Response {
    if !fleet_handoff_authorized(&caller) { return forbidden("authenticated fleet admin required"); }
    if request.operation_id.is_empty() || request.operation_id.len() > 256 {
        return err(StatusCode::BAD_REQUEST,"operationId must be a bounded non-empty identity").into_response();
    }
    request.staged_spec.id = id.clone();
    request.staged_spec.normalize();
    let _change = state.registry.change_guard().await;
    let result = state.registry.prepare_handoff(&request.operation_id,
        &request.expected_predecessor_fingerprint, request.staged_spec);
    if result.is_ok() {
        // A retry after discovery has prepared the hidden runtime upgrades the
        // durable receipt. Failure means it remains safely in preparing.
        if state.registry.staged(&id).and_then(|d| d.regional.as_ref()
            .and_then(|r| r.preparation(!d.spec.maintenance))).is_some_and(|p| p.prepared && p.adopted) {
            return handoff_response(state.registry.mark_handoff_prepared(&id));
        }
    }
    handoff_response(result)
}

async fn inspect_route_handoff(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>) -> Response {
    if !fleet_handoff_authorized(&caller) { return forbidden("authenticated fleet admin required"); }
    let _change = state.registry.change_guard().await;
    match state.registry.inspect_handoff(&id) {
        Some(receipt) => ([(header::CACHE_CONTROL,"no-store")],Json(receipt)).into_response(),
        None => err(StatusCode::NOT_FOUND,"route handoff not found").into_response(),
    }
}

async fn commit_route_handoff(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>, Json(request): Json<CommitRouteHandoff>) -> Response {
    if !fleet_handoff_authorized(&caller) { return forbidden("authenticated fleet admin required"); }
    let _change = state.registry.change_guard().await;
    handoff_response(state.registry.commit_handoff(&id,&request.operation_id))
}

const MAX_DRAIN_REASON_LEN: usize = 512;

/// Optional operator context for a static-upstream drain.
#[derive(Debug, Default, Deserialize)]
struct DrainUpstreamRequest {
    /// Override the safety check that requires another healthy, accepting
    /// upstream. Explicit because this can take the deployment fully offline.
    #[serde(default)]
    force: bool,
    /// Stored with the drain so a later operator can tell why it exists.
    reason: Option<String>,
}

/// The administrative and live state of one static upstream.
#[derive(Serialize)]
struct UpstreamTrafficResponse {
    deployment_id: String,
    upstream: String,
    /// `accepting`, `draining` (requests remain), or `drained` (zero in flight).
    state: &'static str,
    healthy: bool,
    in_flight: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<u64>,
}

fn upstream_traffic_status(
    deployment: &Arc<crate::deployment::Deployment>,
    upstream: &str,
) -> UpstreamTrafficResponse {
    let drain = deployment.upstream_drain(upstream);
    let backends = deployment.backends();
    let matching: Vec<_> = backends
        .iter()
        .filter(|backend| backend.peer == upstream)
        .collect();
    let in_flight = matching.iter().map(|backend| backend.in_flight()).sum();
    let state = if drain.is_none() {
        "accepting"
    } else if in_flight == 0 {
        "drained"
    } else {
        "draining"
    };
    UpstreamTrafficResponse {
        deployment_id: deployment.spec.id.clone(),
        upstream: upstream.to_string(),
        state,
        healthy: matching.iter().all(|backend| backend.is_healthy()),
        in_flight,
        reason: drain.as_ref().and_then(|drain| drain.reason.clone()),
        started_at: drain.map(|drain| drain.started_at),
    }
}

/// Uber's drain-safety invariant in app-lb's smaller model: never withdraw the
/// last technically healthy destination unless the operator explicitly forces
/// it. Health and drain are separate — a failed probe cannot erase intent.
fn has_healthy_alternative(
    deployment: &crate::deployment::Deployment,
    upstream: &str,
) -> bool {
    deployment
        .backends()
        .iter()
        .any(|backend| backend.peer != upstream && backend.is_available())
}

fn normalized_drain_reason(reason: Option<String>) -> Result<Option<String>, Response> {
    let reason = reason
        .map(|reason| reason.trim().to_string())
        .filter(|reason| !reason.is_empty());
    if reason.as_ref().is_some_and(|reason| reason.len() > MAX_DRAIN_REASON_LEN) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("drain reason must be at most {MAX_DRAIN_REASON_LEN} bytes"),
        )
        .into_response());
    }
    Ok(reason)
}

/// Publish the cordon before attempting persistence. If any durability step
/// fails, the caller reports the error but the live backend remains closed to
/// new traffic; reverting it could disagree with a rename that already landed.
fn apply_upstream_drain(
    registry: &Registry,
    deployment: &crate::deployment::Deployment,
    id: &str,
    upstream: &str,
    reason_was_supplied: bool,
    reason: Option<String>,
) -> std::io::Result<()> {
    deployment.mutate_state(|runtime| {
        if let Some(drain) = runtime
            .upstream_drains
            .iter_mut()
            .find(|drain| drain.upstream == upstream)
        {
            if reason_was_supplied {
                drain.reason = reason.clone();
            }
        } else {
            runtime.upstream_drains.push(UpstreamDrain {
                upstream: upstream.to_string(),
                reason,
                started_at: now_secs(),
            });
            runtime
                .upstream_drains
                .sort_by(|left, right| left.upstream.cmp(&right.upstream));
        }
    });
    registry.persist_one(id)
}

/// Stop assigning new requests to a static upstream while existing requests
/// finish. The intent is persisted before the request succeeds.
async fn drain_upstream(
    State(state): State<AdminState>,
    Path((id, upstream)): Path<(String, String)>,
    Json(request): Json<DrainUpstreamRequest>,
) -> Response {
    // The registry-level guard is stable across deployment replacement. It
    // keeps the safety check, live mutation, and persisted record one operation.
    let _change = state.registry.change_guard().await;
    let Some(deployment) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if !deployment.spec.is_static() {
        return err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} has no static upstreams to drain"),
        )
        .into_response();
    }
    if !deployment
        .backends()
        .iter()
        .any(|backend| backend.peer == upstream)
    {
        return err(
            StatusCode::NOT_FOUND,
            format!("no upstream {upstream:?} in deployment {id:?}"),
        )
        .into_response();
    }

    let reason_was_supplied = request.reason.is_some();
    let reason = match normalized_drain_reason(request.reason) {
        Ok(reason) => reason,
        Err(response) => return response,
    };

    let existing = deployment.upstream_drain(&upstream);
    if existing.is_none()
        && !request.force
        && !has_healthy_alternative(&deployment, &upstream)
    {
        return err(
            StatusCode::CONFLICT,
            format!(
                "refusing to drain upstream {upstream:?}: deployment {id:?} has no other healthy, \
                 accepting upstream; retry with force=true only if taking it offline is intended"
            ),
        )
        .into_response();
    }

    if let Err(error) = apply_upstream_drain(
        &state.registry,
        &deployment,
        &id,
        &upstream,
        reason_was_supplied,
        reason,
    ) {
        // Fail closed. The rename may already have committed before a later
        // fsync reported an error, so restoring the accepting state could
        // disagree with disk and would reopen traffic during a storage fault.
        // A retry is idempotent and can confirm durability later.
        tracing::error!(deployment = %id, %upstream, %error, "failed to persist upstream drain");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "upstream is cordoned, but drain durability could not be confirmed: {error}"
            ),
        )
        .into_response();
    }

    let response = upstream_traffic_status(&deployment, &upstream);
    tracing::info!(
        deployment = %id,
        %upstream,
        force = request.force,
        in_flight = response.in_flight,
        reason = ?response.reason,
        "static upstream cordoned; draining existing traffic",
    );
    let status = if response.in_flight == 0 {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    (status, Json(response)).into_response()
}

/// Remove a durable static-upstream drain. A healthy target becomes eligible
/// immediately; an unhealthy one remains excluded by the independent probe.
async fn uncordon_upstream(
    State(state): State<AdminState>,
    Path((id, upstream)): Path<(String, String)>,
) -> Response {
    let _change = state.registry.change_guard().await;
    let Some(deployment) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if !deployment.spec.is_static() {
        return err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} has no static upstreams to uncordon"),
        )
        .into_response();
    }
    if !deployment
        .backends()
        .iter()
        .any(|backend| backend.peer == upstream)
    {
        return err(
            StatusCode::NOT_FOUND,
            format!("no upstream {upstream:?} in deployment {id:?}"),
        )
        .into_response();
    }

    // Persist before publishing the accepting state. If the write fails, the
    // live backend remains cordoned and no request can slip through a failed
    // control-plane operation.
    let mut next = (*deployment.state()).clone();
    next.upstream_drains
        .retain(|drain| drain.upstream != upstream);
    if let Err(error) = state.registry.persist_snapshot(&deployment, &next) {
        tracing::error!(deployment = %id, %upstream, %error, "failed to persist upstream uncordon");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("upstream uncordon was not saved: {error}"),
        )
        .into_response();
    }
    deployment.set_state(next);

    tracing::info!(deployment = %id, %upstream, "static upstream uncordoned");
    Json(upstream_traffic_status(&deployment, &upstream)).into_response()
}

#[cfg(test)]
fn record_only_refusal(d: &Deployment, workspace_state: bool) -> Option<&'static str> {
    record_removal_refusal(d, workspace_state, false)
}

fn record_removal_refusal(d: &Deployment, workspace_state: bool, archive_history: bool) -> Option<&'static str> {
    let state = d.state();
    if archive_history && d.spec.vm.as_ref().is_none_or(|vm| vm.driver != crate::config::Driver::Firecracker) {
        return Some("retired record archival requires a managed Firecracker deployment");
    }
    if state.create_attempts.iter().any(|a| a.allocation.is_some()) {
        return Some("correlated allocation receipts must be retained");
    }
    if archive_history && state.create_attempts.iter().any(|a| !a.runtime_observed) {
        return Some("unobserved allocation attempts require reconciliation");
    }
    if !d.spec.routes.is_empty() {
        return Some("record-only removal requires a route-less deployment");
    }
    if d.desired_replicas() != 0 {
        return Some("record-only removal requires zero desired replicas");
    }
    if !d.backends().is_empty() {
        return Some("record-only removal requires zero live backends");
    }
    if !d.pending().is_empty() {
        return Some("record-only removal requires zero pending or provisioning VMs");
    }
    if !state.suspended.is_empty() {
        return Some("record-only removal requires zero suspended VMs");
    }
    if crate::rollout::reserved(d) || (!archive_history && (state.active_prefix.is_some() || !state.rollouts.is_empty())) {
        return Some("record-only removal requires no retained rollout generations");
    }
    if archive_history && state.rollouts.iter().any(|op| match op.status.as_str() {
        "succeeded" => !op.readiness_verified || !op.previous_stopped,
        "failed" => !op.failure_settled,
        _ => true,
    }) {
        return Some("only settled terminal rollout history can be archived");
    }
    if d.spec.vm.as_ref().is_some_and(|vm| vm.workspace.is_some()) || workspace_state {
        return Some("record-only removal requires no workspace configuration or retained workspace state");
    }
    if d.spec.build.is_some() || d.spec.artifact.is_some() || d.spec.update.is_some()
        || d.spec.vm.as_ref().is_some_and(|vm| vm.workspace_archive.is_some()
            || vm.mounts.iter().any(|mount| !archive_history || !mount.read_only))
    {
        return Some("record-only removal requires no build, artifact, host-update or mount job configuration");
    }
    if d.spec.discovery.is_some()
        || !state.upstream_drains.is_empty()
        || state.discovery_version.is_some()
        || state.discovery_source_url.is_some()
        || state.route_handoff.is_some()
    {
        return Some("record-only removal requires no retained service state");
    }
    None
}

// Inside the auth layer, but also present on intentionally ungated CRUD.
// Shells own a read lease through WebSocket EOF in their handler instead.
async fn retirement_admission(State(state):State<AdminState>,req:Request,next:Next)->Response {
    let matched=req.extensions().get::<MatchedPath>().map(|m|m.as_str());
    let mutation=matched.is_some_and(|m|m=="/deployments" || m.starts_with("/deployments/:id"))
        && matched!=Some("/deployments/:id/retirement")
        && !matches!(*req.method(),axum::http::Method::GET|axum::http::Method::HEAD);
    let _lease=if mutation {Some(state.registry.retirement_gate.read().await)} else {None};
    if mutation && matched.and_then(|m|deployment_of(m,req.uri().path()))
        .is_some_and(|id|state.registry.retirement_frozen(id)) {
        return err(StatusCode::CONFLICT,"deployment permanently frozen for retirement").into_response();
    }
    next.run(req).await
}

async fn retirement_status(State(state):State<AdminState>, axum::Extension(caller):axum::Extension<Caller>,Path(id):Path<String>) -> Response {
    let Some(d)=state.registry.get(&id) else {return StatusCode::NOT_FOUND.into_response()};
    if !recovery_authorized(&caller,&d.spec) {return forbidden("authenticated namespace admin required");}
    Json(serde_json::json!({"deployment":id,"revision":d.state().rollout_revision,
        "spec_sha256":crate::rollout::fingerprint(&d.spec),"retirement":d.state().retirement})).into_response()
}

async fn retire_deployment(State(state):State<AdminState>,axum::Extension(caller):axum::Extension<Caller>,Path(id):Path<String>,
    Json(request):Json<crate::retirement::Request>) -> Response {
    let Some(d)=state.registry.get(&id) else {return StatusCode::NOT_FOUND.into_response()};
    if !recovery_authorized(&caller,&d.spec) {return forbidden("authenticated namespace admin required");}
    let _retirement=state.registry.retirement_gate.write().await;
    let _rollout=state.autoscaler.rollout_guard().await;
    let _change=state.registry.change_guard().await;
    let _creates=state.autoscaler.workspace_recovery_guard().await;
    let _workspace=state.autoscaler.workspaces().lifecycle_guard().await;
    let Some(d)=state.registry.get(&id) else {return StatusCode::NOT_FOUND.into_response()};
    if !recovery_authorized(&caller,&d.spec) {return forbidden("authenticated namespace admin required");}
    if let Err(error)=crate::retirement::freeze(&state.registry,&d,request) {
        return err(StatusCode::CONFLICT,error).into_response();
    }
    // History may represent an interrupted worker, not proof of no effects.
    // No historical failure is silently converted to completed retirement.
    let blocker=(!state.jobs.records(Some(&id)).is_empty())
        .then(||"job history requires explicit effect reconciliation".to_string())
        .or_else(|| (d.spec.update.is_some() || std::env::var_os("APP_LB_HOST_UPDATE_CONFIG").is_some()
            && crate::host_update::configured().map_or(true,|(_,c)|c.deployment==id))
            .then(||"host update helper requires explicit effect reconciliation".into()))
        .or_else(||state.autoscaler.workspaces().retirement_blocker(&id));
    match crate::retirement::advance(&state.registry,&d,state.autoscaler.vms(),blocker).await {
        Ok(op)=>(if op.state=="retired" {StatusCode::OK} else {StatusCode::ACCEPTED},Json(op)).into_response(),
        Err(error)=>{tracing::warn!(deployment=%id,%error,"retirement remains frozen");
            (StatusCode::ACCEPTED,Json(serde_json::json!({"retirement":d.state().retirement,"pending":true}))).into_response()}
    }
}

async fn deregister_record(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    remove_deployment_record(state, id, headers, false).await
}

async fn deregister_retired_record(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if caller.as_ref().is_none_or(|caller| !fleet_handoff_authorized(&caller.0)) {
        return forbidden("authenticated fleet admin required");
    }
    remove_deployment_record(state, id, headers, true).await
}

async fn remove_deployment_record(
    state: AdminState,
    id: String,
    headers: axum::http::HeaderMap,
    archive_history: bool,
) -> Response {
    // Match rollout cutover's lock order and wait out adoption/promotion and
    // orphan sweeps, not just allocations. A separate endpoint makes an old
    // server reject this request instead of ignoring a query flag and tearing down.
    let _reconcile = state.autoscaler.rollout_guard().await;
    let _change = state.registry.change_guard().await;
    {
        let expected_etag = match if_match(&headers) {
            Ok(value) => value.map(str::to_owned),
            Err(response) => return response,
        };
        let Some(expected_etag) = expected_etag.as_deref() else {
            return err(StatusCode::PRECONDITION_REQUIRED, "record-only removal requires If-Match from GET /deployments/:id").into_response();
        };
        // This waits for create/boot completion while the registry writer is
        // held. A completing boot must publish its pending/backend state before
        // releasing the permit; no later boot can pass its is_live check after
        // the record is removed.
        let _allocations = state.autoscaler.workspace_recovery_guard().await;
        let _workspace_lifecycle = state.autoscaler.workspaces().lifecycle_guard().await;
        let Some(d) = state.registry.get(&id) else {
            return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
        };
        if let Err(status) = check_etag_precondition(Some(expected_etag), &d.spec) {
            let message = if status == StatusCode::PRECONDITION_FAILED {
                "If-Match does not match the current deployment spec"
            } else {
                "failed to serialize deployment ETag"
            };
            return err(status, message).into_response();
        }
        if let Some(message) = record_removal_refusal(
            &d,
            state.autoscaler.workspaces().has_retained_state(&id),
            archive_history,
        ) {
            return err(StatusCode::CONFLICT, message).into_response();
        }
        if !state.jobs.records(Some(&id)).is_empty() {
            return err(StatusCode::CONFLICT, "job history still references this deployment").into_response();
        }
        if std::env::var_os("APP_LB_HOST_UPDATE_CONFIG").is_some() {
            match crate::host_update::configured() {
                Ok((_, config)) if config.deployment != id => {}
                Ok(_) => return err(StatusCode::CONFLICT, "host update mapping still references this deployment").into_response(),
                Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "host update mapping could not be verified").into_response(),
            }
        }
        match state.autoscaler.has_owned_resources(&id).await {
            Ok(false) => {}
            Ok(true) => return err(StatusCode::CONFLICT, "runtime still reports resources owned by this deployment").into_response(),
            Err(error) => {
                tracing::warn!(deployment = %id, %error, "record-only inventory unavailable");
                return err(StatusCode::SERVICE_UNAVAILABLE, "complete runtime inventory is required for record-only removal").into_response();
            }
        }
        let Some(disks) = state.disks.as_ref() else {
            return err(StatusCode::SERVICE_UNAVAILABLE, "disk inventory is required for record-only removal").into_response();
        };
        let inventory = disks.inventory().await;
        if !inventory.complete {
            return err(StatusCode::SERVICE_UNAVAILABLE, "complete disk inventory is required for record-only removal").into_response();
        }
        let saved = d.state();
        let historical_ids: std::collections::HashSet<&String> = crate::rollout::protected_ids(&saved)
            .chain(saved.create_attempts.iter().filter_map(|attempt| attempt.sandbox_id.as_ref())).collect();
        if inventory.disks.iter().any(|disk| disk.deployment.as_deref() == Some(id.as_str())
            || historical_ids.contains(&disk.sandbox_id)) {
            return err(StatusCode::CONFLICT, "retained disks still reference this deployment").into_response();
        }
        if archive_history {
            // Names may have changed outside this controller. Check historical
            // IDs as well as ownership, including stopped runtimes with no disks.
            let vms = state.autoscaler.vms();
            match (vms.list().await, vms.list_inactive().await) {
                (Ok(active), Ok(inactive)) => {
                    if active.iter().chain(inactive.iter()).any(|vm| historical_ids.contains(&vm.id)) {
                        return err(StatusCode::CONFLICT, "runtime still references a historical sandbox ID").into_response();
                    }
                }
                _ => return err(StatusCode::SERVICE_UNAVAILABLE, "historical runtime inventory unavailable").into_response(),
            }
            if let Err(error) = state.registry.archive_record(&d) {
                tracing::error!(deployment = %id, %error, "failed to archive retired deployment");
                return err(StatusCode::INTERNAL_SERVER_ERROR, "deployment history was not archived; record retained").into_response();
            }
        }
        // Unlink first. A failure leaves the live registry untouched; a crash
        // between unlink and the in-memory removal merely keeps the record
        // until restart. This path deliberately never invokes teardown.
        if let Err(error) = state.registry.forget(&id) {
            tracing::error!(deployment = %id, %error, "failed record-only deregistration");
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("deployment record was not removed: {error}")).into_response();
        }
        let d = state.registry.remove(&id).expect("deployment remained under registry mutation gate");
        state.metrics.retire(&id);
        tracing::info!(deployment = %id, "removed empty deployment record only");
        state.feed.announce(
            &d.spec,
            crate::feed::FeedEventKind::Removed,
            "the empty deployment record was removed without resource cleanup".to_string(),
            now_secs(),
        );
        return StatusCode::NO_CONTENT.into_response();
    }
}

async fn deregister(State(state): State<AdminState>, Path(id): Path<String>) -> impl IntoResponse {
    let change = state.registry.change_guard().await;
    if state.registry.get(&id).is_some_and(|d| d.state().create_attempts.iter().any(|a| a.allocation.is_some())) {
        return err(StatusCode::CONFLICT, "correlated allocation receipts must be retained").into_response();
    }
    if state.registry.get(&id).is_some_and(|d| crate::rollout::reserved(&d) || !d.state().rollouts.is_empty()) {
        return err(StatusCode::CONFLICT, "rollout generations must be explicitly reconciled before deregistration").into_response();
    }
    if state.autoscaler.workspaces().has_recovery(&id) {
        return err(StatusCode::CONFLICT, "workspace recovery history and retained source must be preserved").into_response();
    }
    let Some(d) = state.registry.remove(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if let Err(e) = state.registry.forget(&id) {
        tracing::error!(deployment = %id, error = %e, "failed to drop persisted state");
    }
    drop(change);
    // Removed from routing first, so the teardown can't race new requests in.
    state.autoscaler.teardown(&d).await;
    // Its counters fold into the global rollup and its entry goes; a fleet whose
    // ids churn would otherwise accumulate one per sandbox that ever existed.
    state.metrics.retire(&id);
    tracing::info!(deployment = %id, "deregistered");
    state.feed.announce(
        &d.spec,
        crate::feed::FeedEventKind::Removed,
        "the deployment was deregistered and its routes released".to_string(),
        now_secs(),
    );
    StatusCode::NO_CONTENT.into_response()
}

/// `?force=true` kills the VM now (dropping in-flight); otherwise it is drained.
#[derive(Deserialize)]
struct EvictParams {
    #[serde(default)]
    force: bool,
}

#[derive(Serialize)]
struct EvictResponse {
    sandbox_id: String,
    /// `"killed"` (gone now) or `"draining"` (will be reaped once idle).
    outcome: &'static str,
}

/// Evict a single VM from a deployment's pool.
///
/// `DELETE /deployments/:id/vms/:sandbox_id[?force=true]`. The autoscaler boots
/// a replacement on its next tick if the scaling policy still wants the
/// capacity, so this is "recycle this instance", not "shrink the deployment".
async fn evict_vm(
    State(state): State<AdminState>,
    Path((id, sandbox_id)): Path<(String, String)>,
    Query(params): Query<EvictParams>,
) -> impl IntoResponse {
    let _change = state.registry.change_guard().await;
    let Some(d) = state.registry.get(&id) else {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    };
    if crate::rollout::reserved(&d) {
        return err(StatusCode::CONFLICT, "candidate rollout reserves this deployment").into_response();
    }

    // Eviction recycles a VM and lets the autoscaler boot a replacement, which
    // only means something for a managed deployment. A static one's upstreams are
    // addresses and a site has no backends at all.
    if !d.spec.is_managed() {
        return err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} has no VMs to evict — edit the spec instead"),
        )
        .into_response();
    }

    match state.autoscaler.evict(&d, &sandbox_id, params.force).await {
        EvictOutcome::Killed => {
            (StatusCode::OK, Json(EvictResponse { sandbox_id, outcome: "killed" })).into_response()
        }
        // 202: the drain is underway but the VM is not gone yet.
        EvictOutcome::Draining => (
            StatusCode::ACCEPTED,
            Json(EvictResponse { sandbox_id, outcome: "draining" }),
        )
            .into_response(),
        EvictOutcome::NotFound => err(
            StatusCode::NOT_FOUND,
            format!("no VM {sandbox_id:?} in deployment {id:?}"),
        )
        .into_response(),
        EvictOutcome::KillFailed(e) => {
            err(StatusCode::BAD_GATEWAY, format!("failed to evict VM: {e}")).into_response()
        }
    }
}

// --- exec and shell -------------------------------------------------------
//
// The two ways into a VM that are not HTTP. Both matter most for a deployment
// with no routes at all — an agent sandbox — where they are the *only* ways in.
//
// Both go through app-lb rather than handing the caller a daemon address,
// because three things have to happen that only app-lb can do: resolve a
// deployment id to whichever sandbox is currently serving it, apply the admin
// gate, and wake a VM that has been scaled to zero or suspended.

/// How long a command may run before the daemon gives up on it, when the caller
/// names no timeout. Long enough for a build step, short enough that a hung
/// command does not hold an admin connection for the rest of the day.
const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 60;

/// Ceiling on a caller-supplied exec timeout.
const MAX_EXEC_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Deserialize)]
struct ExecRequest {
    /// Run through `sh -c` in the guest.
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Boot or resume a VM if none is running. On by default: a sandbox that
    /// scaled to zero should still answer `exec`. `false` asks for a `409`
    /// instead, for callers that want to know rather than wait.
    #[serde(default = "default_true")]
    wake: bool,
    /// Run in *this* VM of the deployment rather than whichever the pool
    /// offers. See [`hold_this_vm`].
    #[serde(default)]
    sandbox_id: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct ExecResponse {
    /// Which VM ran it. Worth returning even for a single-VM sandbox: after a
    /// resume or a rebuild it is a different sandbox than last time.
    sandbox_id: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
    /// stdout and stderr interleaved in the order the guest wrote them, as the
    /// daemon captured it. The only faithful rendering of a command whose
    /// output interleaves.
    output: String,
}

#[derive(Debug, Default, Deserialize)]
struct ShellQuery {
    #[serde(default)]
    cols: Option<u16>,
    #[serde(default)]
    rows: Option<u16>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default = "default_true")]
    wake: bool,
    /// Open the shell in *this* VM of the deployment. See [`hold_this_vm`].
    #[serde(default)]
    sandbox_id: Option<String>,
}

/// The VM an `exec` or `shell` session runs in.
///
/// Two cases, because the pool cannot offer the second one. A ready backend
/// comes with a [`BackendSlot`](crate::deployment::BackendSlot) that holds an
/// in-flight slot for the life of the session, which is what stops the
/// autoscaler scaling the VM away underneath it. A *booting* VM has no slot to
/// take — it is not in the pool — and needs none: nothing scales away a VM that
/// was never promoted. What can still kill it is `boot_timeout_secs`, and that
/// is the autoscaler's call, not something a session should be able to veto.
enum VmTarget {
    Ready(crate::deployment::BackendSlot),
    /// A VM the daemon reports `Running` that has not passed its health check.
    Booting(String),
}

impl VmTarget {
    fn sandbox_id(&self) -> &str {
        match self {
            Self::Ready(slot) => slot.sandbox_id(),
            Self::Booting(id) => id,
        }
    }
}

/// Resolve a deployment to a VM that can run something, waking one if asked.
///
/// The waiting half is the request manager's cold-start path
/// (`request_control::wait_for_capacity`)
/// reused verbatim, so an `exec` against a sleeping sandbox nudges the
/// autoscaler and waits exactly as a request would — including the autoscaler's
/// preference for resuming a suspended VM over booting a fresh one.
///
/// **A booting VM counts.** A guest that is up but whose server never answers
/// the health check is never promoted, so the pool cannot hand it over — and it
/// is the single case where getting inside the VM matters most. Resolving only
/// against ready backends meant `exec` sat out `cold_start_timeout_secs` and
/// answered 503 on exactly the deployment somebody was trying to debug, while
/// the VM they wanted sat there `Running` with a `guest_ip`. So a still-booting
/// VM is used when the pool has nothing, and it is tried *before* waking one:
/// a VM that already exists is the one to look at, and booting another would
/// add a sandbox — and its disks — to a deployment that is already churning.
async fn hold_a_vm(
    state: &AdminState,
    id: &str,
    wake: bool,
    sandbox_id: Option<&str>,
) -> Result<VmTarget, Response> {
    let Some(d) = state.registry.get(id) else {
        return Err(err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response());
    };
    if !d.spec.is_managed() {
        let why = if d.spec.is_site() {
            "a site is files on disk"
        } else {
            "its upstreams are addresses, not VMs"
        };
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("deployment {id:?} has no VM to run a command in — {why}"),
        )
        .into_response());
    }

    if let Some(want) = sandbox_id {
        return hold_this_vm(&d, id, want);
    }

    if let Some(slot) = d.select(&[]).and_then(|backend| backend.try_hold()) {
        return Ok(VmTarget::Ready(slot));
    }
    if let Some(sandbox_id) = booting_vm(&d) {
        tracing::info!(
            deployment = %id,
            sandbox = %sandbox_id,
            "no VM has passed its health check; running in one that is still booting",
        );
        return Ok(VmTarget::Booting(sandbox_id));
    }
    if !wake {
        return Err(err(
            StatusCode::CONFLICT,
            format!("deployment {id:?} has no running VM (pass wake=true to start one)"),
        )
        .into_response());
    }
    match crate::request_control::wait_for_capacity(&d, &[], &state.metrics, &state.feed).await {
        Some(b) => match b.try_hold() {
            Some(slot) => Ok(VmTarget::Ready(slot)),
            None => Err(err(
                StatusCode::CONFLICT,
                format!("deployment {id:?} stopped accepting work while the VM was selected"),
            )
            .into_response()),
        },
        // The wait itself is what created a VM, so ask again before giving up:
        // a boot that got as far as `Running` and stalled on the health check is
        // still something to run a command in, and answering 503 here would send
        // the caller away from the VM their own request had just started.
        None => match booting_vm(&d) {
            Some(sandbox_id) => Ok(VmTarget::Booting(sandbox_id)),
            None => Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "deployment {id:?} has no VM and none became available within \
                     cold_start_timeout_secs"
                ),
            )
            .into_response()),
        },
    }
}

/// The one VM the caller named, or the reason it cannot be used.
///
/// Naming a VM is for looking at *that* VM — the row on the dashboard that has
/// gone red, the sandbox a log line came from — so nothing here falls back to
/// a sibling, and nothing wakes anything: a VM that is not in the deployment
/// is a `404`, not a cold start. A ready backend is held the same way the
/// pool's pick would be; a booting one is used as [`booting_vm`] would use it;
/// one the daemon has not started yet has no guest to talk to and is a `409`,
/// as is a backend that is draining and refuses the hold.
fn hold_this_vm(
    d: &std::sync::Arc<crate::deployment::Deployment>,
    id: &str,
    want: &str,
) -> Result<VmTarget, Response> {
    if let Some(backend) = d.backends().iter().find(|b| b.sandbox_id == want) {
        return backend.try_hold().map(VmTarget::Ready).ok_or_else(|| {
            err(
                StatusCode::CONFLICT,
                format!("VM {want:?} in deployment {id:?} is not accepting work"),
            )
            .into_response()
        });
    }
    match d.pending().iter().find(|p| p.sandbox_id == want) {
        Some(p) if p.status == Some(heyo_sdk::SandboxStatus::Running) => {
            Ok(VmTarget::Booting(want.to_string()))
        }
        Some(_) => Err(err(
            StatusCode::CONFLICT,
            format!("VM {want:?} in deployment {id:?} has not started yet"),
        )
        .into_response()),
        None => Err(err(
            StatusCode::NOT_FOUND,
            format!("no VM {want:?} in deployment {id:?}"),
        )
        .into_response()),
    }
}

/// The oldest pending VM the daemon reports `Running`, if there is one.
///
/// Oldest first: with a pool of stalled boots, the one that has been up longest
/// is the one whose logs cover the most, and picking it keeps repeated `exec`s
/// landing on the same guest instead of scattering across a churning pool.
///
/// `Running` and not merely pending, because a VM the daemon has not started
/// yet has no guest to talk to — the daemon would refuse the exec, and doing so
/// slowly. This is the same distinction `promote_pending` draws, minus the
/// health probe that is the whole reason the caller is here.
fn booting_vm(d: &std::sync::Arc<crate::deployment::Deployment>) -> Option<String> {
    d.pending()
        .iter()
        .filter(|p| p.status == Some(heyo_sdk::SandboxStatus::Running))
        .min_by_key(|p| p.created_at)
        .map(|p| p.sandbox_id.clone())
}

/// `POST /deployments/:id/exec` — run one command in the deployment's VM.
async fn exec(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    if req.command.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "command must not be empty").into_response();
    }

    let slot = match hold_a_vm(&state, &id, req.wake, req.sandbox_id.as_deref()).await {
        Ok(slot) => slot,
        Err(response) => return response,
    };
    let sandbox_id = slot.sandbox_id().to_string();

    let timeout = std::time::Duration::from_secs(
        req.timeout_secs
            .unwrap_or(DEFAULT_EXEC_TIMEOUT_SECS)
            .clamp(1, MAX_EXEC_TIMEOUT_SECS),
    );
    let options = heyo_sdk::CommandRunOptions {
        cwd: req.cwd,
        env: req.env,
        timeout: Some(timeout),
    };

    tracing::info!(deployment = %id, sandbox = %sandbox_id, "exec");
    match state
        .autoscaler
        .vms()
        .exec(&sandbox_id, &req.command, options)
        .await
    {
        Ok(result) => Json(ExecResponse {
            sandbox_id,
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            output: result.output,
        })
        .into_response(),
        // The command's own failure is a 200 with a non-zero `exit_code`; this
        // is app-lb failing to *run* it, which is a different thing entirely and
        // must not be mistaken for one.
        Err(e) => err(
            StatusCode::BAD_GATEWAY,
            format!("could not run the command in {sandbox_id}: {e}"),
        )
        .into_response(),
    }
}

/// `GET /deployments/:id/shell` — an interactive PTY, over a WebSocket.
///
/// `?sandbox_id=` picks a VM; without it the pool chooses, as for `exec`.
///
/// Wire protocol with the client, which is the daemon's own minus the parts the
/// SDK session already handles (sequence numbers and acks):
///
/// - client → server, binary `[0x01, ...stdin]`
/// - client → server, text `{"type":"resize","cols":N,"rows":N}`
/// - server → client, text `{"type":"ready","sandbox_id":"…"}` — sent once
/// - server → client, binary `[0x02, ...stdout]` (the PTY merges stderr in)
/// - server → client, text `{"type":"exit","code":N}` or
///   `{"type":"error","message":"…"}`
async fn shell(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(q): Query<ShellQuery>,
    ws: axum::extract::WebSocketUpgrade,
) -> Response {
    // Everything that can fail with a status code has to fail *before* the
    // upgrade: once the socket is a WebSocket, a client sees a close frame with
    // no explanation instead of a 404.
    let retirement=state.registry.retirement_gate.clone().read_owned().await;
    if state.registry.retirement_frozen(&id) {
        return err(StatusCode::CONFLICT,"deployment permanently frozen for retirement").into_response();
    }
    let slot = match hold_a_vm(&state, &id, q.wake, q.sandbox_id.as_deref()).await {
        Ok(slot) => slot,
        Err(response) => return response,
    };
    let sandbox_id = slot.sandbox_id().to_string();

    let options = heyo_sdk::ShellOptions {
        cwd: q.cwd,
        env: None,
        cols: q.cols.unwrap_or(80),
        rows: q.rows.unwrap_or(24),
        ..Default::default()
    };
    let session = match state.autoscaler.vms().shell(&sandbox_id, options).await {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::BAD_GATEWAY,
                format!("could not open a shell on {sandbox_id}: {e}"),
            )
            .into_response();
        }
    };

    tracing::info!(deployment = %id, sandbox = %sandbox_id, "shell session opened");
    ws.on_upgrade(move |socket| async move {
        let _retirement=retirement;
        // `slot` moves in here, so the VM is held for the life of the session
        // and released however it ends.
        pump_shell(socket, session, sandbox_id.clone(), slot).await;
        tracing::info!(deployment = %id, sandbox = %sandbox_id, "shell session closed");
    })
}

/// Copy between the client's WebSocket and the sandbox's PTY until either ends.
async fn pump_shell(
    socket: axum::extract::ws::WebSocket,
    session: heyo_sdk::ShellSession,
    sandbox_id: String,
    _target: VmTarget,
) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt};

    const STDIN: u8 = 0x01;
    const STDOUT: u8 = 0x02;

    let (mut tx, mut rx) = socket.split();
    if tx
        .send(Message::Text(
            serde_json::json!({ "type": "ready", "sandbox_id": sandbox_id }).to_string(),
        ))
        .await
        .is_err()
    {
        return; // client hung up during the handshake
    }

    let mut output = session.output();
    let mut events = session.events();
    loop {
        tokio::select! {
            // Guest → client.
            Some(chunk) = output.next() => {
                let mut frame = Vec::with_capacity(chunk.len() + 1);
                frame.push(STDOUT);
                frame.extend_from_slice(&chunk);
                if tx.send(Message::Binary(frame)).await.is_err() {
                    break;
                }
            }
            // Client → guest.
            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        // Anything not marked stdin is a client bug, not data to
                        // feed a shell — dropping it beats writing a stray frame
                        // header into somebody's terminal.
                        if bytes.first() == Some(&STDIN)
                            && session.write(&bytes[1..]).await.is_err()
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
                            && v.get("type").and_then(|t| t.as_str()) == Some("resize")
                        {
                            let cols = v.get("cols").and_then(|c| c.as_u64()).unwrap_or(80) as u16;
                            let rows = v.get("rows").and_then(|r| r.as_u64()).unwrap_or(24) as u16;
                            let _ = session.resize(cols, rows).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}       // ping/pong: axum answers these itself
                    Some(Err(_)) => break,  // socket is gone
                }
            }
            // Lifecycle, so a client learns *why* its shell ended.
            Some(event) = events.next() => {
                let msg = match event {
                    heyo_sdk::ShellEvent::Closed { exit_code } => {
                        serde_json::json!({ "type": "exit", "code": exit_code.unwrap_or(0) })
                    }
                    heyo_sdk::ShellEvent::Error(message) => {
                        serde_json::json!({ "type": "error", "message": message })
                    }
                    // Reconnects are the SDK's business; the client's stream is
                    // continuous either way and saying so would only confuse it.
                    _ => continue,
                };
                let closing = msg["type"] == "exit";
                let _ = tx.send(Message::Text(msg.to_string())).await;
                if closing {
                    break;
                }
            }
            else => break,
        }
    }

    let _ = session.close().await;
    let _ = tx.send(Message::Close(None)).await;
}

async fn healthz() -> impl IntoResponse {
    ([("x-heyo-revision", env!("APP_LB_BUILD_REVISION"))], "ok\n")
}

/// Issued certificates: `GET /certs`.
///
/// The only way to see *why* a hostname is not yet serving its own certificate —
/// issuance is asynchronous, so a deployment can be live and routing while its
/// certificate is still pending or failing. A hostname with a route but no entry
/// here is either still in flight, backing off after a failure, or a
/// `host_suffix` rule (which ACME cannot cover; see `src/acme.rs`).
async fn certs(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.certs.status())
}

// -- secrets ---------------------------------------------------------------

/// Persist the secret store, mapping a failure onto a 500.
///
/// Unlike the deployment registry — where a failed write is logged and the
/// in-memory change stands — a secret that only exists in memory is a rotation
/// that silently un-rotates on the next restart. Better to fail the request.
/// `GET /ingress` — where DNS should point a deployment's hostname.
///
/// The one thing a client cannot learn from the spec it wrote: a `routes[].host`
/// only works once an A (or AAAA) record resolves it to this LB, and only the
/// operator knows those addresses. Configured with `APP_LB_PUBLIC_IPS`; empty
/// when it is unset, which a client should render as "ask your operator",
/// not as "no DNS needed".
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Ingress {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

impl Ingress {
    pub fn from_ips(ips: &[std::net::IpAddr]) -> Self {
        let mut out = Self {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        for ip in ips {
            match ip {
                std::net::IpAddr::V4(v4) => out.ipv4.push(v4.to_string()),
                std::net::IpAddr::V6(v6) => out.ipv6.push(v6.to_string()),
            }
        }
        out
    }
}

async fn ingress(State(state): State<AdminState>) -> impl IntoResponse {
    Json((*state.ingress).clone())
}

#[cfg(test)]
mod ingress_tests {
    use super::Ingress;

    #[test]
    fn addresses_are_split_by_family_and_serialize_as_strings() {
        let ips: Vec<std::net::IpAddr> = vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        ];
        let i = Ingress::from_ips(&ips);
        assert_eq!(i.ipv4, vec!["203.0.113.10", "203.0.113.11"]);
        assert_eq!(i.ipv6, vec!["2001:db8::1"]);
        assert_eq!(
            serde_json::to_value(&i).unwrap(),
            serde_json::json!({"ipv4": ["203.0.113.10", "203.0.113.11"], "ipv6": ["2001:db8::1"]})
        );
        let none = Ingress::from_ips(&[]);
        assert!(none.ipv4.is_empty() && none.ipv6.is_empty());
    }
}

/// The namespace a `/secrets` request is about, when it is not in the body.
#[derive(Deserialize)]
struct SecretQuery {
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    force: bool,
}

impl SecretQuery {
    fn namespace(&self) -> &str {
        self.namespace
            .as_deref()
            .map(str::trim)
            .filter(|ns| !ns.is_empty())
            .unwrap_or(crate::config::DEFAULT_NAMESPACE)
    }
}

/// Whether `caller` may read (`admin == false`) or change (`admin == true`)
/// the secrets of `ns`. An ungated or operator caller may do anything; every
/// other kind is measured against its reach, exactly as a deployment in `ns`
/// would be.
fn may_use_secrets(caller: Option<&Caller>, ns: &str, admin: bool) -> Result<(), Response> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if !caller.reaches_namespace(ns) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!("this credential cannot reach the \"{ns}\" namespace's secrets"),
        )
        .into_response());
    }
    if admin && !caller.satisfies_in(crate::tokens::AdminScope::Admin, Some(ns)) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!("this credential may only view the \"{ns}\" namespace, not change its secrets"),
        )
        .into_response());
    }
    Ok(())
}

fn persist_secrets(state: &AdminState) -> Result<(), (StatusCode, Json<ApiError>)> {
    state.secrets.persist().map_err(|e| {
        tracing::error!(error = %e, "failed to persist secrets");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the secret was not saved: {e}"),
        )
    })
}

/// Deployments in `ns` that refer to secret `id` anywhere in their spec — a
/// build's git token, a gate's client secret, a replica's `env_from`. Used to
/// keep a delete from breaking a deployment that still needs it.
fn secret_users(state: &AdminState, ns: &str, id: &str) -> Vec<String> {
    let mut users: Vec<String> = state
        .registry
        .deployments()
        .values()
        .filter(|d| d.spec.namespace == ns && d.spec.secret_ids().iter().any(|s| s == id))
        .map(|d| d.spec.id.clone())
        .collect();
    users.sort();
    users
}

/// `POST /secrets` — create or replace a secret wholesale, in the namespace
/// the body names (`default` when it names none). A confined caller must
/// reach that namespace as an admin; one that does not gets the same 403 a
/// deployment registered there would.
async fn put_secret(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Json(spec): Json<SecretSpec>,
) -> impl IntoResponse {
    store_secret(&state, caller.as_deref(), spec).await
}

async fn store_secret(state: &AdminState, caller: Option<&Caller>, spec: SecretSpec) -> Response {
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(refused) = may_use_secrets(caller, &spec.namespace, true) {
        return refused;
    }
    let id = spec.id.clone();
    let ns = spec.namespace.clone();
    let existed = state.secrets.get(&ns, &id).is_some();
    state.secrets.put(spec);
    if let Err(e) = persist_secrets(state) {
        return e.into_response();
    }
    // Keys, never values — the same rule the read path follows, so enabling
    // debug logging can't turn into a credential dump.
    tracing::info!(secret = %id, namespace = %ns, replaced = existed, "secret stored");
    let summary = state.secrets.summary(&ns, &id).expect("just stored");
    let code = if existed { StatusCode::OK } else { StatusCode::CREATED };
    (code, Json(summary)).into_response()
}

/// `PUT /secrets/:id[?namespace=]` — as `POST`, with the path id and the query
/// namespace winning over the body.
async fn replace_secret(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(q): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
    Json(mut spec): Json<SecretSpec>,
) -> impl IntoResponse {
    spec.id = id;
    if q.namespace.is_some() {
        spec.namespace = q.namespace().to_string();
    }
    store_secret(&state, caller.as_deref(), spec).await
}

#[derive(Deserialize)]
struct SecretPatch {
    /// `"KEY": "value"` sets, `"KEY": null` removes. Anything absent is left
    /// alone, so one key can be rotated without resending the others — which
    /// matters here, because there is no way to read the others back.
    data: BTreeMap<String, Option<String>>,
    #[serde(default)]
    description: Option<String>,
}

/// `PATCH /secrets/:id[?namespace=]`.
async fn patch_secret(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(q): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
    Json(patch): Json<SecretPatch>,
) -> impl IntoResponse {
    let ns = q.namespace();
    if let Err(refused) = may_use_secrets(caller.as_deref(), ns, true) {
        return refused;
    }
    if state.secrets.get(ns, &id).is_none() {
        return err(StatusCode::NOT_FOUND, format!("no secret {id:?}")).into_response();
    }
    let updated = match state.secrets.patch(ns, &id, patch.data) {
        Ok(s) => s,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if let Some(description) = patch.description {
        let mut next = (*updated).clone();
        next.description = Some(description);
        state.secrets.put(next);
    }
    if let Err(e) = persist_secrets(&state) {
        return e.into_response();
    }
    tracing::info!(secret = %id, "secret updated");
    Json(state.secrets.summary(ns, &id).expect("just stored")).into_response()
}

/// `GET /workflows` — every workflow object.
///
/// The orchestrator polls this, so it is the hot path of the whole feature.
/// Lock-free: the store is an `ArcSwap`, and listing clones `Arc`s.
async fn list_workflows(State(state): State<AdminState>) -> impl IntoResponse {
    let items: Vec<_> = state
        .workflows
        .list()
        .into_iter()
        .map(|w| (*w).clone())
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "workflows": items }))).into_response()
}

async fn get_workflow(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.workflows.get(&id) {
        Some(w) => (StatusCode::OK, Json((*w).clone())).into_response(),
        None => err(StatusCode::NOT_FOUND, format!("no workflow {id}")).into_response(),
    }
}

/// `POST /workflows` — create or replace.
///
/// Validated before anything is stored, so an invalid object is a 400 rather
/// than a file on disk that the next load skips with a warning nobody reads.
async fn put_workflow(
    State(state): State<AdminState>,
    Json(spec): Json<crate::config::WorkflowSpec>,
) -> impl IntoResponse {
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let id = spec.id.clone();
    match state.workflows.upsert(spec) {
        Ok(stored) => (StatusCode::CREATED, Json((*stored).clone())).into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not persist workflow {id}: {e}"),
        )
        .into_response(),
    }
}

/// `PUT /workflows/{id}` — replace, with the path id winning.
///
/// A body whose `id` disagrees with the path is a mistake worth naming rather
/// than silently resolving: the two readings (rename, or write to the wrong
/// object) have very different consequences.
async fn replace_workflow(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Json(mut spec): Json<crate::config::WorkflowSpec>,
) -> impl IntoResponse {
    if !spec.id.is_empty() && spec.id != id {
        return err(
            StatusCode::BAD_REQUEST,
            format!(
                "the body's id {:?} does not match the path id {id:?}; \
                 renaming is a delete and a create",
                spec.id
            ),
        )
        .into_response();
    }
    spec.id = id;
    if let Err(e) = spec.validate() {
        return err(StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    match state.workflows.upsert(spec) {
        Ok(stored) => (StatusCode::OK, Json((*stored).clone())).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_workflow(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.workflows.remove(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, format!("no workflow {id}")).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /secrets[?namespace=]` — the secrets the caller may see: one
/// namespace when asked for one, else every namespace within reach.
async fn list_secrets(
    State(state): State<AdminState>,
    Query(q): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let caller = caller.as_deref();
    if let Some(ns) = q.namespace.as_deref().map(str::trim).filter(|ns| !ns.is_empty()) {
        if let Err(refused) = may_use_secrets(caller, ns, false) {
            return refused;
        }
        return Json(state.secrets.list(Some(ns))).into_response();
    }
    let visible: Vec<_> = state
        .secrets
        .list(None)
        .into_iter()
        .filter(|s| caller.is_none_or(|c| c.reaches_namespace(&s.namespace)))
        .collect();
    Json(visible).into_response()
}

/// `GET /secrets/:id[?namespace=]`.
async fn get_secret(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(q): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let ns = q.namespace();
    if let Err(refused) = may_use_secrets(caller.as_deref(), ns, false) {
        return refused;
    }
    match state.secrets.summary(ns, &id) {
        Some(s) => Json(s).into_response(),
        None => err(StatusCode::NOT_FOUND, format!("no secret {id:?}")).into_response(),
    }
}

#[derive(Deserialize)]
struct ForceParams {
    #[serde(default)]
    force: bool,
}

/// `DELETE /secrets/:id[?force=true]`.
///
/// Refused while a deployment's build still references it: the failure would
/// otherwise surface much later, as a build that cannot authenticate.
async fn delete_secret(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(params): Query<SecretQuery>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let ns = params.namespace();
    if let Err(refused) = may_use_secrets(caller.as_deref(), ns, true) {
        return refused;
    }
    if state.secrets.get(ns, &id).is_none() {
        return err(StatusCode::NOT_FOUND, format!("no secret {id:?}")).into_response();
    }
    let users = secret_users(&state, ns, &id);
    if !users.is_empty() && !params.force {
        return err(
            StatusCode::CONFLICT,
            format!(
                "secret {id:?} is referenced by deployment(s) {}; their builds would stop \
                 authenticating. Repoint them first, or delete with ?force=true",
                users.join(", ")
            ),
        )
        .into_response();
    }
    state.secrets.remove(ns, &id);
    if let Err(e) = persist_secrets(&state) {
        return e.into_response();
    }
    tracing::info!(secret = %id, namespace = %ns, forced = params.force, "secret deleted");
    StatusCode::NO_CONTENT.into_response()
}

// -- jobs ------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct BuildRequest {
    /// Build this ref instead of the spec's. A one-off: the stored `build.ref`
    /// is left alone, so a hotfix tag doesn't quietly become the new default.
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
}

#[derive(Deserialize, Default)]
struct MountPullRequest {
    /// Re-fetch trees already on this host. Rarely wanted, for the same reason a
    /// rootfs pull's `force` is: the directory name is the digest, so the tree
    /// being there is proof of what is in it.
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize, Default)]
struct PullRequest {
    /// Pull this reference instead of the spec's. A one-off, like a build's:
    /// `{"ref": "<digest>"}` is what a rollback to known bytes looks like,
    /// without making that digest the deployment's default.
    #[serde(default, rename = "ref")]
    artifact_ref: Option<String>,
    /// Enables durable idempotency and replacement-readiness verification.
    #[serde(default)]
    operation_id: Option<String>,
    /// Re-fetch even when the image is already on disk. Rarely wanted — the
    /// filename is the digest, so the image being there is proof the bytes are
    /// right — and it exists for the case where the file was damaged after it
    /// was written.
    #[serde(default)]
    force: bool,
}

/// Map a start failure onto a status. Shared by both job kinds, because the
/// reasons a job can't start are the same for either.
fn job_start_error(e: StartError) -> Response {
    match e {
        e @ StartError::NoDeployment(_) => {
            err(StatusCode::NOT_FOUND, e.to_string()).into_response()
        }
        e @ (StartError::AlreadyRunning(_) | StartError::ConflictingOperation(_)) => {
            err(StatusCode::CONFLICT, e.to_string()).into_response()
        }
        e @ StartError::Persistence(_) => {
            err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
        e => err(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// `POST /deployments/:id/build` — fetch the recipe, build the image, roll the
/// pool.
///
/// Where the recipe comes from is the deployment's `build` block, not this
/// request: a git checkout, or a Dockerfile manifest in an artifact store. An
/// optional `{"ref": "…"}` overrides the version for this build only, and is
/// read by whichever source the spec selects — a branch or commit for a repo, a
/// tag or digest for a store. It is validated against that source's rules before
/// the job starts, so a git ref handed to a store-backed deployment is a `400`
/// here rather than a build that fails minutes later.
///
/// Returns `202` with a job record as soon as the work is scheduled. A build
/// takes minutes; poll `GET /jobs/:job_id` for the outcome.
async fn start_build(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<BuildRequest>>,
) -> impl IntoResponse {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    match state.jobs.start_build(&id, req.git_ref) {
        Ok(record) => {
            tracing::info!(deployment = %id, job = %record.id, "image build started");
            (StatusCode::ACCEPTED, Json(record)).into_response()
        }
        Err(e) => job_start_error(e),
    }
}

/// `POST /deployments/:id/pull` — materialize a rootfs from an artifact store
/// and roll the pool onto it.
///
/// `202` for the same reason a build is: the bytes may be gigabytes across a
/// network. It is often much faster than a build — an image already on disk is
/// resolved and skipped in one round trip — but "often fast" is not something to
/// hold a request open on.
async fn start_pull(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<PullRequest>>,
) -> impl IntoResponse {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let result = match req.operation_id {
        Some(operation_id) => match req.artifact_ref {
            Some(digest) => state.jobs.start_correlated_pull(&id, operation_id, digest, req.force),
            None => Err(StartError::BadRef("operation_id requires an explicit pinned `ref` digest".into())),
        },
        None => state.jobs.start_pull(&id, req.artifact_ref, req.force),
    };
    match result {
        Ok(record) => {
            tracing::info!(deployment = %id, job = %record.id, "artifact pull started");
            (StatusCode::ACCEPTED, Json(record)).into_response()
        }
        Err(e) => job_start_error(e),
    }
}

/// `POST /deployments/:id/mounts/pull` — unpack every guest mount this
/// deployment declares, and roll the pool onto the trees.
///
/// `202` for the same reason the other two are: a corpus is not something to
/// hold a request open for. Poll `GET /jobs/:job_id` — its `mounts` array
/// carries a per-mount digest, tree and byte count, so a job still running says
/// which mount it is on.
///
/// Not usually called by hand. Registering or editing a deployment whose mounts
/// have no tree on this host starts one of these by itself; this endpoint is for
/// the two cases that leaves: a tag that has moved, and a tree that needs
/// re-fetching under `force`.
async fn start_mount_pull(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    body: Option<Json<MountPullRequest>>,
) -> impl IntoResponse {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    match state.jobs.start_mount_pull(&id, req.force) {
        Ok(record) => {
            tracing::info!(deployment = %id, job = %record.id, "mount pull started");
            (StatusCode::ACCEPTED, Json(record)).into_response()
        }
        Err(e) => job_start_error(e),
    }
}

/// `POST /deployments/:id/update` — run a static deployment's update commands on
/// this host, then re-probe its upstreams.
///
/// The static counterpart of `build`, and `202` for the same reason: `cargo
/// build && systemctl restart` is not something to hold an HTTP request open
/// for. Nothing in the spec changes — the upstreams are the same addresses, and
/// what moved is the code answering on them.
async fn start_update(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if std::env::var_os("APP_LB_HOST_UPDATE_CONFIG").is_some() {
        match crate::host_update::configured() {
            Ok((_, config)) if config.deployment != id => {}
            _ => return err(StatusCode::CONFLICT, "mapped host requires correlated /update/rollouts, not legacy commands").into_response(),
        }
    }
    match state.jobs.start_update(&id) {
        Ok(record) => {
            tracing::info!(deployment = %id, job = %record.id, "host update started");
            (StatusCode::ACCEPTED, Json(record)).into_response()
        }
        Err(e) => job_start_error(e),
    }
}

fn host_update_mapping(state: &AdminState, caller: &Caller, id: &str) -> Result<(std::path::PathBuf, crate::host_update::Config), Response> {
    let (path, config) = crate::host_update::configured().map_err(|e| err(StatusCode::CONFLICT, e).into_response())?;
    let d = state.registry.get(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "deployment not found").into_response())?;
    if config.deployment != id || config.namespace != d.spec.namespace || !recovery_authorized(caller, &d.spec) {
        return Err(forbidden("authenticated mapped namespace admin required"));
    }
    Ok((path, config))
}

async fn host_update_snapshot(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>, Path(id): Path<String>) -> Response {
    let (_, config) = match host_update_mapping(&state, &caller, &id) { Ok(c) => c, Err(e) => return e };
    match crate::host_update::snapshot(&config).await {
        Ok(value) => Json(value).into_response(), Err(e) => err(StatusCode::CONFLICT, e).into_response(),
    }
}

async fn start_host_rollout(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>, Path(id): Path<String>, Json(request): Json<crate::host_update::Request>) -> Response {
    let (path, config) = match host_update_mapping(&state, &caller, &id) { Ok(c) => c, Err(e) => return e };
    match crate::host_update::start(&path, &config, request).await {
        Ok(value) => (StatusCode::ACCEPTED, Json(value)).into_response(), Err(e) => err(StatusCode::CONFLICT, e).into_response(),
    }
}

async fn get_host_rollout(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>, Path((id, operation)): Path<(String,String)>) -> Response {
    let (_, config) = match host_update_mapping(&state, &caller, &id) { Ok(c) => c, Err(e) => return e };
    match crate::host_update::get(&config, &operation).await {
        Ok(value) => Json(value).into_response(),
        Err(e) if e == "operation not found" => err(StatusCode::NOT_FOUND, e).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    }
}

async fn get_host_bootstrap(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>, Path((id, operation)): Path<(String,String)>) -> Response {
    let (path, config) = match host_update_mapping(&state, &caller, &id) { Ok(c) => c, Err(e) => return e };
    match crate::host_update::bootstrap::get(&config, &path, &operation).await {
        Ok(value) => Json(value).into_response(),
        Err(e) if e == "operation not found" => err(StatusCode::NOT_FOUND, e).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, e).into_response(),
    }
}

async fn list_jobs(State(state): State<AdminState>) -> impl IntoResponse {
    Json(state.jobs.records(None))
}

async fn deployment_jobs(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.registry.get(&id).is_none() {
        return err(StatusCode::NOT_FOUND, format!("no deployment {id:?}")).into_response();
    }
    Json(state.jobs.records(Some(&id))).into_response()
}

async fn get_job(
    State(state): State<AdminState>,
    Path(job_id): Path<String>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    let visible = |deployment: &str| match confined(caller.as_deref()) {
        None => true,
        Some(c) => {
            let ns = state.registry.get(deployment).map(|d| d.spec.namespace.clone());
            c.may_touch(deployment, ns.as_deref())
        }
    };
    match state.jobs.record(&job_id).filter(|r| visible(&r.deployment)) {
        Some(r) => Json(r).into_response(),
        // History is in memory and bounded, so an id can be forgotten rather
        // than never having existed. Say so.
        None => err(
            StatusCode::NOT_FOUND,
            format!("no job {job_id:?} — it may have aged out of the job history"),
        )
        .into_response(),
    }
}

async fn start_rollout(State(state): State<AdminState>, Path(id): Path<String>, Json(mut request): Json<crate::rollout::Request>) -> Response {
    if request.spec.id != id { return err(StatusCode::BAD_REQUEST, "spec.id must match deployment").into_response(); }
    request.spec.normalize();
    if let Err(refused) = check_provider_ref(&state, &request.spec) { return refused; }
    let _lifecycle = state.autoscaler.rollout_guard().await;
    let _change = state.registry.change_guard().await;
    let Some(d) = state.registry.get(&id) else { return err(StatusCode::NOT_FOUND, "deployment not found").into_response(); };
    match state.jobs.with_rollout_slot(&id, || state.rollouts.admit(&d, request)) {
        Ok(o) => (StatusCode::ACCEPTED, Json(o.view())).into_response(),
        Err(e) => err(StatusCode::CONFLICT, e).into_response(),
    }
}

async fn get_rollout(State(state): State<AdminState>, Path((id, operation)): Path<(String, String)>) -> Response {
    let Some(d) = state.registry.get(&id) else { return err(StatusCode::NOT_FOUND, "deployment not found").into_response(); };
    match d.state().rollouts.iter().find(|o| o.operation_id == operation) {
        Some(o) => Json(o.view()).into_response(),
        None => err(StatusCode::NOT_FOUND, "rollout not found").into_response(),
    }
}

fn recovery_authorized(caller: &Caller, spec: &DeploymentSpec) -> bool {
    !matches!(caller, Caller::Ungated)
        && caller.satisfies_in(crate::tokens::AdminScope::Admin, Some(&spec.namespace))
        && caller.may_touch(&spec.id, Some(&spec.namespace))
}

async fn recover_workspace(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path(id): Path<String>, Json(request): Json<crate::workspace::RecoveryRequest>) -> Response {
    let _writer = state.registry.change_guard().await;
    let Some(d) = state.registry.get(&id) else { return err(StatusCode::NOT_FOUND, "deployment not found").into_response(); };
    if !recovery_authorized(&caller, &d.spec) { return forbidden("authenticated namespace admin required"); }
    let _creates = state.autoscaler.workspace_recovery_guard().await;
    let ws = state.autoscaler.workspaces();
    let _lifecycle = ws.lifecycle_guard().await;
    match ws.admit_recovery(&d, request).await {
        Ok(operation) => (StatusCode::ACCEPTED, Json(operation)).into_response(),
        Err(message) => err(StatusCode::CONFLICT, message).into_response(),
    }
}

async fn get_workspace_recovery(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Path((id, operation_id)): Path<(String, String)>) -> Response {
    let Some(d) = state.registry.get(&id) else { return err(StatusCode::NOT_FOUND, "deployment not found").into_response(); };
    if !recovery_authorized(&caller, &d.spec) { return forbidden("authenticated namespace admin required"); }
    match state.autoscaler.workspaces().recovery(&id, &operation_id) {
        Some(operation) if operation.namespace == d.spec.namespace => Json(operation).into_response(),
        _ => err(StatusCode::NOT_FOUND, "recovery not found in this namespace").into_response(),
    }
}

fn fleet_credential(caller: &Caller, headers: &axum::http::HeaderMap) -> Option<String> {
    if !matches!(caller, Caller::Federated(_)) { return None; }
    let session = browser_login::session(headers, &axum::http::Method::GET).ok().flatten();
    bearer(headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).or(session.as_deref())).map(str::to_owned)
}

async fn fleet_snapshot(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>, headers: axum::http::HeaderMap) -> Response {
    // Never inherit dashboard_auth=false: remote credentials must not turn an
    // open local dashboard into an unauthenticated cross-region inventory.
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() {
        return forbidden("authenticated fleet view required");
    }
    // Only forward an already-authenticated Heyo identity. Never delegate a
    // gateway-local app-token or Basic password to another gateway.
    let credential = fleet_credential(&caller, &headers);
    let snapshot = state.views.as_ref().map(|views| views.snapshot());
    let fleet = snapshot.as_ref().and_then(|s| s.fleet.as_ref());
    let observations = match fleet {
        Some(fleet) => fleet.observe(credential.as_deref()).await,
        None => Vec::new(),
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(serde_json::json!({
        "configured": fleet.is_some(), "gateways": observations,
    }))).into_response()
}

#[derive(Default, Deserialize)]
struct FleetQuery {
    namespace: Option<String>,
    #[serde(default)]
    offset: usize,
}

/// Who may read a fleet rollup, and with which credentials. A fleet-wide
/// caller reads everything. A caller without fleet coverage must name a
/// namespace it may view, and is then served only by gateways that take its own
/// Heyo identity: service credentials are never spent on its behalf.
fn fleet_reach(caller: &Caller, namespace: Option<&str>) -> Result<crate::fleet::Reach, Response> {
    if matches!(caller, Caller::Ungated) { return Err(forbidden("authenticated fleet view required")); }
    if namespace.is_some_and(|ns| !crate::config::is_valid_namespace(ns)) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid namespace").into_response());
    }
    if caller.covers_fleet() { return Ok(crate::fleet::Reach::Fleet); }
    match namespace {
        Some(ns) if caller.reaches_namespace(ns) && caller.satisfies_in(crate::tokens::AdminScope::View, Some(ns)) =>
            Ok(crate::fleet::Reach::CallerOnly),
        Some(_) => Err(forbidden("this credential cannot view that namespace")),
        None => Err(forbidden("authenticated fleet view required; name a namespace with ?namespace=")),
    }
}

fn fleet_namespace(query: &FleetQuery) -> Option<&str> {
    query.namespace.as_deref().map(str::trim).filter(|ns| !ns.is_empty())
}

/// `GET /fleet/deployments` — namespace × deployment rows with a cell per
/// gateway. Observations only; nothing here places or scales anything.
async fn fleet_deployments(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    headers: axum::http::HeaderMap, Query(query): Query<FleetQuery>) -> Response {
    let namespace = fleet_namespace(&query);
    let reach = match fleet_reach(&caller, namespace) { Ok(r) => r, Err(refused) => return refused };
    let credential = fleet_credential(&caller, &headers);
    let snapshot = state.views.as_ref().map(|views| views.snapshot());
    let Some(fleet) = snapshot.as_ref().and_then(|s| s.fleet.as_ref()) else {
        return ([(header::CACHE_CONTROL, "no-store")], Json(serde_json::json!({"configured":false}))).into_response();
    };
    let workloads = fleet.workloads(namespace, reach, credential.as_deref()).await;
    let mut body = serde_json::to_value(&workloads).unwrap_or_default();
    if let Some(map) = body.as_object_mut() {
        map.insert("configured".into(), true.into());
        map.insert("fleet_view".into(), (reach == crate::fleet::Reach::Fleet).into());
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// `GET /fleet/gateways/:id/metrics` — one allowlisted page of one gateway,
/// through this origin. Guest addresses only for fleet-wide callers.
async fn fleet_gateway_metrics(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    headers: axum::http::HeaderMap, Path(id): Path<String>, Query(query): Query<FleetQuery>) -> Response {
    let namespace = fleet_namespace(&query);
    let reach = match fleet_reach(&caller, namespace) { Ok(r) => r, Err(refused) => return refused };
    let credential = fleet_credential(&caller, &headers);
    let snapshot = state.views.as_ref().map(|views| views.snapshot());
    let Some(fleet) = snapshot.as_ref().and_then(|s| s.fleet.as_ref()) else {
        return err(StatusCode::NOT_FOUND, "no fleet is configured").into_response();
    };
    match fleet.gateway_detail(&id, namespace, query.offset, reach, credential.as_deref()).await {
        None => err(StatusCode::NOT_FOUND, "no such gateway").into_response(),
        Some(Err(e @ crate::fleet::SERVICE_CREDENTIAL_REFUSED)) => forbidden(e),
        Some(Err(e)) => err(StatusCode::BAD_GATEWAY, e).into_response(),
        Some(Ok(detail)) => ([(header::CACHE_CONTROL, "no-store")], Json(detail)).into_response(),
    }
}

/// `GET /fleet/network` — region → gateway → deployments → VMs, with ingress
/// addresses and guest addresses. Fleet-wide callers only.
async fn fleet_network(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    headers: axum::http::HeaderMap) -> Response {
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() {
        return forbidden("authenticated fleet view required");
    }
    let credential = fleet_credential(&caller, &headers);
    let snapshot = state.views.as_ref().map(|views| views.snapshot());
    let Some(fleet) = snapshot.as_ref().and_then(|s| s.fleet.as_ref()) else {
        return err(StatusCode::NOT_FOUND, "no fleet is configured").into_response();
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(fleet.network(credential.as_deref()).await)).into_response()
}

async fn require_fleet_view(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    authorize(state, req, next, crate::tokens::AdminScope::View).await
}

#[derive(Default, Deserialize)]
struct ServicesQuery { after: Option<String> }

async fn services_snapshot(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Query(query): Query<ServicesQuery>) -> Response {
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() {
        return forbidden("authenticated fleet view required");
    }
    let snapshot = state.views.as_ref().map(|views| views.snapshot());
    let Some(control) = snapshot.as_ref().and_then(|s| s.control_plane.as_ref()) else {
        return ([(header::CACHE_CONTROL, "no-store")], Json(serde_json::json!({"configured":false}))).into_response();
    };
    match control.inventory(query.after.as_deref()).await {
        Ok(inventory) => ([(header::CACHE_CONTROL, "no-store")], Json(serde_json::json!({
            "configured":true,"inventory":inventory,
        }))).into_response(),
        Err(error) => err(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
    }
}

async fn view_configuration(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>) -> Response {
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() { return forbidden("authenticated fleet admin required"); }
    let Some(views) = &state.views else { return err(StatusCode::SERVICE_UNAVAILABLE, "view store unavailable").into_response(); };
    let mut body = serde_json::to_value(&*views.snapshot()).unwrap_or_default();
    let sync = state.token_sync.lock().map(|s| s.clone()).unwrap_or_default();
    if let Some(body) = body.as_object_mut() {
        body.insert("token_sync".into(), serde_json::to_value(sync).unwrap_or_default());
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// Seconds between pulls of the token authority's fleet tokens: how long a
/// fleet token minted or revoked at the control plane takes to reach a server.
const TOKEN_SYNC_SECS: u64 = 10;

/// The last pull, for `GET /control-plane/config`. A server keeps serving its
/// last mirror while pulls fail, so how stale it is has to be visible somewhere.
#[derive(Clone, Default, Serialize)]
struct TokenSyncStatus {
    /// The bound authority's id, or `None` when this server mirrors nothing.
    authority: Option<String>,
    /// Fleet tokens currently mirrored.
    tokens: usize,
    last_attempt_at: Option<u64>,
    last_success_at: Option<u64>,
    error: Option<String>,
}

/// `GET /fleet/tokens` — this control plane's fleet tokens, verifiers included,
/// for the servers that name it as their token authority. Never secrets.
async fn fleet_tokens_export(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>) -> Response {
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() {
        return forbidden("authenticated fleet view required");
    }
    if !state.views.as_ref().is_some_and(|v| v.snapshot().fleet.is_some()) {
        return err(StatusCode::CONFLICT, "this app-lb has no gateways configured, so it is not a token authority").into_response();
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(state.tokens.fleet_export(now_secs()))).into_response()
}

/// One pull from the token authority. A failure keeps the last mirror; an
/// unbound authority drops it.
async fn sync_fleet_tokens(state: &AdminState) {
    let authority = state.views.as_ref().and_then(|v| v.snapshot().token_authority.clone());
    let now = now_secs();
    let Some(authority) = authority else {
        match state.tokens.clear_mirror() {
            Ok(true) => tracing::info!("token authority unconfigured; fleet tokens no longer accepted"),
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e, "cannot remove the fleet token mirror"),
        }
        if let Ok(mut status) = state.token_sync.lock() { *status = TokenSyncStatus::default(); }
        return;
    };
    let result = match authority.fleet_tokens().await {
        Ok((id, export)) => state.tokens.replace_mirror(&id, export).map(|changed| (id, changed)).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let (mirrored_from, count) = state.tokens.mirror_status();
    let Ok(mut status) = state.token_sync.lock() else { return };
    status.last_attempt_at = Some(now);
    status.tokens = count;
    match result {
        Ok((id, changed)) => {
            if changed { tracing::info!(authority = %id, tokens = count, "fleet tokens updated"); }
            status.authority = Some(id);
            status.last_success_at = Some(now);
            status.error = None;
        }
        Err(e) => {
            // Only log a change of state, not every failed pull.
            if status.error.as_deref() != Some(e.as_str()) {
                tracing::warn!(error = %e, mirrored = count, "fleet token pull failed; keeping the last mirror");
            }
            status.authority = mirrored_from.or(status.authority.take());
            status.error = Some(e);
        }
    }
}

async fn configure_views(State(state): State<AdminState>, axum::Extension(caller): axum::Extension<Caller>,
    Json(request): Json<crate::fleet::ConfigureViews>) -> Response {
    if matches!(caller, Caller::Ungated) || !caller.covers_fleet() { return forbidden("authenticated fleet admin required"); }
    let Some(views) = &state.views else { return err(StatusCode::SERVICE_UNAVAILABLE, "view store unavailable").into_response(); };
    match views.configure(request) {
        Ok(snapshot) => ([(header::CACHE_CONTROL, "no-store")], Json(snapshot)).into_response(),
        Err((status, message)) => err(status, message).into_response(),
    }
}

fn router(state: AdminState) -> Router {
    // The dashboard view + its data source are always behind the optional gate.
    let view = Router::new()
        // The landing page. Same tier as the dashboard: it lists every hostname
        // this app-lb routes, which is the same inventory `/metrics` exposes.
        .route("/", get(directory))
        .route("/metrics", get(metrics_snapshot))
        .route("/dashboard", get(dashboard))
        // View tier, not CRUD: the dashboard is its consumer, so the browser's
        // cached view credentials have to work. It must never be ungated — it
        // enumerates attacker addresses and the probes that reached the fleet —
        // and this group is the one that is gated whenever a password is set.
        .route("/security", get(security_snapshot))
        // The console that reads it. View tier for the same reason the dashboard
        // is: it renders `/security`, so it must work with whatever credentials
        // the browser already has. The buttons on it post to the CRUD tier and
        // will be refused for a view-only caller — which is the intended split,
        // and the page says so rather than failing silently.
        .route("/siem", get(siem_console))
        // The disk inventory and the console that renders it, on the same tier
        // and for the same reason. Reading what is on the host is a view-tier
        // question; every route that *changes* it is on the CRUD side below.
        .route("/disks", get(disks))
        // View tier beside `/feeds`, and for a narrower reason than that one:
        // it names only namespaces whose deployments the caller can already
        // list, so it is the directory's own information regrouped.
        .route("/namespaces", get(namespaces))
        // View tier, and it narrows itself to the caller's namespaces exactly as
        // `/namespaces` does — a scoped token gets its own providers rather than
        // a 403. The item reads and every write are on the CRUD side below.
        .route("/auth-providers", get(list_auth_providers))
        // The dashboard's "Get started" card. View tier, and it answers only
        // about a namespace the caller reaches; nothing in it is a secret.
        .route("/onboarding", get(onboarding))
        .route("/feeds", get(feeds_index))
        .route("/feeds/:namespace", get(feed_rss))
        // Where DNS should point. View tier: it is the answer to "what do I
        // put in the A record", which anyone who can read the directory of
        // hostnames may as well know.
        .route("/ingress", get(ingress))
        .route("/storage", get(storage_console))
        // The plugin console and the list it renders. Fleet-wide, like the
        // disk console: a plugin is a host-level capability, not a
        // deployment's.
        .route("/plugins", get(plugins_console))
        .route("/api/plugins", get(list_plugins))
        .route("/api/plugins/:id", get(get_plugin))
        .route("/api/plugins/:id/installs", get(plugin_installs))
        // A namespace's plugins: what it has installed, and the installed
        // plugins' own pages. Walled by the namespace in the path (see
        // `decide_access`), so a namespace token reaches these for its own
        // namespace. Every `GET` is view tier; the methods that change
        // something are on the CRUD side below.
        .route("/namespaces/:name/plugins", get(namespace_plugins))
        .route("/namespaces/:name/plugins/:id", get(namespace_plugin))
        .route("/namespaces/:name/plugins/:id/*rest", get(namespace_plugin_surface))
        // The network topology console. View tier, like the dashboard it sits
        // beside: it renders `/metrics` and `/ingress`, so it must work with
        // the browser's cached view credentials.
        .route("/network", get(network_console));

    // The deployment CRUD API — register/edit/scale/delete/evict, plus the reads
    // that expose the spec (env vars can hold secrets). Gated too iff
    // `admin_auth` is on; otherwise it stays open, as before.
    let crud = Router::new()
        .route("/deployments", post(register).get(list))
        .route("/deployments/:id/rollouts", post(start_rollout))
        .route("/deployments/:id/rollouts/:operation", get(get_rollout))
        .route("/deployments/:id", get(get_one).put(update).delete(deregister))
        .route("/deployments/:id/record", axum::routing::delete(deregister_record))
        .route("/deployments/:id/retired-record", axum::routing::delete(deregister_retired_record))
        .route("/deployments/:id/discovery-status", get(discovery_status))
        .route("/deployments/:id/scaling", patch(scale))
        .route("/deployments/:id/vms/:sandbox_id", delete(evict_vm))
        .route(
            "/deployments/:id/upstreams/:upstream/drain",
            put(drain_upstream).delete(uncordon_upstream),
        )
        // CRUD-tier on purpose: running a command in a VM is at least as
        // powerful as editing the spec that boots it.
        .route("/deployments/:id/exec", post(exec))
        .route("/deployments/:id/shell", get(shell))
        // Grouped with the CRUD routes so it inherits the `APP_LB_ADMIN_AUTH`
        // gate: it reports which hostnames app-lb holds keys for.
        .route("/certs", get(certs))
        // Blocking traffic is a mutation with more blast radius than most of the
        // ones above it, so it belongs on this side of the gate. Reads live on
        // `GET /security` with the alerts, which is why there is no `get` here.
        .route("/security/rules", post(create_rule))
        .route("/security/rules/:id", patch(patch_rule).delete(delete_rule))
        // Disk mutations. `DELETE /disks/:id` deletes gigabytes with no undo,
        // which puts it firmly on this side of the gate — it is the single most
        // destructive route app-lb exposes. `/disks/sweep` is registered as a
        // static segment and so cannot be reached by naming a sandbox `sweep`;
        // matchit prefers a literal over a parameter.
        .route("/disks/sweep", post(sweep_disks))
        // Also a static segment, shadowing any sandbox literally named
        // `purge-orphans` — the same trade `/disks/sweep` already makes.
        .route("/disks/purge-orphans", post(purge_orphan_disks))
        .route("/disks/:id", patch(patch_disk).delete(purge_disk))
        .route("/disks/:id/archive", post(archive_disk))
        // Secrets: write-only by design. `GET` returns key *names*, never values.
        // CRUD-tier: a workflow object decides what gets built and on whose
        // hardware, which is at least as consequential as a deployment spec.
        .route("/workflows", post(put_workflow).get(list_workflows))
        .route(
            "/workflows/:id",
            get(get_workflow).put(replace_workflow).delete(delete_workflow),
        )
        .route("/secrets", post(put_secret).get(list_secrets))
        .route(
            "/secrets/:id",
            get(get_secret)
                .put(replace_secret)
                .patch(patch_secret)
                .delete(delete_secret),
        )
        // Jobs. `build` runs `git` and `docker` on this host and `update` runs
        // the deployment's own commands, which is why they belong firmly on the
        // gated side of the API. One history covers both kinds: they have the
        // same lifecycle, and "what happened to this deployment lately?" should
        // have one answer.
        .route("/deployments/:id/build", post(start_build))
        .route("/deployments/:id/pull", post(start_pull))
        .route("/deployments/:id/mounts/pull", post(start_mount_pull))
        .route("/deployments/:id/update", post(start_update))
        .route("/deployments/:id/update/rollouts", get(host_update_snapshot).post(start_host_rollout))
        .route("/deployments/:id/update/rollouts/:operation", get(get_host_rollout))
        .route("/deployments/:id/update/bootstrap/:operation", get(get_host_bootstrap))
        .route("/deployments/:id/jobs", get(deployment_jobs))
        .route("/jobs", get(list_jobs))
        .route("/jobs/:job_id", get(get_job))
        // App-tokens. Firmly CRUD-tier: minting one is minting a credential, so
        // the route that does it must be at least as protected as the things the
        // credential can reach.
        // Declaring and undeclaring namespaces. CRUD tier; the handlers add the
        // fleet-scope requirement the gate cannot express, because `GET
        // /namespaces` is a view-tier route that narrows itself and the gate
        // matches on path, not method.
        .route("/namespaces", post(create_namespace))
        .route("/namespaces/:name", delete(delete_namespace))
        // Auth providers. `POST` shares its path with the view-tier list above,
        // exactly as `/namespaces` does; the item read sits here beside its
        // delete so one path lives on one tier. The item GET is CRUD-tier out of
        // the same caution that keeps a deployment spec there.
        .route("/auth-providers", post(create_auth_provider))
        .route(
            "/auth-providers/:namespace/:name",
            get(get_auth_provider).delete(delete_auth_provider),
        )
        // Switching a plugin on can open a public hostname onto this host or
        // hand out database credentials, so it is CRUD-tier. The item `PUT`
        // shares its path with the view-tier `GET` above, as `/namespaces` does.
        .route("/api/plugins/:id", put(put_plugin))
        .route("/api/plugins/:id/enable", post(enable_plugin))
        .route("/api/plugins/:id/disable", post(disable_plugin))
        .route(
            "/namespaces/:name/plugins/:id",
            put(install_namespace_plugin).delete(uninstall_namespace_plugin),
        )
        .route(
            "/namespaces/:name/plugins/:id/*rest",
            post(namespace_plugin_surface)
                .put(namespace_plugin_surface)
                .patch(namespace_plugin_surface)
                .delete(namespace_plugin_surface),
        )
        .route("/tokens", post(mint_token).get(list_tokens))
        .route(
            "/tokens/:id",
            get(get_token).patch(patch_token).delete(revoke_token),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(),retirement_admission));

    // `route_layer` runs the auth middleware only for the routes it wraps, so a
    // 404 elsewhere never triggers a challenge. `/healthz` is always open.
    //
    // Two layers rather than one, because the tiers want different scopes: a
    // `view` token may read `/metrics`, and only an `admin` one may reach the
    // CRUD routes. When `gate_admin` is off the CRUD routes carry no layer at
    // all — the pre-existing behaviour, and what `main()` warns loudly about.
    let (crud, open) = if state.gate_admin {
        (
            crud.route_layer(middleware::from_fn_with_state(
                state.clone(),
                require_crud_auth,
            )),
            Router::new(),
        )
    } else {
        (Router::new(), crud)
    };
    let view = view.route_layer(middleware::from_fn_with_state(
        state.clone(),
        require_view_auth,
    ));

    // Self-introspection, on its own layer because it is the only route with no
    // tier requirement at all. It is never folded into `view`: `gate_view` off
    // would then make it answer `Ungated` to callers who did present a token,
    // which is the one answer it must never give wrongly.
    let whoami = Router::new()
        .route("/whoami", get(whoami))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_any_credential,
        ));

    // Unlike legacy CRUD, explicit data recovery is never available ungated.
    let recovery = Router::new()
        .route("/deployments/:id/retirement", get(retirement_status).post(retire_deployment))
        .route("/deployments/:id/workspace/recoveries", post(recover_workspace))
        .route("/deployments/:id/workspace/recoveries/:operation_id", get(get_workspace_recovery))
        .route_layer(middleware::from_fn_with_state(state.clone(),retirement_admission))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_crud_auth));

    let regional = Router::new()
        .route("/deployments/:id/regional-probe",post(regional_probe))
        .route("/deployments/:id/regional-active-probe",post(regional_active_probe))
        .route("/deployments/:id/route-handoff",post(prepare_route_handoff).get(inspect_route_handoff))
        .route("/deployments/:id/route-handoff/commit",post(commit_route_handoff))
        .route_layer(middleware::from_fn_with_state(state.clone(),retirement_admission))
        .route_layer(middleware::from_fn_with_state(state.clone(),require_crud_auth));

    let fleet = Router::new()
        .route("/fleet", get(fleet_snapshot))
        .route("/fleet/deployments", get(fleet_deployments))
        .route("/fleet/gateways/:id/metrics", get(fleet_gateway_metrics))
        .route("/fleet/network", get(fleet_network))
        .route("/fleet/tokens", get(fleet_tokens_export))
        .route("/services", get(services_snapshot))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_fleet_view));

    let views = Router::new()
        .route("/control-plane/config", get(view_configuration).put(configure_views))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_crud_auth));

    let releases = Router::new()
        .route("/releases", get(release_console::page))
        .route("/api/releases/:resource", get(release_console::api).post(release_console::api))
        .layer(axum::extract::DefaultBodyLimit::max(8192))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_crud_auth));

    // Each plugin's own routes, under `/api/plugins/<id>/…`, on the same two
    // tiers. They carry no state of ours, so the gate goes on them here and
    // they are merged after `with_state` below.
    let (plugin_view, plugin_crud) = state.plugins.routers();
    let plugin_view = if plugin_view.has_routes() {
        plugin_view.route_layer(middleware::from_fn_with_state(state.clone(), require_view_auth))
    } else {
        plugin_view
    };
    let plugin_crud = if plugin_crud.has_routes() && state.gate_admin {
        plugin_crud.route_layer(middleware::from_fn_with_state(state.clone(), require_crud_auth))
    } else {
        plugin_crud
    };

    Router::new()
        .route("/healthz", get(healthz))
        // Embedded static assets contain no fleet state. Sign-in needs them
        // before the browser has a credential; inventory stays behind its gate.
        .route("/__ui/*path", get(ui_asset))
        .route("/login", get(browser_login::page).post(browser_login::login)
            .layer(axum::extract::DefaultBodyLimit::max(8192)))
        .route("/login/handoff", post(browser_login::handoff)
            .layer(axum::extract::DefaultBodyLimit::max(8192)))
        .route("/logout", post(browser_login::logout))
        .merge(releases)
        .merge(views)
        .merge(fleet)
        .merge(regional)
        .merge(recovery)
        .merge(view)
        .merge(whoami)
        .merge(crud)
        .merge(open)
        .with_state(state)
        .merge(plugin_view)
        .merge(plugin_crud)
}

#[async_trait]
impl BackgroundService for AdminApi {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let listener = match tokio::net::TcpListener::bind(&self.addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(addr = %self.addr, error = %e, "admin API failed to bind");
                return;
            }
        };
        tracing::info!(addr = %self.addr, "admin API listening");
        let sync_state = self.state.clone();
        let mut sync_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(TOKEN_SYNC_SECS));
            loop { tokio::select! {
                _ = tick.tick() => sync_fleet_tokens(&sync_state).await,
                _ = sync_shutdown.changed() => break,
            } }
        });
        let rollouts = self.state.rollouts.clone();
        let mut rollout_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            loop { tokio::select! {
                _ = tick.tick() => rollouts.tick().await,
                _ = rollout_shutdown.changed() => break,
            } }
        });

        // `into_make_service_with_connect_info` rather than the bare router:
        // without it there is no `ConnectInfo` extension anywhere in the admin
        // plane, so every rejected credential would be recorded with no source
        // address and the brute-force rule could never fire. That failure is
        // silent — the SIEM looks healthy and detects nothing — which is why it
        // is worth a comment rather than just a call.
        //
        // The admin listener defaults to 127.0.0.1, so in the usual deployment
        // this is a loopback address and the *count* is the useful part; the
        // address only means something when the port is exposed directly.
        let served = axum::serve(
            listener,
            router(self.state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
        )
            .with_graceful_shutdown(async move {
                while shutdown.changed().await.is_ok() {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            })
            .await;

        if let Err(e) = served {
            tracing::error!(error = %e, "admin API stopped");
        }
    }
}

// -- self-introspection ------------------------------------------------------

/// `GET /whoami` — what this credential is, and what it may do.
///
/// ## Why this route exists
///
/// A token's scope was, until this route, only readable through `GET /tokens`,
/// which needs `admin`. That is a circular dependency dressed as a permission
/// check: the caller who most needs to know their scope is the one whose scope
/// is too small to look it up, so the only way to answer "why am I getting a
/// 401" was to go and find a *second*, wider credential on another machine. A
/// client could not discover its own reach, and every scope problem therefore
/// presented as an authentication problem — which sends people to rotate a
/// token that was never the issue.
///
/// ## Why it discloses nothing
///
/// Every field describes the credential the caller already holds. There is no
/// registry read, no other token, and no fleet inventory here — `deployments`
/// is the token's own scope list as it was minted, not a list of things that
/// exist. Answering "you are `admin` over `["marketing"]`" tells the holder of
/// that token exactly what it could work out by trying two requests, minus the
/// afternoon.
///
/// The secret is never echoed, for the reason [`MintedToken`] gives: only its
/// hash is kept, and a route that could read one back would undo that.
async fn whoami(caller: Option<axum::Extension<Caller>>) -> impl IntoResponse {
    let now = now_secs();
    // The layer always inserts one; `None` would mean the route was reached
    // without the middleware, which is a wiring bug rather than a caller error.
    let Some(axum::Extension(caller)) = caller else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no caller on this request; /whoami was reached without its auth layer",
        )
        .into_response();
    };

    let mut body = serde_json::json!({
        // What kind of credential answered, spelled the way the rest of the API
        // spells them, so "app-token" here and `applb_…` in a header are
        // recognisably the same thing.
        "caller": match &caller {
            Caller::Ungated => "ungated",
            Caller::Operator => "operator",
            Caller::Token(_) => "app-token",
            Caller::Federated(_) => "federated",
        },
        // The two questions a refused request actually raises, answered
        // directly rather than left to be derived from the tier.
        "may": {
            "read_view_routes": caller.satisfies(crate::tokens::AdminScope::View),
            "use_admin_routes": caller.satisfies(crate::tokens::AdminScope::Admin),
        },
        // Whether this credential is confined to a namespace, which is the
        // other half of why a request gets refused and the half that does not
        // show up in the tier at all.
        "fleet": caller.covers_fleet(),
        "confined": caller.confined(),
    });

    match &caller {
        Caller::Ungated => {
            body["admin_scope"] = "unchecked".into();
            body["detail"] = "this listener has no credential configured, so every request                               is admitted and no scope is checked. APP_LB_DASHBOARD_PASSWORD is                               what turns the gate on."
                .into();
        }
        Caller::Operator => {
            body["admin_scope"] = "admin".into();
            body["detail"] = "the configured Basic credential, which is unscoped by                               definition — it is what mints tokens, so it outranks every                               token it could produce."
                .into();
        }
        Caller::Token(t) => {
            body["admin_scope"] = t.admin.as_str().into();
            body["token"] = serde_json::json!({ "id": t.id, "name": t.name });
            body["namespace"] = t.namespace.clone().into();
            // Verbatim, including `["*"]` and the empty list, because both are
            // meaningful and neither means what it looks like: `*` is every
            // deployment, and empty on a *namespace* token is everything in
            // that namespace rather than nothing.
            body["deployments"] = t.deployments.clone().into();
            body["expires_at"] = t.expires_at.into();
            body["expires_in_secs"] = t.expires_at.map(|e| e.saturating_sub(now)).into();
        }
        Caller::Federated(g) => {
            // A grant has a tier per namespace rather than one tier, so the
            // strongest is reported alongside the map instead of instead of it.
            body["admin_scope"] = if caller.satisfies(crate::tokens::AdminScope::Admin) {
                crate::tokens::AdminScope::Admin.as_str()
            } else if caller.satisfies(crate::tokens::AdminScope::View) {
                crate::tokens::AdminScope::View.as_str()
            } else {
                crate::tokens::AdminScope::None.as_str()
            }
            .into();
            body["subject"] = serde_json::json!({
                "user_id": g.subject.user_id,
                "email": g.subject.email,
                "account_id": g.subject.account_id,
            });
            body["namespaces"] = serde_json::json!(
                g.namespaces
                    .iter()
                    .map(|(ns, scope)| (ns.clone(), scope.as_str()))
                    .collect::<std::collections::BTreeMap<_, _>>()
            );
        }
    }

    // Named here rather than left to the caller to know: the gate in front of a
    // deployment and this API check *different* things, and a caller who has
    // only ever seen one of them will attribute a refusal to the wrong one.
    body["note"] = "A deployment's own gate checks whether this credential admits that                     deployment; it does not check the admin tier. This API checks the                     tier as well. A token can therefore pass a gate and still be refused                     here, and vice versa."
        .into();

    Json(body).into_response()
}

// -- app-tokens --------------------------------------------------------------

/// What `POST /tokens` answers with: the summary, plus the secret.
///
/// The secret appears here and in no other response, ever. There is no endpoint
/// that reads one back, because only its hash is kept — losing a token means
/// minting a replacement and revoking the old one, which is the behaviour you
/// want from a credential anyway.
#[derive(Serialize)]
struct MintedToken {
    #[serde(flatten)]
    summary: crate::tokens::TokenSummary,
    /// Store this now. It cannot be retrieved again.
    token: String,
}

fn token_error(e: crate::tokens::TokenError) -> Response {
    use crate::tokens::TokenError;
    let code = match &e {
        TokenError::NoToken(_) => StatusCode::NOT_FOUND,
        TokenError::EmptyName | TokenError::NameTooLong | TokenError::BadScope(_) => {
            StatusCode::BAD_REQUEST
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(code, e.to_string()).into_response()
}

/// Write the token file, turning a failure into a 500.
///
/// Unlike a deployment write — which logs and carries on, because the running
/// pool is the source of truth — a token that exists in memory but not on disk
/// is a credential that silently stops working at the next restart. The caller
/// is told instead.
/// `Box`ed because axum's `Response` is a large type, and this sits in the
/// `Err` half of a `Result` that several handlers thread through.
fn persist_tokens(state: &AdminState) -> Result<(), Box<Response>> {
    state.tokens.persist().map_err(|e| {
        tracing::error!(path = %state.tokens.path().display(), error = %e, "token file write failed");
        Box::new(
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("the token was not saved: {e}"),
            )
            .into_response(),
        )
    })
}

/// The confined caller among those a token route was reached by, if any.
/// The operator, an ungated build and an unconfined token keep the token
/// routes exactly as they were: fleet-wide, with no namespace policy.
fn confined(caller: Option<&Caller>) -> Option<&Caller> {
    caller.filter(|c| c.confined())
}

/// What a namespace-confined caller may mint: a token walled into a namespace
/// it administers, that expires within the tenant cap. Fills in the cap when
/// no lifetime was asked for, so a tenant's token always runs out.
///
/// Nothing else needs checking. A token confined to a namespace can never
/// reach past it whatever its `deployments` say, and administering the whole
/// namespace is already the most any confined credential can hold — so the
/// new token cannot be wider than the one that minted it.
fn confine_new_token(
    caller: &Caller,
    req: &mut crate::tokens::NewToken,
    max_ttl: u64,
) -> Result<(), Response> {
    let ns = req
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|ns| !ns.is_empty())
        .map(str::to_string);
    let Some(ns) = ns else {
        return Err(err(
            StatusCode::FORBIDDEN,
            "a namespace credential mints namespace tokens: set `namespace` to the one you administer",
        )
        .into_response());
    };
    if !caller.administers_namespace(&ns) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!("this credential cannot mint tokens for the \"{ns}\" namespace"),
        )
        .into_response());
    }
    req.namespace = Some(ns);
    match req.expires_in_secs {
        None => req.expires_in_secs = Some(max_ttl),
        Some(secs) if secs > max_ttl => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!(
                    "a namespace token may live at most {max_ttl} seconds ({} days)",
                    max_ttl / 86_400
                ),
            )
            .into_response());
        }
        Some(_) => {}
    }
    Ok(())
}

/// The same policy for a re-scope: the token must stay in a namespace the
/// caller administers and keep an expiry within the cap from now.
fn confine_token_patch(
    caller: &Caller,
    patch: &crate::tokens::TokenPatch,
    max_ttl: u64,
    now: u64,
) -> Result<(), Response> {
    match &patch.namespace {
        Some(None) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "a namespace credential cannot lift a token's namespace wall",
            )
            .into_response());
        }
        Some(Some(ns)) if !caller.administers_namespace(ns.trim()) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                format!("this credential cannot move a token into the \"{}\" namespace", ns.trim()),
            )
            .into_response());
        }
        _ => {}
    }
    match patch.expires_at {
        Some(None) => Err(err(
            StatusCode::FORBIDDEN,
            "a namespace token must expire; this credential cannot clear the expiry",
        )
        .into_response()),
        Some(Some(at)) if at > now.saturating_add(max_ttl) => Err(err(
            StatusCode::BAD_REQUEST,
            format!(
                "a namespace token may expire at most {max_ttl} seconds ({} days) from now",
                max_ttl / 86_400
            ),
        )
        .into_response()),
        _ => Ok(()),
    }
}

/// Whether `caller` may see and handle `token`. A confined caller sees only the
/// tokens of namespaces it administers; everyone else sees them all.
fn token_visible(caller: Option<&Caller>, token: &crate::tokens::TokenSummary) -> bool {
    confined(caller).is_none_or(|c| {
        token
            .namespace
            .as_deref()
            .is_some_and(|ns| c.administers_namespace(ns))
    })
}

/// The refusal to change a fleet token where it is only mirrored. Asked only
/// once the caller is known to see the token.
fn mirrored_token(state: &AdminState, caller: Option<&Caller>, id: &str) -> Option<Response> {
    let authority = state.tokens.mirrored_from(id)?;
    if !state.tokens.summary(id).is_some_and(|t| token_visible(caller, &t)) {
        return Some(no_token(id));
    }
    Some(err(
        StatusCode::CONFLICT,
        format!("{id} is a fleet token mirrored from {authority}; change or revoke it there"),
    )
    .into_response())
}

/// The one refusal for a token id a caller cannot see, worded as the one for an
/// id that does not exist so the two cannot be told apart.
fn no_token(id: &str) -> Response {
    err(StatusCode::NOT_FOUND, format!("no token {id:?}")).into_response()
}

async fn mint_token(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Json(mut req): Json<crate::tokens::NewToken>,
) -> Response {
    let caller = caller.as_deref();
    let mut minted_by = None;
    if let Some(c) = confined(caller) {
        if let Err(refused) =
            confine_new_token(c, &mut req, state.onboarding.tenant_token_max_ttl_secs)
        {
            return refused;
        }
        minted_by = c.principal();
    }
    if req.fleet && !state.views.as_ref().is_some_and(|v| v.snapshot().fleet.is_some()) {
        return err(
            StatusCode::CONFLICT,
            "fleet tokens are minted on a control plane: this app-lb has no gateways configured",
        )
        .into_response();
    }
    let name = req.name.clone();
    let (summary, token) = match state.tokens.mint_by(req, now_secs(), minted_by) {
        Ok(v) => v,
        Err(e) => return token_error(e),
    };
    if let Err(e) = persist_tokens(&state) {
        // Roll back, so a token that could not be saved is not one that works
        // until the next restart and then mysteriously stops.
        state.tokens.revoke(&summary.id);
        return *e;
    }
    tracing::info!(
        token = %summary.id,
        name = %name,
        admin = ?summary.admin,
        namespace = ?summary.namespace,
        deployments = ?summary.deployments,
        minted_by = ?summary.minted_by,
        "app-token minted",
    );
    (StatusCode::CREATED, Json(MintedToken { summary, token })).into_response()
}

async fn list_tokens(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
) -> impl IntoResponse {
    // Expired tokens already fail verification; drop them here so the listing
    // shows live credentials rather than a graveyard that looks like one.
    if state.tokens.sweep_expired(now_secs()) > 0 {
        let _ = state.tokens.persist();
    }
    let caller = caller.as_deref();
    let tokens: Vec<_> = state
        .tokens
        .list()
        .into_iter()
        .filter(|t| token_visible(caller, t))
        .collect();
    Json(tokens)
}

async fn get_token(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Path(id): Path<String>,
) -> Response {
    match state.tokens.summary(&id) {
        Some(t) if token_visible(caller.as_deref(), &t) => Json(t).into_response(),
        _ => no_token(&id),
    }
}

async fn patch_token(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Path(id): Path<String>,
    Json(patch): Json<crate::tokens::TokenPatch>,
) -> Response {
    let caller = caller.as_deref();
    if let Some(refused) = mirrored_token(&state, caller, &id) {
        return refused;
    }
    let before = state.tokens.get(&id);
    if !before.as_ref().is_some_and(|t| token_visible(caller, &t.summary())) {
        return no_token(&id);
    }
    if let Some(c) = confined(caller)
        && let Err(refused) =
            confine_token_patch(c, &patch, state.onboarding.tenant_token_max_ttl_secs, now_secs())
    {
        return refused;
    }
    let summary = match state.tokens.patch(&id, patch) {
        Ok(s) => s,
        Err(e) => return token_error(e),
    };
    if let Err(e) = persist_tokens(&state) {
        if let Some(before) = before {
            state.tokens.restore(before);
        }
        return *e;
    }
    tracing::info!(token = %id, admin = ?summary.admin, namespace = ?summary.namespace, deployments = ?summary.deployments, "app-token updated");
    Json(summary).into_response()
}

async fn revoke_token(
    State(state): State<AdminState>,
    caller: Option<axum::Extension<Caller>>,
    Path(id): Path<String>,
) -> Response {
    if let Some(refused) = mirrored_token(&state, caller.as_deref(), &id) {
        return refused;
    }
    let before = state.tokens.get(&id);
    if !before.as_ref().is_some_and(|t| token_visible(caller.as_deref(), &t.summary())) {
        return no_token(&id);
    }
    if !state.tokens.revoke(&id) {
        return no_token(&id);
    }
    if let Err(e) = persist_tokens(&state) {
        // A revocation that did not reach disk would come back at the next
        // restart, which is the worst possible direction for this to fail in.
        if let Some(before) = before {
            state.tokens.restore(before);
        }
        return *e;
    }
    tracing::info!(token = %id, "app-token revoked");
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_tweaks_merge_over_the_heyo_jwks_policy() {
        let body: CreateProviderBody = serde_json::from_value(serde_json::json!({
            "name": "heyo", "namespace": "acme", "preset": "heyo-jwks",
            "require": {"accountId": ["acct-1"]}, "cookie": "heyo_token",
            "login_url": "https://auth.example/login",
            "authorize_url": "https://auth.example/oauth/authorize",
            "token_url": "https://auth.example/oauth/token"
        }))
        .unwrap();
        assert!(body.has_jwt_tweaks());
        let mut jwt = crate::config::JwtSpec::heyo_jwks("https://auth.example/.well-known/jwks.json".into());
        apply_jwt_tweaks(&mut jwt, JwtTweaks {
            require: body.require,
            cookie: body.cookie,
            login_url: body.login_url,
            login_redirect_param: body.login_redirect_param,
            authorize_url: body.authorize_url,
            token_url: body.token_url,
        });
        assert_eq!(
            jwt.scoped_signin(),
            Some(("https://auth.example/oauth/authorize", "https://auth.example/oauth/token")),
        );
        // The preset's role check survives; the account check is added.
        assert_eq!(jwt.require["role"], serde_json::json!(["user", "admin"]));
        assert_eq!(jwt.require["accountId"], serde_json::json!(["acct-1"]));
        assert_eq!(jwt.cookie.as_deref(), Some("heyo_token"));
        assert_eq!(jwt.login_url.as_deref(), Some("https://auth.example/login"));
        assert_eq!(jwt.audience.as_deref(), Some("heyo-gate"));

        let plain: CreateProviderBody =
            serde_json::from_value(serde_json::json!({"name": "heyo", "preset": "heyo-jwks"})).unwrap();
        assert!(!plain.has_jwt_tweaks());
    }

    #[test]
    fn discovery_bootstrap_cannot_shadow_another_route() {
        let registry = Registry::new("unused.json");
        let spec = |id: &str, host: &str, prefix: &str| -> DeploymentSpec {
            serde_json::from_value(serde_json::json!({"id":id,"discovery":{"service_id":id},
                "routes":[{"host":host,"path_prefix":prefix}]})).unwrap()
        };
        registry.upsert(spec("production", "app.example", "/api"));
        assert!(discovery_route_conflicts(&registry, &spec("new", "app.example", "/api/v2")));
        assert!(discovery_route_conflicts(&registry, &spec("new", "APP.example", "/")));
        assert!(!discovery_route_conflicts(&registry, &spec("new", "app.example", "/test")));
        assert!(!discovery_route_conflicts(&registry, &spec("new", "other.example", "/api")));
    }

    #[test]
    fn discovery_status_uses_durable_version_and_rejects_other_deployments() {
        let registry = Registry::new("unused-discovery-status.json");
        let ordinary: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "ordinary",
            "routes": [{"host": "ordinary.example"}],
            "upstreams": ["ordinary.example:80"]
        }))
        .unwrap();
        registry.upsert(ordinary);
        let rejected = discovery_status_locked(&registry, "ordinary").unwrap_err();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

        let discovered: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "cloud",
            "routes": [{"host": "cloud.example"}],
            "upstreams": ["cloud.example:80"],
            "discovery": {"service_id": "cloud-service"}
        }))
        .unwrap();
        let deployment = registry.upsert(discovered);
        let before = discovery_status_locked(&registry, "cloud").unwrap();
        assert_eq!(before.version, None);
        deployment.mutate_state(|state| state.discovery_version = Some(9));
        let after = discovery_status_locked(&registry, "cloud").unwrap();
        assert_eq!(after.version, Some(9));
        assert_eq!(
            serde_json::to_value(after).unwrap(),
            serde_json::json!({
                "serviceId": "cloud-service",
                "version": 9,
                "upstreams": [{"peer": "cloud.example:80", "draining": false, "inFlight": 0}]
            })
        );
    }

    #[tokio::test]
    async fn healthz_reports_compiled_revision() {
        let response = healthz().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-heyo-revision"], env!("APP_LB_BUILD_REVISION"));
        let body = axum::body::to_bytes(response.into_body(), 32).await.unwrap();
        assert_eq!(body.as_ref(), b"ok\n");
    }

    #[test]
    fn discovery_status_tracks_removed_and_readded_peer_generations() {
        let registry = Registry::new("unused-discovery-generations.json");
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id":"svc", "routes":[{"host":"svc.example"}],
            "upstreams":["eu:8080"], "discovery":{"service_id":"svc"}
        })).unwrap();
        let first = registry.upsert(spec.clone());
        let old = first.backends()[0].clone();
        assert!(old.try_acquire());
        // Admin deletion/re-registration must not lose requests retained by
        // the old proxy generation, either.
        registry.remove("svc");
        assert!(!old.try_acquire());
        let replacement = registry.upsert(spec);
        replacement.mutate_state(|s| s.discovery_version = Some(12));
        let status = discovery_status_locked(&registry,"svc").unwrap();
        assert_eq!(status.upstreams.len(),1);
        assert_eq!(status.upstreams[0].in_flight,1);
        assert!(!status.upstreams[0].draining,"one accepting generation prevents a drained claim");
        registry.apply_discovery_upstreams(&replacement,vec![]);
        let withdrawn = discovery_status_locked(&registry,"svc").unwrap();
        assert!(withdrawn.upstreams[0].draining);
        assert_eq!(withdrawn.upstreams[0].in_flight,1);
        old.release();
        assert!(discovery_status_locked(&registry,"svc").unwrap().upstreams.is_empty());
    }

    mod deployment_etags {
        use super::*;

        fn spec(route: &str) -> DeploymentSpec {
            let mut spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
                "id": "web",
                "routes": [{"host": route}],
                "upstreams": ["127.0.0.1:8080"]
            }))
            .unwrap();
            spec.normalize();
            spec
        }

        fn headers(value: Option<&str>) -> axum::http::HeaderMap {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(value) = value {
                headers.insert(header::IF_MATCH, value.parse().unwrap());
            }
            headers
        }

        #[test]
        fn validator_uses_lexical_keys_even_with_preserve_order() {
            // Independent canonical encoder: sort keys at each object, keeping
            // arrays ordered. Do not use the production sort_all_objects call.
            fn canonical(value: &serde_json::Value) -> String {
                match value {
                    serde_json::Value::Object(map) => {
                        let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
                        format!("{{{}}}", sorted.into_iter().map(|(k, v)|
                            format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v))
                        ).collect::<Vec<_>>().join(","))
                    }
                    serde_json::Value::Array(items) => format!("[{}]", items.iter().map(canonical).collect::<Vec<_>>().join(",")),
                    other => other.to_string(),
                }
            }
            let current = spec("test.example.com");
            let expected = format!("\"{:x}\"", Sha256::digest(canonical(&serde_json::to_value(&current).unwrap()).as_bytes()));
            assert_eq!(deployment_etag(&current).unwrap(), expected);
        }

        #[test]
        fn matching_tag_succeeds_and_unconditioned_update_stays_compatible() {
            let current = spec("old.example.com");
            let tag = deployment_etag(&current).unwrap();
            assert!(check_etag_precondition(if_match(&headers(Some(&tag))).unwrap(), &current).is_ok());
            assert!(check_etag_precondition(if_match(&headers(None)).unwrap(), &current).is_ok());
        }

        #[tokio::test]
        async fn stale_tag_does_not_replace_the_deployment_or_its_pool() {
            let registry = crate::registry::Registry::new("unused-etag-test-state.json");
            let first = registry.upsert(spec("first.example.com"));
            let stale = deployment_etag(&first.spec).unwrap();
            let current = registry.upsert(spec("current.example.com"));

            let _change = registry.change_guard().await;
            let observed = registry.get("web").unwrap();
            assert_eq!(
                check_etag_precondition(Some(&stale), &observed.spec),
                Err(StatusCode::PRECONDITION_FAILED)
            );
            // The failed CAS never calls update/upsert: the exact Deployment
            // object (and therefore its backend pool) remains installed.
            assert!(Arc::ptr_eq(&current, &registry.get("web").unwrap()));
            assert_eq!(registry.get("web").unwrap().spec.routes[0].host.as_deref(), Some("current.example.com"));
        }

        #[test]
        fn malformed_weak_wildcard_and_list_tags_are_refused() {
            for value in [
                "not-an-etag",
                "W/\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                "*",
                "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"",
                "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"",
            ] {
                assert_eq!(if_match(&headers(Some(value))).unwrap_err().status(), StatusCode::BAD_REQUEST, "{value}");
            }
        }

        #[test]
        fn tag_hashes_the_serialized_value_of_the_full_spec() {
            let spec = spec("hash.example.com");
            let mut value = serde_json::to_value(&spec).unwrap();
            value.sort_all_objects();
            let expected = format!("\"{:x}\"", Sha256::digest(serde_json::to_vec(&value).unwrap()));
            assert_eq!(deployment_etag(&spec).unwrap(), expected);
            assert_eq!(expected.len(), 66);
        }
    }

    mod record_only_deregistration {
        use super::*;
        use crate::deployment::PendingVm;
        use axum::{Json, body::Body, http::Request, routing::get};
        use std::path::{Path as FsPath, PathBuf};
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use tower_service::Service;

        static FIXTURE: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            state: AdminState,
            registry: Arc<Registry>,
            root: PathBuf,
            mutations: Arc<AtomicUsize>,
            inactive: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        }

        impl Drop for Fixture {
            fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); }
        }

        async fn fixture(inventory_available: bool) -> Fixture {
            fixture_with_backend(inventory_available,Router::new(),None).await
        }

        async fn fixture_with_backend(inventory_available: bool, extra:Router, restore:Option<PathBuf>) -> Fixture {
            let reload=restore.is_some();
            let root = restore.unwrap_or_else(||std::env::temp_dir().join(format!(
                "app-lb-record-handler-{}-{}", std::process::id(),
                FIXTURE.fetch_add(1, Ordering::Relaxed),
            )));
            std::fs::create_dir_all(&root).unwrap();
            let mutations = Arc::new(AtomicUsize::new(0));
            let mutation_count = mutations.clone();
            let inactive = Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
            let inactive_rows = inactive.clone();
            let app = Router::new()
                .route("/deployed-sandboxes", get(move || async move {
                    if inventory_available { Json(serde_json::json!([])).into_response() }
                    else { StatusCode::SERVICE_UNAVAILABLE.into_response() }
                }))
                .route("/sandboxes/inactive", get(move || {
                    let rows = inactive_rows.lock().unwrap().clone();
                    async move { Json(serde_json::json!({"sandboxes": rows, "next_cursor": null})) }
                }))
                .route("/storage", get(|| async {
                    Json(serde_json::json!({
                        "data_dir": "/data", "tmp_dir": "/tmp",
                        "free_bytes": 10, "total_bytes": 20, "sandboxes": []
                    }))
                }))
                .merge(extra)
                .fallback(move |request: Request<Body>| {
                    let mutation_count = mutation_count.clone();
                    async move {
                        if request.method() != axum::http::Method::GET {
                            mutation_count.fetch_add(1, Ordering::SeqCst);
                        }
                        StatusCode::NOT_FOUND
                    }
                });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let daemon_url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

            let registry = Arc::new(Registry::new(root.join("deployments.json")));
            if reload {registry.load().unwrap(); registry.require_complete_load().unwrap();} else {
                registry.upsert(empty().spec.clone());
                registry.persist_one("obsolete").unwrap();
            }
            let mounts = crate::mounts::MountStore::new(root.join("mounts"), 0);
            let vms = crate::vm::VmManager::new(Some(daemon_url), Some("retirement-test-key".into()), mounts.clone()).unwrap();
            let secrets = Arc::new(crate::secrets::SecretStore::new(root.join("secrets.json"), None));
            let workspaces = Arc::new(crate::workspace::Workspaces::new(
                crate::workspace::WorkspaceConfig {
                    root: root.join("workspaces"), tar_bin: "tar".into(), aws_bin: "aws".into(),
                    art_bin: "art".into(), s3_endpoint: None, home: None,
                    timeout: std::time::Duration::from_secs(1),
                }, vms.clone(), registry.clone(), secrets.clone(),
            ));
            let metrics = Arc::new(Metrics::new());
            let feed = Arc::new(crate::feed::Feed::new());
            let autoscaler = Arc::new(Autoscaler::new(
                registry.clone(),
                crate::runtime::Runtime::new(vms.clone(), crate::config::LxcConfig { enabled: false, ..Default::default() }),
                metrics.clone(), feed.clone(), workspaces, secrets.clone(),
            ));
            let jobs = Arc::new(Jobs::new(crate::jobs::JobConfig {
                work_dir: root.join("jobs"), heyvm_bin: "heyvm".into(), art_bin: "art".into(),
                images_dir: root.join("images"), git_bin: "git".into(), mounts,
                shell: "sh".into(), timeout: std::time::Duration::ZERO, home: None, sites_dir: None,
            }, registry.clone(), autoscaler.clone(), secrets.clone(), None));
            let disks = Arc::new(crate::disks::DiskStore::new(crate::disks::DiskConfig {
                state_path: root.join("disks.json"), ttl_secs: 0, sweep_secs: 60,
                aws_bin: "aws".into(), bucket: None, prefix: "test".into(), endpoint: None,
                archive_on_expire: false, archive_timeout: std::time::Duration::from_secs(60),
                orphan_ttl_secs: 0,
            }, vms, registry.clone()));
            let plugin_secrets = secrets.clone();
            let api = AdminApi::new(
                "127.0.0.1:0".into(), registry.clone(), autoscaler, metrics, "test".into(),
                None, None, false, false, None,
                Arc::new(crate::tls::CertStore::new(root.join("certs"), None)), None, secrets,
                Arc::new(crate::workflows::WorkflowStore::new(root.join("workflows"))),
                Arc::new(crate::namespaces::NamespaceStore::new(root.join("namespaces"))),
                Arc::new(crate::auth_providers::AuthProviderStore::new(root.join("providers"))),
                Arc::new(crate::tokens::TokenStore::new(root.join("tokens.json"))), jobs,
                None, None, Arc::new(crate::guard::Guard::new(root.join("guard.json"), false)),
                Some(disks), PublicUrl::from_config(false, "127.0.0.1:80", "127.0.0.1:443"),
                feed, &[], None,
                Arc::new(crate::plugins::PluginHost::new(
                    vec![crate::plugins::obs::ObsPlugin::new(plugin_secrets)],
                    crate::plugins::PluginStore::new(root.join("plugins")),
                )),
            );
            Fixture { state: api.state, registry, root, mutations, inactive }
        }

        /// Fleet tokens: minted only where gateways are configured, exported
        /// only to fleet-wide callers, and read-only where they are mirrored.
        mod fleet_tokens {
            use super::*;
            use crate::tokens::{AdminScope, NewToken};

            fn new(name: &str, fleet: bool) -> NewToken {
                NewToken { fleet, name: name.into(), admin: AdminScope::Admin, namespace: None,
                    deployments: vec!["*".into()], expires_in_secs: None }
            }

            /// Make the fixture a control plane with one configured gateway.
            fn control_plane(f: &mut Fixture) {
                let path = f.root.join("views.json");
                std::fs::write(&path, serde_json::to_vec(&serde_json::json!({"revision":1,"config":{
                    "gateways":[{"id":"us4","region":"US4","url":"https://admin.us4.example",
                        "auth":{"secret":"fleet-observer-us4","key":"token"}}],
                    "control_plane":[]}})).unwrap()).unwrap();
                let views = crate::fleet::ViewStore::open(path, f.state.secrets.clone(), [None, None]).unwrap();
                f.state.views = Some(Arc::new(views));
            }

            async fn body(r: Response) -> (StatusCode, serde_json::Value) {
                let status = r.status();
                let bytes = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
                (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
            }

            fn operator(f: &Fixture) -> Caller {
                let (summary, _) = f.state.tokens.mint(new("operator", false), now_secs()).unwrap();
                Caller::Token(f.state.tokens.get(&summary.id).unwrap())
            }

            #[tokio::test]
            async fn only_a_control_plane_mints_fleet_tokens() {
                let mut f = fixture(true).await;
                let (status, v) = body(mint_token(State(f.state.clone()), None, Json(new("deploy", true))).await).await;
                assert_eq!(status, StatusCode::CONFLICT, "{v}");
                assert!(f.state.tokens.list().is_empty(), "a refused mint leaves nothing behind");

                control_plane(&mut f);
                let (status, v) = body(mint_token(State(f.state.clone()), None, Json(new("deploy", true))).await).await;
                assert_eq!(status, StatusCode::CREATED, "{v}");
                assert_eq!(v["fleet"], true);
            }

            #[tokio::test]
            async fn the_export_carries_only_fleet_tokens_to_fleet_wide_callers() {
                let mut f = fixture(true).await;
                control_plane(&mut f);
                let op = operator(&f);
                f.state.tokens.mint(new("deploy", true), now_secs()).unwrap();

                let (status, v) = body(fleet_tokens_export(State(f.state.clone()), axum::Extension(op)).await).await;
                assert_eq!(status, StatusCode::OK, "{v}");
                let tokens = v["tokens"].as_array().unwrap();
                assert_eq!(tokens.len(), 1, "the operator's own token is not exported");
                assert_eq!(tokens[0]["name"], "deploy");
                assert_eq!(tokens[0]["secret_sha256"].as_str().unwrap().len(), 64);
                assert!(!v.to_string().contains("applb_"), "never a secret");

                let (summary, _) = f.state.tokens.mint(NewToken { namespace: Some("team-a".into()), ..new("ns", false) }, now_secs()).unwrap();
                let confined = Caller::Token(f.state.tokens.get(&summary.id).unwrap());
                let (status, _) = body(fleet_tokens_export(State(f.state.clone()), axum::Extension(confined)).await).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                let (status, _) = body(fleet_tokens_export(State(f.state.clone()), axum::Extension(Caller::Ungated)).await).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
            }

            #[tokio::test]
            async fn a_server_that_is_not_a_control_plane_exports_nothing() {
                let f = fixture(true).await;
                let op = operator(&f);
                let (status, _) = body(fleet_tokens_export(State(f.state.clone()), axum::Extension(op)).await).await;
                assert_eq!(status, StatusCode::CONFLICT);
            }

            #[tokio::test]
            async fn a_mirrored_token_is_listed_but_changed_and_revoked_only_at_its_control_plane() {
                let f = fixture(true).await;
                let cp = crate::tokens::TokenStore::new(f.root.join("cp-tokens.json"));
                let (t, secret) = cp.mint(new("deploy", true), now_secs()).unwrap();
                f.state.tokens.replace_mirror("us2", cp.fleet_export(now_secs())).unwrap();

                let (status, v) = body(get_token(State(f.state.clone()), None, Path(t.id.clone())).await).await;
                assert_eq!(status, StatusCode::OK, "{v}");
                assert_eq!(v["mirrored_from"], "us2");

                let (status, v) = body(revoke_token(State(f.state.clone()), None, Path(t.id.clone())).await).await;
                assert_eq!(status, StatusCode::CONFLICT, "{v}");
                assert!(v.to_string().contains("us2"), "the refusal names where to go: {v}");
                let patch: crate::tokens::TokenPatch = serde_json::from_value(serde_json::json!({"name":"renamed"})).unwrap();
                let (status, _) = body(patch_token(State(f.state.clone()), None, Path(t.id.clone()), Json(patch)).await).await;
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(f.state.tokens.verify(&secret, now_secs()).is_some(), "still accepted after the refusals");
            }

            #[tokio::test]
            async fn unbinding_the_authority_stops_accepting_its_tokens() {
                let f = fixture(true).await;
                let cp = crate::tokens::TokenStore::new(f.root.join("cp-tokens.json"));
                let (_, secret) = cp.mint(new("deploy", true), now_secs()).unwrap();
                f.state.tokens.replace_mirror("us2", cp.fleet_export(now_secs())).unwrap();
                // No views at all: nothing names a token authority.
                sync_fleet_tokens(&f.state).await;
                assert!(f.state.tokens.verify(&secret, now_secs()).is_none());
                assert_eq!(f.state.token_sync.lock().unwrap().authority, None);
            }
        }

        /// The token routes for a namespace-confined caller, end to end through
        /// the handlers: what it may mint, see, re-scope and revoke.
        mod tenant_tokens {
            use super::*;
            use crate::tokens::{AdminScope, NewToken, TokenPatch};

            fn new(name: &str, ns: Option<&str>, admin: AdminScope, ttl: Option<u64>) -> NewToken {
                NewToken {
                    fleet: false,
                    name: name.into(),
                    admin,
                    namespace: ns.map(str::to_string),
                    deployments: vec![],
                    expires_in_secs: ttl,
                }
            }

            /// A token in the store, as the caller that presents it.
            fn token_caller(f: &Fixture, req: NewToken) -> (Caller, String) {
                let (summary, _) = f.state.tokens.mint(req, now_secs()).unwrap();
                (Caller::Token(f.state.tokens.get(&summary.id).unwrap()), summary.id)
            }

            fn federated(ns: &[(&str, AdminScope)]) -> Caller {
                Caller::Federated(Arc::new(crate::federated::Grant {
                    subject: serde_json::from_value(serde_json::json!({"userId": "u1"})).unwrap(),
                    namespaces: ns.iter().map(|(n, s)| (n.to_string(), *s)).collect(),
                    accounts: Default::default(),
                    fleet: false,
                }))
            }

            async fn body(r: Response) -> (StatusCode, serde_json::Value) {
                let status = r.status();
                let bytes = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
                (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
            }

            async fn mint_as(f: &Fixture, c: Option<&Caller>, req: NewToken) -> (StatusCode, serde_json::Value) {
                body(mint_token(State(f.state.clone()), c.cloned().map(axum::Extension), Json(req)).await).await
            }

            #[tokio::test]
            async fn a_namespace_admin_mints_into_its_own_namespace_with_an_expiry() {
                let f = fixture(true).await;
                let (c, id) = token_caller(&f, new("ops", Some("team-a"), AdminScope::Admin, None));
                let (status, v) = mint_as(&f, Some(&c), new("claude-code", Some("team-a"), AdminScope::Admin, None)).await;
                assert_eq!(status, StatusCode::CREATED, "{v}");
                assert_eq!(v["namespace"], "team-a");
                assert_eq!(v["minted_by"], format!("token:{id}"));
                let max = f.state.onboarding.tenant_token_max_ttl_secs;
                let lifetime = v["expires_at"].as_u64().unwrap() - v["created_at"].as_u64().unwrap();
                assert_eq!(lifetime, max, "an unasked-for lifetime is the cap, never forever");
                assert!(v["token"].as_str().unwrap().starts_with("applb_"));
            }

            #[tokio::test]
            async fn a_namespace_admin_cannot_mint_past_its_wall() {
                let f = fixture(true).await;
                let (c, _) = token_caller(&f, new("ops", Some("team-a"), AdminScope::Admin, None));
                let max = f.state.onboarding.tenant_token_max_ttl_secs;
                for (req, want) in [
                    (new("x", Some("team-b"), AdminScope::Admin, None), StatusCode::FORBIDDEN),
                    (new("x", None, AdminScope::Admin, None), StatusCode::FORBIDDEN),
                    (new("x", Some(" "), AdminScope::View, None), StatusCode::FORBIDDEN),
                    (new("x", Some("team-a"), AdminScope::Admin, Some(max + 1)), StatusCode::BAD_REQUEST),
                ] {
                    let (status, v) = mint_as(&f, Some(&c), req).await;
                    assert_eq!(status, want, "{v}");
                }
                // `"*"` inside a namespace is still only that namespace.
                let mut star = new("x", Some("team-a"), AdminScope::Admin, Some(60));
                star.deployments = vec!["*".into()];
                let (status, v) = mint_as(&f, Some(&c), star).await;
                assert_eq!(status, StatusCode::CREATED);
                let minted = f.state.tokens.get(v["id"].as_str().unwrap()).unwrap();
                assert!(!minted.covers_fleet());
            }

            #[tokio::test]
            async fn only_a_whole_namespace_admin_may_mint() {
                let f = fixture(true).await;
                let (viewer, _) = token_caller(&f, new("v", Some("team-a"), AdminScope::View, None));
                let mut narrow = new("n", Some("team-a"), AdminScope::Admin, None);
                narrow.deployments = vec!["web".into()];
                let (narrow, _) = token_caller(&f, narrow);
                for c in [viewer, narrow] {
                    let (status, _) = mint_as(&f, Some(&c), new("x", Some("team-a"), AdminScope::None, None)).await;
                    assert_eq!(status, StatusCode::FORBIDDEN);
                }
            }

            #[tokio::test]
            async fn a_federated_user_mints_where_it_is_admin() {
                let f = fixture(true).await;
                let c = federated(&[("team-a", AdminScope::Admin), ("team-b", AdminScope::View)]);
                let (status, v) = mint_as(&f, Some(&c), new("x", Some("team-a"), AdminScope::Admin, None)).await;
                assert_eq!(status, StatusCode::CREATED);
                assert_eq!(v["minted_by"], "user:u1");
                let (status, _) = mint_as(&f, Some(&c), new("x", Some("team-b"), AdminScope::View, None)).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
            }

            #[tokio::test]
            async fn the_operator_is_unchanged() {
                let f = fixture(true).await;
                let (status, v) = mint_as(&f, Some(&Caller::Operator), new("fleet", None, AdminScope::Admin, None)).await;
                assert_eq!(status, StatusCode::CREATED);
                assert!(v.get("expires_at").is_none(), "the operator still chooses no expiry");
                assert!(v.get("minted_by").is_none());
                let (status, _) = mint_as(&f, None, new("ungated", None, AdminScope::Admin, None)).await;
                assert_eq!(status, StatusCode::CREATED);
            }

            #[tokio::test]
            async fn a_namespace_admin_sees_and_handles_only_its_own_tokens() {
                let f = fixture(true).await;
                let (c, own_id) = token_caller(&f, new("ops", Some("team-a"), AdminScope::Admin, None));
                let (other, _) = f.state.tokens.mint(new("b", Some("team-b"), AdminScope::Admin, None), now_secs()).unwrap();
                let (fleet, _) = f.state.tokens.mint(new("fleet", None, AdminScope::Admin, None), now_secs()).unwrap();
                let ext = || Some(axum::Extension(c.clone()));

                let listed = list_tokens(State(f.state.clone()), ext()).await.into_response();
                let (_, v) = body(listed).await;
                let ids: Vec<_> = v.as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap().to_string()).collect();
                assert_eq!(ids, vec![own_id.clone()]);

                // The operator still sees all three.
                let (_, v) = body(list_tokens(State(f.state.clone()), None).await.into_response()).await;
                assert_eq!(v.as_array().unwrap().len(), 3);

                // Another namespace's token and a fleet token read as missing.
                for id in [other.id.clone(), fleet.id.clone(), "nope".into()] {
                    let (status, v) = body(get_token(State(f.state.clone()), ext(), Path(id.clone())).await).await;
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    assert_eq!(v["error"], format!("no token {id:?}"));
                    let (status, _) = body(revoke_token(State(f.state.clone()), ext(), Path(id.clone())).await).await;
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    let rename = TokenPatch { name: Some("mine now".into()), ..Default::default() };
                    let (status, _) = body(patch_token(State(f.state.clone()), ext(), Path(id), Json(rename)).await).await;
                    assert_eq!(status, StatusCode::NOT_FOUND);
                }
                assert!(f.state.tokens.get(&other.id).is_some());
                assert!(f.state.tokens.get(&fleet.id).is_some());
            }

            #[tokio::test]
            async fn a_re_scope_cannot_widen_a_namespace_token() {
                let f = fixture(true).await;
                let (c, _) = token_caller(&f, new("ops", Some("team-a"), AdminScope::Admin, None));
                let (target, _) = f.state.tokens.mint(new("t", Some("team-a"), AdminScope::View, Some(60)), now_secs()).unwrap();
                let max = f.state.onboarding.tenant_token_max_ttl_secs;
                let patch = |p: TokenPatch| {
                    let state = f.state.clone();
                    let c = c.clone();
                    let id = target.id.clone();
                    async move { body(patch_token(State(state), Some(axum::Extension(c)), Path(id), Json(p)).await).await.0 }
                };
                assert_eq!(patch(TokenPatch { namespace: Some(None), ..Default::default() }).await, StatusCode::FORBIDDEN);
                assert_eq!(patch(TokenPatch { namespace: Some(Some("team-b".into())), ..Default::default() }).await, StatusCode::FORBIDDEN);
                assert_eq!(patch(TokenPatch { expires_at: Some(None), ..Default::default() }).await, StatusCode::FORBIDDEN);
                assert_eq!(
                    patch(TokenPatch { expires_at: Some(Some(now_secs() + max + 60)), ..Default::default() }).await,
                    StatusCode::BAD_REQUEST
                );
                assert_eq!(patch(TokenPatch { admin: Some(AdminScope::Admin), ..Default::default() }).await, StatusCode::OK);
                assert_eq!(f.state.tokens.get(&target.id).unwrap().namespace.as_deref(), Some("team-a"));
            }

            #[tokio::test]
            async fn a_namespace_admin_revokes_its_own_tokens() {
                let f = fixture(true).await;
                let (c, _) = token_caller(&f, new("ops", Some("team-a"), AdminScope::Admin, None));
                let (target, _) = f.state.tokens.mint(new("t", Some("team-a"), AdminScope::View, Some(60)), now_secs()).unwrap();
                let r = revoke_token(State(f.state.clone()), Some(axum::Extension(c)), Path(target.id.clone())).await;
                assert_eq!(r.status(), StatusCode::NO_CONTENT);
                assert!(f.state.tokens.get(&target.id).is_none());
            }

            #[tokio::test]
            async fn onboarding_answers_about_a_reachable_namespace_only() {
                let f = fixture(true).await;
                let c = federated(&[("team-a", AdminScope::Admin)]);
                let ask = |c: Option<Caller>, ns: Option<&str>| {
                    let state = f.state.clone();
                    let q = OnboardingQuery { namespace: ns.map(str::to_string) };
                    async move { body(onboarding(State(state), c.map(axum::Extension), Query(q)).await).await }
                };
                // The namespace defaults to the caller's only one.
                let (status, v) = ask(Some(c.clone()), None).await;
                assert_eq!(status, StatusCode::OK, "{v}");
                assert_eq!(v["namespace"], "team-a");
                assert_eq!(v["deployments"], 0);
                assert_eq!(v["can_mint"], true);
                assert_eq!(v["fastcar"]["id"], "fastcar-team-a");
                assert_eq!(v["fastcar"]["spec"]["namespace"], "team-a");
                // No catalog in the test environment, and it says so.
                assert_eq!(v["fastcar"]["image"], "unconfigured");
                let spec: crate::config::DeploymentSpec =
                    serde_json::from_value(v["fastcar"]["spec"].clone()).unwrap();
                spec.validate().unwrap();

                let (status, _) = ask(Some(c.clone()), Some("team-b")).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                let (status, _) = ask(Some(Caller::Operator), None).await;
                assert_eq!(status, StatusCode::BAD_REQUEST);
                let (status, _) = ask(Some(Caller::Operator), Some("../x")).await;
                assert_eq!(status, StatusCode::BAD_REQUEST);
            }
        }

        mod retirement_tests {
            use super::*;
            use crate::retirement::{CreateAttempt,Request as RetirementRequest,Target};
            use serde_json::{Value,json};
            use std::sync::Mutex;
            use std::time::Duration;

            #[derive(Default)]
            struct Backend {
                mode: AtomicUsize,
                posts: AtomicUsize,
                reads: AtomicUsize,
                receipt: Mutex<Option<Value>>,
                requests: Mutex<Vec<Value>>,
            }

            fn target() -> Target {
                Target {backend_server_id:"host-us3".into(),backend_sandbox_id:"sb-12345678".into(),
                    created_at_unix_nanos:"1780000000123456789".into(),libvirt_connection_uri:"qemu:///system".into(),
                    libvirt_domain_uuid:"3a7bfa82-b791-4e9d-8be4-4a0bef8c4470".into()}
            }

            fn backend_router(b:Arc<Backend>) -> Router {
                let read=b.clone();
                Router::new().route("/sandboxes/:id/retirement",get(move |headers:axum::http::HeaderMap| {
                    let b=read.clone(); async move {
                        assert_eq!(headers[header::AUTHORIZATION],"Bearer retirement-test-key");
                        b.reads.fetch_add(1,Ordering::SeqCst);
                        let mut t=target();
                        if b.mode.load(Ordering::SeqCst)==3 {t.created_at_unix_nanos="1780000000123456790".into();}
                        let receipt=b.receipt.lock().unwrap().clone();
                        Json(json!({"target":t,"state":if receipt.is_some() {"retired"} else {"active"},"receipt":receipt}))
                    }
                }).post(move |headers:axum::http::HeaderMap,Json(request):Json<Value>| {
                    let b=b.clone(); async move {
                        assert_eq!(headers[header::AUTHORIZATION],"Bearer retirement-test-key");
                        b.posts.fetch_add(1,Ordering::SeqCst);
                        b.requests.lock().unwrap().push(request.clone());
                        match b.mode.load(Ordering::SeqCst) {
                            1=>return (StatusCode::ACCEPTED,Json(json!({"target":target(),"state":"retiring","receipt":null}))).into_response(),
                            5=>return (StatusCode::TEMPORARY_REDIRECT,[(header::LOCATION,"/must-not-follow")]).into_response(),
                            _=>{}
                        }
                        let mut record=json!({"request":request,"state":"retired","retiredAt":"2026-09-25T10:00:00Z"});
                        if b.mode.load(Ordering::SeqCst)==4 {record["request"]["operationId"]=json!("different-operation");}
                        *b.receipt.lock().unwrap()=Some(record.clone());
                        if b.mode.load(Ordering::SeqCst)==2 {return StatusCode::SERVICE_UNAVAILABLE.into_response();}
                        Json(record).into_response()
                    }
                }))
            }

            fn auth(f:&mut Fixture) {
                f.state.auth=Some(Arc::new(DashboardAuth::new("operator","password")));
                f.state.gate_admin=true;
            }

            fn approve(f:&Fixture) -> RetirementRequest {
                let d=f.registry.get("obsolete").unwrap();
                RetirementRequest {operation_id:"retire-1".into(),expected_revision:d.state().rollout_revision.clone(),
                    expected_spec_sha256:crate::rollout::fingerprint(&d.spec),targets:vec![target()]}
            }

            fn tracked(f:&Fixture) {
                let d=f.registry.get("obsolete").unwrap();
                d.set_pending(vec![PendingVm::new(target().backend_sandbox_id.clone())]);
                d.mutate_state(|s|s.create_attempts.push(CreateAttempt {
                    name:"applb-obsolete-000000000001".into(),sandbox_id:Some(target().backend_sandbox_id),..Default::default()}));
                f.registry.persist_one("obsolete").unwrap();
            }

            async fn call(f:&Fixture,method:&str,path:&str,body:Value,credential:bool) -> (StatusCode,Value) {
                let mut req=Request::builder().method(method).uri(path).header(header::CONTENT_TYPE,"application/json");
                if credential {req=req.header(header::AUTHORIZATION,"Basic b3BlcmF0b3I6cGFzc3dvcmQ=");}
                let mut app=router(f.state.clone());
                std::future::poll_fn(|cx|<Router as Service<Request<Body>>>::poll_ready(&mut app,cx)).await.unwrap();
                let response=app.call(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
                let status=response.status();
                let bytes=axum::body::to_bytes(response.into_body(),1<<20).await.unwrap();
                (status,serde_json::from_slice(&bytes).unwrap_or(Value::Null))
            }

            async fn retire(f:&Fixture,r:&RetirementRequest)->(StatusCode,Value) {
                call(f,"POST","/deployments/obsolete/retirement",serde_json::to_value(r).unwrap(),true).await
            }

            #[tokio::test]
            async fn lost_receipt_restart_replay_and_controller_mutations_preserve_state() {
                let b=Arc::new(Backend::default()); b.mode.store(2,Ordering::SeqCst);
                let mut f=fixture_with_backend(true,backend_router(b.clone()),None).await;
                auth(&mut f); tracked(&f);
                let r=approve(&f);
                let preserved=f.root.join("retained-workspace.ext4");
                std::fs::write(&preserved,b"retained bytes").unwrap();
                assert_eq!(retire(&f,&r).await.0,StatusCode::ACCEPTED);
                assert_eq!(b.posts.load(Ordering::SeqCst),1);
                assert_eq!(f.registry.get("obsolete").unwrap().state().retirement.as_ref().unwrap().state,"retiring");
                // Reconstruct controller, workers and registry from the actual files.
                let mut restarted=fixture_with_backend(true,backend_router(b.clone()),Some(f.root.clone())).await;
                auth(&mut restarted);
                let (status,result)=retire(&restarted,&r).await;
                assert_eq!(status,StatusCode::OK,"{result}");
                assert_eq!(result["state"],"retired");
                assert_eq!(b.posts.load(Ordering::SeqCst),1,"lost response must be recovered by exact receipt, not another POST");
                assert_eq!(retire(&restarted,&r).await.1,result);
                let mut changed=r.clone(); changed.targets[0].libvirt_domain_uuid.push('0');
                assert_eq!(retire(&restarted,&changed).await.0,StatusCode::CONFLICT);
                for (method,path) in [("DELETE","/deployments/obsolete"),("DELETE","/deployments/obsolete/record"),
                    ("POST","/deployments/obsolete/update"),("POST","/deployments/obsolete/build"),
                    ("POST","/deployments/obsolete/exec"),("PATCH","/deployments/obsolete")] {
                    assert_eq!(call(&restarted,method,path,json!({}),true).await.0,StatusCode::CONFLICT,"{method} {path}");
                }
                // An intentionally ungated legacy CRUD listener must also refuse.
                restarted.state.gate_admin=false;
                assert_eq!(call(&restarted,"DELETE","/deployments/obsolete",json!({}),false).await.0,StatusCode::CONFLICT);
                assert_eq!(call(&restarted,"POST","/deployments",serde_json::to_value(empty().spec.clone()).unwrap(),false).await.0,StatusCode::CONFLICT);
                restarted.state.autoscaler.adopt_existing().await;
                restarted.state.autoscaler.reconcile().await;
                restarted.state.autoscaler.sweep_suspended().await;
                restarted.state.rollouts.tick().await;
                assert_eq!(std::fs::read(&preserved).unwrap(),b"retained bytes");
                assert!(persisted(&restarted.registry.state_dir()));
                assert_eq!(restarted.mutations.load(Ordering::SeqCst),0,"no create, stop, DELETE or storage mutation");
                assert_eq!(b.posts.load(Ordering::SeqCst),1);
            }

            #[tokio::test]
            async fn pending_replays_exact_request_and_identity_mismatch_never_retargets() {
                for mode in [1,3,4,5] {
                    let b=Arc::new(Backend::default()); b.mode.store(mode,Ordering::SeqCst);
                    let mut f=fixture_with_backend(true,backend_router(b.clone()),None).await;
                    auth(&mut f); tracked(&f); let r=approve(&f);
                    assert_eq!(retire(&f,&r).await.0,StatusCode::ACCEPTED);
                    assert_ne!(f.registry.get("obsolete").unwrap().state().retirement.as_ref().unwrap().state,"retired");
                    assert_eq!(retire(&f,&r).await.0,StatusCode::ACCEPTED);
                    let requests=b.requests.lock().unwrap();
                    assert!(requests.iter().all(|v|*v==json!({"operationId":"retire-1","target":target()})));
                    if mode==3 {assert_eq!(requests.len(),0,"wrong backend creation identity must never receive retirement POST");}
                    if mode==1 {assert_eq!(requests.len(),2,"only explicit retries may replay pending intent");}
                    assert_eq!(f.mutations.load(Ordering::SeqCst),0,"redirects must not be followed");
                }
            }

            #[tokio::test]
            async fn authentication_stale_spec_legacy_history_and_unknown_create_fail_closed() {
                for legacy in [false,true] {
                    let b=Arc::new(Backend::default());
                    let mut f=fixture_with_backend(true,backend_router(b.clone()),None).await;
                    tracked(&f); let mut r=approve(&f);
                    assert_eq!(retire(&f,&r).await.0,StatusCode::FORBIDDEN,"ungated is not authorization to retire");
                    auth(&mut f);
                    assert_eq!(call(&f,"POST","/deployments/obsolete/retirement",serde_json::to_value(&r).unwrap(),false).await.0,StatusCode::UNAUTHORIZED);
                    r.expected_spec_sha256="0".repeat(64);
                    assert_eq!(retire(&f,&r).await.0,StatusCode::CONFLICT);
                    assert!(!f.registry.retirement_frozen("obsolete"));
                    r=approve(&f);
                    let d=f.registry.get("obsolete").unwrap();
                    d.mutate_state(|s|if legacy {s.allocation_history_complete=false;} else {
                        s.create_attempts.push(CreateAttempt {name:"unknown-create".into(),sandbox_id:None,..Default::default()});
                    });
                    let (status,result)=retire(&f,&r).await;
                    assert_eq!(status,StatusCode::ACCEPTED);
                    assert!(result["unresolved"].as_str().unwrap().contains(if legacy {"legacy"} else {"ambiguous"}));
                    assert_eq!(b.reads.load(Ordering::SeqCst),0);
                    assert_eq!(b.posts.load(Ordering::SeqCst),0);
                    let mut restarted=fixture_with_backend(true,backend_router(b.clone()),Some(f.root.clone())).await;
                    auth(&mut restarted);
                    assert_eq!(retire(&restarted,&r).await.1,result);
                }
            }

            #[tokio::test]
            async fn successful_legacy_create_is_not_an_exactly_once_allocation_receipt() {
                let b=Arc::new(Backend::default());
                let extra=backend_router(b.clone()).route("/sandbox-deploy",post(||async {
                    (StatusCode::ACCEPTED,Json(json!({"id":"sb-12345678","status":"provisioning"})))
                }));
                let mut f=fixture_with_backend(true,extra,None).await;auth(&mut f);
                let mut spec=empty().spec.clone();spec.scaling.min_replicas=1;
                let d=f.registry.upsert(spec);
                f.state.autoscaler.reconcile().await;
                assert_eq!(d.pending().len(),1,"exercise successful SDK create through the real controller");
                assert_eq!(d.state().create_attempts[0].sandbox_id.as_deref(),Some("sb-12345678"));
                assert!(!d.state().allocation_history_complete,"queue redelivery could still create another sandbox");
                let r=approve(&f);
                let (status,result)=retire(&f,&r).await;
                assert_eq!(status,StatusCode::ACCEPTED);
                assert!(result["unresolved"].as_str().unwrap().contains("even after successful create"));
                assert_eq!(b.posts.load(Ordering::SeqCst),0,"do not fabricate inventory closure before backend fencing");
                let mut restarted=fixture_with_backend(true,backend_router(b.clone()),Some(f.root.clone())).await;
                auth(&mut restarted);
                assert_eq!(retire(&restarted,&r).await.1,result);
            }

            #[tokio::test]
            async fn in_flight_create_finishes_before_inventory_freeze_and_unknown_outcome_stays_blocked() {
                let entered=Arc::new(tokio::sync::Notify::new());
                let release=Arc::new(tokio::sync::Semaphore::new(0));
                let count=Arc::new(AtomicUsize::new(0));
                let (e,s,c)=(entered.clone(),release.clone(),count.clone());
                let extra=Router::new().route("/sandbox-deploy",post(move || {
                    let (e,s,c)=(e.clone(),s.clone(),c.clone()); async move {
                        c.fetch_add(1,Ordering::SeqCst);e.notify_one();
                        let _permit=s.acquire().await.unwrap();
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }));
                let mut f=fixture_with_backend(true,extra,None).await;auth(&mut f);
                let mut spec=empty().spec.clone();spec.scaling.min_replicas=1;
                let d=f.registry.upsert(spec);
                // Known retained source plus one replacement currently allocating.
                d.mutate_state(|s|s.create_attempts.push(CreateAttempt {name:"earlier".into(),sandbox_id:Some(target().backend_sandbox_id),..Default::default()}));
                let r=approve(&f);
                let scaler=f.state.autoscaler.clone();
                let tick=tokio::spawn(async move {scaler.reconcile().await;});
                tokio::time::timeout(Duration::from_secs(3),entered.notified()).await.unwrap();
                let future=retire(&f,&r);tokio::pin!(future);
                assert!(tokio::time::timeout(Duration::from_millis(30),&mut future).await.is_err());
                assert!(!f.registry.retirement_frozen("obsolete"),"wait for the admitted allocation before snapshot");
                release.add_permits(1);tick.await.unwrap();
                let (status,result)=tokio::time::timeout(Duration::from_secs(3),&mut future).await.unwrap();
                assert_eq!(status,StatusCode::ACCEPTED,"{result}");
                assert!(result["unresolved"].as_str().unwrap().contains("ambiguous"));
                f.state.autoscaler.reconcile().await;
                assert_eq!(count.load(Ordering::SeqCst),1,"ambiguous create must not be repeated");
                let mut restarted=fixture_with_backend(true,Router::new(),Some(f.root.clone())).await;auth(&mut restarted);
                assert_eq!(retire(&restarted,&r).await.1,result);
                restarted.state.autoscaler.reconcile().await;
                assert_eq!(restarted.mutations.load(Ordering::SeqCst),0);
            }
        }

        fn persisted(root: &FsPath) -> bool { root.join("obsolete.json").exists() }

        async fn send(f: &Fixture, method: &str, uri: &str, body: &str) -> (StatusCode, (), serde_json::Value) {
            let mut app = router(f.state.clone());
            std::future::poll_fn(|cx| <Router as Service<Request<Body>>>::poll_ready(&mut app, cx)).await.unwrap();
            let request = Request::builder().method(method).uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())).unwrap();
            let response = app.call(request).await.unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, (), serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
        }

        /// A namespace token watches the jobs of its own deployments — the pull
        /// it just started — and a job elsewhere answers like one that never
        /// existed.
        #[tokio::test]
        async fn a_namespace_token_reads_its_own_jobs_and_nobody_elses() {
            let f = fixture(true).await;
            let mut mine = (*empty()).spec.clone();
            mine.id = "mine".into();
            mine.namespace = "team-a".into();
            f.registry.upsert(mine);
            let job = |id: &str, deployment: &str| -> crate::jobs::JobRecord {
                serde_json::from_value(serde_json::json!({
                    "id": id, "deployment": deployment, "kind": "artifact-pull",
                    "status": "succeeded", "started_at": 1, "finished_at": 2, "log": []
                }))
                .unwrap()
            };
            f.state.jobs.remember_for_test(job("job-mine", "mine"));
            f.state.jobs.remember_for_test(job("job-theirs", "obsolete"));

            let (summary, _) = f
                .state
                .tokens
                .mint(
                    crate::tokens::NewToken {
                        name: "ns".into(),
                        admin: crate::tokens::AdminScope::Admin,
                        namespace: Some("team-a".into()),
                        deployments: vec![],
                        expires_in_secs: None,
                        fleet: false,
                    },
                    now_secs(),
                )
                .unwrap();
            let caller = Caller::Token(f.state.tokens.get(&summary.id).unwrap());
            let get = |id: &str, c: Option<Caller>| {
                get_job(State(f.state.clone()), Path(id.to_string()), c.map(axum::Extension))
            };
            assert_eq!(get("job-mine", Some(caller.clone())).await.into_response().status(), StatusCode::OK);
            let theirs = get("job-theirs", Some(caller.clone())).await.into_response();
            let never = get("job-never", Some(caller)).await.into_response();
            assert_eq!(theirs.status(), StatusCode::NOT_FOUND);
            assert_eq!(never.status(), StatusCode::NOT_FOUND);
            let body = |r: Response| async { axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap() };
            assert_eq!(
                String::from_utf8_lossy(&body(theirs).await).replace("job-theirs", "X"),
                String::from_utf8_lossy(&body(never).await).replace("job-never", "X"),
                "another namespace's job is indistinguishable from none"
            );
            // The operator reads every job.
            assert_eq!(get("job-theirs", Some(Caller::Operator)).await.into_response().status(), StatusCode::OK);
        }

        /// The namespace plugin routes, through the real router: install and
        /// the surface's path rewrite onto app-obs's `/ns/<ns>/…`.
        #[tokio::test]
        async fn a_namespace_installs_obs_and_reads_through_the_router() {
            let obs = Router::new().fallback(|request: Request<Body>| async move {
                Json(serde_json::json!({
                    "method": request.method().as_str(),
                    "path": request.uri().path(),
                    "query": request.uri().query(),
                }))
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let obs_url = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, obs).await.unwrap() });
            let f = fixture(true).await;

            let (status, _, list) = send(&f, "GET", "/namespaces/team-a/plugins", "").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(list[0]["id"], "obs");
            assert_eq!(list[0]["installed"], false);
            let (status, _, v) = send(&f, "PUT", "/namespaces/team-a/plugins/obs", "{}").await;
            assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("plugin_disabled")));

            f.state.plugins.set("obs", true, Some(serde_json::json!({"url": obs_url}))).await.unwrap();
            let (status, _, v) = send(&f, "GET", "/namespaces/team-a/plugins/obs/api/fleet", "").await;
            assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("plugin_not_installed")));

            let (status, _, v) = send(&f, "PUT", "/namespaces/team-a/plugins/obs", "").await;
            assert_eq!(status, StatusCode::OK, "{v}");
            assert_eq!(v["installed"], true);
            let (status, _, v) = send(&f, "GET", "/namespaces/team-a/plugins/obs", "").await;
            assert_eq!((status, &v["installed"]), (StatusCode::OK, &serde_json::json!(true)));
            let (status, _, v) = send(&f, "GET", "/api/plugins/obs/installs", "").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(v["namespaces"], serde_json::json!(["team-a"]));

            let (status, _, v) = send(&f, "GET", "/namespaces/team-a/plugins/obs/api/deployments/web/logs?level=error", "").await;
            assert_eq!(status, StatusCode::OK, "{v}");
            assert_eq!(v["path"], "/ns/team-a/api/deployments/web/logs");
            assert_eq!(v["query"], "level=error");
            let (status, _, v) = send(&f, "DELETE", "/namespaces/team-a/plugins/obs/api/alerts/a1", "").await;
            assert_eq!((status, v["method"].as_str()), (StatusCode::OK, Some("DELETE")));
            assert_eq!(v["path"], "/ns/team-a/api/alerts/a1");
            let (status, _, v) = send(&f, "GET", "/namespaces/team-a/plugins/obs/ui", "").await;
            assert_eq!((status, v["path"].as_str()), (StatusCode::OK, Some("/ns/team-a/")));
            let (status, _, _) = send(&f, "GET", "/namespaces/team-a/plugins/obs/api/%2e%2e/%2e%2e/api/fleet", "").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, _, _) = send(&f, "GET", "/namespaces/a%20b/plugins", "").await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            let (status, _, v) = send(&f, "DELETE", "/namespaces/team-a/plugins/obs", "").await;
            assert_eq!((status, &v["installed"]), (StatusCode::OK, &serde_json::json!(false)));
            f.state.plugins.set("obs", false, None).await.unwrap();
        }

        async fn remove(f: &Fixture, etag: Option<&str>) -> StatusCode {
            let mut request = Request::builder().method("DELETE").uri("/deployments/obsolete/record");
            if let Some(etag) = etag { request = request.header(header::IF_MATCH, etag); }
            let mut app = router(f.state.clone());
            std::future::poll_fn(|cx| <Router as Service<Request<Body>>>::poll_ready(&mut app, cx)).await.unwrap();
            app.call(request.body(Body::empty()).unwrap()).await.unwrap().status()
        }

        fn empty() -> Arc<Deployment> {
            Arc::new(Deployment::new(serde_json::from_value(serde_json::json!({
                "id": "obsolete",
                "routes": [],
                "vm": {"driver": "firecracker", "port": 8080},
                "scaling": {"min_replicas": 0, "warm_pool": 0}
            })).unwrap()))
        }

        fn completed_history(d: &Deployment) {
            let op = crate::rollout::Operation {
                operation_id: "finished-1".into(), deployment: d.spec.id.clone(),
                source_revision: "before".into(), target_spec_sha256: crate::rollout::fingerprint(&d.spec),
                status: "succeeded".into(), phase: "complete".into(), readiness_verified: true,
                previous_stopped: true, error: None, preparation_stage: None,
                spec: d.spec.clone(), prepared: None, prefix: "applb-obsolete-r123-".into(),
                allocations: vec![crate::rollout::Allocation { name: "applb-obsolete-r123-0".into(),
                    sandbox_id: Some("sb-retired".into()), attempted: true }],
                previous: vec!["sb-predecessor".into()], stopped: vec!["sb-predecessor".into()],
                deadline: 1, drain_deadline: Some(1), reclaimed_candidate_ids: vec![], failure_settled: false,
            };
            d.mutate_state(|s| {s.active_prefix = Some(op.prefix.clone()); s.rollouts = vec![op];});
        }

        #[test]
        fn retired_record_requires_settled_history_without_relaxing_normal_delete() {
            let d = empty();
            completed_history(&d);
            assert!(record_only_refusal(&d, false).is_some());
            assert_eq!(record_removal_refusal(&d, false, true), None);
            for (status, settled, ready, stopped, permitted) in [
                ("failed", false, true, true, false), ("failed", true, false, false, true),
                ("running", true, true, true, false), ("reconciliation_required", true, true, true, false),
                ("unknown", true, true, true, false), ("succeeded", false, false, true, false),
                ("succeeded", false, true, false, false), ("succeeded", false, true, true, true),
            ] {
                d.mutate_state(|s| {let op = &mut s.rollouts[0]; op.status = status.into();
                    op.failure_settled = settled; op.readiness_verified = ready; op.previous_stopped = stopped;});
                assert_eq!(record_removal_refusal(&d, false, true).is_none(), permitted, "{status}/{settled}/{ready}/{stopped}");
            }
        }

        #[tokio::test]
        async fn retired_record_archives_exact_history_and_does_not_resurrect_on_restart() {
            let f = fixture(true).await;
            let d = f.registry.get("obsolete").unwrap();
            completed_history(&d);
            let saved = (*d.state()).clone();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(header::IF_MATCH, deployment_etag(&d.spec).unwrap().parse().unwrap());
            assert_eq!(remove_deployment_record(f.state.clone(), "obsolete".into(), headers, true).await.status(), StatusCode::NO_CONTENT);
            let files: Vec<_> = std::fs::read_dir(f.registry.state_dir().join("retired")).unwrap().map(Result::unwrap).collect();
            assert_eq!(files.len(), 1);
            let report: serde_json::Value = serde_json::from_slice(&std::fs::read(files[0].path()).unwrap()).unwrap();
            assert_eq!(report["state"], serde_json::to_value(saved).unwrap());
            assert_eq!(report["spec"], serde_json::to_value(&d.spec).unwrap());
            let restarted = Registry::new(f.root.join("deployments.json"));
            restarted.load().unwrap();
            restarted.require_complete_load().unwrap();
            assert!(restarted.get("obsolete").is_none());
            assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn retired_record_archive_failure_keeps_registration_and_history() {
            let f = fixture(true).await;
            let d = f.registry.get("obsolete").unwrap();
            completed_history(&d);
            let saved = (*d.state()).clone();
            std::fs::write(f.registry.state_dir().join("retired"), b"not a directory").unwrap();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(header::IF_MATCH, deployment_etag(&d.spec).unwrap().parse().unwrap());
            assert_eq!(remove_deployment_record(f.state.clone(), "obsolete".into(), headers, true).await.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(f.registry.get("obsolete").is_some());
            assert!(persisted(&f.registry.state_dir()));
            assert_eq!(*d.state(), saved);
            assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn retired_record_refuses_renamed_historical_runtime_and_missing_inventory() {
            for available in [true, false] {
                let f = fixture(available).await;
                let d = f.registry.get("obsolete").unwrap();
                completed_history(&d);
                if available {
                    f.inactive.lock().unwrap().push(serde_json::json!({
                        "id":"sb-retired", "name":"applb-other-000000000001", "status":"stopped",
                        "image":"artifacts", "uptime_secs":0, "is_deployed":true, "status_changed_at":"", "urls":[]
                    }));
                }
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(header::IF_MATCH, deployment_etag(&d.spec).unwrap().parse().unwrap());
                let result = remove_deployment_record(f.state.clone(), "obsolete".into(), headers, true).await;
                assert_eq!(result.status(), if available {StatusCode::CONFLICT} else {StatusCode::SERVICE_UNAVAILABLE});
                assert!(f.registry.get("obsolete").is_some());
                assert!(!f.registry.state_dir().join("retired").exists());
                assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
            }
        }

        #[tokio::test]
        async fn retired_record_requires_authentication_even_on_ungated_crud() {
            let f = fixture(true).await;
            let request = Request::builder().method("DELETE").uri("/deployments/obsolete/retired-record")
                .body(Body::empty()).unwrap();
            let mut app = router(f.state.clone());
            std::future::poll_fn(|cx| <Router as Service<Request<Body>>>::poll_ready(&mut app, cx)).await.unwrap();
            assert_eq!(app.call(request).await.unwrap().status(), StatusCode::FORBIDDEN);
            assert!(f.registry.get("obsolete").is_some());
        }

        #[test]
        fn empty_route_less_zero_desired_record_is_removable() {
            let d = empty();
            assert_eq!(d.desired_replicas(), 0);
            assert_eq!(record_only_refusal(&d, false), None);
        }

        #[test]
        fn host_job_configuration_is_not_an_empty_record() {
            let mut spec = empty().spec.clone();
            spec.update = Some(serde_json::from_value(serde_json::json!({
                "working_dir": "/protected-service", "commands": ["service-update"]
            })).unwrap());
            let d = Deployment::new(spec);
            assert!(record_only_refusal(&d, false).unwrap().contains("host-update"));
        }

        #[test]
        fn exact_revision_is_required_and_a_stale_revision_fails() {
            let d = empty();
            let current = deployment_etag(&d.spec).unwrap();
            assert!(check_etag_precondition(Some(&current), &d.spec).is_ok());
            assert_eq!(
                check_etag_precondition(
                    Some("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
                    &d.spec,
                ),
                Err(StatusCode::PRECONDITION_FAILED),
            );
            assert!(if_match(&axum::http::HeaderMap::new()).unwrap().is_none());
        }

        #[test]
        fn invisible_pending_suspended_and_workspace_state_are_not_empty() {
            let pending = empty();
            pending.set_pending(vec![PendingVm::new("sb-booting".into())]);
            assert!(record_only_refusal(&pending, false).unwrap().contains("pending"));

            let suspended = empty();
            suspended.mutate_state(|state| state.suspended.push("sb-stopped".into()));
            assert!(record_only_refusal(&suspended, false).unwrap().contains("suspended"));

            assert!(record_only_refusal(&empty(), true).unwrap().contains("workspace"));
        }

        #[test]
        fn active_routes_and_retained_rollout_generations_are_not_empty() {
            let mut routed_spec = empty().spec.clone();
            routed_spec.routes.push(crate::config::RouteRule {
                host: Some("obsolete.example.com".into()),
                ..Default::default()
            });
            let routed = Deployment::new(routed_spec);
            assert!(record_only_refusal(&routed, false).unwrap().contains("route-less"));

            let rollout = empty();
            rollout.mutate_state(|state| state.active_prefix = Some("candidate-".into()));
            assert!(record_only_refusal(&rollout, false).unwrap().contains("rollout"));
        }

        #[tokio::test]
        async fn handler_fails_closed_and_never_mutates_retained_records_or_resources() {
            let f = fixture(true).await;
            assert_eq!(remove(&f, None).await, StatusCode::PRECONDITION_REQUIRED);
            assert_eq!(remove(&f, Some("\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")).await, StatusCode::PRECONDITION_FAILED);
            let current = deployment_etag(&f.registry.get("obsolete").unwrap().spec).unwrap();
            f.registry.get("obsolete").unwrap().set_pending(vec![PendingVm::new("sb-live".into())]);
            assert_eq!(remove(&f, Some(&current)).await, StatusCode::CONFLICT);
            assert!(f.registry.get("obsolete").is_some());
            assert!(persisted(&f.registry.state_dir()));
            assert_eq!(f.mutations.load(Ordering::SeqCst), 0, "no stop, destroy or disk cleanup request");
        }

        #[tokio::test]
        async fn handler_unlinks_only_an_empty_record_without_runtime_cleanup() {
            let f = fixture(true).await;
            let current = deployment_etag(&f.registry.get("obsolete").unwrap().spec).unwrap();
            assert_eq!(remove(&f, Some(&current)).await, StatusCode::NO_CONTENT);
            assert!(f.registry.get("obsolete").is_none());
            assert!(!persisted(&f.registry.state_dir()));
            assert_eq!(f.mutations.load(Ordering::SeqCst), 0, "record cleanup must not call teardown or disk purge");
        }

        #[tokio::test]
        async fn handler_keeps_live_and_persisted_record_when_inventory_is_unavailable() {
            let f = fixture(false).await;
            let current = deployment_etag(&f.registry.get("obsolete").unwrap().spec).unwrap();
            assert_eq!(remove(&f, Some(&current)).await, StatusCode::SERVICE_UNAVAILABLE);
            assert!(f.registry.get("obsolete").is_some());
            assert!(persisted(&f.registry.state_dir()));
            assert_eq!(f.mutations.load(Ordering::SeqCst), 0);
        }
    }

    mod upstream_drains {
        use super::*;

        fn deployment() -> Arc<crate::deployment::Deployment> {
            let spec = serde_json::from_str(
                r#"{
                    "id": "stage",
                    "routes": [{"host": "stage.example.com"}],
                    "upstreams": ["eu1.example:443", "us1.example:443"]
                }"#,
            )
            .expect("the static deployment fixture parses");
            Arc::new(crate::deployment::Deployment::new(spec))
        }

        #[test]
        fn draining_requires_another_healthy_accepting_upstream() {
            let deployment = deployment();
            let us1 = deployment.backends()[1].clone();
            assert!(has_healthy_alternative(&deployment, "eu1.example:443"));

            us1.set_healthy(false);
            assert!(
                !has_healthy_alternative(&deployment, "eu1.example:443"),
                "an unhealthy destination is not a safe alternative",
            );

            us1.set_healthy(true);
            us1.set_draining(true);
            assert!(
                !has_healthy_alternative(&deployment, "eu1.example:443"),
                "a destination already under operator drain is not an alternative",
            );
        }

        #[test]
        fn drain_reasons_are_trimmed_and_bounded() {
            assert_eq!(
                normalized_drain_reason(Some("  maintenance  ".into())).unwrap(),
                Some("maintenance".into()),
            );
            assert_eq!(normalized_drain_reason(Some("  ".into())).unwrap(), None);
            assert!(
                normalized_drain_reason(Some("x".repeat(MAX_DRAIN_REASON_LEN + 1))).is_err()
            );
        }

        #[test]
        fn a_persistence_failure_leaves_the_upstream_cordoned() {
            let blocked_parent = std::env::temp_dir().join(format!(
                "app-lb-drain-failure-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::write(&blocked_parent, b"not a directory").unwrap();
            let registry = Registry::new(blocked_parent.join("drain-state.json"));
            let deployment = registry.upsert((*deployment()).spec.clone());

            let result = apply_upstream_drain(
                &registry,
                &deployment,
                "stage",
                "eu1.example:443",
                true,
                Some("maintenance".into()),
            );

            assert!(result.is_err(), "the fixture must fail before durability is confirmed");
            assert!(
                deployment.backends()[0].is_draining(),
                "a storage error must fail closed rather than reopen traffic",
            );
            assert_eq!(
                deployment
                    .upstream_drain("eu1.example:443")
                    .and_then(|drain| drain.reason),
                Some("maintenance".into()),
            );
            std::fs::remove_file(blocked_parent).unwrap();
        }
    }

    /// Both auth schemes must survive into the response as *separate*
    /// `WWW-Authenticate` lines. This has now broken twice, silently, in
    /// opposite directions: comma-joining them suppressed Chrome's Basic
    /// prompt, and the fix's plain tuple-array *inserted* the second line over
    /// the first, so the response advertised only `Bearer` — no Basic
    /// challenge, no prompt in any browser without cached credentials.
    #[test]
    fn a_401_advertises_basic_and_bearer_on_separate_lines() {
        let response = unauthorized();
        let challenges: Vec<&str> = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().expect("ascii header"))
            .collect();
        assert_eq!(challenges.len(), 2, "both schemes must be present: {challenges:?}");
        assert!(
            challenges[0].starts_with("Basic "),
            "Basic first, so a browser tries it before the Bearer it cannot do: {challenges:?}",
        );
        assert!(
            !challenges[0].contains("Bearer"),
            "one scheme per line — no comma-joined challenge: {challenges:?}",
        );
        assert_eq!(challenges[1], "Bearer");
    }

    /// The two routing decisions behind the security console, both of which are
    /// silent when wrong: one produces a 403 for a caller who should see the
    /// page, the other hands a scoped token a fleet-wide control.
    #[test]
    fn the_console_narrows_itself_and_the_rule_api_does_not() {
        for view in ["/", "/metrics", "/dashboard", "/security", "/siem", "/ingress", "/network"] {
            assert!(narrows_itself(view), "{view} must narrow for a scoped token");
        }
        // A deployment-scoped token has no business arming a fleet-wide block,
        // so these must fall through to the "does not cover the fleet" refusal.
        for mutating in ["/security/rules", "/security/rules/:id"] {
            assert!(!narrows_itself(mutating), "{mutating} must not narrow");
        }
    }

    /// `exec` and `shell` against a deployment whose VMs boot but never pass
    /// their health check — the case they are needed for, and the one the pool
    /// cannot serve, because such a VM is never promoted out of `pending`.
    mod booting_targets {
        use super::*;
        use crate::deployment::{Deployment, PendingVm};
        use heyo_sdk::SandboxStatus;

        fn deployment() -> std::sync::Arc<Deployment> {
            let spec = serde_json::from_str(
                r#"{"id":"demo","routes":[],"vm":{"driver":"firecracker","port":8080}}"#,
            )
            .expect("the fixture spec parses");
            std::sync::Arc::new(Deployment::new(spec))
        }

        fn pending(id: &str, created_at: u64, status: Option<SandboxStatus>) -> PendingVm {
            PendingVm {
                sandbox_id: id.into(),
                created_at,
                status,
                ..PendingVm::new(id.into())
            }
        }

        #[test]
        fn nothing_pending_offers_nothing() {
            assert_eq!(booting_vm(&deployment()), None);
        }

        /// A VM the daemon has not started has no guest to talk to. Offering it
        /// would trade a fast 503 for a slow one at the daemon.
        #[test]
        fn a_vm_the_daemon_has_not_started_is_not_a_target() {
            let d = deployment();
            d.set_pending(vec![
                pending("sb-1", 100, None),
                pending("sb-2", 200, Some(SandboxStatus::Provisioning)),
            ]);
            assert_eq!(booting_vm(&d), None);
        }

        #[test]
        fn a_running_vm_that_never_passed_its_health_check_is() {
            let d = deployment();
            d.set_pending(vec![
                pending("sb-1", 100, Some(SandboxStatus::Provisioning)),
                pending("sb-2", 200, Some(SandboxStatus::Running)),
            ]);
            assert_eq!(booting_vm(&d).as_deref(), Some("sb-2"));
        }

        /// Oldest first, so a pool of stalled boots sends every `exec` to the
        /// same guest — the one whose logs cover the most — instead of
        /// scattering them across VMs that are each about to be killed.
        #[test]
        fn the_oldest_running_one_wins() {
            let d = deployment();
            d.set_pending(vec![
                pending("sb-new", 300, Some(SandboxStatus::Running)),
                pending("sb-old", 100, Some(SandboxStatus::Running)),
                pending("sb-mid", 200, Some(SandboxStatus::Running)),
            ]);
            assert_eq!(booting_vm(&d).as_deref(), Some("sb-old"));
        }

        fn status_of(r: Result<VmTarget, Response>) -> Result<String, StatusCode> {
            match r {
                Ok(t) => Ok(t.sandbox_id().to_string()),
                Err(resp) => Err(resp.status()),
            }
        }

        /// A named VM is that VM or an error — never a sibling, never a wake.
        /// The one thing a caller naming a sandbox does not want is to end up
        /// somewhere else without being told.
        #[test]
        fn a_named_vm_is_that_vm_or_nothing() {
            let d = deployment();
            d.set_pending(vec![
                pending("sb-boot", 100, Some(SandboxStatus::Running)),
                pending("sb-cold", 200, Some(SandboxStatus::Provisioning)),
                pending("sb-unknown", 300, None),
            ]);
            assert_eq!(status_of(hold_this_vm(&d, "demo", "sb-boot")), Ok("sb-boot".into()));
            assert_eq!(status_of(hold_this_vm(&d, "demo", "sb-cold")), Err(StatusCode::CONFLICT));
            assert_eq!(status_of(hold_this_vm(&d, "demo", "sb-unknown")), Err(StatusCode::CONFLICT));
            assert_eq!(status_of(hold_this_vm(&d, "demo", "sb-nope")), Err(StatusCode::NOT_FOUND));
        }
    }

    #[test]
    fn a_guard_rejection_maps_onto_a_status_a_client_can_act_on() {
        use crate::guard::GuardError as E;
        let status = |e: E| guard_error(e).status();
        assert_eq!(status(E::EmptyMatch), StatusCode::BAD_REQUEST);
        assert_eq!(status(E::BadClient("x".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status(E::TooLong("match.host")), StatusCode::BAD_REQUEST);
        // The cap is about the server's state, not the request: deleting a rule
        // and retrying the identical body is the correct next move.
        assert_eq!(status(E::Full), StatusCode::CONFLICT);
        assert_eq!(status(E::NoRule("x".into())), StatusCode::NOT_FOUND);
    }

    /// The landing page at `/`. Rendering is a pure function of the collected
    /// entries, so all of this runs without a listener or a registry.
    mod directory {
        use super::*;

        fn entry(id: &str, url: &str, state: EntryState) -> DirectoryEntry {
            DirectoryEntry {
                url: url.into(),
                deployment: id.into(),
                kind: "vm",
                state,
                detail: "2 VMs ready".into(),
                gated: false,
            }
        }

        /// Following a gated card can bounce through Google, so the card says so
        /// first. With `auth.cookie_domain` set across the fleet that bounce
        /// happens once rather than once per card — see `AuthGate::cookie_domain`.
        #[test]
        fn a_gated_destination_is_labelled_before_it_is_clicked() {
            let open = entry("api", "https://api.example.com", EntryState::Ready);
            let gated = DirectoryEntry {
                gated: true,
                ..entry("private", "https://private.example.com", EntryState::Ready)
            };
            let html = render_directory_cards(&[open, gated], &[]);
            assert_eq!(html.matches("tag gated").count(), 1, "{html}");
            assert!(html.contains(">sign-in<"), "{html}");
        }

        #[test]
        fn a_card_links_to_the_data_plane_url() {
            let html = render_directory_cards(
                &[entry("demo", "https://demo.example.com", EntryState::Ready)],
                &[],
            );
            assert!(html.contains(r#"href="https://demo.example.com""#));
            assert!(html.contains(">demo<"));
            assert!(html.contains("dot ready"));
        }

        /// A deployment with several hostnames offers several destinations, and
        /// this page exists to be clicked — so each gets its own card.
        #[test]
        fn every_url_gets_its_own_card() {
            let html = render_directory_cards(
                &[
                    entry("demo", "https://a.example.com", EntryState::Ready),
                    entry("demo", "https://b.example.com", EntryState::Ready),
                ],
                &[],
            );
            assert_eq!(html.matches("class=\"card\"").count(), 2);
        }

        /// Silently omitting them would make "why isn't my deployment listed?"
        /// unanswerable from the page.
        #[test]
        fn a_deployment_with_no_linkable_host_is_explained_not_dropped() {
            let html = render_directory_cards(
                &[entry("demo", "https://demo.example.com", EntryState::Ready)],
                &["internal-only".into()],
            );
            assert!(html.contains("internal-only"));
            assert!(html.contains("host_suffix"));
        }

        #[test]
        fn an_empty_fleet_says_how_to_fill_it() {
            let html = render_directory_cards(&[], &[]);
            assert!(html.contains("Nothing is registered yet"));
            assert!(html.contains("POST /deployments"));
        }

        /// Everything on this page arrives through the admin API's JSON, which
        /// is close enough to untrusted that escaping is not optional.
        #[test]
        fn operator_supplied_text_is_escaped() {
            let html = render_directory_cards(
                &[entry(
                    "<script>alert(1)</script>",
                    "https://x/\"><img src=x onerror=alert(1)>",
                    EntryState::Ready,
                )],
                &["<b>bad</b>".into()],
            );
            assert!(!html.contains("<script>alert"), "id must be escaped");
            assert!(!html.contains("<img src=x"), "url must be escaped");
            assert!(!html.contains("<b>bad"), "the note must be escaped too");
            assert!(html.contains("&lt;script&gt;"));
        }

        #[test]
        fn the_lede_counts_urls_deployments_and_outages() {
            let entries = vec![
                entry("a", "https://a1", EntryState::Ready),
                entry("a", "https://a2", EntryState::Ready),
                entry("b", "https://b1", EntryState::Down),
            ];
            let lede = directory_lede(&entries);
            assert!(lede.contains("3 URLs"), "{lede}");
            assert!(lede.contains("2 deployments"), "{lede}");
            assert!(lede.contains("1 with nothing healthy behind it"), "{lede}");
        }

        /// A deployment that contributes no URL must not be counted in "across
        /// N deployments" — it has its own line under the cards.
        #[test]
        fn the_lede_counts_only_deployments_that_contributed_a_url() {
            // The unlinkable one is reported under the cards, not counted here.
            let lede = directory_lede(&[entry("a", "https://a1", EntryState::Ready)]);
            assert!(lede.contains("1 URL across 1 deployment."), "{lede}");
        }

        #[test]
        fn the_lede_stays_grammatical_in_the_singular() {
            let lede = directory_lede(&[entry("a", "https://a1", EntryState::Ready)]);
            assert!(lede.contains("1 URL across 1 deployment."), "{lede}");
        }

        /// Scale-to-zero is the configured state, not a fault. Calling it "down"
        /// would send somebody debugging a system that is working as asked.
        #[test]
        fn an_idle_scale_to_zero_deployment_is_not_reported_as_down() {
            let html = render_directory_cards(
                &[DirectoryEntry {
                    detail: "idle — starts on first request".into(),
                    ..entry("demo", "https://demo", EntryState::Starting)
                }],
                &[],
            );
            assert!(html.contains("dot starting"));
            assert!(!html.contains("dot down"));
        }

        /// The shell must have no placeholder left in it after rendering, or the
        /// page ships literal `{{CARDS}}` to a browser.
        #[test]
        fn the_template_has_exactly_the_placeholders_the_handler_fills() {
            assert!(DIRECTORY_HTML.contains("{{APP_NAME}}"));
            assert!(DIRECTORY_HTML.contains("{{LEDE}}"));
            assert!(DIRECTORY_HTML.contains("{{CARDS}}"));
            let rendered = DIRECTORY_HTML
                .replace("{{APP_NAME}}", "app-lb")
                .replace("{{HTML_ATTRS}}", r#"data-theme="dark""#)
                .replace("{{WHO}}", "")
                .replace("{{LEDE}}", &directory_lede(&[]))
                .replace("{{CARDS}}", &render_directory_cards(&[], &[]));
            assert!(!rendered.contains("{{"), "an unfilled placeholder would ship to a browser");
        }

        /// Every page carries the two the shell fills per request, and nothing
        /// survives rendering.
        ///
        /// `{{HTML_ATTRS}}` is the load-bearing one: it is how the theme reaches
        /// the `<html>` tag in the first byte. A page that lost it would render
        /// dark for somebody who chose light and only correct itself when the
        /// script ran — the flash this design exists to avoid.
        #[test]
        fn every_page_carries_the_per_request_placeholders() {
            for (name, page) in [
                ("dashboard", DASHBOARD_HTML),
                ("directory", DIRECTORY_HTML),
                ("siem", SIEM_HTML),
                ("disks", DISKS_HTML),
                ("network", NETWORK_HTML),
            ] {
                assert!(page.contains("{{HTML_ATTRS}}"), "{name} lost the theme attributes");
                assert!(page.contains("{{WHO}}"), "{name} lost the identity slot");
                let rendered = page
                    .replace("{{APP_NAME}}", "app-lb")
                    .replace("{{HTML_ATTRS}}", r#"data-theme="light""#)
                    .replace("{{WHO}}", "ops@example.com")
                    .replace("{{SESSION_ACTION}}", "")
                    .replace("{{HOME_URL}}", "")
                    .replace("{{LEDE}}", "")
                    .replace("{{CARDS}}", "");
                assert!(!rendered.contains("{{"), "{name} left a placeholder unfilled");
            }
        }

        /// The five pages share one stylesheet, one script and one toggle, all
        /// served by this binary. A page that grew its own palette would drift
        /// from the other four apps the moment either changed.
        #[test]
        fn every_page_uses_the_shared_ui_and_declares_no_palette_of_its_own() {
            for (name, page) in [
                ("dashboard", DASHBOARD_HTML),
                ("directory", DIRECTORY_HTML),
                ("siem", SIEM_HTML),
                ("disks", DISKS_HTML),
                ("network", NETWORK_HTML),
            ] {
                assert!(page.contains(r#"href="/__ui/heyo.css""#), "{name} does not load the shared sheet");
                assert!(page.contains(r#"src="/__ui/theme.js""#), "{name} does not load the shared toggle");
                assert!(page.contains("data-theme-toggle"), "{name} has no theme control");
                // The theme is a cookie now: localStorage is per-origin, so a
                // choice made here would not survive a hop to ci or app-obs.
                assert!(!page.contains("localStorage.setItem"), "{name} still persists a theme locally");
                assert!(!page.contains("prefers-color-scheme"), "{name} redeclares a palette");
                assert!(!page.contains("src=\"http"), "{name} loads an external asset");
            }
        }
    }

    /// The disk console. Unlike the directory it is client-rendered, so the
    /// only server-side contract is the display name and the route it polls.
    mod disk_console {
        use super::*;

        #[test]
        fn the_page_has_only_the_placeholders_the_handler_fills() {
            assert!(DISKS_HTML.contains("{{APP_NAME}}"));
            // `{{APP_NAME}}` is filled once at startup; the other two are filled
            // per request, because the theme and the signed-in name belong to
            // the caller rather than to the process.
            let rendered = DISKS_HTML
                .replace("{{APP_NAME}}", "app-lb")
                .replace("{{HTML_ATTRS}}", r#"data-theme="dark""#)
                .replace("{{WHO}}", "");
            assert!(
                !rendered.contains("{{"),
                "an unfilled placeholder would ship to a browser",
            );
        }

        /// The page hard-codes the routes it calls, so a rename here has to
        /// break a test rather than a browser.
        #[test]
        fn the_page_calls_the_routes_the_router_registers() {
            for route in [
                "\"GET\", \"/disks\"",
                "\"PATCH\", \"/disks/\"",
                "/archive`",
                "\"POST\", \"/disks/sweep\"",
                "\"POST\", \"/disks/purge-orphans\"",
                "\"DELETE\", \"/disks/\"",
            ] {
                assert!(DISKS_HTML.contains(route), "page never calls {route}");
            }
        }

        /// Sandbox ids, paths and daemon error strings all reach this markup.
        #[test]
        fn the_page_escapes_what_it_interpolates() {
            assert!(DISKS_HTML.contains("function esc(v)"));
            assert!(DISKS_HTML.contains("encodeURIComponent(id)"));
        }

        /// The status code is the whole contract with the page: it offers the
        /// force override on a 409 and nothing else, so a guard that answered
        /// 403 would be unoverridable and one that answered 500 would look like
        /// a bug.
        #[test]
        fn each_refusal_maps_to_the_code_the_page_acts_on() {
            use crate::disks::DiskError as E;
            let code = |e: E| disk_error(e).status();

            assert_eq!(
                code(E::Held {
                    sandbox_id: "sb-1".into(),
                    reason: "the sandbox is running",
                    forceable: false,
                }),
                StatusCode::CONFLICT,
                "the page offers ?force=1 on a 409 and only on a 409",
            );
            assert_eq!(
                code(E::AlreadyArchiving("sb-1".into())),
                StatusCode::CONFLICT
            );
            assert_eq!(
                code(E::NothingToArchive("sb-1".into())),
                StatusCode::CONFLICT
            );
            assert_eq!(code(E::BadId("../etc".into())), StatusCode::BAD_REQUEST);
            assert_eq!(code(E::NotFound("sb-1".into())), StatusCode::NOT_FOUND);
            // Not 500: nothing is broken, the feature is simply unconfigured.
            assert_eq!(code(E::NoArchiveTarget), StatusCode::NOT_IMPLEMENTED);
            assert_eq!(
                code(E::Io("disk full".into())),
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }

        /// Every refusal has to say what to do next — these messages are shown
        /// verbatim in a `confirm()` dialog, and the page decides whether to
        /// offer the force retry by looking for `force=1` in this very string.
        /// A message that promises an override the server would refuse produces
        /// a dialog whose "yes" fails a second time.
        #[test]
        fn only_a_forceable_refusal_advertises_the_override() {
            use crate::disks::DiskError as E;

            let forceable = E::Held {
                sandbox_id: "sb-1".into(),
                reason: "a deployment expects to resume it",
                forceable: true,
            }
            .to_string();
            assert!(forceable.contains("force=1"), "{forceable}");
            assert!(forceable.contains("sb-1"), "{forceable}");

            let never = E::Held {
                sandbox_id: "sb-1".into(),
                reason: "the sandbox is running; evict or stop it first",
                forceable: false,
            }
            .to_string();
            assert!(!never.contains("force"), "{never}");
            // It still has to say what *would* work.
            assert!(never.contains("stop it first"), "{never}");

            let no_target = E::NoArchiveTarget.to_string();
            assert!(no_target.contains("APP_LB_DISK_ARCHIVE_BUCKET"), "{no_target}");
        }

        /// The page's force-retry condition, pinned against the message it
        /// reads. These two live in different languages and cannot share a
        /// constant, so the coupling is asserted instead.
        #[test]
        fn the_page_gates_its_force_retry_on_that_same_string() {
            assert!(
                DISKS_HTML.contains(r#"reason(r).includes("force=1")"#),
                "the page must not offer force for a refusal that forbids it",
            );
        }
    }

    mod security_console {
        use super::*;

        #[test]
        fn the_page_calls_the_rule_routes_the_router_registers() {
            for route in [
                r#""POST", "/security/rules""#,
                r#""PATCH", "/security/rules/""#,
                r#""DELETE", "/security/rules/""#,
            ] {
                assert!(SIEM_HTML.contains(route), "page never calls {route}");
            }
        }

        /// An all-zero series means "this rule refused nothing", which is the
        /// finding — not "no data". A page that rendered the two the same way
        /// would hide exactly the rule worth removing.
        #[test]
        fn a_rule_that_never_fires_is_called_out_rather_than_drawn_flat() {
            assert!(SIEM_HTML.contains(r#">no hits<"#));
            assert!(SIEM_HTML.contains(r#">no data yet<"#));
        }

        /// Making a block permanent is the one action here with no natural end,
        /// so it must not be reachable without saying so.
        #[test]
        fn keeping_a_rule_forever_is_confirmed() {
            assert!(SIEM_HTML.contains("Keep rule"));
            assert!(
                SIEM_HTML.contains("secs === null && !confirm("),
                "a forever rule must be confirmed and a timed one must not be",
            );
        }

        /// `expires_in_secs` is required on the PATCH: absent must not be read
        /// as "forever", or a client that forgets the field silently makes a
        /// block permanent.
        #[test]
        fn an_absent_expiry_is_refused_rather_than_read_as_forever() {
            let absent: RuleExpiryBody = serde_json::from_str("{}").unwrap();
            assert!(absent.expires_in_secs.is_none(), "absent");

            let forever: RuleExpiryBody =
                serde_json::from_str(r#"{"expires_in_secs":null}"#).unwrap();
            assert_eq!(forever.expires_in_secs, Some(None), "explicitly forever");

            let timed: RuleExpiryBody =
                serde_json::from_str(r#"{"expires_in_secs":3600}"#).unwrap();
            assert_eq!(timed.expires_in_secs, Some(Some(3600)));
        }
    }

    /// The network topology console. Client-rendered against `/metrics` and
    /// `/ingress`, like the dashboard is against `/metrics`, so the contract
    /// worth pinning is the routes the page fetches and the states it draws.
    mod network_console {
        use super::*;

        /// The page hard-codes the endpoints it polls, so a rename here has to
        /// break a test rather than a browser.
        #[test]
        fn the_page_calls_the_routes_the_router_registers() {
            // `summary=false` is what carries the per-VM rows the leaf column
            // draws; a bare `metrics` would return an empty VM list.
            assert!(NETWORK_HTML.contains("metrics?summary=false"), "page never polls /metrics");
            assert!(NETWORK_HTML.contains("ingress"), "page never polls /ingress");
            // Global scope first, local on `?view=local` or when refused.
            assert!(NETWORK_HTML.contains("fetch(\"fleet/network\""), "page never polls /fleet/network");
            assert!(NETWORK_HTML.contains("/network?view=local"), "no way back to the local view");
        }

        /// The dashboard's workload rollup and server drill-down fetch the
        /// fleet routes the router registers, relative to `/dashboard`.
        #[test]
        fn the_dashboard_calls_the_fleet_rollup_routes() {
            assert!(DASHBOARD_HTML.contains("\"fleet/deployments\""));
            assert!(DASHBOARD_HTML.contains("\"fleet/gateways/\" + encodeURIComponent("));
            assert!(DASHBOARD_HTML.contains("\"/metrics?\""));
        }

        /// All five legend states must appear in the page, because the canvas
        /// distinguishes them by colour and a missing label would mean a state
        /// that can happen but is not drawn.
        #[test]
        fn every_vm_state_is_labelled_in_the_legend() {
            for label in ["serving", "cold-booting", "draining", "down", "cold-idle"] {
                assert!(NETWORK_HTML.contains(label), "legend never describes {label}");
            }
        }
    }

    /// The five pages are separate `include_str!`d files with no build step to
    /// share anything through, so what makes them one product is only ever
    /// convention. These pin the parts of that convention a user would notice.
    mod page_consistency {
        use super::*;

        fn pages() -> [(&'static str, &'static str); 6] {
            [
                ("dashboard", DASHBOARD_HTML),
                ("directory", DIRECTORY_HTML),
                ("siem", SIEM_HTML),
                ("disks", DISKS_HTML),
                ("plugins", PLUGINS_HTML),
                ("network", NETWORK_HTML),
            ]
        }

        /// Every page links every other: a page missing from one nav bar is
        /// a page nobody finds.
        #[test]
        fn every_page_links_every_page() {
            for (name, html) in pages() {
                for href in ["/", "/dashboard", "/siem", "/storage", "/plugins", "/metrics"] {
                    assert!(
                        html.contains(&format!(r#"<a href="{href}""#)),
                        "{name}'s nav has no link to {href}",
                    );
                }
            }
        }

        /// The theme is a **cookie** now, not this origin's localStorage, and no
        /// page may keep one of its own.
        ///
        /// The property the old localStorage test protected — follow a link
        /// between these five pages and the theme survives — is the weaker half
        /// of what a cookie gives: localStorage is per *origin*, so the choice
        /// stopped at app-lb. It now follows a person to ci, app-obs,
        /// heyosecret and artifacts as well, because all five read the same
        /// cookie. See `ui/README.md`.
        #[test]
        fn no_page_keeps_a_theme_of_its_own() {
            for (name, html) in pages() {
                // The accesses, not the word: the comment left where the old
                // script stood explains why it went away, and says `localStorage`.
                for access in ["localStorage.getItem", "localStorage.setItem"] {
                    assert!(
                        !html.contains(access),
                        "{name} still keeps theme state in this origin's localStorage ({access})",
                    );
                }
                assert!(
                    html.contains("data-theme-toggle"),
                    "{name} has no theme control at all",
                );
                assert!(
                    html.contains(r#"src="/__ui/theme.js""#),
                    "{name} does not load the shared toggle",
                );
            }
        }

        /// The theme has to be on `<html>` in the markup itself — not applied by
        /// a script, however early it runs.
        ///
        /// The old test demanded the restore live in `<head>`, which was the
        /// best a client-side theme could do: one blocking read before the body
        /// exists. A server-rendered attribute is strictly better — the first
        /// byte is already correct, and it is correct with scripting off.
        #[test]
        fn the_theme_is_in_the_markup_not_applied_by_script() {
            for (name, html) in pages() {
                let open_tag = html
                    .split_once('>')
                    .and_then(|(_, rest)| rest.split_once('>'))
                    .map(|(tag, _)| tag.to_string())
                    .unwrap_or_default();
                assert!(
                    open_tag.contains("<html") && open_tag.contains("{{HTML_ATTRS}}"),
                    "{name}: the theme must be stamped on the <html> tag, found {open_tag:?}",
                );
                // And nothing may set it afterwards: a page that also assigned
                // `data-theme` from script would fight the server and flash.
                let body = html.split_once("</head>").map(|(_, b)| b).unwrap_or(html);
                assert!(
                    !body.contains("setAttribute(\"data-theme\""),
                    "{name} sets the theme from its own script",
                );
            }
        }

        /// One stylesheet for all five, served by this binary.
        ///
        /// Not a CDN: these pages are read over SSH tunnels and from networks
        /// with no route out, where a remote stylesheet leaves an operator
        /// staring at unstyled HTML during an incident.
        #[test]
        fn every_page_loads_the_shared_stylesheet_and_nothing_remote() {
            for (name, html) in pages() {
                assert!(
                    html.contains(r#"href="/__ui/heyo.css""#),
                    "{name} does not load the shared stylesheet",
                );
                for external in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
                    assert!(!html.contains(external), "{name} loads an external asset ({external})");
                }
            }
        }
    }

    /// The link has to reach the *data plane*, which the dashboard cannot infer
    /// from its own location — it is served by the admin listener, on a
    /// different port and (usually) a different scheme.
    mod public_url {
        use super::*;

        fn rule(host: Option<&str>, path: Option<&str>) -> crate::config::RouteRule {
            crate::config::RouteRule {
                host: host.map(str::to_string),
                host_suffix: None,
                path_prefix: path.map(str::to_string),
                strip_prefix: false,
            }
        }

        #[test]
        fn plaintext_on_the_default_port_needs_no_port() {
            let u = PublicUrl::from_config(false, "0.0.0.0:80", "0.0.0.0:6189");
            assert_eq!(u.of(&rule(Some("web.example.com"), None)).unwrap(), "http://web.example.com");
        }

        /// The out-of-the-box config. Linking `http://host` here would connect
        /// to nothing, which is worse than not linking at all.
        #[test]
        fn a_non_default_port_is_carried_into_the_link() {
            let u = PublicUrl::from_config(false, "0.0.0.0:6188", "0.0.0.0:6189");
            assert_eq!(
                u.of(&rule(Some("web.example.com"), None)).unwrap(),
                "http://web.example.com:6188",
            );
        }

        /// With TLS on, a browser belongs on the HTTPS listener — not the
        /// plaintext one, which would redirect at best.
        #[test]
        fn tls_links_the_https_listener() {
            let u = PublicUrl::from_config(true, "0.0.0.0:80", "0.0.0.0:443");
            assert_eq!(u.of(&rule(Some("web.example.com"), None)).unwrap(), "https://web.example.com");

            let u = PublicUrl::from_config(true, "0.0.0.0:80", "0.0.0.0:6189");
            assert_eq!(
                u.of(&rule(Some("web.example.com"), None)).unwrap(),
                "https://web.example.com:6189",
            );
        }

        /// A host+path rule only matches under its prefix, so linking the bare
        /// host would 404 against this very deployment.
        #[test]
        fn a_path_prefix_is_part_of_the_link() {
            let u = PublicUrl::from_config(false, "0.0.0.0:80", "0.0.0.0:443");
            assert_eq!(
                u.of(&rule(Some("web.example.com"), Some("/api"))).unwrap(),
                "http://web.example.com/api",
            );
        }

        /// Neither a subtree nor a bare path names a hostname a browser could
        /// be sent to, so neither is linkable.
        #[test]
        fn rules_without_a_host_are_not_linkable() {
            let u = PublicUrl::from_config(false, "0.0.0.0:80", "0.0.0.0:443");
            assert!(u.of(&rule(None, Some("/legacy"))).is_none());
            assert!(u.of(&rule(Some("  "), None)).is_none());

            let suffix = crate::config::RouteRule {
                host: None,
                host_suffix: Some("apps.example.com".into()),
                path_prefix: None,
                strip_prefix: false,
            };
            assert!(u.of(&suffix).is_none());
        }

        #[test]
        fn ipv6_listen_addresses_parse() {
            assert_eq!(port_of("[::]:6188"), Some(6188));
            assert_eq!(port_of("[::1]:443"), Some(443));
            assert_eq!(port_of("0.0.0.0:6188"), Some(6188));
            assert_eq!(port_of("no-port"), None);
        }
    }

    fn header_for(user: &str, password: &str) -> String {
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        format!("Basic {token}")
    }

    #[test]
    fn accepts_matching_credentials() {
        let auth = DashboardAuth::new("admin", "s3cret");
        assert!(auth.accepts(Some(&header_for("admin", "s3cret"))));
    }

    #[test]
    fn rejects_wrong_or_missing_credentials() {
        let auth = DashboardAuth::new("admin", "s3cret");
        assert!(!auth.accepts(Some(&header_for("admin", "wrong"))));
        assert!(!auth.accepts(Some(&header_for("root", "s3cret"))));
        assert!(!auth.accepts(Some("Bearer s3cret")), "wrong scheme");
        assert!(!auth.accepts(Some("Basic not-base64")));
        assert!(!auth.accepts(None), "no Authorization header");
    }

    #[test]
    fn password_with_colon_round_trips() {
        // `user:pass:word` must authenticate as password `pass:word`, since
        // Basic auth splits only on the first colon.
        let auth = DashboardAuth::new("admin", "pass:word");
        assert!(auth.accepts(Some(&header_for("admin", "pass:word"))));
    }

    // -- the gate ----------------------------------------------------------

    mod gate {
        use super::super::*;
        use super::b64_basic;
        use crate::tokens::{AdminScope, NewToken, TokenStore};

        const NOW: u64 = 1_000;

        fn store() -> TokenStore {
            // Never persisted, so the path is never touched.
            TokenStore::new("/nonexistent/tokens.json")
        }

        fn mint(s: &TokenStore, admin: AdminScope, deployments: &[&str]) -> String {
            s.mint(
                NewToken {
                    fleet: false,
                    name: "test".into(),
                    admin,
                    namespace: None,
                    deployments: deployments.iter().map(|d| d.to_string()).collect(),
                    expires_in_secs: None,
                },
                NOW,
            )
            .unwrap()
            .1
        }

        fn basic() -> DashboardAuth {
            DashboardAuth::new("admin", "hunter2")
        }

        /// `decide_access` with the common shape: a header, a route, no query.
        fn on(
            auth: Option<&DashboardAuth>,
            tokens: &TokenStore,
            header: Option<&str>,
            matched: &str,
            path: &str,
            want: AdminScope,
        ) -> Verdict {
            decide_access(
                auth,
                tokens,
                &Presented {
                    header,
                    matched: Some(matched),
                    path,
                    query: None,
                    target_namespace: None,
                federated: None,
                },
                want,
                NOW,
            )
        }

        fn allowed(v: Verdict) -> Caller {
            match v {
                Verdict::Allow(c) => c,
                other => panic!("expected Allow, got {other:?}"),
            }
        }

        fn forbidden_because(v: Verdict) -> String {
            match v {
                Verdict::Forbidden(d) => d,
                other => panic!("expected Forbidden, got {other:?}"),
            }
        }

        fn mint_in_namespace(s: &TokenStore, admin: AdminScope, ns: &str) -> String {
            s.mint(
                NewToken {
                    fleet: false,
                    name: "ns test".into(),
                    admin,
                    namespace: Some(ns.into()),
                    deployments: vec![],
                    expires_in_secs: None,
                },
                NOW,
            )
            .unwrap()
            .1
        }

        /// `decide_access` for a route naming a deployment whose namespace the
        /// registry resolved to `target_ns`.
        fn on_deployment(
            tokens: &TokenStore,
            header: &str,
            target_ns: Option<&str>,
        ) -> Verdict {
            decide_access(
                Some(&basic()),
                tokens,
                &Presented {
                    header: Some(header),
                    matched: Some("/deployments/:id/exec"),
                    path: "/deployments/web/exec",
                    query: None,
                    target_namespace: target_ns,
                federated: None,
                },
                AdminScope::Admin,
                NOW,
            )
        }

        /// The circularity `/whoami` exists to break: the credential that most
        /// needs to know its own scope is the one whose scope is too small to
        /// look it up.
        #[test]
        fn a_token_with_no_admin_scope_can_still_ask_what_it_is() {
            let t = store();
            let hdr = format!("Bearer {}", mint(&t, AdminScope::None, &["marketing"]));

            // The route it needs, at the tier its layer asks for.
            assert!(matches!(
                on(Some(&basic()), &t, Some(&hdr), "/whoami", "/whoami", AdminScope::None),
                Verdict::Allow(_)
            ));

            // And every other way of asking stays shut, which is the whole
            // reason the scope was undiscoverable: listing tokens is `admin`,
            // and the dashboard's data is `view`.
            assert!(matches!(
                on(Some(&basic()), &t, Some(&hdr), "/tokens", "/tokens", AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
            assert!(matches!(
                on(Some(&basic()), &t, Some(&hdr), "/metrics", "/metrics", AdminScope::View),
                Verdict::Forbidden(_)
            ));
        }

        /// A deployment-scoped token is not "fleet-wide" on this route: there is
        /// nothing on it to reach past, because the answer is only ever about
        /// the caller. Without `narrows_itself` the fleet-route rule would
        /// refuse exactly the callers the route is for.
        #[test]
        fn a_scoped_token_is_not_refused_at_whoami_as_a_fleet_route() {
            let t = store();
            let scoped = format!("Bearer {}", mint(&t, AdminScope::Admin, &["marketing"]));
            let confined = format!("Bearer {}", mint_in_namespace(&t, AdminScope::None, "team-a"));

            for hdr in [&scoped, &confined] {
                assert!(
                    matches!(
                        on(Some(&basic()), &t, Some(hdr), "/whoami", "/whoami", AdminScope::None),
                        Verdict::Allow(_)
                    ),
                    "a confined caller must be able to ask about itself",
                );
            }

            // The contrast: a genuinely fleet-wide route still refuses both.
            assert!(matches!(
                on(Some(&basic()), &t, Some(&scoped), "/jobs", "/jobs", AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
        }

        /// No credential is still no credential. `/whoami` lowers the tier, not
        /// the requirement — an anonymous caller has no "self" to report.
        #[test]
        fn whoami_still_needs_a_credential() {
            let t = store();
            assert!(matches!(
                on(Some(&basic()), &t, None, "/whoami", "/whoami", AdminScope::None),
                Verdict::Unauthorized
            ));
            assert!(matches!(
                on(Some(&basic()), &t, Some("Bearer applb_nope_nope"), "/whoami", "/whoami", AdminScope::None),
                Verdict::Unauthorized
            ));
        }

        #[test]
        fn a_namespace_token_reaches_its_namespace_and_nothing_else() {
            let t = store();
            let hdr = format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));

            assert!(matches!(on_deployment(&t, &hdr, Some("team-a")), Verdict::Allow(_)));
            assert!(matches!(on_deployment(&t, &hdr, Some("team-b")), Verdict::Forbidden(_)));
            // The deployment does not exist: refused, and indistinguishably
            // from the out-of-namespace case, so probing can't map the fleet.
            assert!(matches!(on_deployment(&t, &hdr, None), Verdict::Forbidden(_)));
        }

        #[test]
        fn a_namespace_token_may_list_and_create_but_not_roam_the_fleet() {
            let t = store();
            let hdr = format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));
            let at = |matched: &str, path: &str| {
                decide_access(
                    Some(&basic()),
                    &t,
                    &Presented {
                        header: Some(&hdr),
                        matched: Some(matched),
                        path,
                        query: None,
                        target_namespace: None,
                    federated: None,
                    },
                    AdminScope::Admin,
                    NOW,
                )
            };

            // `/deployments` narrows (list) or is checked in the handler
            // (create), so the gate lets it through.
            assert!(matches!(at("/deployments", "/deployments"), Verdict::Allow(_)));
            // Token routes are walled in the handler: a namespace admin mints
            // only tokens confined to its own namespace (`tenant_tokens`).
            assert!(matches!(at("/tokens", "/tokens"), Verdict::Allow(_)));
            assert!(matches!(at("/tokens/:id", "/tokens/abc"), Verdict::Allow(_)));
            // The routes that see past a namespace stay closed: the job
            // history is fleet state.
            assert!(matches!(at("/jobs", "/jobs"), Verdict::Forbidden(_)));
            assert!(matches!(at("/services", "/services"), Verdict::Forbidden(_)));
            assert!(matches!(at("/fleet", "/fleet"), Verdict::Forbidden(_)));
            assert!(matches!(at("/fleet/network", "/fleet/network"), Verdict::Forbidden(_)));
            // The rollup and drill-down narrow to a namespace in the handler,
            // which also restricts them to caller-auth gateways.
            assert!(matches!(at("/fleet/deployments", "/fleet/deployments"), Verdict::Allow(_)));
            assert!(matches!(at("/fleet/gateways/:id/metrics", "/fleet/gateways/us2/metrics"), Verdict::Allow(_)));
            // Secrets are walled in the handler, per namespace, so the gate
            // lets a confined caller through to be measured there.
            assert!(matches!(at("/secrets", "/secrets"), Verdict::Allow(_)));
            assert!(matches!(at("/secrets/:id", "/secrets/github"), Verdict::Allow(_)));
        }

        #[test]
        fn workspace_recovery_requires_explicit_namespace_admin_even_when_ungated() {
            let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({"id":"svc","namespace":"team-a","routes":[]})).unwrap();
            assert!(!recovery_authorized(&Caller::Ungated, &spec));
            assert!(recovery_authorized(&Caller::Operator, &spec));
            let t = store();
            for (namespace, tier, allowed) in [("team-a", AdminScope::Admin, true), ("team-b", AdminScope::Admin, false), ("team-a", AdminScope::View, false)] {
                let token = mint_in_namespace(&t, tier, namespace);
                let caller = Caller::Token(t.verify(&token, NOW).unwrap());
                assert_eq!(recovery_authorized(&caller, &spec), allowed);
            }
            assert_eq!(deployment_of("/deployments/:id/workspace/recoveries", "/deployments/svc/workspace/recoveries"), Some("svc"));
        }

        /// The handler-side wall: a confined caller reaches its own
        /// namespace's secrets at its own tier, and nothing past it.
        #[test]
        fn secrets_are_walled_by_namespace_in_the_handler() {
            let t = store();
            let raw = mint_in_namespace(&t, AdminScope::Admin, "team-a");
            let token = Caller::Token(t.verify(&raw, NOW).unwrap());
            assert!(may_use_secrets(Some(&token), "team-a", true).is_ok());
            assert!(may_use_secrets(Some(&token), "team-b", false).is_err());
            assert!(may_use_secrets(Some(&token), "default", false).is_err());

            let view = grant(&[("team-a", AdminScope::View), ("team-b", AdminScope::Admin)], false);
            let caller = Caller::Federated(view);
            assert!(may_use_secrets(Some(&caller), "team-a", false).is_ok());
            assert!(may_use_secrets(Some(&caller), "team-a", true).is_err());
            assert!(may_use_secrets(Some(&caller), "team-b", true).is_ok());
            assert!(may_use_secrets(Some(&caller), "team-c", false).is_err());

            let fleet = Caller::Federated(grant(&[], true));
            assert!(may_use_secrets(Some(&fleet), "anything", true).is_ok());
            assert!(may_use_secrets(Some(&Caller::Operator), "anything", true).is_ok());
            assert!(may_use_secrets(None, "anything", true).is_ok());
        }

        /// Namespace narrowing on the fleet rollup: a confined caller must name
        /// a namespace it may view, and is then served caller-auth gateways
        /// only. Fleet callers keep full reach; nobody ungated gets any.
        #[test]
        fn fleet_rollup_reach_is_measured_per_namespace() {
            use crate::fleet::Reach;
            let t = store();
            let raw = mint_in_namespace(&t, AdminScope::View, "team-a");
            let token = Caller::Token(t.verify(&raw, NOW).unwrap());
            assert!(fleet_reach(&token, Some("team-a")).ok() == Some(Reach::CallerOnly));
            assert!(fleet_reach(&token, Some("team-b")).is_err());
            assert!(fleet_reach(&token, None).is_err());
            assert!(fleet_reach(&token, Some("../x")).is_err());

            let federated = Caller::Federated(grant(&[("team-a", AdminScope::View)], false));
            assert!(fleet_reach(&federated, Some("team-a")).ok() == Some(Reach::CallerOnly));
            assert!(fleet_reach(&federated, Some("team-c")).is_err());

            let fleet = Caller::Federated(grant(&[], true));
            assert!(fleet_reach(&fleet, None).ok() == Some(Reach::Fleet));
            assert!(fleet_reach(&fleet, Some("team-c")).ok() == Some(Reach::Fleet));
            assert!(fleet_reach(&Caller::Operator, None).ok() == Some(Reach::Fleet));
            assert!(fleet_reach(&Caller::Ungated, None).is_err());
            // A deployment-scoped token names no namespace wall to narrow to.
            let scoped = Caller::Token(t.verify(&mint(&t, AdminScope::View, &["sb-1"]), NOW).unwrap());
            assert!(fleet_reach(&scoped, Some("default")).is_err());
        }

        fn grant(ns: &[(&str, AdminScope)], fleet: bool) -> Arc<crate::federated::Grant> {
            Arc::new(crate::federated::Grant {
                subject: serde_json::from_value(
                    serde_json::json!({"userId": "u1", "accountId": "acc-own"}),
                )
                .unwrap(),
                namespaces: ns.iter().map(|(n, s)| (n.to_string(), *s)).collect(),
                accounts: ns
                    .iter()
                    .map(|(n, _)| (n.to_string(), format!("acc-{n}")))
                    .collect(),
                fleet,
            })
        }

        #[test]
        fn only_authenticated_federated_credentials_can_be_delegated() {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(header::COOKIE, "__Host-heyo-admin=session.token".parse().unwrap());
            let federated = Caller::Federated(grant(&[], true));
            assert_eq!(fleet_credential(&federated, &headers).as_deref(), Some("session.token"));
            assert!(fleet_credential(&Caller::Operator, &headers).is_none());
            assert!(fleet_credential(&Caller::Ungated, &headers).is_none());
            headers.insert(header::AUTHORIZATION, "Bearer explicit-token".parse().unwrap());
            assert_eq!(fleet_credential(&federated, &headers).as_deref(), Some("explicit-token"));
            headers.insert(header::AUTHORIZATION, "Basic operator".parse().unwrap());
            assert!(fleet_credential(&federated, &headers).is_none());
        }

        fn spec_in(ns: &str, body_account: Option<&str>) -> DeploymentSpec {
            serde_json::from_value(serde_json::json!({
                "id": "web",
                "namespace": ns,
                "routes": [],
                "upstreams": ["127.0.0.1:1"],
                "account_id": body_account,
            }))
            .unwrap()
        }

        /// The owner comes from the grant, not the body: a customer cannot
        /// bill its namespace to another account by naming one.
        #[test]
        fn a_federated_register_is_metered_to_the_namespace_owner() {
            let g = grant(&[("team-a", AdminScope::Admin)], false);
            let mut spec = spec_in("team-a", Some("acc-somebody-else"));
            stamp_owner(&mut spec, Some(&Caller::Federated(g.clone())));
            assert_eq!(spec.account_id.as_deref(), Some("acc-team-a"));
            assert_eq!(spec.user_id.as_deref(), Some("u1"));

            // A fleet admin deploying into a namespace it holds no grant for
            // (its own account is the fallback) is still stamped, not skipped.
            let mut spec = spec_in("team-b", None);
            stamp_owner(&mut spec, Some(&Caller::Federated(g)));
            assert_eq!(spec.account_id.as_deref(), Some("acc-own"));
        }

        /// The platform's own hands keep what they sent — including nothing.
        #[test]
        fn an_operator_register_keeps_the_body_owner() {
            for caller in [None, Some(Caller::Operator), Some(Caller::Ungated)] {
                let mut spec = spec_in("team-a", Some("acc-explicit"));
                stamp_owner(&mut spec, caller.as_ref());
                assert_eq!(spec.account_id.as_deref(), Some("acc-explicit"));
                assert_eq!(spec.user_id, None);
                let mut spec = spec_in("team-a", None);
                stamp_owner(&mut spec, caller.as_ref());
                assert_eq!(spec.account_id, None);
            }
        }

        /// A confined credential reaching exactly one namespace has an unnamed
        /// spec (the `default` namespace) filled in with its own; an explicit,
        /// different namespace is left for the scope check to refuse; and a
        /// caller with no single namespace rewrites nothing.
        #[test]
        fn a_confined_caller_has_its_lone_namespace_assumed() {
            let t = store();
            let raw = mint_in_namespace(&t, AdminScope::Admin, "team-a");
            let token = Caller::Token(t.verify(&raw, NOW).unwrap());

            // Unnamed spec (default) → the token's own namespace.
            let mut spec = spec_in("default", None);
            assume_namespace(&mut spec, Some(&token));
            assert_eq!(spec.namespace, "team-a");

            // An explicit, different namespace is untouched — the downstream
            // scope check refuses it rather than have it silently rewritten.
            let mut spec = spec_in("team-b", None);
            assume_namespace(&mut spec, Some(&token));
            assert_eq!(spec.namespace, "team-b");

            // A federated grant naming exactly one namespace is assumed too...
            let one = Caller::Federated(grant(&[("team-a", AdminScope::Admin)], false));
            let mut spec = spec_in("default", None);
            assume_namespace(&mut spec, Some(&one));
            assert_eq!(spec.namespace, "team-a");

            // ...but one naming several has no lone namespace to assume, and a
            // fleet, operator, ungated or absent caller never assumes at all.
            let many = Caller::Federated(grant(
                &[("team-a", AdminScope::Admin), ("team-b", AdminScope::Admin)],
                false,
            ));
            for caller in [
                Some(many),
                Some(Caller::Federated(grant(&[], true))),
                Some(Caller::Operator),
                Some(Caller::Ungated),
                None,
            ] {
                let mut spec = spec_in("default", None);
                assume_namespace(&mut spec, caller.as_ref());
                assert_eq!(spec.namespace, "default");
            }
        }

        fn spec_json(v: serde_json::Value) -> DeploymentSpec {
            serde_json::from_value(v).unwrap()
        }

        fn only_host(spec: &DeploymentSpec) -> Option<&str> {
            match spec.routes.as_slice() {
                [one] => one.host.as_deref(),
                _ => None,
            }
        }

        /// A backend that cannot be reached without a route — a site or a static
        /// upstream list — gets `<id>.<base>` when it names no host, and a VM
        /// gets one only once it has exposed a port with a route. A routeless VM
        /// stays private, and a pinned host or an absent base is left alone.
        #[test]
        fn a_hostless_deployment_is_routed_under_the_base_domain() {
            let base = Some("us2.heyo.work");

            // A routeless site is dead weight without a host — it gets one.
            let mut site = spec_json(serde_json::json!({
                "id": "docs", "routes": [], "site": { "root": "/srv/docs" },
            }));
            assume_host(&mut site, base);
            assert_eq!(only_host(&site), Some("docs.us2.heyo.work"));

            // So does a routeless static upstream list.
            let mut api = spec_json(serde_json::json!({
                "id": "api", "routes": [], "upstreams": ["127.0.0.1:9000"],
            }));
            assume_host(&mut api, base);
            assert_eq!(only_host(&api), Some("api.us2.heyo.work"));

            // A routeless VM is a headless sandbox on purpose — no host.
            let mut headless = spec_json(serde_json::json!({
                "id": "agent", "routes": [], "vm": { "driver": "firecracker", "port": 8080 },
            }));
            assume_host(&mut headless, base);
            assert!(headless.routes.is_empty());

            // A VM that has exposed a port with a (host-less) route gets a host
            // route added beside it, leaving the original route untouched.
            let mut web = spec_json(serde_json::json!({
                "id": "web", "routes": [{ "path_prefix": "/" }],
                "vm": { "driver": "firecracker", "port": 8080 },
            }));
            assume_host(&mut web, base);
            assert!(web.has_host_route());
            assert!(web.routes.iter().any(|r| r.host.as_deref() == Some("web.us2.heyo.work")));
            assert!(web.routes.iter().any(|r| r.path_prefix.as_deref() == Some("/")));

            // A pinned host is respected; nothing is added.
            let mut pinned = spec_json(serde_json::json!({
                "id": "x", "routes": [{ "host": "chosen.example.com" }],
                "site": { "root": "/srv/x" },
            }));
            assume_host(&mut pinned, base);
            assert_eq!(only_host(&pinned), Some("chosen.example.com"));

            // No base configured ⇒ host synthesis is off entirely.
            let mut no_base = spec_json(serde_json::json!({
                "id": "docs", "routes": [], "site": { "root": "/srv/docs" },
            }));
            assume_host(&mut no_base, None);
            assert!(no_base.routes.is_empty());
        }

        /// A site with no root gets a managed one under the sites dir,
        /// namespaced; a root that was named is the caller's choice and left
        /// alone; with no sites dir the empty root reaches `validate`.
        #[test]
        fn a_rootless_site_gets_a_managed_root() {
            let dir = std::path::Path::new("/var/lib/app-lb/sites");
            let mut site = spec_json(serde_json::json!({
                "id": "docs", "namespace": "team-a", "routes": [{ "host": "d" }], "site": {},
            }));
            assume_site_root(&mut site, Some(dir));
            assert_eq!(site.site.as_ref().unwrap().root, "/var/lib/app-lb/sites/team-a/docs");
            assert!(site.validate().is_ok());

            let mut named = spec_json(serde_json::json!({
                "id": "docs", "routes": [{ "host": "d" }], "site": { "root": "/srv/docs" },
            }));
            assume_site_root(&mut named, Some(dir));
            assert_eq!(named.site.as_ref().unwrap().root, "/srv/docs");

            let mut unmanaged = spec_json(serde_json::json!({
                "id": "docs", "routes": [{ "host": "d" }], "site": {},
            }));
            assume_site_root(&mut unmanaged, None);
            assert!(unmanaged.validate().is_err(), "an empty root is still refused");
        }

        fn host_sandbox(id: &str, account: Option<&str>) -> HostSandboxView {
            HostSandboxView {
                sandbox_id: id.into(),
                name: id.into(),
                status: heyo_sdk::SandboxStatus::Running,
                image: "ubuntu:24.04".into(),
                size_class: None,
                guest_ip: None,
                uptime_secs: 1,
                cpu_percent: None,
                memory_bytes: None,
                account_id: account.map(str::to_string),
                created_at: None,
            }
        }

        fn host_ids(views: Vec<HostSandboxView>) -> Vec<String> {
            views.into_iter().map(|v| v.sandbox_id).collect()
        }

        /// The host inventory is scoped by *account*, the one thing a sandbox
        /// outside every namespace still has: a namespace caller sees the
        /// sandboxes billed to the accounts behind its namespaces, the
        /// operator sees the host, and an unattributed sandbox is the
        /// operator's alone.
        #[test]
        fn host_sandboxes_are_narrowed_by_account() {
            let all = vec![
                host_sandbox("sb-a", Some("acc-team-a")),
                host_sandbox("sb-b", Some("acc-team-b")),
                host_sandbox("sb-own", Some("acc-own")),
                host_sandbox("sb-nobody", None),
            ];
            let everything = vec!["sb-a", "sb-b", "sb-own", "sb-nobody"];
            for caller in [None, Some(Caller::Operator), Some(Caller::Ungated)] {
                assert_eq!(
                    host_ids(visible_host_sandboxes(&all, caller.as_ref(), None)),
                    everything
                );
                // The operator's `namespace=` filters the table, not the host.
                assert_eq!(
                    host_ids(visible_host_sandboxes(&all, caller.as_ref(), Some("team-a"))),
                    everything
                );
            }

            let member = Caller::Federated(grant(&[("team-a", AdminScope::View)], false));
            // Direct to app-lb, no query: every account the grant names, and
            // the caller's own.
            assert_eq!(
                host_ids(visible_host_sandboxes(&all, Some(&member), None)),
                vec!["sb-a", "sb-own"]
            );
            // Through the cloud door the namespace is pinned: its owner only.
            assert_eq!(
                host_ids(visible_host_sandboxes(&all, Some(&member), Some("team-a"))),
                vec!["sb-a"]
            );
            // A namespace they do not hold yields nothing rather than everything.
            assert!(visible_host_sandboxes(&all, Some(&member), Some("team-b")).is_empty());

            let fleet = Caller::Federated(grant(&[("team-b", AdminScope::Admin)], true));
            assert_eq!(
                host_ids(visible_host_sandboxes(&all, Some(&fleet), None)),
                everything
            );
            assert_eq!(
                host_ids(visible_host_sandboxes(&all, Some(&fleet), Some("team-b"))),
                vec!["sb-b"]
            );
            // A namespace the auth service named no owner for cannot narrow.
            assert_eq!(
                host_ids(visible_host_sandboxes(&all, Some(&fleet), Some("elsewhere"))),
                everything
            );
        }

        /// An app-token is a key to deployments; the host's other tenants are
        /// not behind that door unless the token is a fleet token.
        #[test]
        fn scoped_tokens_see_no_host_sandboxes() {
            let all = vec![host_sandbox("sb-a", Some("acc-team-a"))];
            let s = store();
            let token = |namespace: Option<&str>, deployments: &[&str]| {
                let secret = s
                    .mint(
                        NewToken {
                            fleet: false,
                            name: "test".into(),
                            admin: AdminScope::Admin,
                            namespace: namespace.map(str::to_string),
                            deployments: deployments.iter().map(|d| d.to_string()).collect(),
                            expires_in_secs: None,
                        },
                        NOW,
                    )
                    .unwrap()
                    .1;
                Caller::Token(s.verify(&secret, NOW).unwrap())
            };
            let scoped = token(None, &["web"]);
            assert!(visible_host_sandboxes(&all, Some(&scoped), None).is_empty());
            let namespaced = token(Some("team-a"), &[]);
            assert!(visible_host_sandboxes(&all, Some(&namespaced), None).is_empty());
            let fleet = token(None, &["*"]);
            assert_eq!(host_ids(visible_host_sandboxes(&all, Some(&fleet), None)), vec!["sb-a"]);
        }

        /// A federated caller presents a bearer the local store does not know;
        /// `authorize` will have resolved it into `Presented::federated`.
        fn federated_at(
            t: &TokenStore,
            g: &Arc<crate::federated::Grant>,
            matched: &str,
            path: &str,
            target_ns: Option<&str>,
            want: AdminScope,
        ) -> Verdict {
            decide_access(
                Some(&basic()),
                t,
                &Presented {
                    header: Some("Bearer eyJ.heyo.jwt"),
                    matched: Some(matched),
                    path,
                    query: None,
                    target_namespace: target_ns,
                    federated: Some(g.clone()),
                },
                want,
                NOW,
            )
        }

        #[test]
        fn a_federated_grant_reaches_its_namespaces_and_nothing_else() {
            let t = store();
            let g = grant(&[("team-a", AdminScope::Admin), ("team-b", AdminScope::Admin)], false);
            let on = |ns: Option<&str>| {
                federated_at(&t, &g, "/deployments/:id/exec", "/deployments/web/exec", ns, AdminScope::Admin)
            };
            assert!(matches!(on(Some("team-a")), Verdict::Allow(Caller::Federated(_))));
            assert!(matches!(on(Some("team-b")), Verdict::Allow(_)));
            assert!(matches!(on(Some("team-c")), Verdict::Forbidden(_)));
            assert!(matches!(on(Some("default")), Verdict::Forbidden(_)));
            assert!(matches!(on(None), Verdict::Forbidden(_)));
        }

        #[test]
        fn a_federated_grant_may_list_and_create_but_not_roam_the_fleet() {
            let t = store();
            let g = grant(&[("team-a", AdminScope::Admin)], false);
            let at = |m: &str, p: &str| federated_at(&t, &g, m, p, None, AdminScope::Admin);
            assert!(matches!(at("/deployments", "/deployments"), Verdict::Allow(_)));
            assert!(matches!(at("/metrics", "/metrics"), Verdict::Allow(_)));
            // Walled in the handler, like `/secrets`.
            assert!(matches!(at("/tokens", "/tokens"), Verdict::Allow(_)));
            assert!(matches!(at("/secrets", "/secrets"), Verdict::Allow(_)));
            assert!(matches!(at("/ingress", "/ingress"), Verdict::Allow(_)));
            assert!(matches!(at("/jobs", "/jobs"), Verdict::Forbidden(_)));
            assert!(matches!(
                federated_at(&t, &g, "/feeds/:namespace", "/feeds/team-a", None, AdminScope::View),
                Verdict::Allow(_)
            ));
            assert!(matches!(
                federated_at(&t, &g, "/feeds/:namespace", "/feeds/team-b", None, AdminScope::View),
                Verdict::Forbidden(_)
            ));
        }

        #[test]
        fn a_view_grant_cannot_mutate_in_its_namespace() {
            let t = store();
            let g = grant(&[("team-a", AdminScope::View), ("team-b", AdminScope::Admin)], false);
            let on = |ns: &str, want: AdminScope| {
                federated_at(&t, &g, "/deployments/:id", "/deployments/web", Some(ns), want)
            };
            assert!(matches!(on("team-a", AdminScope::View), Verdict::Allow(_)));
            assert!(matches!(on("team-a", AdminScope::Admin), Verdict::Forbidden(_)));
            assert!(matches!(on("team-b", AdminScope::Admin), Verdict::Allow(_)));
            // With no target to judge by, any admin namespace admits an admin route.
            assert!(matches!(
                federated_at(&t, &g, "/deployments", "/deployments", None, AdminScope::Admin),
                Verdict::Allow(_)
            ));
        }

        #[test]
        fn a_fleet_grant_roams() {
            let t = store();
            let g = grant(&[], true);
            let at = |m: &str, p: &str| federated_at(&t, &g, m, p, None, AdminScope::Admin);
            assert!(matches!(at("/tokens", "/tokens"), Verdict::Allow(_)));
            assert!(matches!(at("/secrets", "/secrets"), Verdict::Allow(_)));
            assert!(matches!(
                federated_at(&t, &g, "/deployments/:id", "/deployments/web", Some("anything"), AdminScope::Admin),
                Verdict::Allow(_)
            ));
            assert!(!Caller::Federated(g).confined());
        }

        #[test]
        fn a_local_token_is_preferred_over_a_grant() {
            let t = store();
            let hdr = format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));
            let g = grant(&[("team-b", AdminScope::Admin)], false);
            let verdict = decide_access(
                Some(&basic()),
                &t,
                &Presented {
                    header: Some(&hdr),
                    matched: Some("/deployments/:id"),
                    path: "/deployments/web",
                    query: None,
                    target_namespace: Some("team-b"),
                    federated: Some(g),
                },
                AdminScope::Admin,
                NOW,
            );
            // The token, not the grant, is the caller: team-b is out of reach.
            assert!(matches!(verdict, Verdict::Forbidden(_)));
        }

        #[test]
        fn federation_is_ignored_when_no_gate_is_configured() {
            let t = store();
            let g = grant(&[("team-a", AdminScope::View)], false);
            let verdict = decide_access(
                None,
                &t,
                &Presented {
                    header: Some("Bearer eyJ.heyo.jwt"),
                    matched: Some("/tokens"),
                    path: "/tokens",
                    query: None,
                    target_namespace: None,
                    federated: Some(g),
                },
                AdminScope::Admin,
                NOW,
            );
            assert!(matches!(verdict, Verdict::Allow(Caller::Ungated)));
        }

        #[test]
        fn the_feed_route_is_walled_by_namespace() {
            let t = store();
            let ns_hdr = format!("Bearer {}", mint_in_namespace(&t, AdminScope::View, "team-a"));
            let fleet_hdr = format!("Bearer {}", mint(&t, AdminScope::View, &["*"]));
            let scoped_hdr = format!("Bearer {}", mint(&t, AdminScope::View, &["web"]));
            let at = |hdr: &str, path: &str| {
                decide_access(
                    Some(&basic()),
                    &t,
                    &Presented {
                        header: Some(hdr),
                        matched: Some("/feeds/:namespace"),
                        path,
                        query: None,
                        target_namespace: None,
                    federated: None,
                    },
                    AdminScope::View,
                    NOW,
                )
            };

            assert!(matches!(at(&ns_hdr, "/feeds/team-a"), Verdict::Allow(_)));
            // The `.xml` spelling is the same feed.
            assert!(matches!(at(&ns_hdr, "/feeds/team-a.xml"), Verdict::Allow(_)));
            assert!(matches!(at(&ns_hdr, "/feeds/team-b"), Verdict::Forbidden(_)));
            // Fleet scope reads any feed; a deployment-list token reads none —
            // which namespaces exist is fleet information.
            assert!(matches!(at(&fleet_hdr, "/feeds/team-a"), Verdict::Allow(_)));
            assert!(matches!(at(&scoped_hdr, "/feeds/team-a"), Verdict::Forbidden(_)));
        }

        /// A namespace's plugin routes are walled by the namespace in their
        /// path, and a federated grant's tier is measured in that namespace.
        #[test]
        fn namespace_plugin_routes_are_walled_by_namespace() {
            let t = store();
            let ns_view = format!("Bearer {}", mint_in_namespace(&t, AdminScope::View, "team-a"));
            let ns_admin =
                format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));
            let fleet_hdr = format!("Bearer {}", mint(&t, AdminScope::Admin, &["*"]));
            let scoped_hdr = format!("Bearer {}", mint(&t, AdminScope::Admin, &["web"]));
            let at = |hdr: Option<&str>,
                      federated: Option<Arc<crate::federated::Grant>>,
                      matched: &str,
                      path: &str,
                      want: AdminScope| {
                decide_access(
                    Some(&basic()),
                    &t,
                    &Presented {
                        header: hdr,
                        matched: Some(matched),
                        path,
                        query: None,
                        target_namespace: namespace_plugin_target(matched, path),
                        federated,
                    },
                    want,
                    NOW,
                )
            };
            const SURFACE: &str = "/namespaces/:name/plugins/:id/*rest";
            const ITEM: &str = "/namespaces/:name/plugins/:id";
            const LIST: &str = "/namespaces/:name/plugins";

            // Its own namespace: read the list and the plugin's pages.
            for (m, p) in [
                (LIST, "/namespaces/team-a/plugins"),
                (SURFACE, "/namespaces/team-a/plugins/obs/api/fleet"),
            ] {
                assert!(matches!(at(Some(&ns_view), None, m, p, AdminScope::View), Verdict::Allow(_)));
            }
            // Another namespace: refused, on every tier.
            for (m, p, want) in [
                (LIST, "/namespaces/team-b/plugins", AdminScope::View),
                (SURFACE, "/namespaces/team-b/plugins/obs/api/fleet", AdminScope::View),
                (ITEM, "/namespaces/team-b/plugins/obs", AdminScope::Admin),
            ] {
                assert!(matches!(at(Some(&ns_admin), None, m, p, want), Verdict::Forbidden(_)));
            }
            // Installing is CRUD tier: a view token cannot, an admin one can.
            let install = "/namespaces/team-a/plugins/obs";
            assert!(matches!(
                at(Some(&ns_view), None, ITEM, install, AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
            assert!(matches!(
                at(Some(&ns_admin), None, ITEM, install, AdminScope::Admin),
                Verdict::Allow(_)
            ));
            // Fleet scope reaches any namespace; a deployment-list token none.
            assert!(matches!(
                at(Some(&fleet_hdr), None, ITEM, "/namespaces/team-b/plugins/obs", AdminScope::Admin),
                Verdict::Allow(_)
            ));
            assert!(matches!(
                at(Some(&scoped_hdr), None, LIST, "/namespaces/team-a/plugins", AdminScope::View),
                Verdict::Forbidden(_)
            ));

            // Admin in team-b and view in team-a must not post in team-a.
            let g = grant(&[("team-a", AdminScope::View), ("team-b", AdminScope::Admin)], false);
            let alerts = "/namespaces/team-a/plugins/obs/api/alerts";
            assert!(matches!(
                at(Some("Bearer eyJ.heyo.jwt"), Some(g.clone()), SURFACE, alerts, AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
            assert!(matches!(
                at(Some("Bearer eyJ.heyo.jwt"), Some(g.clone()), SURFACE, alerts, AdminScope::View),
                Verdict::Allow(_)
            ));
            assert!(matches!(
                at(
                    Some("Bearer eyJ.heyo.jwt"),
                    Some(g),
                    SURFACE,
                    "/namespaces/team-b/plugins/obs/api/alerts",
                    AdminScope::Admin
                ),
                Verdict::Allow(_)
            ));
        }

        #[test]
        fn a_namespace_token_reaches_single_jobs_but_not_the_job_list() {
            let t = store();
            let hdr = format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));
            let at = |matched: &str, path: &str| on(Some(&basic()), &t, Some(&hdr), matched, path, AdminScope::Admin);
            assert!(matches!(at("/jobs/:job_id", "/jobs/job-1"), Verdict::Allow(_)));
            assert!(matches!(at("/jobs", "/jobs"), Verdict::Forbidden(_)));
        }

        /// A namespace token narrowed to some of the namespace's deployments
        /// reaches the plugin pages but cannot install for the whole room.
        #[test]
        fn installing_needs_the_whole_namespace() {
            let t = store();
            let narrow = t
                .mint(
                    NewToken {
                        fleet: false,
                        name: "narrow".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("team-a".into()),
                        deployments: vec!["web".into()],
                        expires_in_secs: None,
                    },
                    NOW,
                )
                .unwrap()
                .1;
            let narrow = Caller::Token(t.verify(&narrow, NOW).unwrap());
            assert!(narrow.reaches_namespace("team-a"));
            assert!(refuse_unless_administers(Some(&narrow), "team-a").is_some());
            let whole = Caller::Token(
                t.verify(&mint_in_namespace(&t, AdminScope::Admin, "team-a"), NOW)
                    .unwrap(),
            );
            assert!(refuse_unless_administers(Some(&whole), "team-a").is_none());
            assert!(refuse_unless_administers(Some(&whole), "team-b").is_some());
            assert!(refuse_unless_administers(None, "team-a").is_none());
        }

        #[test]
        fn no_configured_credential_means_no_gate() {
            let t = store();
            let v = on(None, &t, None, "/deployments", "/deployments", AdminScope::Admin);
            assert!(matches!(allowed(v), Caller::Ungated));
        }

        #[test]
        fn basic_auth_still_works_and_is_unscoped() {
            let t = store();
            let auth = basic();
            let hdr = format!("Basic {}", b64_basic("admin", "hunter2"));

            let caller = allowed(on(
                Some(&auth),
                &t,
                Some(&hdr),
                "/deployments/:id/exec",
                "/deployments/anything/exec",
                AdminScope::Admin,
            ));
            assert!(matches!(caller, Caller::Operator));
            assert!(caller.may_touch("anything", None));
            assert!(caller.covers_fleet());
            assert!(
                caller.visible().is_none(),
                "the operator credential must not be narrowed"
            );
        }

        #[test]
        fn a_bearer_token_authenticates_where_basic_would() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["*"]);
            let hdr = format!("Bearer {secret}");
            let caller = allowed(on(
                Some(&basic()),
                &t,
                Some(&hdr),
                "/deployments",
                "/deployments",
                AdminScope::Admin,
            ));
            assert!(matches!(caller, Caller::Token(_)));
        }

        #[test]
        fn a_revoked_token_is_unauthorized_not_forbidden() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["*"]);
            let id = t.list()[0].id.clone();
            t.revoke(&id);

            let hdr = format!("Bearer {secret}");
            assert!(matches!(
                on(Some(&basic()), &t, Some(&hdr), "/deployments", "/deployments", AdminScope::Admin),
                Verdict::Unauthorized
            ));
        }

        #[test]
        fn garbage_credentials_are_unauthorized() {
            let t = store();
            let auth = basic();
            for header in [
                None,
                Some("Bearer applb_000000000000_nope"),
                Some("Bearer "),
                Some("Basic bm9wZTpub3Bl"),
                Some("applb_000000000000_nope"),
                Some("Token applb_000000000000_nope"),
            ] {
                assert!(
                    matches!(
                        on(Some(&auth), &t, header, "/deployments", "/deployments", AdminScope::Admin),
                        Verdict::Unauthorized
                    ),
                    "{header:?} should not authenticate",
                );
            }
        }

        #[test]
        fn a_view_token_reads_metrics_but_cannot_reach_the_crud_tier() {
            let t = store();
            let secret = mint(&t, AdminScope::View, &["*"]);
            let hdr = format!("Bearer {secret}");
            let auth = basic();

            allowed(on(Some(&auth), &t, Some(&hdr), "/metrics", "/metrics", AdminScope::View));

            let why = forbidden_because(on(
                Some(&auth),
                &t,
                Some(&hdr),
                "/deployments",
                "/deployments",
                AdminScope::Admin,
            ));
            assert!(why.contains("admin scope"), "{why}");
        }

        #[test]
        fn a_data_plane_only_token_cannot_read_the_admin_api_at_all() {
            let t = store();
            // `admin: none` — the token an application carries to get past its own
            // deployment's gate, and nothing more.
            let secret = mint(&t, AdminScope::None, &["sb-1"]);
            let hdr = format!("Bearer {secret}");
            let auth = basic();

            assert!(matches!(
                on(Some(&auth), &t, Some(&hdr), "/metrics", "/metrics", AdminScope::View),
                Verdict::Forbidden(_)
            ));
            assert!(matches!(
                on(Some(&auth), &t, Some(&hdr), "/deployments/:id/exec", "/deployments/sb-1/exec", AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
        }

        #[test]
        fn a_scoped_token_reaches_its_own_deployment_and_no_other() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["sb-1"]);
            let hdr = format!("Bearer {secret}");
            let auth = basic();

            for route in [
                ("/deployments/:id", "/deployments/sb-1"),
                ("/deployments/:id/exec", "/deployments/sb-1/exec"),
                ("/deployments/:id/shell", "/deployments/sb-1/shell"),
                ("/deployments/:id/scaling", "/deployments/sb-1/scaling"),
                ("/deployments/:id/jobs", "/deployments/sb-1/jobs"),
                (
                    "/deployments/:id/vms/:sandbox_id",
                    "/deployments/sb-1/vms/applb-x",
                ),
            ] {
                allowed(on(Some(&auth), &t, Some(&hdr), route.0, route.1, AdminScope::Admin));
            }

            let why = forbidden_because(on(
                Some(&auth),
                &t,
                Some(&hdr),
                "/deployments/:id/exec",
                "/deployments/sb-2/exec",
                AdminScope::Admin,
            ));
            assert!(why.contains("sb-2"), "the message should name the deployment: {why}");
        }

        #[test]
        fn a_scoped_token_is_refused_the_fleet_wide_routes() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["sb-1"]);
            let hdr = format!("Bearer {secret}");
            let auth = basic();

            // Creating deployments, reading the secret store and listing every job
            // are not about the one deployment this token was given.
            for route in [
                "/fleet",
                "/fleet/deployments",
                "/fleet/gateways/:id/metrics",
                "/fleet/network",
                "/services",
                "/control-plane/config",
                "/deployments",
                "/secrets",
                "/secrets/:id",
                "/jobs",
                "/jobs/:job_id",
                "/certs",
                "/tokens",
                "/tokens/:id",
            ] {
                assert!(
                    matches!(
                        on(Some(&auth), &t, Some(&hdr), route, route, AdminScope::Admin),
                        Verdict::Forbidden(_)
                    ),
                    "{route} should be refused a deployment-scoped token",
                );
            }
        }

        #[test]
        fn control_plane_configuration_requires_fleet_admin() {
            let t = store();
            let route = "/control-plane/config";
            let view = format!("Bearer {}", mint(&t, AdminScope::View, &["*"]));
            let admin = format!("Bearer {}", mint(&t, AdminScope::Admin, &["*"]));
            let namespace = format!("Bearer {}", mint_in_namespace(&t, AdminScope::Admin, "team-a"));
            for credential in [&view, &namespace] {
                assert!(matches!(on(Some(&basic()), &t, Some(credential), route, route, AdminScope::Admin), Verdict::Forbidden(_)));
            }
            assert!(matches!(on(Some(&basic()), &t, None, route, route, AdminScope::Admin), Verdict::Unauthorized));
            assert!(matches!(on(Some(&basic()), &t, Some(&admin), route, route, AdminScope::Admin), Verdict::Allow(_)));
        }

        /// Minting is how you escalate, so it must not be reachable by anything
        /// less than a fleet-wide admin token.
        #[test]
        fn a_scoped_token_cannot_mint_itself_a_wider_one() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["sb-1"]);
            let hdr = format!("Bearer {secret}");
            assert!(matches!(
                on(Some(&basic()), &t, Some(&hdr), "/tokens", "/tokens", AdminScope::Admin),
                Verdict::Forbidden(_)
            ));
        }

        /// Every route that can refuse a deployment refuses it in the same
        /// words, so a caller cannot tell "exists, not yours" from "never
        /// existed" by reading the body. The register path is the one that had
        /// to be brought into line: it decides partly from a deployment the
        /// caller cannot see, and it used to name the caller's *own* namespace
        /// in the refusal — which was both wrong and a tell that something
        /// invisible had been consulted.
        #[test]
        fn every_refusal_names_only_the_id_the_caller_supplied() {
            let t = store();
            let secret = t
                .mint(
                    NewToken {
                        fleet: false,
                        name: "sam".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("sam".into()),
                        deployments: Vec::new(),
                        expires_in_secs: None,
                    },
                    NOW,
                )
                .unwrap()
                .1;
            let hdr = format!("Bearer {secret}");

            // The gate's wording, for an id in somebody else's namespace and for
            // one that does not exist: the same sentence, naming only the id.
            for id in ["bob-web", "never-existed"] {
                let why = forbidden_because(on(
                    Some(&basic()),
                    &t,
                    Some(&hdr),
                    "/deployments/:id",
                    &format!("/deployments/{id}"),
                    AdminScope::Admin,
                ));
                assert_eq!(why, out_of_scope(id), "{id}");
                // Nothing about a namespace, the caller's or anyone's: a body
                // that mentions one is describing something unseen.
                assert!(!why.contains("namespace"), "{why}");
                assert!(!why.contains("sam"), "{why}");
            }

            // And the register path answers with that identical string, so
            // POST cannot be told apart from GET/PUT/DELETE by its body.
            assert_eq!(out_of_scope("bob-web"), out_of_scope("bob-web"));
            assert!(!out_of_scope("bob-web").contains("register"));
        }

        /// A namespace token's picker is its own room and nothing else, even
        /// before anything is in it. The registry answers "what is in a
        /// namespace"; only the token itself can answer "which namespace is
        /// mine", which is why an empty room still has to appear.
        #[test]
        fn a_namespace_token_sees_its_own_room_when_it_is_still_empty() {
            let t = store();
            let secret = t
                .mint(
                    NewToken {
                        fleet: false,
                        name: "sam".into(),
                        admin: AdminScope::Admin,
                        namespace: Some("sam".into()),
                        // Empty, which for a namespace token means everything
                        // *there* rather than nothing — see `AppToken::namespace`.
                        deployments: Vec::new(),
                        expires_in_secs: None,
                    },
                    NOW,
                )
                .unwrap()
                .1;
            let hdr = format!("Bearer {secret}");
            let caller = allowed(on(
                Some(&basic()),
                &t,
                Some(&hdr),
                "/namespaces",
                "/namespaces",
                AdminScope::View,
            ));
            assert!(caller.confined(), "a namespace token is walled");
            assert_eq!(own_namespaces(Some(&caller)), ["sam".to_string()]);

            // And it is walled *out* of everyone else's, which is the whole
            // point: bob's deployments are invisible whatever they are called.
            assert!(caller.may_view("web", "sam"));
            assert!(!caller.may_view("web", "bob"));
            assert!(!caller.reaches_namespace("bob"));
        }

        /// The unconfined callers carry no room of their own, so the index is
        /// whatever the registry shows them — inventing a namespace here would
        /// be inventing a confinement.
        #[test]
        fn an_unconfined_caller_carries_no_namespace_of_its_own() {
            let t = store();
            let fleet = format!("Bearer {}", mint(&t, AdminScope::Admin, &["*"]));
            let scoped = format!("Bearer {}", mint(&t, AdminScope::View, &["sb-1"]));
            for hdr in [&fleet, &scoped] {
                let caller = allowed(on(
                    Some(&basic()),
                    &t,
                    Some(hdr),
                    "/namespaces",
                    "/namespaces",
                    AdminScope::View,
                ));
                assert!(own_namespaces(Some(&caller)).is_empty());
            }
            assert!(own_namespaces(Some(&Caller::Operator)).is_empty());
            assert!(own_namespaces(Some(&Caller::Ungated)).is_empty());
            assert!(own_namespaces(None).is_empty());

            // A deployment-scoped token is not confined: its wall is a list of
            // ids, and it still narrows `/namespaces` through `may_view`.
            let caller = allowed(on(
                Some(&basic()),
                &t,
                Some(&scoped),
                "/namespaces",
                "/namespaces",
                AdminScope::View,
            ));
            assert!(!caller.confined());
            assert!(caller.may_view("sb-1", "anything"));
            assert!(!caller.may_view("sb-9", "anything"));
        }

        #[test]
        fn metrics_narrows_itself_rather_than_refusing_a_scoped_token() {
            let t = store();
            let secret = mint(&t, AdminScope::View, &["sb-1", "sb-2"]);
            let hdr = format!("Bearer {secret}");

            let caller = allowed(on(
                Some(&basic()),
                &t,
                Some(&hdr),
                "/metrics",
                "/metrics",
                AdminScope::View,
            ));
            assert_eq!(
                caller.visible().expect("a scoped token narrows the answer"),
                ["sb-1".to_string(), "sb-2".to_string()],
            );
        }

        #[test]
        fn a_fleet_scoped_token_narrows_nothing() {
            let t = store();
            let secret = mint(&t, AdminScope::View, &["*"]);
            let hdr = format!("Bearer {secret}");
            let caller = allowed(on(
                Some(&basic()),
                &t,
                Some(&hdr),
                "/metrics",
                "/metrics",
                AdminScope::View,
            ));
            assert!(caller.visible().is_none());
        }

        #[test]
        fn a_query_token_works_on_the_shell_route_and_nowhere_else() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["sb-1"]);
            let auth = basic();
            let query = format!("cols=80&app_token={secret}&rows=24");

            // The one route a browser cannot send a header to.
            let v = decide_access(
                Some(&auth),
                &t,
                &Presented {
                    header: None,
                    matched: Some("/deployments/:id/shell"),
                    path: "/deployments/sb-1/shell",
                    query: Some(&query),
                    target_namespace: None,
                federated: None,
                },
                AdminScope::Admin,
                NOW,
            );
            assert!(matches!(allowed(v), Caller::Token(_)));

            // Everywhere else it is not a credential at all, because everywhere
            // else can use a header — and a token in a URL lands in access logs.
            for (matched, path) in [
                ("/deployments/:id/exec", "/deployments/sb-1/exec"),
                ("/deployments/:id", "/deployments/sb-1"),
                ("/metrics", "/metrics"),
            ] {
                assert!(
                    matches!(
                        decide_access(
                            Some(&auth),
                            &t,
                            &Presented {
                                header: None,
                                matched: Some(matched),
                                path,
                                query: Some(&query),
                                target_namespace: None,
                            federated: None,
                            },
                            AdminScope::Admin,
                            NOW,
                        ),
                        Verdict::Unauthorized
                    ),
                    "{matched} must not accept a credential in the query string",
                );
            }
        }

        #[test]
        fn the_query_token_still_has_to_be_in_scope() {
            let t = store();
            let secret = mint(&t, AdminScope::Admin, &["sb-1"]);
            let query = format!("app_token={secret}");
            assert!(matches!(
                decide_access(
                    Some(&basic()),
                    &t,
                    &Presented {
                        header: None,
                        matched: Some("/deployments/:id/shell"),
                        path: "/deployments/sb-2/shell",
                        query: Some(&query),
                        target_namespace: None,
                    federated: None,
                    },
                    AdminScope::Admin,
                    NOW,
                ),
                Verdict::Forbidden(_)
            ));
        }

        #[test]
        fn an_expired_token_stops_working_without_anyone_revoking_it() {
            let t = store();
            let secret = t
                .mint(
                    NewToken {
                        fleet: false,
                        name: "short".into(),
                        admin: AdminScope::Admin,
                        namespace: None,
                        deployments: vec!["*".into()],
                        expires_in_secs: Some(60),
                    },
                    NOW,
                )
                .unwrap()
                .1;
            let hdr = format!("Bearer {secret}");
            let auth = basic();
            let at = |now| {
                decide_access(
                    Some(&auth),
                    &t,
                    &Presented {
                        header: Some(&hdr),
                        matched: Some("/deployments"),
                        path: "/deployments",
                        query: None,
                        target_namespace: None,
                    federated: None,
                    },
                    AdminScope::Admin,
                    now,
                )
            };
            assert!(matches!(at(NOW + 59), Verdict::Allow(_)));
            assert!(matches!(at(NOW + 60), Verdict::Unauthorized));
        }

        /// The id is read positionally out of the real path, so this pins the
        /// assumption that every deployment route is `/deployments/:id/…`.
        #[test]
        fn the_deployment_is_read_off_the_matched_route() {
            assert_eq!(
                deployment_of("/deployments/:id/exec", "/deployments/sb-1/exec"),
                Some("sb-1")
            );
            assert_eq!(
                deployment_of("/deployments/:id", "/deployments/sb-1"),
                Some("sb-1")
            );
            assert_eq!(
                deployment_of("/deployments/:id/vms/:sandbox_id", "/deployments/sb-1/vms/x"),
                Some("sb-1")
            );
            // Not a deployment route, however much the path looks like one.
            assert_eq!(deployment_of("/deployments", "/deployments"), None);
            assert_eq!(deployment_of("/jobs/:job_id", "/jobs/deployments"), None);
            assert_eq!(deployment_of("/metrics", "/metrics"), None);
        }

        #[test]
        fn bearer_parsing_is_exact() {
            assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
            assert_eq!(bearer(Some("Bearer  abc ")), Some("abc"));
            assert_eq!(bearer(Some("bearer abc")), None, "the scheme is case-sensitive here");
            assert_eq!(bearer(Some("Bearer")), None);
            assert_eq!(bearer(Some("Bearer ")), None);
            assert_eq!(bearer(Some("Basic abc")), None);
            assert_eq!(bearer(None), None);
        }
    }

    /// Basic credentials as the header value they must produce, for the gate
    /// tests. Deliberately re-derived rather than reusing `DashboardAuth`'s own
    /// encoding, so a change to that encoding fails a test instead of silently
    /// agreeing with itself.
    fn b64_basic(user: &str, password: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    }

    #[test]
    fn ct_eq_matches_std_eq() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"ab", b"abc"));
    }
}

/// Wire-contract fixtures for the clients that re-declare these types.
/// A child module rather than part of `mod tests` above, because it needs to see
/// the private response structs and nothing else in this file needs to see it.
#[cfg(test)]
#[path = "wire_golden.rs"]
mod wire_golden;
