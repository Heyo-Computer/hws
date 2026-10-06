//! The dashboard and the JSON it runs on.
//!
//! Bound to loopback by default and reached through app-lb, which terminates TLS
//! and can put interactive sign-in in front of it. An optional bearer token also
//! protects direct service routes used by Cloud. Every query takes a slot from a
//! bounded pool and a deadline, so a month-wide refresh degrades into a 503
//! rather than competing with ingest for the machine.
//!
//! The endpoints are typed rather than a SQL passthrough. Each one is a query
//! this module built, so partition pruning and a row cap are always applied —
//! neither is something a caller can forget.
//!
//! # Namespace routes
//!
//! `/ns/{ns}/…` is the same dashboard and API narrowed to one app-lb namespace,
//! for app-lb's obs plugin to put behind its own gate: a tenant reaches it as
//! `/namespaces/{ns}/plugins/obs/…`, app-lb checks the tenant may read `{ns}`
//! and forwards with this service's token. Nothing here trusts the caller to
//! name its own namespace — the token is the operator's — so the narrowing is
//! all in what these handlers will return:
//!
//! - every query filters on the stored `namespace` column, so history follows
//!   the namespace a row was written under, not today's deployment list;
//! - a deployment in another namespace, or one of the platform partitions,
//!   answers 404 exactly as one that never existed;
//! - the fleet view carries no host usage and no host sandboxes;
//! - alerts are the namespace's own, and their webhooks may only leave for a
//!   public `https` address.

use crate::alerts::{Alert, AlertMetric, new_id};
use crate::ingest::{Sink, token_matches};
use crate::namespaces::{Directory, is_platform_id, is_valid_namespace};
use crate::query::{
    Engine, HOST_DEPLOYMENT, LogBucket, LogFilter, MAX_LOG_LIMIT, MetricBucket, QueryError, Window,
};
use crate::sources::applb::{HostSandboxView, LiveStatus};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The dashboard page. Self-contained — no external fetches — so it works on a
/// host with no route to the internet, which is most of them.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Ranges the dashboard offers as one-click presets, longest label first for
/// the picker.
///
/// Presets, not the whole vocabulary: `resolve_window` also accepts any
/// relative duration ("1d", "36h", "45m"), and the bucket ladder picks a
/// workable step for whatever span comes out. These are the rungs worth a
/// permanent button.
const WINDOWS: &[(&str, i64)] = &[
    ("15m", 900),
    ("1h", 3_600),
    ("6h", 21_600),
    ("24h", 86_400),
    ("7d", 604_800),
    ("30d", 2_592_000),
];

/// Points to aim for across a window. The overview draws a row-height sparkline
/// per deployment and the detail page draws full-width charts, so they want
/// different resolutions from the same range.
const FLEET_POINTS: u32 = 40;
const DETAIL_POINTS: u32 = 140;

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Engine>,
    pub sink: Sink,
    /// Bearer token for every dashboard/query route. `None` preserves the
    /// loopback-only default; `/healthz` is always open.
    pub api_token: Option<Arc<String>>,
    /// Rows buffered in the writer, published by the drain task.
    pub buffered: Arc<AtomicUsize>,
    pub flush_secs: u64,
    pub retain_days: u32,
    /// Last successful app-lb poll. A failed poll leaves the snapshot in place;
    /// the endpoint marks it stale instead of replacing evidence with emptiness.
    pub live: tokio::sync::watch::Receiver<Option<LiveStatus>>,
    pub stale_after_secs: u64,
    /// Where the theme cookie is written and under what name — from
    /// `APP_OBS_UI_COOKIE_*`, else the fleet-wide `HEYO_UI_*`. Point it at the
    /// same parent domain as app-lb's `auth.cookie_domain` and one choice of
    /// light or dark covers every app.
    pub ui_cookies: Arc<crate::heyo_ui::CookieConfig>,
    /// Alert rules, shared with the background checker task. Reads via the API
    /// take a read lock; creates and deletes take a write lock and persist to
    /// `alerts_file`.
    pub alerts: Arc<tokio::sync::RwLock<Vec<Alert>>>,
    /// Where alert rules are persisted on every create/delete.
    pub alerts_file: String,
    /// Which namespace each deployment is in, for the `/ns/{ns}` routes.
    pub directory: Arc<Directory>,
}

pub fn router(state: ApiState) -> Router {
    let protected = Router::new()
        // The bare hostname should land somewhere useful; app-lb routes a whole
        // host here, so `/` is what someone actually types.
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(dashboard))
        .route("/api/fleet", get(fleet))
        .route("/api/platform-status", get(platform_status))
        .route("/api/deployments/{id}", get(detail))
        .route("/api/deployments/{id}/logs", get(logs))
        .route("/api/alerts", get(list_alerts).post(create_alert))
        .route("/api/alerts/{id}", delete(delete_alert))
        .route("/stats", get(stats))
        // One namespace's view, for app-lb's obs plugin. See the module docs.
        .route("/ns/{ns}", get(ns_redirect))
        .route("/ns/{ns}/", get(ns_dashboard))
        .route("/ns/{ns}/api/fleet", get(ns_fleet))
        .route("/ns/{ns}/api/deployments/{id}", get(ns_detail))
        .route("/ns/{ns}/api/deployments/{id}/logs", get(ns_logs))
        .route(
            "/ns/{ns}/api/alerts",
            get(ns_list_alerts).post(ns_create_alert),
        )
        .route("/ns/{ns}/api/alerts/{id}", delete(ns_delete_alert))
        .route_layer(middleware::from_fn_with_state(
            state.api_token.clone(),
            require_api_token,
        ));

    Router::new()
        // Always open, and deliberately not behind a query slot: app-lb health
        // checks this, and a probe that fails because a dashboard is busy would
        // take the deployment out of rotation for no reason.
        .route("/healthz", get(health))
        // Open alongside `/healthz`: the stylesheet and fonts are static public
        // bytes, and a page that renders unstyled because its CSS needed a
        // token is worse than one whose CSS anyone can fetch.
        .route("/__ui/{*path}", get(ui_asset))
        .merge(protected)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    health_response(std::env::var("APP_OBS_REVISION").ok())
}

fn health_response(revision: Option<String>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Some(value) = revision.and_then(|value| HeaderValue::from_str(&value).ok()) {
        headers.insert("x-heyo-revision", value);
    }
    (headers, "ok\n")
}

async fn require_api_token(
    State(expected): State<Option<Arc<String>>>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if !api_request_authorized(expected.as_deref().map(String::as_str), presented) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "invalid api token\n",
        )
            .into_response();
    }
    next.run(request).await
}

fn api_request_authorized(expected: Option<&str>, presented: Option<&str>) -> bool {
    expected.is_none_or(|expected| token_matches(expected, presented))
}

/// The dashboard shell.
///
/// Substituted rather than served verbatim so the theme is on the `<html>` tag
/// in the first response — otherwise every navigation flashes the wrong palette
/// before script can correct it. `{{WHO}}` is the identity app-lb forwarded,
/// which is empty unless this deployment is gated.
///
/// `str::replace` rather than a template engine, matching app-lb's dashboards,
/// with a test standing in for the compile-time check maud would have given.
async fn dashboard(State(st): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    Html(render_dashboard(&st, &headers, None))
}

/// `GET /ns/{ns}` — the page's URLs are relative, so it must be served from a
/// path ending in `/` or every fetch resolves one level too high.
async fn ns_redirect(Path(ns): Path<String>) -> Result<Redirect, ApiError> {
    let ns = namespace_param(&ns)?;
    Ok(Redirect::permanent(&format!("/ns/{ns}/")))
}

/// `GET /ns/{ns}/` — the dashboard in namespace mode.
async fn ns_dashboard(
    State(st): State<ApiState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
) -> Result<Html<String>, ApiError> {
    let ns = namespace_param(&ns)?;
    Ok(Html(render_dashboard(&st, &headers, Some(ns))))
}

fn render_dashboard(st: &ApiState, headers: &HeaderMap, namespace: Option<&str>) -> String {
    let cookies = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    // Shown, never trusted: this page is read-only and the identity is a label.
    // app-lb strips these headers before setting them, so on a gated deployment
    // they are the gate's word; on an ungated one they are the caller's, which
    // is why nothing here is authorized on them.
    let who = crate::heyo_ui::identity_from(|n| headers.get(n).and_then(|v| v.to_str().ok()))
        .map(|i| crate::heyo_ui::escape(i.display()))
        .unwrap_or_default();
    // Validated before it gets here, and escaped anyway: it lands in an
    // attribute.
    let namespace = namespace.map(crate::heyo_ui::escape).unwrap_or_default();
    DASHBOARD_HTML
        .replace("{{HTML_ATTRS}}", &st.ui_cookies.attrs(cookies))
        .replace("{{WHO}}", &who)
        .replace("{{NAMESPACE}}", &namespace)
}

/// `GET /__ui/{*path}` — the platform stylesheet, theme script and fonts,
/// served by this binary rather than a CDN.
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
        None => (axum::http::StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

/// Ingest counters plus what is still in memory.
async fn stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "accepted": state.sink.accepted(),
        "dropped": state.sink.dropped(),
        "gated": state.sink.gated(),
        // Which namespaces are being collected: "open" (all of them),
        // "unknown" (app-lb has not answered yet), or the installed list.
        "collecting": match state.directory.gate() {
            crate::namespaces::Gate::Open => serde_json::json!("open"),
            crate::namespaces::Gate::Unknown => serde_json::json!("unknown"),
            crate::namespaces::Gate::Installed(set) => {
                serde_json::json!(set.into_iter().collect::<BTreeSet<_>>())
            }
        },
        "buffered_rows": state.buffered.load(Ordering::Relaxed),
        "flush_secs": state.flush_secs,
        "retain_days": state.retain_days,
    }))
}

#[derive(Debug, Serialize)]
struct PlatformStatusResponse {
    generated_at_ms: i64,
    status: &'static str,
    stale: bool,
    stale_after_secs: u64,
    snapshot: Option<LiveStatus>,
}

/// Current routing topology and observation health. Unlike `/api/fleet`, this
/// never scans parquet: a status page must still answer while historical query
/// capacity is exhausted.
async fn platform_status(State(state): State<ApiState>) -> Json<PlatformStatusResponse> {
    let now = Utc::now().timestamp_millis();
    let snapshot = state.live.borrow().clone();
    let stale = observation_is_stale(now, snapshot.as_ref(), state.stale_after_secs);
    Json(PlatformStatusResponse {
        generated_at_ms: now,
        status: overall_status(snapshot.as_ref(), stale),
        stale,
        stale_after_secs: state.stale_after_secs,
        snapshot,
    })
}

fn observation_is_stale(now_ms: i64, snapshot: Option<&LiveStatus>, stale_after_secs: u64) -> bool {
    snapshot.is_none_or(|snapshot| {
        now_ms.saturating_sub(snapshot.observed_at_ms)
            > (stale_after_secs as i64).saturating_mul(1000)
    })
}

fn overall_status(snapshot: Option<&LiveStatus>, stale: bool) -> &'static str {
    let Some(snapshot) = snapshot else {
        return "unavailable";
    };
    if stale {
        return "unavailable";
    }

    let mut degraded = false;
    let mut routed_deployments = 0;
    let mut routing_unknown = false;
    for deployment in &snapshot.deployments {
        let kind = deployment.kind.as_deref().unwrap_or("vm");
        match deployment.routed {
            Some(false) => continue,
            None => {
                routing_unknown = true;
                continue;
            }
            Some(true) => {}
        }
        routed_deployments += 1;
        if kind == "site" {
            continue;
        }
        let accepting = deployment
            .vms
            .iter()
            .filter(|backend| backend.healthy && !backend.draining)
            .count();
        if accepting == 0 {
            let intentionally_idle = kind == "vm"
                && deployment.vms.is_empty()
                && deployment.pool.pending == 0
                && deployment.pool.min_replicas == Some(0)
                && deployment.pool.desired_replicas == Some(0);
            if intentionally_idle {
                continue;
            }
            if deployment.pool.min_replicas.is_none() || deployment.pool.desired_replicas.is_none()
            {
                degraded = true;
                continue;
            }
            return "unavailable";
        }
        if accepting < deployment.vms.len() {
            degraded = true;
        }
    }
    if routed_deployments == 0 {
        return if routing_unknown {
            "degraded"
        } else {
            "unavailable"
        };
    }
    if degraded || routing_unknown {
        "degraded"
    } else {
        "healthy"
    }
}

#[derive(Debug, Deserialize)]
struct WindowParams {
    window: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogParams {
    window: Option<String>,
    level: Option<String>,
    backend: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
    before: Option<i64>,
    /// Explicit range bounds, epoch milliseconds UTC. Either or both; see
    /// `resolve_range`.
    from: Option<i64>,
    to: Option<i64>,
}

/// What is on disk right now, and how stale it might be.
///
/// `buffered_rows` is the reason this is here at all: a partition flushes on a
/// timer, so the newest rows are legitimately not queryable yet. Without saying
/// so, a dashboard that has just been shown a burst of traffic looks like it lost
/// it.
#[derive(Debug, Serialize)]
struct Freshness {
    buffered_rows: usize,
    flush_secs: u64,
    dropped: u64,
}

#[derive(Debug, Serialize)]
struct FleetResponse {
    generated_at_ms: i64,
    from_ms: i64,
    to_ms: i64,
    step_secs: u32,
    window: String,
    windows: Vec<String>,
    retain_days: u32,
    freshness: Freshness,
    /// Whole-host CPU and memory. `None` when nothing has ever landed under
    /// `_host` — app-lb reports it only once the daemon has sampled the host, and
    /// "never sampled" should not look like "idle".
    host: Option<Vec<MetricBucket>>,
    deployments: Vec<FleetRow>,
    /// Sandboxes on the host outside every deployment, live from the last
    /// app-lb poll rather than from parquet — this is an inventory, not a
    /// series. `None` before the first successful poll; empty when app-lb
    /// reported none (or predates reporting them). Their history is the
    /// `_unmanaged` row above, keyed by `backend`.
    host_sandboxes: Option<Vec<HostSandboxView>>,
}

#[derive(Debug, Serialize)]
struct FleetRow {
    id: String,
    /// Coarse series behind the row's sparkline.
    buckets: Vec<MetricBucket>,
    log_buckets: Vec<LogBucket>,
    /// Most recent non-null of each measure in the window — see `latest_of`.
    latest: MetricBucket,
    log_lines: u64,
    error_logs: u64,
}

#[derive(Debug, Serialize)]
struct DetailResponse {
    id: String,
    generated_at_ms: i64,
    from_ms: i64,
    to_ms: i64,
    step_secs: u32,
    window: String,
    windows: Vec<String>,
    retain_days: u32,
    freshness: Freshness,
    buckets: Vec<MetricBucket>,
    log_buckets: Vec<LogBucket>,
    latest: MetricBucket,
    log_lines: u64,
    error_logs: u64,
    /// Backends that logged in the window, for the log filter.
    backends: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    id: String,
    from_ms: i64,
    to_ms: i64,
    rows: Vec<crate::query::LogRow>,
    /// Pass back as `before` for the next page, or `None` at the end.
    ///
    /// Inclusive, so a burst spanning a page edge is re-sent rather than lost;
    /// the caller drops lines it already has.
    next_before_ms: Option<i64>,
    limit: usize,
}

async fn fleet(
    State(state): State<ApiState>,
    Query(params): Query<WindowParams>,
) -> Result<Json<FleetResponse>, ApiError> {
    fleet_view(&state, params, None).await
}

/// `GET /ns/{ns}/api/fleet`
async fn ns_fleet(
    State(state): State<ApiState>,
    Path(ns): Path<String>,
    Query(params): Query<WindowParams>,
) -> Result<Json<FleetResponse>, ApiError> {
    let ns = namespace_param(&ns)?;
    fleet_view(&state, params, Some(ns)).await
}

async fn fleet_view(
    state: &ApiState,
    params: WindowParams,
    namespace: Option<&str>,
) -> Result<Json<FleetResponse>, ApiError> {
    let (label, window) = resolve_window(params.window.as_deref());
    let step = window.step_secs(FLEET_POINTS);

    // One scan for the whole fleet rather than one per row: `deployment` is a
    // partition column, so the engine still only opens the directories the
    // window touches.
    let metrics = state.engine.metrics(window, step, None, namespace).await?;
    let volume = state
        .engine
        .log_volume(window, step, None, namespace)
        .await?;

    // The operator's list is what is on disk. A namespace's is what app-lb
    // says is in it now — so a deployment quiet for the whole window still
    // gets a row — plus whatever left rows under it in the window, which is
    // how a deleted deployment's last hours stay readable.
    let ids: Vec<String> = match namespace {
        None => state.engine.deployments(),
        Some(ns) => {
            let mut ids: BTreeSet<String> =
                state.directory.deployments_in(ns).into_iter().collect();
            ids.extend(metrics.keys().cloned());
            ids.extend(volume.keys().cloned());
            ids.into_iter()
                .filter(|id| visible_in(state, ns, id))
                .collect()
        }
    };

    let mut deployments = Vec::new();
    for id in ids {
        let buckets = metrics.get(&id).cloned().unwrap_or_default();
        let log_buckets = volume.get(&id).cloned().unwrap_or_default();
        deployments.push(FleetRow {
            latest: latest_of(&buckets),
            log_lines: log_buckets.iter().map(|b| b.lines).sum(),
            error_logs: log_buckets.iter().map(|b| b.errors).sum(),
            id,
            buckets,
            log_buckets,
        });
    }

    Ok(Json(FleetResponse {
        generated_at_ms: Utc::now().timestamp_millis(),
        from_ms: window.start_ms(),
        to_ms: window.end_ms(),
        step_secs: step,
        window: label,
        windows: window_labels(),
        retain_days: state.retain_days,
        freshness: freshness(state),
        // An empty vec and `None` mean different things: the first is "host
        // samples exist, none in this window", the second is "the daemon has
        // never reported host usage at all". A namespace gets neither: the
        // host is shared, and how loaded it is says something about every
        // other tenant on it.
        host: match namespace {
            Some(_) => None,
            None => metrics
                .get(HOST_DEPLOYMENT)
                .cloned()
                .or_else(|| state.engine.has_host_data().then(Vec::new)),
        },
        deployments,
        host_sandboxes: match namespace {
            Some(_) => None,
            None => state
                .live
                .borrow()
                .as_ref()
                .map(|live| live.host_sandboxes.clone()),
        },
    }))
}

/// Whether deployment `id` may be shown to namespace `ns` at all.
///
/// app-lb's word decides when it has one: in `ns`, yes; in another namespace,
/// no — even if older rows say otherwise, an id re-registered elsewhere must
/// not carry its history across. When app-lb no longer reports the id (it was
/// deleted), the stored rows decide, because every query below filters on
/// the namespace they were written under. The platform partitions are never
/// a tenant's.
fn visible_in(state: &ApiState, ns: &str, id: &str) -> bool {
    match state.directory.namespace_of(id) {
        Some(owner) => owner == ns,
        None => !is_platform_id(id),
    }
}

/// A namespace path segment, or the 404 an unknown one gets.
fn namespace_param(ns: &str) -> Result<&str, ApiError> {
    if is_valid_namespace(ns) {
        Ok(ns)
    } else {
        Err(ApiError::NotFound)
    }
}

async fn detail(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<WindowParams>,
) -> Result<Json<DetailResponse>, ApiError> {
    detail_view(&state, id, params, None).await
}

/// `GET /ns/{ns}/api/deployments/{id}`
async fn ns_detail(
    State(state): State<ApiState>,
    Path((ns, id)): Path<(String, String)>,
    Query(params): Query<WindowParams>,
) -> Result<Json<DetailResponse>, ApiError> {
    let ns = namespace_param(&ns)?;
    if !visible_in(&state, ns, &id) {
        return Err(ApiError::NotFound);
    }
    detail_view(&state, id, params, Some(ns)).await
}

async fn detail_view(
    state: &ApiState,
    id: String,
    params: WindowParams,
    namespace: Option<&str>,
) -> Result<Json<DetailResponse>, ApiError> {
    let (label, window) = resolve_window(params.window.as_deref());
    let step = window.step_secs(DETAIL_POINTS);

    let metrics = state
        .engine
        .metrics(window, step, Some(&id), namespace)
        .await?;
    let volume = state
        .engine
        .log_volume(window, step, Some(&id), namespace)
        .await?;
    let backends = state.engine.backends(window, &id, namespace).await?;

    let buckets = metrics.get(&id).cloned().unwrap_or_default();
    let log_buckets = volume.get(&id).cloned().unwrap_or_default();

    // A deployment app-lb no longer reports, with nothing under this
    // namespace in the window, is one this namespace cannot be shown to have
    // had — the same 404 as an id that never existed.
    if let Some(ns) = namespace
        && buckets.is_empty()
        && log_buckets.is_empty()
        && state.directory.namespace_of(&id).as_deref() != Some(ns)
    {
        return Err(ApiError::NotFound);
    }

    Ok(Json(DetailResponse {
        generated_at_ms: Utc::now().timestamp_millis(),
        from_ms: window.start_ms(),
        to_ms: window.end_ms(),
        step_secs: step,
        window: label,
        windows: window_labels(),
        retain_days: state.retain_days,
        freshness: freshness(state),
        latest: latest_of(&buckets),
        log_lines: log_buckets.iter().map(|b| b.lines).sum(),
        error_logs: log_buckets.iter().map(|b| b.errors).sum(),
        id,
        buckets,
        log_buckets,
        backends,
    }))
}

async fn logs(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<LogParams>,
) -> Result<Json<LogsResponse>, ApiError> {
    logs_view(&state, id, params, None).await
}

/// `GET /ns/{ns}/api/deployments/{id}/logs`
async fn ns_logs(
    State(state): State<ApiState>,
    Path((ns, id)): Path<(String, String)>,
    Query(params): Query<LogParams>,
) -> Result<Json<LogsResponse>, ApiError> {
    let ns = namespace_param(&ns)?;
    if !visible_in(&state, ns, &id) {
        return Err(ApiError::NotFound);
    }
    let gone = state.directory.namespace_of(&id).is_none();
    let response = logs_view(&state, id, params, Some(ns)).await?;
    // As for the detail view: a deleted deployment with nothing under this
    // namespace is indistinguishable from one that never existed.
    if gone && response.rows.is_empty() && response.next_before_ms.is_none() {
        return Err(ApiError::NotFound);
    }
    Ok(response)
}

async fn logs_view(
    state: &ApiState,
    id: String,
    params: LogParams,
    namespace: Option<&str>,
) -> Result<Json<LogsResponse>, ApiError> {
    let (_, window) = resolve_window(params.window.as_deref());
    let window = resolve_range(window, params.from, params.to);
    let limit = params.limit.unwrap_or(200).clamp(1, MAX_LOG_LIMIT);

    let filter = LogFilter {
        deployment: id.clone(),
        namespace: namespace.map(str::to_string),
        // An empty query string is what a cleared form field sends. Treating it
        // as a filter would match everything or nothing depending on the
        // operator, and either way it isn't what was meant.
        level: non_empty(params.level),
        backend: non_empty(params.backend),
        search: non_empty(params.q),
        limit,
        before_ms: params.before,
    };

    let rows = state.engine.logs(window, &filter).await?;
    // Only offer another page when this one filled up. A short page is the end
    // of the data, and a `next` that returns nothing invites an endless scroll.
    let next_before_ms = (rows.len() >= limit)
        .then(|| rows.last().map(|r| r.ts))
        .flatten();

    Ok(Json(LogsResponse {
        id,
        from_ms: window.start_ms(),
        to_ms: window.end_ms(),
        rows,
        next_before_ms,
        limit,
    }))
}

/// The body of `POST /api/alerts`.
#[derive(Debug, Deserialize)]
struct CreateAlertRequest {
    deployment: String,
    /// Defaults to `errors` when omitted — it is the only metric today, and
    /// requiring a field that has one value would be busywork for the caller.
    #[serde(default)]
    metric: Option<AlertMetric>,
    threshold: f64,
    webhook_url: String,
}

/// `GET /api/alerts` — every rule, in storage order. A snapshot under a read
/// lock rather than a re-read from disk, so the list and the checker always
/// agree about what is configured.
async fn list_alerts(State(state): State<ApiState>) -> Json<Vec<Alert>> {
    Json(state.alerts.read().await.clone())
}

/// `GET /ns/{ns}/api/alerts` — the rules this namespace created, and no others.
/// An operator's rule on one of its deployments is the operator's.
async fn ns_list_alerts(
    State(state): State<ApiState>,
    Path(ns): Path<String>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let ns = namespace_param(&ns)?;
    Ok(Json(
        state
            .alerts
            .read()
            .await
            .iter()
            .filter(|a| a.namespace.as_deref() == Some(ns))
            .cloned()
            .collect(),
    ))
}

/// `POST /ns/{ns}/api/alerts` — a rule on one of this namespace's deployments.
///
/// Stricter than the operator's route in two ways. The deployment must be one
/// app-lb reports in this namespace now: a rule fires on the metric series by
/// id, and that series is not filtered by namespace. And the webhook must be a
/// public `https` address, because the request comes from this host and a
/// tenant must not be able to aim it at the host's own listeners.
async fn ns_create_alert(
    State(state): State<ApiState>,
    Path(ns): Path<String>,
    Json(req): Json<CreateAlertRequest>,
) -> Result<(StatusCode, Json<Alert>), AlertsApiError> {
    let ns = namespace_param(&ns).map_err(|_| AlertsApiError::UnknownDeployment)?;
    if state.directory.namespace_of(&req.deployment).as_deref() != Some(ns) {
        return Err(AlertsApiError::UnknownDeployment);
    }
    if !public_https_url(&req.webhook_url) {
        return Err(AlertsApiError::PrivateWebhook);
    }
    store_alert(&state, req, Some(ns.to_string())).await
}

/// `DELETE /ns/{ns}/api/alerts/{id}` — idempotent like the operator's route,
/// and never reaches a rule this namespace did not create.
async fn ns_delete_alert(
    State(state): State<ApiState>,
    Path((ns, id)): Path<(String, String)>,
) -> Result<StatusCode, AlertsApiError> {
    let ns = namespace_param(&ns).map_err(|_| AlertsApiError::UnknownDeployment)?;
    remove_alert(&state, |a| a.id == id && a.namespace.as_deref() == Some(ns)).await
}

/// `POST /api/alerts` — create a rule.
///
/// The deployment must be one the engine knows about, so a typo cannot leave a
/// rule that can never fire (and that would never be caught, because the
/// checker silently skips unknown deployments). Persisted before the lock is
/// released, so the rule is live the moment the 201 comes back.
async fn create_alert(
    State(state): State<ApiState>,
    Json(req): Json<CreateAlertRequest>,
) -> Result<(StatusCode, Json<Alert>), AlertsApiError> {
    if !state.engine.deployments().contains(&req.deployment) {
        return Err(AlertsApiError::UnknownDeployment);
    }
    // `reqwest` builds any URL; validate the scheme so a stored rule cannot be
    // pointed at an internal listener by someone who only has the API. Both
    // http and https are allowed because the webhook is reached over loopback
    // or a private network as often as the internet.
    if !valid_webhook_url(&req.webhook_url) {
        return Err(AlertsApiError::BadWebhook);
    }
    store_alert(&state, req, None).await
}

async fn store_alert(
    state: &ApiState,
    req: CreateAlertRequest,
    namespace: Option<String>,
) -> Result<(StatusCode, Json<Alert>), AlertsApiError> {
    let alert = Alert {
        id: new_id(),
        deployment: req.deployment,
        metric: req.metric.unwrap_or(AlertMetric::Errors),
        threshold: req.threshold,
        webhook_url: req.webhook_url,
        namespace,
    };

    let path = state.alerts_file.clone();
    {
        let mut alerts = state.alerts.write().await;
        alerts.push(alert.clone());
        crate::alerts::save(std::path::Path::new(&path), &alerts)
            .map_err(AlertsApiError::Persist)?;
    }

    Ok((StatusCode::CREATED, Json(alert)))
}

/// `DELETE /api/alerts/:id` — remove a rule by id. Idempotent: a missing id is
/// 204, because the caller's end state ("that rule is gone") is already true.
async fn delete_alert(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AlertsApiError> {
    remove_alert(&state, |a| a.id == id).await
}

async fn remove_alert(
    state: &ApiState,
    matches: impl Fn(&Alert) -> bool,
) -> Result<StatusCode, AlertsApiError> {
    let path = state.alerts_file.clone();
    let mut alerts = state.alerts.write().await;
    let before = alerts.len();
    alerts.retain(|a| !matches(a));
    if alerts.len() == before {
        // Nothing changed on disk, so no rewrite — and no error either.
        return Ok(StatusCode::NO_CONTENT);
    }
    crate::alerts::save(std::path::Path::new(&path), &alerts).map_err(AlertsApiError::Persist)?;
    Ok(StatusCode::NO_CONTENT)
}

/// A webhook URL must be `http` or `https` with a host. Anything else is a
/// mistake or an attempt to reach a non-HTTP listener.
fn valid_webhook_url(url: &str) -> bool {
    reqwest::Url::parse(url)
        .map(|u| {
            matches!(u.scheme(), "http" | "https")
                && u.host_str().map(|h| !h.is_empty()).unwrap_or(false)
        })
        .unwrap_or(false)
}

/// A webhook a namespace may point the collector at: `https`, and a host that
/// is not loopback, link-local, private or otherwise this side of the
/// internet when written as an address. A name is resolved later by the
/// sender; this stops the obvious aims at the host's own listeners rather
/// than every DNS trick, which is what the `https` requirement is for.
fn public_https_url(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    // `host_str` keeps an IPv6 literal's brackets.
    match host
        .trim_matches(|c| c == '[' || c == ']')
        .parse::<std::net::IpAddr>()
    {
        Ok(std::net::IpAddr::V4(ip)) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                // 100.64.0.0/10, carrier-grade NAT and tailnets.
                || (a == 100 && (b & 0xc0) == 64))
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some())
        }
        Err(_) => {
            let d = host.trim_end_matches('.').to_ascii_lowercase();
            !d.is_empty()
                && d != "localhost"
                && !d.ends_with(".localhost")
                && !d.ends_with(".internal")
        }
    }
}

/// Failures from the alert routes, mapped to status codes a caller can act on.
enum AlertsApiError {
    UnknownDeployment,
    BadWebhook,
    PrivateWebhook,
    Persist(std::io::Error),
}

impl IntoResponse for AlertsApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::UnknownDeployment => (
                StatusCode::BAD_REQUEST,
                "deployment is not known to this collector",
            ),
            Self::BadWebhook => (
                StatusCode::BAD_REQUEST,
                "webhook_url must be an absolute http or https URL with a host",
            ),
            Self::PrivateWebhook => (
                StatusCode::BAD_REQUEST,
                "webhook_url must be an https URL on a public host",
            ),
            Self::Persist(e) => {
                tracing::error!(error = %e, "could not persist alerts file");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not persist the alert",
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn freshness(state: &ApiState) -> Freshness {
    Freshness {
        buffered_rows: state.buffered.load(Ordering::Relaxed),
        flush_secs: state.flush_secs,
        dropped: state.sink.dropped(),
    }
}

fn window_labels() -> Vec<String> {
    WINDOWS.iter().map(|(l, _)| (*l).to_string()).collect()
}

/// Resolve a window label, falling back to a day.
///
/// A preset label takes its listed span; anything else is tried as a relative
/// duration — "1d", "90m", "2 days" — so the picker's closed set bounds the
/// buttons, not the vocabulary. An unrecognised label gets the default rather
/// than a 400: this arrives from a URL someone may have bookmarked or
/// hand-edited, and showing them a day of data is more use than an error about
/// a query parameter.
fn resolve_window(label: Option<&str>) -> (String, Window) {
    let now = Utc::now();
    let (label, seconds) = label
        .and_then(|want| {
            let want = want.trim();
            WINDOWS
                .iter()
                .find(|(l, _)| *l == want)
                .map(|(l, s)| ((*l).to_string(), *s))
                .or_else(|| parse_relative(want).map(|s| (relative_label(s), s)))
        })
        .unwrap_or_else(|| ("24h".to_string(), 86_400));
    (label, Window::trailing(now, seconds))
}

/// The narrowest window a caller can name. One minute: below that the 10s
/// bucket floor leaves too few points to draw, and "the last 20 seconds" is a
/// question for the log view's range, not for a chart.
const MIN_WINDOW_SECS: i64 = 60;

/// The widest. Ninety days — comfortably past the longest retention anyone
/// configures, so the clamp never hides data, only caps how much nothing a
/// typo like "1000d" asks the engine to scan for.
const MAX_WINDOW_SECS: i64 = 90 * 86_400;

/// A relative duration — `<count><unit>`, unit spelled as a letter or a word,
/// with or without a space — as clamped seconds, or `None` for anything else.
fn parse_relative(s: &str) -> Option<i64> {
    let t = s.trim().to_ascii_lowercase();
    let split = t.find(|c: char| !c.is_ascii_digit())?;
    let (count, unit) = t.split_at(split);
    let count: i64 = count.parse().ok()?;
    if count == 0 {
        return None;
    }
    let unit_secs = match unit.trim_start() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "wk" | "wks" | "week" | "weeks" => 604_800,
        _ => return None,
    };
    Some(
        count
            .saturating_mul(unit_secs)
            .clamp(MIN_WINDOW_SECS, MAX_WINDOW_SECS),
    )
}

/// The label echoed back for a free-form window.
///
/// Derived from the *clamped* seconds rather than the caller's spelling, so the
/// page never claims a span ("1000d") that the query did not run.
fn relative_label(seconds: i64) -> String {
    match seconds {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Narrow a window to the range a caller named, in epoch milliseconds.
///
/// Logs are the one view a trailing window is not enough for. An incident is
/// bounded by two instants somebody read off a chart, and "the last six hours"
/// means something different every time the page refreshes — so a range, once
/// given, is fixed, and the same URL shows the same lines tomorrow.
///
/// One end is enough: the window label supplies the span for the other, so
/// "since 09:12" on a 1h window ends at now, and "until 09:12" starts an hour
/// before it.
///
/// Nothing in here is a 400. These arrive from a bookmarked URL or from two
/// pickers that can be dragged past each other, and a reversed pair is a
/// mis-entry rather than a request for no rows.
fn resolve_range(window: Window, from: Option<i64>, to: Option<i64>) -> Window {
    let (from, to) = match (from, to) {
        // Neither: the window picker above the page still scopes the list.
        (None, None) => return window,
        (Some(a), Some(b)) => (a, b),
        (Some(a), None) => (a, window.end_ms()),
        (None, Some(b)) => (b.saturating_sub(window.seconds().saturating_mul(1_000)), b),
    };
    // Ordered after conversion rather than before, so a value no timestamp can
    // hold — which falls back to the window's own edge — cannot leave the range
    // inverted either.
    let (from, to) = (at_ms(from, window.from), at_ms(to, window.to));
    Window {
        from: from.min(to),
        to: from.max(to),
    }
}

/// Epoch milliseconds as a UTC instant, or `fallback` when the value is outside
/// what a timestamp can represent.
fn at_ms(ms: i64, fallback: DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or(fallback)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// The most recent non-null value of each measure in the window.
///
/// Field by field rather than "the last bucket", because the measures do not
/// arrive together: latency is null in any bucket that served no request, and a
/// tile that blanks out because the final bucket happened to be quiet reads as a
/// broken collector. `t` is the last bucket's, so the page can say how old this
/// is.
fn latest_of(buckets: &[MetricBucket]) -> MetricBucket {
    let mut latest = MetricBucket::default();
    for bucket in buckets {
        latest.t = bucket.t;
        for (into, from) in [
            (&mut latest.requests_per_sec, bucket.requests_per_sec),
            (&mut latest.errors_per_sec, bucket.errors_per_sec),
            (&mut latest.mean_latency_ms, bucket.mean_latency_ms),
            (&mut latest.p50_ms, bucket.p50_ms),
            (&mut latest.p90_ms, bucket.p90_ms),
            (&mut latest.p99_ms, bucket.p99_ms),
            (&mut latest.cpu_percent, bucket.cpu_percent),
            (&mut latest.memory_bytes, bucket.memory_bytes),
            (&mut latest.in_flight, bucket.in_flight),
            (&mut latest.ready, bucket.ready),
            (&mut latest.pending, bucket.pending),
            (&mut latest.draining, bucket.draining),
        ] {
            if from.is_some() {
                *into = from;
            }
        }
    }
    latest
}

/// A query failure, as a status the dashboard can act on.
enum ApiError {
    Query(QueryError),
    /// A namespace route asked about something outside its namespace — or
    /// about nothing at all; the two answer alike.
    NotFound,
}

impl From<QueryError> for ApiError {
    fn from(e: QueryError) -> Self {
        Self::Query(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let error = match self {
            Self::Query(e) => e,
            Self::NotFound => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "no such deployment" })),
                )
                    .into_response();
            }
        };
        let status = match &error {
            // Not an error in the deployment, so not a 500: the caller should
            // come back, and app-lb should not conclude anything is wrong.
            QueryError::Busy => StatusCode::SERVICE_UNAVAILABLE,
            QueryError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            QueryError::BadDeployment(_) => StatusCode::BAD_REQUEST,
            QueryError::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if let QueryError::Engine(e) = &error {
            tracing::error!(error = %e, "query failed");
        }
        // The message goes back as well as to the log: this is an operator's
        // tool, and "something went wrong" would just mean two places to look.
        let body = Json(serde_json::json!({ "error": error.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod shell_tests {
    use super::DASHBOARD_HTML;

    /// `str::replace` gives no compile-time proof that every placeholder was
    /// filled — that is the cost of an `include_str!`d page, and this is what
    /// pays it. A survivor is rendered literally into somebody's browser.
    #[test]
    fn every_placeholder_is_filled_and_none_are_invented() {
        for token in ["{{HTML_ATTRS}}", "{{WHO}}", "{{NAMESPACE}}"] {
            assert!(
                DASHBOARD_HTML.contains(token),
                "{token} is gone from the page"
            );
        }
        let rendered = DASHBOARD_HTML
            .replace("{{HTML_ATTRS}}", r#"data-theme="dark""#)
            .replace("{{WHO}}", "ops@example.com")
            .replace("{{NAMESPACE}}", "team-a");
        assert!(!rendered.contains("{{"), "a placeholder survived rendering");
    }

    /// This dashboard is read from private networks; every asset it names is
    /// served by this binary.
    #[test]
    fn the_page_names_no_external_asset() {
        assert!(DASHBOARD_HTML.contains(r#"href="/__ui/heyo.css""#));
        assert!(DASHBOARD_HTML.contains(r#"src="/__ui/theme.js""#));
        for external in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
            assert!(
                !DASHBOARD_HTML.contains(external),
                "external asset: {external}"
            );
        }
    }

    /// The theme is a cookie now, not this origin's localStorage: three
    /// dashboards on three subdomains are three origins, and a per-origin
    /// choice is one a person makes over and over.
    #[test]
    fn the_page_does_not_keep_its_own_theme_state() {
        // The accesses, not the word: the comments that explain why this moved
        // to a cookie say `localStorage` and should keep saying it.
        for access in ["localStorage.getItem", "localStorage.setItem"] {
            assert!(
                !DASHBOARD_HTML.contains(access),
                "{access} — theme state belongs in the shared cookie, which crosses \
                 origins; localStorage stops at this one"
            );
        }
        assert!(DASHBOARD_HTML.contains("data-theme-toggle"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::applb::{
        DeploymentMetrics, DeploymentView, Histogram, HostUsage, PoolStatus, StatusCounts, VmView,
    };

    #[test]
    fn health_reports_the_managed_release_revision() {
        let response = health_response(Some("release-sha".into())).into_response();
        assert_eq!(response.headers()["x-heyo-revision"], "release-sha");
    }

    fn bucket(t: i64, cpu: Option<f64>, latency: Option<f64>) -> MetricBucket {
        MetricBucket {
            t,
            cpu_percent: cpu,
            mean_latency_ms: latency,
            ..Default::default()
        }
    }

    fn backend(name: &str, healthy: bool, draining: bool) -> VmView {
        VmView {
            backend: name.into(),
            in_flight: 0,
            healthy,
            draining,
            uptime_secs: 60,
            cpu_percent: None,
            memory_bytes: None,
        }
    }

    fn static_status(backends: Vec<VmView>) -> LiveStatus {
        LiveStatus {
            schema_version: 1,
            source: "stage-edge".into(),
            observed_at_ms: 1_000,
            app_lb_generated_at_ms: 1_000,
            host: HostUsage {
                available: true,
                cpu_percent: 10.0,
                memory_used_bytes: 1024,
            },
            host_sandboxes: Vec::new(),
            deployments: vec![DeploymentView {
                id: "stage".into(),
                namespace: None,
                kind: Some("static".into()),
                upstreams: vec!["eu1:80".into(), "us1:80".into()],
                routed: Some(true),
                pool: PoolStatus {
                    desired_replicas: Some(0),
                    ready: backends.len() as u32,
                    draining: backends.iter().filter(|backend| backend.draining).count() as u32,
                    pending: 0,
                    min_replicas: Some(0),
                    total_in_flight: 0,
                    cpu_percent: None,
                    memory_bytes: None,
                },
                vms: backends,
                metrics: DeploymentMetrics {
                    requests: StatusCounts {
                        total: 0,
                        errors: 0,
                    },
                    latency_ms: Histogram {
                        count: 0,
                        sum: 0,
                        p50: 0.0,
                        p90: 0.0,
                        p99: 0.0,
                    },
                },
            }],
        }
    }

    #[test]
    fn api_auth_is_optional_but_exact_when_configured() {
        assert!(api_request_authorized(None, None));
        assert!(api_request_authorized(
            Some("status-secret"),
            Some("Bearer status-secret")
        ));
        assert!(!api_request_authorized(Some("status-secret"), None));
        assert!(!api_request_authorized(
            Some("status-secret"),
            Some("Bearer wrong")
        ));
    }

    #[test]
    fn webhook_urls_must_be_http_or_https_with_a_host() {
        // Absolute http and https URLs with a host are accepted; loopback and
        // private hosts are fine, because the webhook is often reached locally.
        assert!(valid_webhook_url("http://127.0.0.1:9090/hook"));
        assert!(valid_webhook_url("https://example.com/hook"));
        // Other schemes, missing hosts, and garbage are refused — a stored rule
        // must not be pointed at a file or an internal non-HTTP listener.
        assert!(!valid_webhook_url("file:///etc/passwd"));
        assert!(!valid_webhook_url("ftp://example.com/hook"));
        assert!(!valid_webhook_url("http://"));
        assert!(!valid_webhook_url("not a url"));
        assert!(!valid_webhook_url(""));
    }

    #[test]
    fn platform_status_distinguishes_partial_and_total_withdrawal() {
        let healthy = static_status(vec![
            backend("eu1:80", true, false),
            backend("us1:80", true, false),
        ]);
        assert_eq!(overall_status(Some(&healthy), false), "healthy");

        let partial = static_status(vec![
            backend("eu1:80", true, false),
            backend("us1:80", true, true),
        ]);
        assert_eq!(overall_status(Some(&partial), false), "degraded");

        let offline = static_status(vec![
            backend("eu1:80", false, false),
            backend("us1:80", true, true),
        ]);
        assert_eq!(overall_status(Some(&offline), false), "unavailable");
        assert_eq!(overall_status(Some(&healthy), true), "unavailable");
        assert_eq!(overall_status(None, false), "unavailable");
    }

    #[test]
    fn platform_status_staleness_tolerates_clock_correction() {
        let status = static_status(vec![backend("eu1:80", true, false)]);
        assert!(observation_is_stale(20_001, Some(&status), 19));
        assert!(!observation_is_stale(20_000, Some(&status), 19));
        assert!(observation_is_stale(20_000, None, 19));

        let future = LiveStatus {
            observed_at_ms: 30_000,
            ..status
        };
        assert!(
            !observation_is_stale(20_000, Some(&future), 19),
            "a wall clock correction must not underflow into a stale snapshot",
        );
    }

    #[test]
    fn platform_status_requires_capacity_or_intentional_scale_to_zero() {
        let no_deployments = LiveStatus {
            deployments: Vec::new(),
            ..static_status(Vec::new())
        };
        assert_eq!(overall_status(Some(&no_deployments), false), "unavailable");

        let empty_pool = static_status(Vec::new());
        assert_eq!(overall_status(Some(&empty_pool), false), "unavailable");

        let managed_pool = LiveStatus {
            deployments: vec![DeploymentView {
                kind: Some("vm".into()),
                ..empty_pool.deployments[0].clone()
            }],
            ..empty_pool
        };
        assert_eq!(
            overall_status(Some(&managed_pool), false),
            "healthy",
            "an intentionally idle scale-to-zero deployment is not an outage",
        );
    }

    #[test]
    fn unrouted_sandboxes_do_not_degrade_routed_capacity() {
        let mut status = static_status(vec![backend("eu1:80", true, false)]);
        status.deployments.push(DeploymentView {
            id: "agent-sandbox".into(),
            namespace: None,
            kind: Some("vm".into()),
            upstreams: Vec::new(),
            routed: Some(false),
            pool: PoolStatus {
                desired_replicas: Some(0),
                ready: 0,
                draining: 0,
                pending: 0,
                min_replicas: Some(0),
                total_in_flight: 0,
                cpu_percent: None,
                memory_bytes: None,
            },
            vms: Vec::new(),
            metrics: DeploymentMetrics {
                requests: StatusCounts {
                    total: 0,
                    errors: 0,
                },
                latency_ms: Histogram {
                    count: 0,
                    sum: 0,
                    p50: 0.0,
                    p90: 0.0,
                    p99: 0.0,
                },
            },
        });

        assert_eq!(overall_status(Some(&status), false), "healthy");
    }

    #[test]
    fn scale_to_zero_and_sites_are_serving_states() {
        let mut idle = static_status(Vec::new());
        idle.deployments[0].kind = Some("vm".into());
        assert_eq!(overall_status(Some(&idle), false), "healthy");

        idle.deployments[0].pool.desired_replicas = Some(1);
        assert_eq!(overall_status(Some(&idle), false), "unavailable");

        let mut site = static_status(Vec::new());
        site.deployments[0].kind = Some("site".into());
        assert_eq!(overall_status(Some(&site), false), "healthy");
    }

    #[test]
    fn an_old_app_lb_is_unknown_instead_of_inventing_routes() {
        let mut status = static_status(Vec::new());
        status.deployments[0].routed = None;
        assert_eq!(overall_status(Some(&status), false), "degraded");
    }

    #[test]
    fn a_quiet_final_bucket_does_not_blank_the_tiles() {
        // Latency is null in any bucket that served no request. Reading the tile
        // off the last bucket alone would blank a perfectly healthy deployment
        // the moment traffic paused.
        let latest = latest_of(&[
            bucket(1000, Some(10.0), Some(8.0)),
            bucket(2000, Some(12.0), None),
        ]);
        assert_eq!(latest.cpu_percent, Some(12.0), "newest sample wins");
        assert_eq!(latest.mean_latency_ms, Some(8.0), "carried forward");
        assert_eq!(latest.t, 2000, "timestamp is the newest bucket's");
    }

    #[test]
    fn nothing_measured_stays_nothing() {
        // An empty window must not invent zeros; the dashboard renders these as
        // dashes.
        let latest = latest_of(&[]);
        assert_eq!(latest.cpu_percent, None);
        assert_eq!(latest.requests_per_sec, None);
        assert_eq!(latest.t, 0);
    }

    #[test]
    fn an_unknown_window_falls_back_instead_of_failing() {
        assert_eq!(resolve_window(Some("6h")).0, "6h");
        assert_eq!(resolve_window(None).0, "24h");
        // A hand-edited or stale URL should still show something.
        assert_eq!(resolve_window(Some("99y")).0, "24h");
        assert_eq!(resolve_window(Some("")).0, "24h");
        assert_eq!(resolve_window(Some("d")).0, "24h");
        assert_eq!(resolve_window(Some("-1d")).0, "24h");
        assert_eq!(resolve_window(Some("0d")).0, "24h");
    }

    #[test]
    fn a_relative_duration_is_a_window_too() {
        // The example that motivated this: "the last day", spelled how people
        // spell it rather than how the preset happens to.
        let (label, window) = resolve_window(Some("1d"));
        assert_eq!(label, "1d");
        assert_eq!(window.seconds(), 86_400);

        // Unit words, spaces and case all mean the same thing.
        for spelling in ["1 day", "24 hours", "24H", " 1440 minutes "] {
            assert_eq!(
                resolve_window(Some(spelling)).1.seconds(),
                86_400,
                "{spelling}"
            );
        }
        assert_eq!(resolve_window(Some("45m")).1.seconds(), 2_700);
        assert_eq!(resolve_window(Some("2w")).1.seconds(), 1_209_600);
        // A preset spelling stays the preset, not a re-derived label.
        assert_eq!(resolve_window(Some("7d")).0, "7d");
    }

    #[test]
    fn a_free_form_window_is_clamped_and_labelled_honestly() {
        // Too narrow to chart, too wide to ever hold data — both clamp, and the
        // label reports the span that actually ran, not the one typed.
        let (label, window) = resolve_window(Some("5s"));
        assert_eq!(window.seconds(), MIN_WINDOW_SECS);
        assert_eq!(label, "1m");

        let (label, window) = resolve_window(Some("1000d"));
        assert_eq!(window.seconds(), MAX_WINDOW_SECS);
        assert_eq!(label, "90d");
    }

    #[test]
    fn free_form_extremes_still_have_a_workable_bucket_width() {
        // The preset test above pins the closed set; the clamp bounds are what
        // guard every window in between.
        for seconds in [MIN_WINDOW_SECS, MAX_WINDOW_SECS] {
            let window = Window::trailing(Utc::now(), seconds);
            for target in [FLEET_POINTS, DETAIL_POINTS] {
                let step = window.step_secs(target);
                let points = seconds / i64::from(step);
                assert!(
                    (2..=600).contains(&points),
                    "{seconds}s at {target} points gives {points} buckets of {step}s",
                );
            }
        }
    }

    #[test]
    fn window_lengths_all_have_a_workable_bucket_width() {
        // Every offered range must produce a plottable number of points at both
        // resolutions — no thousand-point sparkline, no two-point chart.
        for (label, seconds) in WINDOWS {
            let window = Window::trailing(Utc::now(), *seconds);
            for target in [FLEET_POINTS, DETAIL_POINTS] {
                let step = window.step_secs(target);
                let points = seconds / i64::from(step);
                assert!(
                    (2..=600).contains(&points),
                    "{label} at {target} points gives {points} buckets of {step}s",
                );
            }
        }
    }

    #[test]
    fn a_range_pins_the_log_view_and_survives_being_dragged_backwards() {
        let (_, window) = resolve_window(Some("1h"));
        let now = window.end_ms();
        let (earlier, later) = (now - 7_200_000, now - 3_600_000);

        // No bounds at all: the window picker still scopes the list.
        let following = resolve_range(window, None, None);
        assert_eq!(
            (following.start_ms(), following.end_ms()),
            (window.start_ms(), window.end_ms()),
        );

        // Two ends, in either order, are the same range — a picker whose handles
        // have crossed is a mis-entry, not a request for an empty page.
        for (a, b) in [(earlier, later), (later, earlier)] {
            let pinned = resolve_range(window, Some(a), Some(b));
            assert_eq!((pinned.start_ms(), pinned.end_ms()), (earlier, later));
        }

        // One end, and the window label supplies the other.
        let since = resolve_range(window, Some(earlier), None);
        assert_eq!(since.start_ms(), earlier);
        assert_eq!(since.end_ms(), now, "\"since\" runs up to now");

        let until = resolve_range(window, None, Some(later));
        assert_eq!(until.end_ms(), later);
        assert_eq!(
            until.start_ms(),
            later - 3_600_000,
            "an hour back, from the 1h label",
        );
    }

    #[test]
    fn an_instant_no_timestamp_can_hold_falls_back_to_the_window() {
        // A hand-edited URL should show a day of logs, not an error about a
        // query parameter — the same bargain `resolve_window` makes.
        let (_, window) = resolve_window(Some("1h"));
        let absurd = resolve_range(window, Some(i64::MIN), Some(i64::MAX));
        assert_eq!(
            (absurd.start_ms(), absurd.end_ms()),
            (window.start_ms(), window.end_ms()),
        );
    }

    #[test]
    fn a_cleared_form_field_is_not_a_filter() {
        assert_eq!(non_empty(Some("error".into())), Some("error".into()));
        assert_eq!(non_empty(Some("".into())), None);
        assert_eq!(non_empty(Some("   ".into())), None);
        assert_eq!(non_empty(None), None);
    }
}

#[cfg(test)]
mod ns_tests {
    use super::*;
    use crate::namespaces::Gate;
    use crate::store::schema::{LogRecord, MetricRecord, Record};
    use crate::store::writer::Writer;
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    const TOKEN: &str = "svc-token";

    /// A collector over two namespaces' worth of stored rows, served on a
    /// loopback port, with the directory saying where each deployment lives.
    async fn serve(tag: &str) -> (String, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("app-obs-ns-api-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = Utc::now().timestamp_millis();
        let mut writer = Writer::new(&dir, 10_000, Duration::from_secs(3600));
        for (dep, ns) in [("web", "team-a"), ("api", "team-b"), ("_lb", "_")] {
            writer
                .push(Record::Log(LogRecord {
                    ts_millis: now - 1_000,
                    deployment: dep.into(),
                    backend: None,
                    source: "stdout".into(),
                    level: Some("error".into()),
                    message: format!("{dep} says hi"),
                    fields: None,
                    host: None,
                    namespace: Some(ns.into()),
                }))
                .unwrap();
            writer
                .push(Record::Metric(MetricRecord {
                    ts_millis: now - 1_000,
                    deployment: dep.into(),
                    ready: Some(1),
                    namespace: Some(ns.into()),
                    ..Default::default()
                }))
                .unwrap();
        }
        writer.flush_all().unwrap();

        let directory = Arc::new(Directory::new(true));
        directory.set_namespaces(HashMap::from([
            ("web".to_string(), "team-a".to_string()),
            ("api".to_string(), "team-b".to_string()),
            ("quiet".to_string(), "team-a".to_string()),
        ]));
        directory.set_gate(Gate::Installed(HashSet::from(["team-a".to_string()])));
        let engine = Arc::new(Engine::new(&dir, 2, Duration::from_secs(30)).await.unwrap());
        let (sink, _rx) = Sink::new(16);
        let (_live_tx, live) = tokio::sync::watch::channel(None);
        let state = ApiState {
            engine,
            sink,
            api_token: Some(Arc::new(TOKEN.into())),
            buffered: Arc::new(AtomicUsize::new(0)),
            flush_secs: 60,
            retain_days: 30,
            live,
            stale_after_secs: 30,
            ui_cookies: Arc::new(crate::heyo_ui::CookieConfig::default()),
            alerts: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            alerts_file: dir.join("alerts.json").display().to_string(),
            directory,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        (format!("http://{addr}"), dir)
    }

    async fn get(base: &str, path: &str) -> (u16, serde_json::Value) {
        let r = reqwest::Client::new()
            .get(format!("{base}{path}"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(serde_json::Value::Null))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_namespace_route_sees_its_own_deployments_and_nothing_else() {
        let (base, dir) = serve("fleet").await;

        let (code, fleet) = get(&base, "/ns/team-a/api/fleet?window=1h").await;
        assert_eq!(code, 200);
        let ids: Vec<&str> = fleet["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec!["quiet", "web"],
            "a quiet deployment still gets a row"
        );
        assert!(fleet["host"].is_null() && fleet["host_sandboxes"].is_null());

        let (code, logs) = get(&base, "/ns/team-a/api/deployments/web/logs?window=1h").await;
        assert_eq!(code, 200);
        assert_eq!(logs["rows"][0]["message"], "web says hi");

        // Another namespace's deployment, a platform partition and an id that
        // never existed all answer alike.
        for path in [
            "/ns/team-a/api/deployments/api",
            "/ns/team-a/api/deployments/api/logs",
            "/ns/team-a/api/deployments/_lb",
            "/ns/team-a/api/deployments/_lb/logs",
            "/ns/team-a/api/deployments/ghost",
            "/ns/team-a/api/deployments/ghost/logs",
            "/ns/_/api/fleet",
        ] {
            let (code, body) = get(&base, path).await;
            assert_eq!(code, 404, "{path}");
            assert!(!body.to_string().contains("says hi"), "{path}");
        }

        // The operator's routes are unchanged.
        let (code, fleet) = get(&base, "/api/fleet?window=1h").await;
        assert_eq!(code, 200);
        assert_eq!(fleet["deployments"].as_array().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn namespace_alerts_are_private_and_aim_only_outward() {
        let (base, dir) = serve("alerts").await;
        let client = reqwest::Client::new();
        let post = |ns: &str, body: serde_json::Value| {
            client
                .post(format!("{base}/ns/{ns}/api/alerts"))
                .bearer_auth(TOKEN)
                .json(&body)
                .send()
        };

        let r = post(
            "team-a",
            serde_json::json!({"deployment": "web", "threshold": 1, "webhook_url": "https://hooks.example.com/x"}),
        )
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 201);
        let created: serde_json::Value = r.json().await.unwrap();
        assert_eq!(created["namespace"], "team-a");

        for (ns, dep, url) in [
            ("team-a", "api", "https://hooks.example.com/x"), // not team-a's
            ("team-a", "web", "http://hooks.example.com/x"),  // not https
            ("team-a", "web", "https://127.0.0.1:9600/x"),
            ("team-a", "web", "https://10.0.0.1/x"),
            ("team-a", "web", "https://[::1]/x"),
            ("team-a", "web", "https://localhost/x"),
        ] {
            let r = post(
                ns,
                serde_json::json!({"deployment": dep, "threshold": 1, "webhook_url": url}),
            )
            .await
            .unwrap();
            assert_eq!(r.status().as_u16(), 400, "{dep} {url}");
        }

        let (_, mine) = get(&base, "/ns/team-a/api/alerts").await;
        assert_eq!(mine.as_array().unwrap().len(), 1);
        let (_, theirs) = get(&base, "/ns/team-b/api/alerts").await;
        assert!(theirs.as_array().unwrap().is_empty());

        // team-b cannot delete team-a's rule, even by id.
        let id = created["id"].as_str().unwrap();
        let r = client
            .delete(format!("{base}/ns/team-b/api/alerts/{id}"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 204);
        let (_, mine) = get(&base, "/ns/team-a/api/alerts").await;
        assert_eq!(mine.as_array().unwrap().len(), 1, "still there");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_namespace_page_is_served_with_its_namespace_and_needs_the_token() {
        let (base, dir) = serve("page").await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let r = client
            .get(format!("{base}/ns/team-a/"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let html = r.text().await.unwrap();
        assert!(html.contains(r#"<meta name="obs-namespace" content="team-a">"#));

        let r = client
            .get(format!("{base}/ns/team-a"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 308);
        assert_eq!(r.headers()["location"], "/ns/team-a/");

        let r = client
            .get(format!("{base}/ns/team-a/api/fleet"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 401, "the service token still gates it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Absolute `/api/...` paths would break the page behind app-lb's
    /// `/namespaces/<ns>/plugins/obs/` prefix.
    #[test]
    fn the_page_fetches_only_relative_api_paths() {
        for absolute in ["(`/api/", "(\"/api/", "('/api/"] {
            assert!(!DASHBOARD_HTML.contains(absolute), "{absolute}");
        }
        assert!(DASHBOARD_HTML.contains("api(`api/fleet"));
    }
}
