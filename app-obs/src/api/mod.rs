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

use crate::alerts::{Alert, AlertMetric, new_id};
use crate::ingest::{Sink, token_matches};
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
    Html(render_dashboard(&st, &headers))
}

fn render_dashboard(st: &ApiState, headers: &HeaderMap) -> String {
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
    DASHBOARD_HTML
        .replace("{{HTML_ATTRS}}", &st.ui_cookies.attrs(cookies))
        .replace("{{WHO}}", &who)
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
    let (label, window) = resolve_window(params.window.as_deref());
    let step = window.step_secs(FLEET_POINTS);

    // One scan for the whole fleet rather than one per row: `deployment` is a
    // partition column, so the engine still only opens the directories the
    // window touches.
    let metrics = state.engine.metrics(window, step, None).await?;
    let volume = state.engine.log_volume(window, step, None).await?;

    let mut deployments = Vec::new();
    for id in state.engine.deployments() {
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
        freshness: freshness(&state),
        // An empty vec and `None` mean different things: the first is "host
        // samples exist, none in this window", the second is "the daemon has
        // never reported host usage at all".
        host: metrics
            .get(HOST_DEPLOYMENT)
            .cloned()
            .or_else(|| state.engine.has_host_data().then(Vec::new)),
        deployments,
        host_sandboxes: state
            .live
            .borrow()
            .as_ref()
            .map(|live| live.host_sandboxes.clone()),
    }))
}

async fn detail(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<WindowParams>,
) -> Result<Json<DetailResponse>, ApiError> {
    let (label, window) = resolve_window(params.window.as_deref());
    let step = window.step_secs(DETAIL_POINTS);

    let metrics = state.engine.metrics(window, step, Some(&id)).await?;
    let volume = state.engine.log_volume(window, step, Some(&id)).await?;
    let backends = state.engine.backends(window, &id).await?;

    let buckets = metrics.get(&id).cloned().unwrap_or_default();
    let log_buckets = volume.get(&id).cloned().unwrap_or_default();

    Ok(Json(DetailResponse {
        generated_at_ms: Utc::now().timestamp_millis(),
        from_ms: window.start_ms(),
        to_ms: window.end_ms(),
        step_secs: step,
        window: label,
        windows: window_labels(),
        retain_days: state.retain_days,
        freshness: freshness(&state),
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
    let (_, window) = resolve_window(params.window.as_deref());
    let window = resolve_range(window, params.from, params.to);
    let limit = params.limit.unwrap_or(200).clamp(1, MAX_LOG_LIMIT);

    let filter = LogFilter {
        deployment: id.clone(),
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

    let alert = Alert {
        id: new_id(),
        deployment: req.deployment,
        metric: req.metric.unwrap_or(AlertMetric::Errors),
        threshold: req.threshold,
        webhook_url: req.webhook_url,
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
    let path = state.alerts_file.clone();
    let mut alerts = state.alerts.write().await;
    let before = alerts.len();
    alerts.retain(|a| a.id != id);
    if alerts.len() == before {
        // Nothing changed on disk, so no rewrite — and no error either.
        return Ok(StatusCode::NO_CONTENT);
    }
    crate::alerts::save(std::path::Path::new(&path), &alerts)
        .map_err(AlertsApiError::Persist)?;
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

/// Failures from the alert routes, mapped to status codes a caller can act on.
enum AlertsApiError {
    UnknownDeployment,
    BadWebhook,
    Persist(std::io::Error),
}

impl IntoResponse for AlertsApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::UnknownDeployment => {
                (StatusCode::BAD_REQUEST, "deployment is not known to this collector")
            }
            Self::BadWebhook => (
                StatusCode::BAD_REQUEST,
                "webhook_url must be an absolute http or https URL with a host",
            ),
            Self::Persist(e) => {
                tracing::error!(error = %e, "could not persist alerts file");
                (StatusCode::INTERNAL_SERVER_ERROR, "could not persist the alert")
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
struct ApiError(QueryError);

impl From<QueryError> for ApiError {
    fn from(e: QueryError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self.0 {
            // Not an error in the deployment, so not a 500: the caller should
            // come back, and app-lb should not conclude anything is wrong.
            QueryError::Busy => StatusCode::SERVICE_UNAVAILABLE,
            QueryError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            QueryError::BadDeployment(_) => StatusCode::BAD_REQUEST,
            QueryError::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if let QueryError::Engine(e) = &self.0 {
            tracing::error!(error = %e, "query failed");
        }
        // The message goes back as well as to the log: this is an operator's
        // tool, and "something went wrong" would just mean two places to look.
        let body = Json(serde_json::json!({ "error": self.0.to_string() }));
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
        for token in ["{{HTML_ATTRS}}", "{{WHO}}"] {
            assert!(DASHBOARD_HTML.contains(token), "{token} is gone from the page");
        }
        let rendered = DASHBOARD_HTML
            .replace("{{HTML_ATTRS}}", r#"data-theme="dark""#)
            .replace("{{WHO}}", "ops@example.com");
        assert!(!rendered.contains("{{"), "a placeholder survived rendering");
    }

    /// This dashboard is read from private networks; every asset it names is
    /// served by this binary.
    #[test]
    fn the_page_names_no_external_asset() {
        assert!(DASHBOARD_HTML.contains(r#"href="/__ui/heyo.css""#));
        assert!(DASHBOARD_HTML.contains(r#"src="/__ui/theme.js""#));
        for external in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
            assert!(!DASHBOARD_HTML.contains(external), "external asset: {external}");
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
            assert_eq!(resolve_window(Some(spelling)).1.seconds(), 86_400, "{spelling}");
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
