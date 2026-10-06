//! The dashboard and the JSON it runs on.
//!
//! Two endpoints carry the page. `/api/overview` is one scrape of the whole
//! server — every account's streams, their consumers, the connected clients and
//! the throughput history — because the panels describe one moment and fetching
//! them separately would let them disagree on screen. `/api/logs` is separate
//! and incremental: it is the only thing here that grows line by line, and
//! re-sending the buffer every few seconds to a page that already has it would
//! be most of the bytes this app serves.
//!
//! Bound to loopback by default and reached through app-lb, which terminates
//! TLS and puts interactive sign-in in front of it. `QUEUE_API_TOKEN` gates
//! direct access for anything scripted against it; `/healthz` and the shared UI
//! assets stay open either way.

use crate::logs::{LogBuffer, LogFilter, LogLine, LogStatus, normalize_level};
use crate::state::Store;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The dashboard page. Self-contained — no external fetches, no CDN — so it
/// renders on a host with no route to the internet, which is most of them.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Log lines returned when the caller does not ask for a number.
const DEFAULT_LOG_LIMIT: usize = 200;

/// Ceiling on one log response, whatever was asked for. The buffer is bounded
/// too, so this only bounds the serialization.
const MAX_LOG_LIMIT: usize = 5_000;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub logs: Arc<LogBuffer>,
    /// Bearer token for the dashboard and its JSON. `None` preserves the
    /// loopback-only default.
    pub api_token: Option<Arc<String>>,
    /// Where the theme cookie is written and under what name — from
    /// `QUEUE_UI_COOKIE_*`, else the fleet-wide `HEYO_UI_*`. Point it at the
    /// same parent domain as app-lb's `auth.cookie_domain` and one choice of
    /// light or dark covers every app.
    pub ui_cookies: Arc<crate::heyo_ui::CookieConfig>,
}

pub fn router(state: ApiState) -> Router {
    let protected = Router::new()
        // app-lb routes a whole host here, so `/` is what a person types.
        .route("/", get(|| async { Redirect::temporary("/dashboard") }))
        .route("/dashboard", get(dashboard))
        .route("/api/overview", get(overview))
        .route("/api/logs", get(logs))
        .route_layer(middleware::from_fn_with_state(
            state.api_token.clone(),
            require_api_token,
        ));

    Router::new()
        // Always open: app-lb health-checks this, and a probe that failed
        // because the monitoring port was down would take this deployment out
        // of rotation for reporting exactly the thing it exists to report.
        .route("/healthz", get(health))
        // Open alongside `/healthz`, as in app-obs: a page that renders
        // unstyled because its stylesheet needed a token is worse than one
        // whose stylesheet anyone can fetch.
        .route("/__ui/{*path}", get(ui_asset))
        .merge(protected)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    health_response(std::env::var("QUEUE_REVISION").ok())
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
    if !authorized(expected.as_deref().map(String::as_str), presented) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "invalid api token\n",
        )
            .into_response();
    }
    next.run(request).await
}

fn authorized(expected: Option<&str>, presented: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(presented) = presented.and_then(|v| v.strip_prefix("Bearer ")) else {
        return false;
    };
    constant_time_eq(expected.as_bytes(), presented.trim().as_bytes())
}

/// Compare without an early return on the first differing byte.
///
/// The token is a shared secret an attacker can submit repeatedly, which is the
/// shape a timing oracle needs. Length is allowed to leak — it is not the
/// secret, and padding to hide it would be theatre.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The dashboard shell.
///
/// Substituted rather than served verbatim so the theme is on the `<html>` tag
/// in the first response — otherwise every navigation flashes the wrong palette
/// before script can correct it. `{{WHO}}` is the identity app-lb forwarded,
/// empty unless this deployment is gated.
async fn dashboard(State(st): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    Html(render_dashboard(&st, &headers))
}

fn render_dashboard(st: &ApiState, headers: &HeaderMap) -> String {
    let cookies = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
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
                (header::CONTENT_TYPE, a.content_type),
                (header::CACHE_CONTROL, crate::heyo_ui::cache_control(&a)),
            ],
            a.bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

/// `GET /api/overview` — the whole server, as of the last scrape.
async fn overview(State(st): State<ApiState>) -> impl IntoResponse {
    Json(OverviewResponse {
        overview: st.store.overview(),
        logs: st.logs.status(),
    })
}

#[derive(Serialize)]
struct OverviewResponse {
    #[serde(flatten)]
    overview: crate::state::Overview,
    /// Whether the log panel has anything to show, and why not when it does
    /// not. Carried here so the page knows before it asks.
    logs: LogStatus,
}

#[derive(Debug, Deserialize)]
struct LogQuery {
    since: Option<u64>,
    level: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
}

/// `GET /api/logs` — the tail of nats-server's log.
///
/// `?since=<seq>` is the incremental poll the dashboard uses; `?level=` is a
/// severity floor and `?q=` a case-insensitive substring, both applied before
/// the limit so "the last 20 errors" means twenty errors.
async fn logs(State(st): State<ApiState>, Query(q): Query<LogQuery>) -> Response {
    let min_level = match q.level.as_deref().filter(|v| !v.trim().is_empty()) {
        Some(raw) => match normalize_level(raw) {
            Some(level) => Some(level),
            // Rejected rather than ignored: silently dropping an unknown level
            // would answer a filtered request with unfiltered lines, which is
            // the wrong answer rather than a missing one.
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "unknown level {raw:?}; use trace, debug, info, warn, error or fatal\n"
                    ),
                )
                    .into_response();
            }
        },
        None => None,
    };
    let filter = LogFilter {
        since: q.since,
        min_level,
        contains: q.q.filter(|v| !v.is_empty()),
        limit: q.limit.unwrap_or(DEFAULT_LOG_LIMIT).clamp(1, MAX_LOG_LIMIT),
    };
    let status = st.logs.status();
    Json(LogsResponse {
        lines: st.logs.query(&filter),
        status,
    })
    .into_response()
}

#[derive(Serialize)]
struct LogsResponse {
    lines: Vec<LogLine>,
    #[serde(flatten)]
    status: LogStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn health_reports_the_managed_release_revision() {
        let response = health_response(Some("release-sha".into())).into_response();
        assert_eq!(response.headers()["x-heyo-revision"], "release-sha");
    }

    fn state() -> ApiState {
        ApiState {
            store: Arc::new(Store::new(&Config::default())),
            logs: Arc::new(LogBuffer::new(10, None)),
            api_token: None,
            ui_cookies: Arc::new(crate::heyo_ui::CookieConfig::default()),
        }
    }

    #[test]
    fn an_unset_token_leaves_the_dashboard_open() {
        assert!(authorized(None, None));
        assert!(authorized(None, Some("Bearer anything")));
    }

    #[test]
    fn a_set_token_rejects_a_missing_or_wrong_one() {
        assert!(!authorized(Some("s3cret"), None));
        assert!(
            !authorized(Some("s3cret"), Some("s3cret")),
            "needs the scheme"
        );
        assert!(!authorized(Some("s3cret"), Some("Bearer wrong")));
        assert!(authorized(Some("s3cret"), Some("Bearer s3cret")));
    }

    /// The two substitutions have to actually happen: a page served with
    /// `{{HTML_ATTRS}}` still in it loads with no theme and the literal text
    /// visible in the markup.
    #[test]
    fn the_rendered_page_has_no_placeholders_left_in_it() {
        let html = render_dashboard(&state(), &HeaderMap::new());
        assert!(!html.contains("{{"), "an unsubstituted placeholder shipped");
        assert!(html.contains("<html"));
    }

    /// A display name is escaped before it reaches the page. app-lb strips
    /// these headers before setting them, so this is defence for the ungated
    /// case, where they are whatever the caller sent.
    #[test]
    fn a_forwarded_identity_cannot_inject_markup() {
        let mut headers = HeaderMap::new();
        // All three, because `identity_from` reads a half-set identity as
        // anonymous — which would make this test pass without escaping anything.
        headers.insert(crate::heyo_ui::HEADER_USER, "1234567890".parse().unwrap());
        headers.insert(
            crate::heyo_ui::HEADER_EMAIL,
            "operator@example.test".parse().unwrap(),
        );
        headers.insert(
            crate::heyo_ui::HEADER_NAME,
            "<script>alert(1)</script>".parse().unwrap(),
        );
        let html = render_dashboard(&state(), &headers);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    /// Every id the page's script writes into has to exist in the markup. A
    /// typo here is a silent failure: `$()` returns null, the render throws,
    /// the catch swallows it, and the panel simply stops updating.
    #[test]
    fn the_page_has_a_target_for_every_element_its_script_writes() {
        let html = DASHBOARD_HTML;
        for id in [
            "updated",
            "livedot",
            "banner",
            "server-line",
            "tiles",
            "chart-msgs",
            "chart-depth",
            "chart-meta",
            "streams-body",
            "streams-empty",
            "streams-meta",
            "clients-body",
            "clients-empty",
            "clients-meta",
            "log-lines",
            "log-empty",
            "log-meta",
            "log-level",
            "log-search",
            "log-follow",
            "pause",
        ] {
            assert!(
                html.contains(&format!("id=\"{id}\"")),
                "the script writes #{id} but the markup has no such element",
            );
        }
    }

    /// The rule `ui/README.md` states for every app's local stylesheet: it
    /// declares no palette. A hard-coded colour is one the theme toggle cannot
    /// move, so the page would go half-light the moment somebody switched.
    #[test]
    fn the_pages_own_css_declares_no_colours_of_its_own() {
        let style = DASHBOARD_HTML
            .split_once("<style>")
            .and_then(|(_, rest)| rest.split_once("</style>"))
            .map(|(css, _)| css)
            .expect("the page has a style block");
        for banned in ["#", "rgb(", "rgba(", "hsl(", "prefers-color-scheme"] {
            assert!(
                !style.contains(banned),
                "the local stylesheet contains {banned:?}; every colour must be a var(--token) \
                 so it follows the shared theme",
            );
        }
        assert!(
            style.contains("var(--"),
            "and it does use the shared tokens"
        );
    }

    /// The page must never reach off-host for an asset: these dashboards run on
    /// machines with no route to the internet.
    #[test]
    fn the_page_fetches_nothing_from_the_internet() {
        for pattern in ["http://", "https://", "//cdn", "fonts.googleapis"] {
            assert!(
                !DASHBOARD_HTML.contains(pattern),
                "the dashboard references {pattern}, which will not load on an air-gapped host",
            );
        }
    }
}
