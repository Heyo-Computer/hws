//! The obs plugin: a namespace's own view of app-obs.
//!
//! app-obs is one collector per region, run by the operator and reachable
//! with one service token that sees every deployment. This plugin is what
//! turns that into something a tenant can use. The operator enables it with
//! app-obs's URL and a reference to its token; each namespace then *installs*
//! it, which does two things:
//!
//! - app-obs starts collecting that namespace's deployments. It reads the
//!   install list from `GET /api/plugins/obs/installs` on every poll, so an
//!   install takes effect within one tick and an uninstall stops collection
//!   the same way.
//! - The namespace gets `/namespaces/<ns>/plugins/obs/…`: the app-obs
//!   dashboard and its JSON API, narrowed to that namespace. Every request is
//!   rewritten onto app-obs's `/ns/<ns>/…` routes and sent with the service
//!   token; the caller's own credential never leaves app-lb. The namespace
//!   comes from the gate's [`NamespaceScope`], which the admin gate has
//!   already measured against the caller's reach, never from the path the
//!   caller wrote.
//!
//! `…/obs/ui` is the dashboard, served at a path with no trailing slash so
//! the page's relative `api/…` URLs resolve beside it whichever prefix it is
//! served under.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{NamespaceScope, Plugin, PluginMeta};
use crate::secrets::{SecretRef, SecretStore};

/// Log searches scan parquet; app-obs bounds them itself and answers 504 past
/// its own deadline, so this only has to be longer than that.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_POLL_SECS: u64 = 30;
/// Alert definitions are the only bodies sent upstream.
const MAX_BODY: usize = 64 * 1024;

// ---- configuration --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObsConfig {
    /// app-obs's API listener, e.g. `http://127.0.0.1:9600`.
    pub url: String,
    /// app-obs's `APP_OBS_API_TOKEN`, as a reference into the secret store:
    /// `{"secret": "app-obs", "key": "api_token"}`. Omit only when app-obs
    /// runs without one, which leaves its fleet-wide routes open to anyone
    /// who can reach it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<SecretRef>,
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Install into every namespace automatically: each new one when it is
    /// created or first gets a deployment, and every existing one when the
    /// plugin is switched on. A namespace that uninstalls is left alone.
    #[serde(default = "default_auto_install")]
    pub auto_install: bool,
}

fn default_poll_secs() -> u64 {
    DEFAULT_POLL_SECS
}

fn default_auto_install() -> bool {
    true
}

fn parse_config(config: &Value) -> Result<ObsConfig, String> {
    let cfg: ObsConfig = serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
    match url::Url::parse(&cfg.url) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => {}
        _ => return Err(format!("url {:?} must be an http(s) URL", cfg.url)),
    }
    if !(5..=3600).contains(&cfg.poll_secs) {
        return Err("poll_secs must be between 5 and 3600".into());
    }
    if let Some(r) = &cfg.api_token {
        r.validate().map_err(|e| format!("api_token: {e}"))?;
    }
    Ok(cfg)
}

#[derive(Debug, Clone, Default, Serialize)]
struct Health {
    up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    polled_at: u64,
}

// ---- the plugin -----------------------------------------------------------

pub struct ObsPlugin {
    me: std::sync::Weak<ObsPlugin>,
    secrets: Arc<SecretStore>,
    http: reqwest::Client,
    config: RwLock<Option<Arc<ObsConfig>>>,
    health: RwLock<Health>,
    poller: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ObsPlugin {
    pub fn new(secrets: Arc<SecretStore>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            secrets,
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds"),
            config: RwLock::new(None),
            health: RwLock::new(Health::default()),
            poller: Mutex::new(None),
        })
    }

    /// A request to app-obs's `<path_and_query>` with the service token.
    /// Resolved per request, so rotating the secret needs no re-apply.
    fn request(
        &self,
        cfg: &ObsConfig,
        method: reqwest::Method,
        path_and_query: &str,
    ) -> Result<reqwest::RequestBuilder, String> {
        let url = format!("{}{path_and_query}", cfg.url.trim_end_matches('/'));
        let mut req = self.http.request(method, url);
        if let Some(r) = &cfg.api_token {
            let token = self
                .secrets
                .resolve(r)
                .map_err(|e| format!("cannot resolve app-obs's api_token: {e}"))?;
            req = req.bearer_auth(token);
        }
        Ok(req)
    }

    async fn poll(&self, cfg: &ObsConfig) {
        let polled_at = crate::deployment::now_secs();
        let result = async {
            let resp = self
                .request(cfg, reqwest::Method::GET, "/healthz")?
                .timeout(POLL_TIMEOUT)
                .send()
                .await
                .map_err(|e| format!("/healthz: {e}"))?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("/healthz: HTTP {}", resp.status()))
            }
        }
        .await;
        *self.health.write().unwrap() = Health {
            up: result.is_ok(),
            error: result.err(),
            polled_at,
        };
    }

    fn stop_poller(&self) {
        if let Some(h) = self.poller.lock().unwrap().take() {
            h.abort();
        }
    }
}

#[async_trait]
impl Plugin for ObsPlugin {
    fn meta(&self) -> PluginMeta {
        PluginMeta {
            id: "obs",
            name: "Observability",
            description: "Logs, metrics and alerts for every app in a namespace, from app-obs. \
                 The operator points it at app-obs; each namespace installs it to start \
                 collection and to read its own telemetry with a namespace token.",
            config_schema: json!({
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string", "description": "app-obs's API listener, e.g. http://127.0.0.1:9600"},
                    "api_token": {
                        "type": "object",
                        "description": "A secret reference to APP_OBS_API_TOKEN: {\"secret\": \"app-obs\", \"key\": \"api_token\"}.",
                        "required": ["secret"],
                        "properties": {"secret": {"type": "string"}, "key": {"type": "string"}}
                    },
                    "poll_secs": {"type": "integer", "minimum": 5, "maximum": 3600, "default": DEFAULT_POLL_SECS},
                    "auto_install": {"type": "boolean", "default": true, "description": "Install into every namespace automatically (new ones as they appear, existing ones when switched on); a namespace that uninstalls is left alone."}
                }
            }),
        }
    }

    fn validate(&self, config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    async fn apply(&self, config: Option<Value>) -> Result<(), String> {
        self.stop_poller();
        let Some(config) = config else {
            *self.config.write().unwrap() = None;
            *self.health.write().unwrap() = Health::default();
            return Ok(());
        };
        let cfg = Arc::new(parse_config(&config)?);
        *self.config.write().unwrap() = Some(cfg.clone());
        self.poll(&cfg).await;
        let me = self.me.clone();
        let every = Duration::from_secs(cfg.poll_secs);
        let poll_cfg = cfg.clone();
        *self.poller.lock().unwrap() = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(me) = me.upgrade() else { return };
                me.poll(&poll_cfg).await;
            }
        }));
        match self.health.read().unwrap().error.clone() {
            None => Ok(()),
            Some(e) => Err(format!("app-obs at {}: {e}", cfg.url)),
        }
    }

    async fn status(&self) -> Value {
        let Some(cfg) = self.config.read().unwrap().clone() else {
            return json!({});
        };
        let health = self.health.read().unwrap().clone();
        json!({
            "url": cfg.url,
            "authenticated": cfg.api_token.is_some(),
            "up": health.up,
            "error": health.error,
            "polled_at": health.polled_at,
        })
    }

    fn per_namespace(&self) -> bool {
        true
    }

    fn auto_install(&self, config: &Value) -> bool {
        parse_config(config).is_ok_and(|c| c.auto_install)
    }

    fn validate_install(&self, _namespace: &str, config: &Value) -> Result<(), String> {
        match config {
            Value::Null => Ok(()),
            Value::Object(m) if m.is_empty() => Ok(()),
            _ => Err("the obs plugin takes no per-namespace configuration yet; send {}".into()),
        }
    }

    fn namespace_routes(self: Arc<Self>) -> Router {
        Router::new().fallback(proxy).with_state(self)
    }
}

// ---- the namespace surface ------------------------------------------------

fn fail(code: StatusCode, error: impl Into<String>) -> Response {
    (code, axum::Json(json!({ "error": error.into() }))).into_response()
}

/// Whether a path segment is, or percent-decodes to, `.` or `..`. Either
/// would be resolved away by the URL parser on the way upstream and could
/// climb out of `/ns/<ns>` onto app-obs's fleet-wide routes.
fn is_dot_segment(segment: &str) -> bool {
    let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

/// Where a namespace-surface path goes on app-obs, or `None` if it is not one
/// this plugin forwards.
fn upstream_path(ns: &str, rest: &str) -> Option<String> {
    if rest.contains('\\') || rest.split('/').any(is_dot_segment) {
        return None;
    }
    if rest == "/ui" {
        return Some(format!("/ns/{ns}/"));
    }
    if rest.starts_with("/api/") {
        return Some(format!("/ns/{ns}{rest}"));
    }
    None
}

async fn proxy(
    axum::extract::State(p): axum::extract::State<Arc<ObsPlugin>>,
    req: Request,
) -> Response {
    let Some(NamespaceScope(ns)) = req.extensions().get::<NamespaceScope>().cloned() else {
        return fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no namespace scope on the request",
        );
    };
    let rest = req.uri().path().to_string();

    let Some(mut target) = upstream_path(&ns, &rest) else {
        return fail(StatusCode::NOT_FOUND, format!("no obs route at {rest}"));
    };
    if let Some(q) = req.uri().query() {
        target.push('?');
        target.push_str(q);
    }

    let Some(cfg) = p.config.read().unwrap().clone() else {
        return fail(StatusCode::CONFLICT, "the obs plugin is not configured");
    };
    let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
        Ok(m) => m,
        Err(e) => return fail(StatusCode::METHOD_NOT_ALLOWED, e.to_string()),
    };
    let content_type = req.headers().get(header::CONTENT_TYPE).cloned();
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"),
    };
    let mut upstream = match p.request(&cfg, method, &target) {
        Ok(r) => r,
        Err(e) => return fail(StatusCode::BAD_GATEWAY, e),
    };
    if !body.is_empty() {
        if let Some(ct) = content_type.as_ref().and_then(|v| v.to_str().ok()) {
            upstream = upstream.header(reqwest::header::CONTENT_TYPE, ct);
        }
        upstream = upstream.body(body);
    }
    let resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            return fail(
                StatusCode::BAD_GATEWAY,
                format!("app-obs is unreachable: {e}"),
            );
        }
    };
    let status = resp.status().as_u16();
    // A 401 from app-obs means app-lb's stored token is wrong, not the
    // caller's credential; passing it through would read as their session
    // failing.
    if status == 401 {
        return fail(
            StatusCode::BAD_GATEWAY,
            "app-obs rejected the api_token configured for the obs plugin",
        );
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return fail(
                StatusCode::BAD_GATEWAY,
                format!("reading app-obs's response: {e}"),
            );
        }
    };
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::{PluginHost, PluginStore};

    fn secrets_with(token: &str) -> Arc<SecretStore> {
        let dir =
            std::env::temp_dir().join(format!("app-lb-obs-{}-{}", std::process::id(), token.len()));
        let store = Arc::new(SecretStore::new(dir.join("secrets.json"), None));
        store.put(crate::secrets::SecretSpec {
            id: "app-obs".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("api_token".to_string(), token.to_string())].into(),
            updated_at: 0,
        });
        store
    }

    /// An app-obs-shaped server: `/healthz` open, everything else behind the
    /// bearer, echoing the path and query it was asked for.
    async fn fake_obs(token: &str) -> String {
        let expected = format!("Bearer {token}");
        let app = Router::new().fallback(move |req: Request| {
            let expected = expected.clone();
            async move {
                if req.uri().path() == "/healthz" {
                    return "ok".into_response();
                }
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if auth != expected {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let method = req.method().to_string();
                let path = req.uri().path().to_string();
                let query = req.uri().query().unwrap_or("").to_string();
                let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                    .await
                    .unwrap();
                axum::Json(json!({"method": method, "path": path, "query": query,
                    "body": String::from_utf8_lossy(&body)}))
                .into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("app-lb-obs-host-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn dispatch(
        host: &PluginHost,
        ns: &str,
        method: &str,
        uri: &str,
        body: &str,
    ) -> (StatusCode, Value) {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = host.dispatch_namespace("obs", ns, req).await;
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn configured(url: &str) -> Value {
        json!({"url": url, "api_token": {"secret": "app-obs", "key": "api_token"}})
    }

    #[test]
    fn a_config_is_checked_before_it_is_stored() {
        assert!(parse_config(&configured("http://127.0.0.1:9600")).is_ok());
        for bad in [
            json!({}),
            json!({"url": "ftp://x"}),
            json!({"url": "http://x", "poll_secs": 1}),
            json!({"url": "http://x", "token": "inline"}),
        ] {
            assert!(parse_config(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn paths_cannot_climb_out_of_the_namespace() {
        assert_eq!(
            upstream_path("a", "/api/fleet").as_deref(),
            Some("/ns/a/api/fleet")
        );
        assert_eq!(upstream_path("a", "/ui").as_deref(), Some("/ns/a/"));
        for bad in [
            "/api/../../api/fleet",
            "/api/%2e%2e/%2E%2E/api/fleet",
            "/api/.%2e/x",
            "/api/./x",
            "/api\\..\\x",
            "/stats",
            "/healthz",
        ] {
            assert_eq!(upstream_path("a", bad), None, "forwarded {bad}");
        }
    }

    #[tokio::test]
    async fn a_namespace_reads_through_the_service_token_only_once_installed() {
        let url = fake_obs("obs-svc-1").await;
        let dir = TempDir::new("flow");
        let plugin = ObsPlugin::new(secrets_with("obs-svc-1"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));

        // Disabled on the fleet: neither installable nor readable.
        let e = host
            .install("obs", "team-a", json!({}), None)
            .await
            .unwrap_err();
        assert!(matches!(e, crate::plugins::SetError::Disabled(_)));
        let (code, body) = dispatch(&host, "team-a", "GET", "/api/fleet", "").await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(body["code"], "plugin_disabled");

        host.set("obs", true, Some(configured(&url))).await.unwrap();
        let (code, body) = dispatch(&host, "team-a", "GET", "/api/fleet", "").await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(body["code"], "plugin_not_installed");

        let view = host
            .install("obs", "team-a", json!({}), Some("token:abc".into()))
            .await
            .unwrap();
        assert!(view.installed);
        assert_eq!(view.installed_by.as_deref(), Some("token:abc"));
        assert!(
            host.install("obs", "team-a", json!({"x": 1}), None)
                .await
                .is_err()
        );

        let (code, body) = dispatch(
            &host,
            "team-a",
            "GET",
            "/api/deployments/web/logs?level=error",
            "",
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["path"], "/ns/team-a/api/deployments/web/logs");
        assert_eq!(body["query"], "level=error");

        let (code, body) = dispatch(
            &host,
            "team-a",
            "POST",
            "/api/alerts",
            r#"{"deployment":"web"}"#,
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["method"], "POST");
        assert_eq!(body["path"], "/ns/team-a/api/alerts");
        assert_eq!(body["body"], r#"{"deployment":"web"}"#);

        // Another namespace has not installed it.
        let (code, _) = dispatch(&host, "team-b", "GET", "/api/fleet", "").await;
        assert_eq!(code, StatusCode::CONFLICT);

        let installs = host.installs("obs").unwrap();
        assert!(installs.enabled);
        assert_eq!(installs.namespaces, vec!["team-a".to_string()]);

        // Disabling pauses installs without forgetting them.
        host.set("obs", false, None).await.unwrap();
        assert_eq!(
            host.installs("obs").unwrap().namespaces,
            vec!["team-a".to_string()]
        );
        host.set("obs", true, None).await.unwrap();

        host.uninstall("obs", "team-a").await.unwrap();
        let (code, _) = dispatch(&host, "team-a", "GET", "/api/fleet", "").await;
        assert_eq!(code, StatusCode::CONFLICT);
        plugin.apply(None).await.unwrap();
    }

    /// With `auto_install` (the default), every namespace gets the plugin
    /// unless it declined it; an explicit install undoes the opt-out.
    #[tokio::test]
    async fn auto_install_reaches_every_namespace_except_one_that_declined() {
        let url = fake_obs("obs-auto").await;
        let dir = TempDir::new("auto");
        let plugin = ObsPlugin::new(secrets_with("obs-auto"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));

        // Disabled: nothing is installed automatically.
        assert!(host.auto_install("team-a", None).await.is_empty());

        host.set("obs", true, Some(configured(&url))).await.unwrap();
        assert_eq!(host.auto_install("team-a", Some("auto".into())).await, vec!["obs"]);
        assert!(host.is_installed("obs", "team-a"));
        assert!(host.auto_install("team-a", None).await.is_empty(), "idempotent");

        host.uninstall("obs", "team-a").await.unwrap();
        assert!(host.auto_install("team-a", None).await.is_empty(), "an opt-out sticks");
        assert!(!host.is_installed("obs", "team-a"));
        // Disabling and re-enabling keeps the opt-out too.
        host.set("obs", false, None).await.unwrap();
        host.set("obs", true, None).await.unwrap();
        assert!(host.auto_install("team-a", None).await.is_empty());
        host.install("obs", "team-a", json!({}), None).await.unwrap();
        host.uninstall("obs", "team-a").await.unwrap();
        host.install("obs", "team-a", json!({}), None).await.unwrap();
        assert!(host.store().get("obs").unwrap().declined.is_empty(), "installing clears it");

        // Opted out at the fleet level.
        let mut off = configured(&url);
        off["auto_install"] = json!(false);
        host.set("obs", true, Some(off)).await.unwrap();
        assert!(host.auto_install("team-b", None).await.is_empty());
        plugin.apply(None).await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_stored_token_is_a_bad_gateway_not_the_callers_401() {
        let url = fake_obs("obs-right").await;
        let dir = TempDir::new("wrong");
        let plugin = ObsPlugin::new(secrets_with("obs-wrong-token"));
        let host = PluginHost::new(vec![plugin.clone()], PluginStore::new(&dir.0));
        host.set("obs", true, Some(configured(&url))).await.unwrap();
        host.install("obs", "a", json!({}), None).await.unwrap();
        let (code, _) = dispatch(&host, "a", "GET", "/api/fleet", "").await;
        assert_eq!(code, StatusCode::BAD_GATEWAY);
        plugin.apply(None).await.unwrap();
    }
}
