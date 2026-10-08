//! The namespace proxy: how a plugin backed by a fleet service gives each
//! namespace its own slice of that service.
//!
//! app-obs and ci are each one process per region, reachable with one service
//! token that sees everything. Both expose a namespace-scoped surface at
//! `/ns/<ns>/…` and trust the token to have been checked by someone who knows
//! which namespace the caller may reach. That someone is app-lb: a request to
//! `/namespaces/<ns>/plugins/<id>/…` has already passed the namespace wall, and
//! this module rewrites it onto `/ns/<ns>/…`, attaches the service token, and
//! sends it on. The caller's own credential never leaves app-lb.
//!
//! The upstream's pages are served on app-lb's admin origin, inside the
//! plugin-console frame, so every response is sent with headers that keep it
//! there: it may only be framed by app-lb, may only fetch from and post to
//! app-lb, and a redirect is followed only when it stays inside the plugin's
//! own prefix.

use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

use super::NamespaceScope;
use crate::secrets::{SecretRef, SecretStore};

/// app-obs's log searches scan parquet and bound themselves; this only has to
/// be longer than either service's own deadline. An event stream is exempt:
/// it is meant to stay open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
/// Alert definitions and form posts are the only bodies sent upstream.
const MAX_BODY: usize = 64 * 1024;

/// Sent on every proxied response. Inline scripts stay allowed because both
/// upstream pages are single files with their script inline; what is closed is
/// where the page can be framed from, talk to and post to.
const CONTENT_SECURITY_POLICY: &str = "frame-ancestors 'self'; connect-src 'self'; \
     form-action 'self'; base-uri 'none'; object-src 'none'";

/// The caller behind a namespace-surface request, as the admin gate saw it.
/// Forwarded to an upstream that records who did what; never trusted by app-lb
/// itself, which has already decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceActor {
    /// `token:<id>` or `user:<id>`, the form tokens record their minter in.
    /// `None` for the operator.
    pub principal: Option<String>,
    pub email: Option<String>,
    /// Whether the caller administers all of the namespace.
    pub admin: bool,
}

/// Where the fleet service is and how to authenticate to it.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub url: String,
    pub api_token: Option<SecretRef>,
}

/// Check a configured upstream URL.
pub fn check_url(url: &str) -> Result<(), String> {
    match url::Url::parse(url) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host().is_some() => Ok(()),
        _ => Err(format!("url {url:?} must be an http(s) URL")),
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Health {
    pub up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub polled_at: u64,
}

/// One plugin's proxy onto its fleet service, plus the health poll that
/// tells the operator whether that service is answering.
pub struct NsProxy {
    me: Weak<NsProxy>,
    /// The service's name in errors: `app-obs`, `ci`.
    label: &'static str,
    plugin_id: &'static str,
    secrets: Arc<SecretStore>,
    http: reqwest::Client,
    /// Also forward `/ui/<page>`, for an upstream with more than one page.
    ui_subpaths: bool,
    /// Send the caller's identity upstream, for one that records it.
    forward_actor: bool,
    /// Where the upstream serves a namespace: `/ns` puts it at `/ns/<ns>/…`.
    ns_prefix: &'static str,
    upstream: RwLock<Option<Arc<Upstream>>>,
    health: RwLock<Health>,
    poller: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl NsProxy {
    pub fn new(
        label: &'static str,
        plugin_id: &'static str,
        secrets: Arc<SecretStore>,
        ui_subpaths: bool,
        forward_actor: bool,
    ) -> Arc<Self> {
        Self::new_at(label, plugin_id, "/ns", secrets, ui_subpaths, forward_actor)
    }

    /// [`NsProxy::new`] for an upstream that serves a namespace somewhere
    /// other than `/ns/<ns>/…`, because its own root already belongs to
    /// namespaces (remote's `/-/ns/<ns>/…`).
    pub fn new_at(
        label: &'static str,
        plugin_id: &'static str,
        ns_prefix: &'static str,
        secrets: Arc<SecretStore>,
        ui_subpaths: bool,
        forward_actor: bool,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            label,
            plugin_id,
            secrets,
            // No total timeout on the client: an event stream outlives any
            // fixed one. Everything else is bounded per request below.
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builds"),
            ui_subpaths,
            forward_actor,
            ns_prefix,
            upstream: RwLock::new(None),
            health: RwLock::new(Health::default()),
            poller: Mutex::new(None),
        })
    }

    pub fn upstream(&self) -> Option<Arc<Upstream>> {
        self.upstream.read().unwrap().clone()
    }

    pub fn health(&self) -> Health {
        self.health.read().unwrap().clone()
    }

    /// Point the proxy at `upstream` and poll it every `every`, or (with
    /// `None`) stop. Returns the first poll's error, for the plugin's
    /// `last_error`.
    pub async fn configure(
        &self,
        upstream: Option<Upstream>,
        every: Duration,
    ) -> Result<(), String> {
        if let Some(h) = self.poller.lock().unwrap().take() {
            h.abort();
        }
        let Some(upstream) = upstream else {
            *self.upstream.write().unwrap() = None;
            *self.health.write().unwrap() = Health::default();
            return Ok(());
        };
        let upstream = Arc::new(upstream);
        *self.upstream.write().unwrap() = Some(upstream.clone());
        self.poll(&upstream).await;
        let me = self.me.clone();
        let poll_up = upstream.clone();
        *self.poller.lock().unwrap() = Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(me) = me.upgrade() else { return };
                me.poll(&poll_up).await;
            }
        }));
        match self.health.read().unwrap().error.clone() {
            None => Ok(()),
            Some(e) => Err(format!("{} at {}: {e}", self.label, upstream.url)),
        }
    }

    /// A request to the upstream's `<path_and_query>` with the service token.
    /// Resolved per request, so rotating the secret needs no re-apply.
    fn request(
        &self,
        up: &Upstream,
        method: reqwest::Method,
        path_and_query: &str,
    ) -> Result<reqwest::RequestBuilder, String> {
        let url = format!("{}{path_and_query}", up.url.trim_end_matches('/'));
        let mut req = self.http.request(method, url);
        if let Some(r) = &up.api_token {
            let token = self
                .secrets
                .resolve(r)
                .map_err(|e| format!("cannot resolve {}'s api_token: {e}", self.label))?;
            req = req.bearer_auth(token);
        }
        Ok(req)
    }

    async fn poll(&self, up: &Upstream) {
        let polled_at = crate::deployment::now_secs();
        let result = async {
            let resp = self
                .request(up, reqwest::Method::GET, "/healthz")?
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

    /// Serve one request on the plugin's namespace surface.
    pub async fn forward(&self, req: Request) -> Response {
        let Some(NamespaceScope(ns)) = req.extensions().get::<NamespaceScope>().cloned() else {
            return fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no namespace scope on the request",
            );
        };
        let actor = req.extensions().get::<NamespaceActor>().cloned();
        let base = format!("/namespaces/{ns}/plugins/{}", self.plugin_id);
        let rest = req.uri().path().to_string();

        let Some(mut target) = upstream_path_at(self.ns_prefix, &ns, &rest, self.ui_subpaths)
        else {
            return fail(
                StatusCode::NOT_FOUND,
                format!("no {} route at {rest}", self.plugin_id),
            );
        };
        if let Some(q) = req.uri().query() {
            target.push('?');
            target.push_str(q);
        }

        let Some(up) = self.upstream() else {
            return fail(
                StatusCode::CONFLICT,
                format!("the {} plugin is not configured", self.plugin_id),
            );
        };
        let method = match reqwest::Method::from_bytes(req.method().as_str().as_bytes()) {
            Ok(m) => m,
            Err(e) => return fail(StatusCode::METHOD_NOT_ALLOWED, e.to_string()),
        };
        // Built from scratch rather than copied: nothing the caller sent
        // reaches the upstream except these, so a caller cannot speak for
        // app-lb with an `x-heyo-*` header of its own.
        let content_type = req.headers().get(header::CONTENT_TYPE).cloned();
        let accept = req.headers().get(header::ACCEPT).cloned();
        let body = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
            Ok(b) => b,
            Err(_) => return fail(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"),
        };
        let mut upstream = match self.request(&up, method, &target) {
            Ok(r) => r,
            Err(e) => return fail(StatusCode::BAD_GATEWAY, e),
        };
        upstream = upstream.header("x-heyo-base", &base);
        if let Some(a) = accept.as_ref().and_then(|v| v.to_str().ok()) {
            upstream = upstream.header(reqwest::header::ACCEPT, a);
        }
        if self.forward_actor {
            let actor = actor.unwrap_or_default();
            if let Some(p) = &actor.principal {
                upstream = upstream.header("x-heyo-actor", p);
            }
            if let Some(e) = &actor.email {
                upstream = upstream.header("x-heyo-actor-email", e);
            }
            upstream = upstream.header(
                "x-heyo-actor-admin",
                if actor.admin { "true" } else { "false" },
            );
        }
        if !body.is_empty() {
            if let Some(ct) = content_type.as_ref().and_then(|v| v.to_str().ok()) {
                upstream = upstream.header(reqwest::header::CONTENT_TYPE, ct);
            }
            upstream = upstream.body(body);
        }
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let resp = match tokio::time::timeout_at(deadline, upstream.send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                return fail(
                    StatusCode::BAD_GATEWAY,
                    format!("{} is unreachable: {e}", self.label),
                );
            }
            Err(_) => {
                return fail(
                    StatusCode::GATEWAY_TIMEOUT,
                    format!("{} did not answer in time", self.label),
                );
            }
        };
        let status = resp.status().as_u16();
        // A 401 from upstream means app-lb's stored token is wrong, not the
        // caller's credential; passing it through would read as their session
        // failing.
        if status == 401 {
            return fail(
                StatusCode::BAD_GATEWAY,
                format!(
                    "{} rejected the api_token configured for the {} plugin",
                    self.label, self.plugin_id
                ),
            );
        }
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .filter(|l| stays_under(l, &base))
            .and_then(|l| HeaderValue::from_str(l).ok());

        let body = if content_type.starts_with("text/event-stream") {
            Body::from_stream(resp.bytes_stream())
        } else {
            match tokio::time::timeout_at(deadline, resp.bytes()).await {
                Ok(Ok(b)) => Body::from(b),
                Ok(Err(e)) => {
                    return fail(
                        StatusCode::BAD_GATEWAY,
                        format!("reading {}'s response: {e}", self.label),
                    );
                }
                Err(_) => {
                    return fail(
                        StatusCode::GATEWAY_TIMEOUT,
                        format!("{} did not finish its response in time", self.label),
                    );
                }
            }
        };
        let mut out = Response::new(body);
        *out.status_mut() = status;
        let h = out.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&content_type) {
            h.insert(header::CONTENT_TYPE, v);
        }
        if let Some(l) = location {
            h.insert(header::LOCATION, l);
        }
        harden(h);
        out
    }
}

/// The headers every proxied response carries. See the module docs.
fn harden(h: &mut axum::http::HeaderMap) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    // An event stream must not sit in a buffer in front of the admin listener.
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
}

/// Whether an upstream redirect stays inside the plugin's own prefix. Anything
/// else — another plugin, the admin API, another host — is dropped, so an
/// upstream cannot send a browser somewhere on the strength of app-lb's origin.
fn stays_under(location: &str, base: &str) -> bool {
    let Some(tail) = location.strip_prefix(base) else {
        return false;
    };
    (tail.is_empty() || tail.starts_with('/') || tail.starts_with('?'))
        && !tail.contains('\\')
        && !tail.split(['/', '?']).any(is_dot_segment)
}

pub fn fail(code: StatusCode, error: impl Into<String>) -> Response {
    (code, axum::Json(json!({ "error": error.into() }))).into_response()
}

/// Whether a path segment is, or percent-decodes to, `.` or `..`. Either
/// would be resolved away by the URL parser on the way upstream and could
/// climb out of `/ns/<ns>` onto the service's fleet-wide routes.
fn is_dot_segment(segment: &str) -> bool {
    let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
    decoded == "." || decoded == ".."
}

/// Where a namespace-surface path goes upstream, or `None` if it is not one
/// the proxy forwards. `/ui` is the dashboard, served with no trailing slash
/// so the page's relative `api/…` URLs resolve beside it whichever prefix it
/// is served under; with `ui_subpaths`, `/ui/<page>` is the upstream's
/// `/ns/<ns>/<page>`.
#[cfg(test)]
pub fn upstream_path(ns: &str, rest: &str, ui_subpaths: bool) -> Option<String> {
    upstream_path_at("/ns", ns, rest, ui_subpaths)
}

/// [`upstream_path`] onto `<prefix>/<ns>/…`.
pub fn upstream_path_at(prefix: &str, ns: &str, rest: &str, ui_subpaths: bool) -> Option<String> {
    if rest.contains('\\') || rest.split('/').any(is_dot_segment) {
        return None;
    }
    if rest == "/ui" {
        return Some(format!("{prefix}/{ns}/"));
    }
    if ui_subpaths && let Some(tail) = rest.strip_prefix("/ui/") {
        return Some(format!("{prefix}/{ns}/{tail}"));
    }
    if rest.starts_with("/api/") {
        return Some(format!("{prefix}/{ns}{rest}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use serde_json::Value;

    fn secrets_with(token: &str) -> Arc<SecretStore> {
        let dir =
            std::env::temp_dir().join(format!("app-lb-nsproxy-{}-{}", std::process::id(), token));
        let store = Arc::new(SecretStore::new(dir.join("secrets.json"), None));
        store.put(crate::secrets::SecretSpec {
            id: "svc".into(),
            namespace: crate::config::DEFAULT_NAMESPACE.into(),
            description: None,
            data: [("api_token".to_string(), token.to_string())].into(),
            updated_at: 0,
        });
        store
    }

    fn svc_ref() -> SecretRef {
        serde_json::from_value(json!({"secret": "svc", "key": "api_token"})).unwrap()
    }

    /// An upstream that checks the bearer and echoes what it was sent, plus
    /// a redirect, an event stream and a page.
    async fn fake(token: &str) -> String {
        let expected = format!("Bearer {token}");
        let app = Router::new().fallback(move |req: Request| {
            let expected = expected.clone();
            async move {
                let path = req.uri().path().to_string();
                if path == "/healthz" {
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
                if let Some(to) = path.strip_prefix("/ns/a/redirect/") {
                    let to = to.replace('~', "/");
                    return (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response();
                }
                if path == "/ns/a/api/stream" {
                    use futures::StreamExt;
                    // One event, then nothing: a proxy that buffered to the
                    // end would never answer.
                    let stream = futures::stream::once(async {
                        Ok::<_, std::io::Error>(bytes::Bytes::from("data: one\n\n"))
                    })
                    .chain(futures::stream::pending());
                    return (
                        [(header::CONTENT_TYPE, "text/event-stream")],
                        Body::from_stream(stream),
                    )
                        .into_response();
                }
                let h = |n: &str| {
                    req.headers()
                        .get(n)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                };
                axum::Json(json!({
                    "path": path,
                    "query": req.uri().query(),
                    "base": h("x-heyo-base"),
                    "actor": h("x-heyo-actor"),
                    "email": h("x-heyo-actor-email"),
                    "admin": h("x-heyo-actor-admin"),
                    "accept": h("accept"),
                }))
                .into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    async fn proxy(token: &str, stored: &str, actor: bool) -> Arc<NsProxy> {
        let url = fake(token).await;
        let p = NsProxy::new("svc", "svc", secrets_with(stored), true, actor);
        p.configure(
            Some(Upstream {
                url,
                api_token: Some(svc_ref()),
            }),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
        p
    }

    fn req(uri: &str, actor: Option<NamespaceActor>) -> Request {
        let mut r = axum::http::Request::get(uri)
            .header("x-heyo-actor", "forged")
            .header("x-heyo-base", "/elsewhere")
            .header(header::ACCEPT, "text/html")
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(NamespaceScope("a".into()));
        if let Some(a) = actor {
            r.extensions_mut().insert(a);
        }
        r
    }

    async fn json_of(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn paths_cannot_climb_out_of_the_namespace() {
        assert_eq!(
            upstream_path("a", "/api/fleet", false).as_deref(),
            Some("/ns/a/api/fleet")
        );
        assert_eq!(upstream_path("a", "/ui", false).as_deref(), Some("/ns/a/"));
        assert_eq!(
            upstream_path("a", "/ui/runs/7", false),
            None,
            "pages are opt-in"
        );
        assert_eq!(
            upstream_path("a", "/ui/runs/7/jobs/b", true).as_deref(),
            Some("/ns/a/runs/7/jobs/b")
        );
        for bad in [
            "/api/../../api/fleet",
            "/api/%2e%2e/%2E%2E/api/fleet",
            "/api/.%2e/x",
            "/api/./x",
            "/api\\..\\x",
            "/ui/../../vms",
            "/stats",
            "/healthz",
            "/",
        ] {
            assert_eq!(upstream_path("a", bad, true), None, "forwarded {bad}");
        }
    }

    #[test]
    fn a_redirect_is_kept_only_inside_the_plugin() {
        let base = "/namespaces/a/plugins/ci";
        for ok in [
            base,
            "/namespaces/a/plugins/ci/ui/repos",
            "/namespaces/a/plugins/ci/ui?x=1",
        ] {
            assert!(stays_under(ok, base), "dropped {ok}");
        }
        for bad in [
            "/namespaces/a/plugins/cix",
            "/namespaces/a/plugins/ci/../../obs/ui",
            "/namespaces/a/plugins/ci/%2e%2e/x",
            "/namespaces/b/plugins/ci/ui",
            "https://evil.example/",
            "//evil.example/namespaces/a/plugins/ci",
            "/api/tokens",
        ] {
            assert!(!stays_under(bad, base), "kept {bad}");
        }
    }

    #[tokio::test]
    async fn the_callers_identity_is_app_lbs_word_not_theirs() {
        let p = proxy("t1", "t1", true).await;
        let actor = NamespaceActor {
            principal: Some("user:u1".into()),
            email: Some("u1@example.com".into()),
            admin: true,
        };
        let resp = p.forward(req("/ui/repos?x=1", Some(actor))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        for (h, v) in [
            ("x-frame-options", "SAMEORIGIN"),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ] {
            assert_eq!(resp.headers()[h], v);
        }
        assert!(
            resp.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'self'")
        );
        let body = json_of(resp).await;
        assert_eq!(body["path"], "/ns/a/repos");
        assert_eq!(body["query"], "x=1");
        assert_eq!(body["base"], "/namespaces/a/plugins/svc");
        assert_eq!(body["actor"], "user:u1");
        assert_eq!(body["email"], "u1@example.com");
        assert_eq!(body["admin"], "true");
        assert_eq!(body["accept"], "text/html");

        // No actor on the request: the forged header still does not pass.
        let body = json_of(p.forward(req("/api/x", None)).await).await;
        assert_eq!(body["actor"], Value::Null);
        assert_eq!(body["admin"], "false");

        // An upstream that does not record actors is not sent them.
        let quiet = proxy("t2", "t2", false).await;
        let body = json_of(quiet.forward(req("/api/x", None)).await).await;
        assert_eq!(body["actor"], Value::Null);
        assert_eq!(body["admin"], Value::Null);
        assert_eq!(body["base"], "/namespaces/a/plugins/svc");
        p.configure(None, Duration::ZERO).await.unwrap();
        quiet.configure(None, Duration::ZERO).await.unwrap();
    }

    #[tokio::test]
    async fn redirects_pass_only_within_the_prefix() {
        let p = proxy("t3", "t3", true).await;
        let resp = p
            .forward(req("/ui/redirect/~namespaces~a~plugins~svc~ui~repos", None))
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()["location"],
            "/namespaces/a/plugins/svc/ui/repos"
        );
        let resp = p.forward(req("/ui/redirect/~api~tokens", None)).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert!(resp.headers().get("location").is_none());
        p.configure(None, Duration::ZERO).await.unwrap();
    }

    #[tokio::test]
    async fn an_event_stream_is_passed_through_as_it_arrives() {
        use futures::StreamExt;
        let p = proxy("t4", "t4", true).await;
        let resp = p.forward(req("/api/stream", None)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "text/event-stream");
        let mut body = resp.into_body().into_data_stream();
        let first = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .expect("the first event arrives before the stream ends")
            .unwrap()
            .unwrap();
        assert_eq!(&first[..], b"data: one\n\n");
        p.configure(None, Duration::ZERO).await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_stored_token_is_a_bad_gateway() {
        let p = NsProxy::new("svc", "svc", secrets_with("wrong"), false, false);
        let url = fake("right").await;
        let e = p
            .configure(
                Some(Upstream {
                    url,
                    api_token: Some(svc_ref()),
                }),
                Duration::from_secs(3600),
            )
            .await;
        assert!(e.is_ok(), "/healthz is open, so the poll is fine: {e:?}");
        let resp = p.forward(req("/api/x", None)).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        p.configure(None, Duration::ZERO).await.unwrap();
    }
}
