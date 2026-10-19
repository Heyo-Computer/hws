//! The global artifact store, and the namespace-walled API app-lb puts in
//! front of it.
//!
//! An `art serve` store answers to one shared key (`ART_API_KEY`) and knows
//! nothing about namespaces, so a customer who could talk to it directly would
//! need that key — and the key reads and writes every namespace's images. This
//! module keeps the key on app-lb instead:
//!
//! - **Pulls.** A deployment whose `artifact` block leaves out `store` pulls
//!   from the global store. app-lb presents its own key only for a ref under
//!   the deployment's namespace (or a content digest), so naming somebody
//!   else's tag pulls anonymously and gets what the public gets.
//! - **The admin API.** `/namespaces/:name/artifacts/…` mirrors the store's
//!   own paths (`tags`, `manifests`, `blobs`, `repos`) and forwards them with
//!   app-lb's key after [`classify`] has confined the request to `<ns>/`.
//!   The gate has already measured the caller's reach and tier against the
//!   namespace in the path, exactly as for a namespace's plugins.
//!
//! Configured by the `artifacts` plugin ([`crate::plugins::artifacts`]) when
//! the operator enables it, and otherwise by `APP_LB_ARTIFACT_STORE` (the
//! store's URL) and `APP_LB_ARTIFACT_STORE_API_KEY` (delivered from HeyoSecret
//! like `APP_LB_DAEMON_API_KEY`), which are also the plugin's defaults. The
//! [`StoreSlot`] holds whichever is current. Without either there is no global
//! store: the API answers 503 and an `artifact` block must name its `store`,
//! as before.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::{ArtifactSpec, is_valid_artifact_ref};

pub const STORE_ENV: &str = "APP_LB_ARTIFACT_STORE";
pub const KEY_ENV: &str = "APP_LB_ARTIFACT_STORE_API_KEY";

/// The store every namespace shares, and the key only app-lb holds.
pub struct GlobalStore {
    /// No trailing slash, so `{base}{path}` is always one slash apart.
    base: String,
    api_key: Option<String>,
    http: reqwest::Client,
    limits: Limits,
}

impl std::fmt::Debug for GlobalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalStore")
            .field("base", &self.base)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl GlobalStore {
    /// `Ok(None)` when `APP_LB_ARTIFACT_STORE` is unset or blank.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(url) = std::env::var(STORE_ENV).ok().filter(|v| !v.trim().is_empty()) else {
            return Ok(None);
        };
        let key = std::env::var(KEY_ENV).ok().filter(|v| !v.trim().is_empty());
        Self::new(&url, key).map(Some)
    }

    /// HTTPS only, except to a loopback host: the key travels with every
    /// forwarded request, and a pinned rollout insists on HTTPS anyway.
    pub fn new(url: &str, api_key: Option<String>) -> Result<Self, String> {
        let base = url.trim().trim_end_matches('/').to_string();
        let parsed = reqwest::Url::parse(&base)
            .map_err(|e| format!("{STORE_ENV}={base:?} is not a URL: {e}"))?;
        let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        match parsed.scheme() {
            "https" => {}
            "http" if loopback => {}
            other => {
                return Err(format!(
                    "{STORE_ENV}={base:?} must be an https:// URL (http:// only to a loopback host), not {other}://"
                ));
            }
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(format!("{STORE_ENV}={base:?} must not carry a query or fragment"));
        }
        // No `read_timeout`: reqwest runs it while the request body is still
        // going out, so a push that took more than a minute failed however
        // steadily its bytes moved. [`GlobalStore::forward`] times stalls
        // itself, from the last byte moved in either direction.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("artifact store client: {e}"))?;
        Ok(Self { base, api_key: api_key.map(|k| k.trim().to_string()), http, limits: Limits::default() })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn has_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// The key itself, so the plugin can reuse the environment's for the same
    /// store. Never leaves app-lb.
    pub(crate) fn key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    /// Whether `store` names this store, however it is spelled at the end.
    pub fn is_this(&self, store: &str) -> bool {
        let s = store.trim().trim_end_matches('/');
        s.is_empty() || s == self.base
    }

    /// The key to pull `reference` with on behalf of `namespace`: app-lb's own
    /// for a ref the namespace owns or a content digest, and none otherwise —
    /// a ref outside the namespace pulls anonymously, so only a public
    /// repository answers it.
    pub fn key_for(&self, namespace: &str, reference: &str) -> Option<&str> {
        (owns(namespace, reference) || is_digest(reference))
            .then_some(self.api_key.as_deref())
            .flatten()
    }

    /// Forward one already-[`classify`]-ed request and stream the answer back.
    ///
    /// The store's 401 becomes a 502: the caller's credential was app-lb's to
    /// judge and it passed, so a refusal here is app-lb's key being wrong — a
    /// 401 would send the caller after their own token.
    pub async fn forward(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &HeaderMap,
        body: Option<Body>,
    ) -> Response {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        for name in [header::CONTENT_TYPE, header::CONTENT_LENGTH, header::IF_MATCH, header::IF_NONE_MATCH] {
            if let Some(v) = headers.get(&name) {
                req = req.header(name, v.clone());
            }
        }
        let length = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let progress = Progress::new(body.is_some(), length, self.limits);
        if let Some(body) = body {
            req = req.body(reqwest::Body::wrap_stream(progress.watch(body.into_data_stream())));
        } else {
            progress.finish();
        }
        let send = req.send();
        tokio::pin!(send);
        let resp = loop {
            tokio::select! {
                r = &mut send => break r,
                _ = tokio::time::sleep_until(progress.deadline()) => {
                    if let Some(why) = progress.expired() {
                        tracing::warn!(path, "artifact store request timed out: {why}");
                        return gateway_error(StatusCode::GATEWAY_TIMEOUT, why);
                    }
                }
            }
        };
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                let e = error_chain(&e);
                tracing::warn!(error = %e, path, "artifact store request failed");
                return gateway_error(StatusCode::BAD_GATEWAY, format!("the artifact store did not answer: {e}"));
            }
        };
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        if status == StatusCode::UNAUTHORIZED {
            tracing::error!(path, "the artifact store refused app-lb's key ({KEY_ENV})");
            return gateway_error(
                StatusCode::BAD_GATEWAY,
                "the artifact store refused this app-lb's credential; the operator must check its store key",
            );
        }
        let mut out = Response::builder().status(status);
        for name in [header::CONTENT_TYPE, header::CONTENT_LENGTH, header::ETAG] {
            if let Some(v) = resp.headers().get(&name) {
                out = out.header(name, v.clone());
            }
        }
        out.body(Body::from_stream(idle_limited(resp.bytes_stream().map_err(std::io::Error::other), self.limits.stall)))
            .unwrap_or_else(|e| gateway_error(StatusCode::BAD_GATEWAY, e.to_string()))
    }

    /// `GET /tags`, cut down to the namespace's own. The store has no prefix
    /// query, so the filter has to happen here, and nothing outside `<ns>/`
    /// may leave app-lb — not even a tag's name.
    pub async fn namespace_tags(&self, namespace: &str) -> Response {
        let mut req = self.http.get(format!("{}/tags", self.base)).timeout(self.limits.stall);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                return gateway_error(
                    StatusCode::BAD_GATEWAY,
                    format!("the artifact store did not answer: {}", error_chain(&e)),
                );
            }
        };
        match resp.status().as_u16() {
            200 => {}
            401 => {
                tracing::error!("the artifact store refused app-lb's key ({KEY_ENV})");
                return gateway_error(
                    StatusCode::BAD_GATEWAY,
                    "the artifact store refused this app-lb's credential; the operator must check its store key",
                );
            }
            code => {
                return gateway_error(StatusCode::BAD_GATEWAY, format!("the artifact store answered {code} listing tags"));
            }
        }
        match resp.json::<Vec<TagEntry>>().await {
            Ok(rows) => axum::Json(filter_tags(rows, namespace)).into_response(),
            Err(e) => gateway_error(StatusCode::BAD_GATEWAY, format!("the artifact store's tag listing did not parse: {e}")),
        }
    }
}

/// How long a request to the store may go without progress.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Bytes stopped moving, either way.
    stall: Duration,
    /// The store has the whole body and has not answered. It publishes a blob
    /// to its remote tier before it says "stored", and a multi-gigabyte
    /// rootfs takes minutes to upload there.
    reply_wait: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { stall: Duration::from_secs(60), reply_wait: Duration::from_secs(900) }
    }
}

/// Where a forwarded request stands, for timing out a stall rather than a
/// slow but moving transfer.
struct Progress {
    has_body: bool,
    /// The body's declared length. Once that much is sent hyper never asks
    /// for the stream's end, so the end is the byte count reaching it.
    length: Option<u64>,
    sent: std::sync::atomic::AtomicU64,
    limits: Limits,
    state: std::sync::Mutex<(tokio::time::Instant, Option<tokio::time::Instant>)>,
}

impl Progress {
    fn new(has_body: bool, length: Option<u64>, limits: Limits) -> Arc<Self> {
        Arc::new(Self { has_body, length, sent: Default::default(), limits, state: std::sync::Mutex::new((tokio::time::Instant::now(), None)) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (tokio::time::Instant, Option<tokio::time::Instant>)> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn touch(&self, n: usize) {
        self.lock().0 = tokio::time::Instant::now();
        let sent = self.sent.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed) + n as u64;
        if self.length.is_some_and(|len| sent >= len) {
            self.finish();
        }
    }

    fn finish(&self) {
        self.lock().1 = Some(tokio::time::Instant::now());
    }

    /// When the request runs out of time if nothing changes before then.
    fn deadline(&self) -> tokio::time::Instant {
        match *self.lock() {
            (last, None) => last + self.limits.stall,
            (_, Some(sent)) => sent + if self.has_body { self.limits.reply_wait } else { self.limits.stall },
        }
    }

    /// Why the request has run out of time, if it has.
    fn expired(&self) -> Option<String> {
        if tokio::time::Instant::now() < self.deadline() {
            return None;
        }
        Some(match self.lock().1 {
            None => format!(
                "the upload to the artifact store stalled: no bytes moved for {}s",
                self.limits.stall.as_secs()
            ),
            Some(_) if self.has_body => format!(
                "the artifact store took the whole upload but did not answer within {}s",
                self.limits.reply_wait.as_secs()
            ),
            Some(_) => format!("the artifact store did not answer within {}s", self.limits.stall.as_secs()),
        })
    }

    /// `body`, noting each chunk as it is taken and the end when it comes.
    /// A chunk is only asked for once the store has taken the last one, so
    /// this sees a store that stops reading as surely as a caller that stops
    /// sending.
    fn watch<S, E>(self: &Arc<Self>, body: S) -> impl futures::Stream<Item = Result<bytes::Bytes, E>> + use<S, E>
    where
        S: futures::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
    {
        use futures::StreamExt;
        futures::stream::unfold((body, self.clone()), |(mut body, progress)| async move {
            match body.next().await {
                Some(chunk) => {
                    progress.touch(chunk.as_ref().map_or(0, |c| c.len()));
                    Some((chunk, (body, progress)))
                }
                None => {
                    progress.finish();
                    None
                }
            }
        })
    }
}

/// `stream`, ended with an error once it has gone `stall` without a chunk.
fn idle_limited<S>(stream: S, stall: Duration) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>>
where
    S: futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin,
{
    use futures::StreamExt;
    futures::stream::unfold(Some(stream), move |stream| async move {
        let mut stream = stream?;
        match tokio::time::timeout(stall, stream.next()).await {
            Ok(Some(chunk)) => Some((chunk, Some(stream))),
            Ok(None) => None,
            Err(_) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("the artifact store sent nothing for {}s", stall.as_secs()),
                )),
                None,
            )),
        }
    })
}

/// An error and its causes on one line: reqwest's own text stops at "error
/// sending request for url (…)" and leaves out why.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// The global store as it stands right now: the `artifacts` plugin's while
/// the operator has it enabled, else the one the environment names.
///
/// Pulls, the `/namespaces/:name/artifacts` gateway and the plugin's own
/// namespace surface all read it per request, so enabling, reconfiguring or
/// disabling the plugin takes effect without a restart.
#[derive(Debug, Default)]
pub struct StoreSlot {
    env: Option<Arc<GlobalStore>>,
    plugin: RwLock<Option<Arc<GlobalStore>>>,
}

impl StoreSlot {
    pub fn new(env: Option<GlobalStore>) -> Self {
        Self { env: env.map(Arc::new), plugin: RwLock::default() }
    }

    /// The store pulls and the gateway use now.
    pub fn current(&self) -> Option<Arc<GlobalStore>> {
        self.plugin.read().unwrap().clone().or_else(|| self.env.clone())
    }

    /// The store `APP_LB_ARTIFACT_STORE` names, which the plugin defaults to.
    pub fn env(&self) -> Option<&GlobalStore> {
        self.env.as_deref()
    }

    /// `plugin`, `env` or `none`: where [`Self::current`] comes from.
    pub fn source(&self) -> &'static str {
        if self.plugin.read().unwrap().is_some() {
            "plugin"
        } else if self.env.is_some() {
            "env"
        } else {
            "none"
        }
    }

    /// Set (or, with `None`, clear) the plugin's store. Clearing falls back to
    /// the environment's.
    pub fn set_plugin(&self, store: Option<Arc<GlobalStore>>) {
        *self.plugin.write().unwrap() = store;
    }
}

/// `GET …/artifacts` — whether there is a global store, whether this app-lb
/// can write to it, and the prefix the namespace's tags must carry. Names no
/// URL: the store is app-lb's business, not the caller's.
pub fn describe(namespace: &str, store: Option<&GlobalStore>) -> Response {
    axum::Json(serde_json::json!({
        "namespace": namespace,
        "available": store.is_some(),
        "writable": store.is_some_and(GlobalStore::has_key),
        "prefix": format!("{namespace}/"),
    }))
    .into_response()
}

/// Confine one request to `namespace`'s corner of `store` and forward it:
/// the whole of a namespace's artifact API after the caller's reach and tier
/// were checked. Shared by `/namespaces/:name/artifacts/…` and the plugin's
/// `/namespaces/:name/plugins/artifacts/api/…`.
pub async fn serve(
    store: Option<Arc<GlobalStore>>,
    namespace: &str,
    rest: &str,
    method: reqwest::Method,
    headers: &HeaderMap,
    body: Option<Body>,
) -> Response {
    let Some(store) = store else {
        return gateway_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "this app-lb has no global artifact store: enable the artifacts plugin, or set {STORE_ENV}"
            ),
        );
    };
    match classify(namespace, &method, rest) {
        Err(why) => gateway_error(StatusCode::FORBIDDEN, why),
        Ok(Route::TagList) => store.namespace_tags(namespace).await,
        Ok(Route::Forward(path)) => {
            if method != reqwest::Method::GET && method != reqwest::Method::HEAD && !store.has_key() {
                return gateway_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "this app-lb's global artifact store is read-only: it holds no store key",
                );
            }
            store.forward(method, &path, headers, body).await
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TagEntry {
    pub tag: String,
    pub digest: String,
}

pub fn filter_tags(rows: Vec<TagEntry>, namespace: &str) -> Vec<TagEntry> {
    rows.into_iter().filter(|r| owns(namespace, &r.tag)).collect()
}

/// `{"error": …}`, app-lb's error shape.
pub fn gateway_error(code: StatusCode, message: impl Into<String>) -> Response {
    (code, axum::Json(serde_json::json!({ "error": message.into() }))).into_response()
}

/// A 64-hex content digest, the form the store addresses blobs and manifests by.
pub fn is_digest(r: &str) -> bool {
    r.len() == 64 && r.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `reference` lives under `<namespace>/`. Dot segments never do,
/// whatever they are prefixed with.
pub fn owns(namespace: &str, reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix(namespace).and_then(|r| r.strip_prefix('/')) else {
        return false;
    };
    !namespace.is_empty()
        && !rest.is_empty()
        && !reference.split('/').any(|s| s == "." || s == "..")
}

/// The spec a pull actually runs: an `artifact` block with no `store` names
/// the global one. Fails when there is no global store to name.
pub fn effective(spec: &ArtifactSpec, global: Option<&GlobalStore>) -> Result<ArtifactSpec, String> {
    if !spec.store.trim().is_empty() {
        return Ok(spec.clone());
    }
    let Some(global) = global else {
        return Err(format!(
            "this deployment's `artifact` block names no `store`, and this app-lb has no global artifact store \
             ({STORE_ENV}); set `artifact.store`"
        ));
    };
    Ok(ArtifactSpec { store: global.base().to_string(), ..spec.clone() })
}

/// What a `/namespaces/:name/artifacts/…` request becomes at the store.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Forward to this store path unchanged.
    Forward(String),
    /// `GET /tags`, which [`GlobalStore::namespace_tags`] narrows.
    TagList,
}

/// Confine one request to the namespace's corner of the store.
///
/// The same rules the MCP server used to apply when it held the key: blobs by
/// digest only, manifests by digest or by a ref the namespace owns (and created
/// with a bare `PUT /manifests`), tags and repositories only under `<ns>/`, and
/// nothing store-wide. `rest` is the path after `/artifacts`, with or without
/// its leading slash. The answer's `Err` is the reason, for a 403.
pub fn classify(namespace: &str, method: &reqwest::Method, rest: &str) -> Result<Route, String> {
    use reqwest::Method;
    let read = method == Method::GET || method == Method::HEAD;
    let rest = rest.trim_start_matches('/');
    let (top, reference) = rest.split_once('/').unwrap_or((rest, ""));
    let prefix = format!("{namespace}/");
    let outside = |what: &str| {
        format!(
            "namespace {namespace} may only reach artifacts under {prefix}; {what}. \
             Publish under a namespaced tag such as {prefix}app:latest"
        )
    };
    if reference.split('/').any(|s| s == "." || s == "..") {
        return Err(outside("dot segments are not allowed"));
    }
    let own = owns(namespace, reference) && is_valid_artifact_ref(reference);
    let digest = is_digest(reference);

    match top {
        "blobs" if digest && (read || method == Method::PUT) => Ok(Route::Forward(format!("/blobs/{reference}"))),
        "blobs" if reference.is_empty() => Err(outside("the store-wide blob listing is not available")),
        "blobs" => Err(outside("blobs are addressed by their sha256 digest")),
        "manifests" if reference.is_empty() && method == Method::PUT => Ok(Route::Forward("/manifests".into())),
        "manifests" if reference.is_empty() => Err(outside("the store-wide manifest listing is not available")),
        "manifests" if read && (digest || own) => Ok(Route::Forward(format!("/manifests/{reference}"))),
        "manifests" => Err(outside(&format!("{reference} is outside it"))),
        "tags" if reference.is_empty() && read => Ok(Route::TagList),
        "tags" if reference.is_empty() => Err(outside("tags are changed one at a time")),
        "tags" if own && (read || method == Method::PUT || method == Method::DELETE) => {
            Ok(Route::Forward(format!("/tags/{reference}")))
        }
        "tags" => Err(outside(&format!("{reference} is outside it"))),
        // A repository is the part of a tag before `:`, so it must not carry one.
        "repos" if own && !reference.contains(':') && (read || method == Method::PUT) => {
            Ok(Route::Forward(format!("/repos/{reference}")))
        }
        "repos" if reference.is_empty() => Err(outside("the store-wide repository listing is not available")),
        "repos" => Err(outside(&format!("{reference} is not a repository it owns"))),
        other => Err(outside(&format!("/{other} is store-wide"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Method;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_namespace_owns_only_its_own_prefix() {
        assert!(owns("us5", "us5/farm-rsvp"));
        assert!(owns("us5", "us5/farm-rsvp:latest"));
        assert!(!owns("us5", "us5"));
        assert!(!owns("us5", "us5/"));
        assert!(!owns("us5", "us50/app"), "a longer namespace is not this one");
        assert!(!owns("us5", "other/app"));
        assert!(!owns("us5", "us5/../other/app"));
        assert!(!owns("", "/app"));
    }

    #[test]
    fn blobs_go_by_digest_and_nothing_lists_the_store() {
        assert_eq!(classify("us5", &Method::GET, &format!("blobs/{D}")), Ok(Route::Forward(format!("/blobs/{D}"))));
        assert_eq!(classify("us5", &Method::PUT, &format!("/blobs/{D}")), Ok(Route::Forward(format!("/blobs/{D}"))));
        assert!(classify("us5", &Method::DELETE, &format!("blobs/{D}")).is_err());
        assert!(classify("us5", &Method::GET, "blobs").is_err());
        assert!(classify("us5", &Method::GET, "blobs/us5/app").is_err());
        assert!(classify("us5", &Method::GET, "usage").is_err());
        assert!(classify("us5", &Method::GET, "labels/us5/app").is_err());
        assert!(classify("us5", &Method::GET, "public/us5/app").is_err());
    }

    #[test]
    fn manifests_are_read_by_digest_or_an_owned_ref() {
        assert!(classify("us5", &Method::GET, &format!("manifests/{D}")).is_ok());
        assert!(classify("us5", &Method::GET, "manifests/us5/app:v1").is_ok());
        assert!(classify("us5", &Method::GET, "manifests/other/app:v1").is_err());
        assert_eq!(classify("us5", &Method::PUT, "manifests"), Ok(Route::Forward("/manifests".into())));
        assert!(classify("us5", &Method::GET, "manifests").is_err());
        assert!(classify("us5", &Method::PUT, "manifests/us5/app").is_err());
    }

    #[test]
    fn tags_are_walled_and_the_listing_is_narrowed() {
        assert_eq!(classify("us5", &Method::GET, "tags"), Ok(Route::TagList));
        assert!(classify("us5", &Method::PUT, "tags").is_err());
        for m in [Method::GET, Method::PUT, Method::DELETE] {
            assert_eq!(
                classify("us5", &m, "tags/us5/app:v2"),
                Ok(Route::Forward("/tags/us5/app:v2".into())),
                "{m}"
            );
            assert!(classify("us5", &m, "tags/other/app:v2").is_err(), "{m}");
            assert!(classify("us5", &m, "tags/app:v2").is_err(), "a bare tag is nobody's: {m}");
        }
        assert!(classify("us5", &Method::GET, "tags/us5/../x/app").is_err());
        assert!(classify("us5", &Method::PUT, "tags/us5/App Name").is_err(), "not a valid ref");
    }

    #[test]
    fn repositories_are_the_namespaces_own() {
        assert!(classify("us5", &Method::PUT, "repos/us5/app").is_ok());
        assert!(classify("us5", &Method::GET, "repos/us5/app").is_ok());
        assert!(classify("us5", &Method::DELETE, "repos/us5/app").is_err());
        assert!(classify("us5", &Method::PUT, "repos/us5/app:v1").is_err());
        assert!(classify("us5", &Method::PUT, "repos/us5").is_err());
        assert!(classify("us5", &Method::GET, "repos").is_err());
    }

    #[test]
    fn tag_listings_keep_only_the_namespace() {
        let rows = vec![
            TagEntry { tag: "us5/app:v1".into(), digest: D.into() },
            TagEntry { tag: "us50/app:v1".into(), digest: D.into() },
            TagEntry { tag: "other/app".into(), digest: D.into() },
            TagEntry { tag: "flat-tag".into(), digest: D.into() },
        ];
        let kept: Vec<_> = filter_tags(rows, "us5").into_iter().map(|r| r.tag).collect();
        assert_eq!(kept, ["us5/app:v1"]);
    }

    #[test]
    fn the_key_goes_only_with_an_owned_ref_or_a_digest() {
        let g = GlobalStore::new("https://art.example.com/", Some("k".into())).unwrap();
        assert_eq!(g.base(), "https://art.example.com");
        assert_eq!(g.key_for("us5", "us5/app:v1"), Some("k"));
        assert_eq!(g.key_for("us5", D), Some("k"));
        assert_eq!(g.key_for("us5", "other/app:v1"), None, "anonymous: only a public repo answers");
        assert_eq!(g.key_for("us5", "flat"), None);
        assert!(g.is_this("https://art.example.com/"));
        assert!(g.is_this(""));
        assert!(!g.is_this("https://art.other.com"));
    }

    #[test]
    fn the_store_url_must_keep_the_key_off_plaintext() {
        assert!(GlobalStore::new("http://art.example.com", None).is_err());
        assert!(GlobalStore::new("http://127.0.0.1:8080", None).is_ok());
        assert!(GlobalStore::new("ftp://art.example.com", None).is_err());
        assert!(GlobalStore::new("https://art.example.com/?x=1", None).is_err());
        assert!(GlobalStore::new("not a url", None).is_err());
    }

    #[test]
    fn a_storeless_artifact_names_the_global_store() {
        let spec: ArtifactSpec = serde_json::from_value(serde_json::json!({"ref": "us5/app:v1"})).unwrap();
        assert!(effective(&spec, None).unwrap_err().contains(STORE_ENV));
        let g = GlobalStore::new("https://art.example.com", None).unwrap();
        assert_eq!(effective(&spec, Some(&g)).unwrap().store, "https://art.example.com");
        let named = ArtifactSpec { store: "https://art.other.com".into(), ..spec };
        assert_eq!(effective(&named, Some(&g)).unwrap().store, "https://art.other.com");
    }

    #[test]
    fn the_plugins_store_wins_and_clearing_it_falls_back_to_the_environments() {
        let slot = StoreSlot::new(Some(GlobalStore::new("https://env.example.com", None).unwrap()));
        assert_eq!(slot.source(), "env");
        assert_eq!(slot.current().unwrap().base(), "https://env.example.com");
        slot.set_plugin(Some(Arc::new(GlobalStore::new("https://plugin.example.com", Some("k".into())).unwrap())));
        assert_eq!(slot.source(), "plugin");
        assert_eq!(slot.current().unwrap().base(), "https://plugin.example.com");
        slot.set_plugin(None);
        assert_eq!(slot.current().unwrap().base(), "https://env.example.com");
        let empty = StoreSlot::new(None);
        assert_eq!(empty.source(), "none");
        assert!(empty.current().is_none());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let g = GlobalStore::new("https://art.example.com", Some("sekrit".into())).unwrap();
        assert!(!format!("{g:?}").contains("sekrit"));
    }

    /// Pushes against a real socket whose reader behaves as `store` says.
    mod pushes {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Clone, Copy)]
        enum Store {
            /// Reads 256 KiB every 10ms, then answers 201.
            Slow,
            /// Reads 64 KiB, then nothing more.
            StopsReading,
            /// Reads everything, then never answers.
            Silent,
        }

        const BODY: usize = 1024 * 1024;

        async fn push(store: Store, body_len: usize) -> (StatusCode, String, Duration) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 256 * 1024];
                let mut head = Vec::new();
                let mut body = 0usize;
                loop {
                    if matches!(store, Store::StopsReading) && body >= 64 * 1024 {
                        std::future::pending::<()>().await;
                    }
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    if body == 0 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        head.extend_from_slice(&buf[..n]);
                        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                            body = head.len() - i - 4;
                        }
                    } else {
                        body += n;
                    }
                    if body >= body_len {
                        break;
                    }
                    if matches!(store, Store::Slow) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                if matches!(store, Store::Silent) {
                    std::future::pending::<()>().await;
                }
                s.write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 2\r\n\r\n{}").await.unwrap();
            });
            let mut g = GlobalStore::new(&format!("http://{addr}"), Some("k".into())).unwrap();
            g.limits = Limits { stall: Duration::from_millis(300), reply_wait: Duration::from_millis(1500) };
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_LENGTH, body_len.into());
            let chunks = futures::stream::iter(
                (0..body_len / (16 * 1024)).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![7u8; 16 * 1024]))),
            );
            let started = std::time::Instant::now();
            let r = g
                .forward(Method::PUT, &format!("/blobs/{D}"), &headers, Some(Body::from_stream(chunks)))
                .await;
            let status = r.status();
            let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            (status, String::from_utf8_lossy(&body).into_owned(), started.elapsed())
        }

        /// Regression: the client's 60s `read_timeout` ran while the body was
        /// still going out, so any push longer than a minute failed.
        #[tokio::test]
        async fn a_slow_push_that_keeps_moving_outlasts_the_stall_limit() {
            let (status, body, took) = push(Store::Slow, 32 * BODY).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert!(took > Duration::from_millis(900), "the push must outlast the stall limit thrice over: {took:?}");
        }

        #[tokio::test]
        async fn a_store_that_stops_reading_is_a_stall() {
            let (status, body, _) = push(Store::StopsReading, 32 * BODY).await;
            assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
            assert!(body.contains("stalled"), "{body}");
        }

        #[tokio::test]
        async fn a_store_that_takes_the_body_and_never_answers_runs_out_the_reply_wait() {
            let (status, body, took) = push(Store::Silent, BODY / 4).await;
            assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
            assert!(body.contains("did not answer"), "{body}");
            assert!(took >= Duration::from_millis(1500), "{took:?}");
        }
    }
}
