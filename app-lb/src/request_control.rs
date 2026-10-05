//! Manager-owned request admission, backend reservation, and retry state.
//!
//! This module deliberately knows nothing about Pingora sessions or peers. The
//! proxy adapter supplies HTTP-derived admission inputs, then translates the
//! selected [`Peer`] into its transport's peer type.

use crate::deployment::{Deployment, VmBackend};
use crate::feed::Feed;
use crate::auth::{Authenticator, Decision as AuthDecision, Identity, RequestInfo};
use crate::acme::ChallengeTable;
use crate::guard::{Decision as GuardVerdict, Guard, RequestFacts};
use crate::metrics::Metrics;
use crate::regional::Assignment;
use crate::registry::Registry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const MAX_SCANNED_UA: usize = 512;
pub const MAX_LOGIN_BODY: usize = 8192;
pub const FEED_PAGE: usize = 100;

/// Everything the manager needs to decide a request, detached from Pingora.
#[derive(Clone)]
pub struct RequestHead {
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub peer: Option<SocketAddr>,
    pub tls_terminated: bool,
}

impl RequestHead {
    pub fn host(&self) -> Option<String> {
        let raw = self.uri.authority().map(|a| a.as_str().to_string()).or_else(|| {
            self.headers.get(http::header::HOST)?.to_str().ok().map(str::to_string)
        })?;
        let host = raw.rsplit_once('@').map_or(raw.as_str(), |(_, h)| h);
        let host = if let Some(end) = host.find(']') { &host[..=end] } else { host.split(':').next().unwrap_or(host) };
        (!host.is_empty()).then(|| host.to_ascii_lowercase())
    }

    fn secure(&self) -> bool {
        self.tls_terminated || self.headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"))
    }
}

#[derive(Debug)]
pub struct ResponseData {
    pub status: u16,
    pub body: String,
    pub content_type: &'static str,
    pub headers: Vec<(http::HeaderName, String)>,
    pub cache_control: Option<&'static str>,
}

impl ResponseData {
    fn plain(status: u16, body: impl Into<String>) -> Self {
        Self { status, body: body.into(), content_type: "text/plain; charset=utf-8", headers: vec![], cache_control: None }
    }
    fn auth(r: crate::auth::Response) -> Self {
        let mut headers = Vec::new();
        if let Some(value) = r.location {
            headers.push((http::header::LOCATION, value));
        }
        for cookie in r.cookies {
            headers.push((http::header::SET_COOKIE, cookie));
        }
        headers.push((http::HeaderName::from_static("x-frame-options"), "DENY".into()));
        headers.push((http::HeaderName::from_static("referrer-policy"), "same-origin".into()));
        Self { status: r.status, body: r.body, content_type: r.content_type, headers, cache_control: Some("no-store") }
    }
}

pub enum RequestDecision {
    Respond(ResponseData),
    ReadLoginBody,
    ServeSite { spec: crate::config::SiteSpec, path: String },
    Proxy,
}

pub enum HeaderModification {
    Remove(http::HeaderName),
    Set(http::HeaderName, http::HeaderValue),
    RewriteUri(String),
}

struct PendingLogin {
    gate: crate::config::AuthGate,
    deployment_id: String,
    info: OwnedRequestInfo,
    origin: Option<String>,
}

struct OwnedRequestInfo {
    host: String, path: String, query: Option<String>, cookies: Vec<String>, secure: bool,
    wants_html: bool, fronts_admin_api: bool, bearer: Option<String>, client: Option<std::net::IpAddr>,
}

impl OwnedRequestInfo {
    fn borrowed(&self) -> RequestInfo<'_> { RequestInfo { host: &self.host, path: &self.path, query: self.query.as_deref(), cookies: self.cookies.clone(), secure: self.secure, wants_html: self.wants_html, fronts_admin_api: self.fronts_admin_api, bearer: self.bearer.clone(), client: self.client } }
}

/// Split `APP_LB_STRIP_COOKIES` into cookie names: comma-separated, trimmed,
/// empties dropped.
pub fn parse_cookie_names(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_string).collect()
}

/// The `Cookie` header to forward with `names` removed, or `None` when nothing
/// needs to change. Every `Cookie` header on the request is considered (HTTP/2
/// may split them), and the survivors are joined into one with `"; "`, which
/// is how RFC 9113 says they recombine for HTTP/1.1. `Some(None)` means no
/// cookie survives and the header should go. A header that is not valid
/// visible ASCII cannot be parsed into pairs, so it is dropped whole rather
/// than forwarded with a named cookie possibly still inside it.
fn strip_cookies(headers: &http::HeaderMap, names: &[String]) -> Option<Option<http::HeaderValue>> {
    if names.is_empty() || !headers.contains_key(http::header::COOKIE) {
        return None;
    }
    let mut kept = Vec::new();
    let mut changed = false;
    for value in headers.get_all(http::header::COOKIE) {
        let Ok(text) = value.to_str() else {
            changed = true;
            continue;
        };
        for pair in text.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let name = pair.split_once('=').map_or(pair, |(n, _)| n).trim();
            if names.iter().any(|n| n == name) {
                changed = true;
            } else {
                kept.push(pair);
            }
        }
    }
    if !changed {
        return None;
    }
    if kept.is_empty() {
        return Some(None);
    }
    // Every piece came from a valid header value and `"; "` is visible ASCII,
    // so the join is a valid value too; fall back to removal regardless.
    Some(http::HeaderValue::from_str(&kept.join("; ")).ok())
}

/// Manager-side authority boundary. Workers supply request data and execute the
/// resulting transport instructions; stores and admission counters remain here.
pub struct RequestControl {
    registry: Arc<Registry>, metrics: Arc<Metrics>, challenges: Arc<ChallengeTable>, auth: Arc<Authenticator>,
    guard: Arc<Guard>, feed: Arc<Feed>, auth_providers: Arc<crate::auth_providers::AuthProviderStore>,
    secrets: Arc<crate::secrets::SecretStore>,
    strip_cookies: Arc<[String]>,
}

const MAX_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Internal,
    Connect,
}

#[derive(Debug)]
pub struct RequestError {
    pub kind: ErrorKind,
    pub message: &'static str,
}

impl RequestError {
    fn internal(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Internal,
            message,
        }
    }
    fn connect(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Connect,
            message,
        }
    }
}

/// Transport-independent result of backend selection and reservation.
pub struct Peer {
    pub address: SocketAddr,
    pub tls: bool,
    pub sni: String,
}

#[derive(Default)]
pub struct RequestState {
    deployment: Option<Arc<Deployment>>,
    backend: Option<Arc<VmBackend>>,
    failed: Vec<String>,
    attempts: usize,
    regional_assignment: Option<Assignment>,
    identity: Option<Identity>,
    route_prefix: Option<String>,
    gateway_token: Option<String>,
    /// The upstream `Cookie` header once `APP_LB_STRIP_COOKIES` has been
    /// applied: `None` leaves the request's own header alone, `Some(None)`
    /// removes it, `Some(Some(v))` replaces it.
    cookie_rewrite: Option<Option<http::HeaderValue>>,
    forward_identity: bool,
    pending_login: Option<PendingLogin>,
}

impl RequestState {
    pub fn deployment(&self) -> Option<&Arc<Deployment>> {
        self.deployment.as_ref()
    }
    pub fn set_deployment(&mut self, deployment: Arc<Deployment>) {
        self.deployment = Some(deployment);
    }
    pub fn backend(&self) -> Option<&Arc<VmBackend>> {
        self.backend.as_ref()
    }
    pub fn regional_assignment(&self) -> Option<&Assignment> {
        self.regional_assignment.as_ref()
    }

    pub fn forwarding_modifications(&self, uri: &http::Uri) -> Result<Vec<HeaderModification>, String> {
        fn value(value: &str, description: &str) -> Result<http::HeaderValue, String> {
            http::HeaderValue::from_str(value)
                .map_err(|error| format!("invalid {description} header: {error}"))
        }

        let mut out = Vec::new();
        if let Some(assignment) = &self.regional_assignment {
            if let Some((spec, token, environment)) = &assignment.forward {
                let mut headers = http::HeaderMap::new();
                crate::gateway::write_forward_headers(&mut headers, spec, token).map_err(|e| e.to_string())?;
                out.extend(headers.into_iter().filter_map(|(n, v)| n.map(|n| HeaderModification::Set(n, v))));
                out.push(HeaderModification::Set(http::HeaderName::from_static(crate::regional::GENERATION), value(&assignment.generation.to_string(), "generation")?));
                out.push(HeaderModification::Set(http::HeaderName::from_static(crate::regional::ENVIRONMENT), value(environment, "environment")?));
            }
        }
        if let (Some(spec), Some(token)) = (self.deployment.as_ref().and_then(|d| d.spec.gateway.as_ref()), self.gateway_token.as_deref()) {
            let mut headers = http::HeaderMap::new();
            crate::gateway::write_forward_headers(&mut headers, spec, token).map_err(|e| e.to_string())?;
            out.extend(headers.into_iter().filter_map(|(n, v)| n.map(|n| HeaderModification::Set(n, v))));
        }
        if let Some(prefix) = self.route_prefix.as_deref() {
            out.push(HeaderModification::RewriteUri(strip_uri_prefix(uri, prefix)));
        }
        match &self.cookie_rewrite {
            None => {}
            Some(None) => out.push(HeaderModification::Remove(http::header::COOKIE)),
            Some(Some(v)) => out.push(HeaderModification::Set(http::header::COOKIE, v.clone())),
        }
        if self.deployment.as_ref().is_some_and(|d| d.spec.auth.is_some()) {
            out.extend(crate::auth::IDENTITY_HEADERS.iter().map(|name| HeaderModification::Remove(http::HeaderName::from_static(name))));
            if let Some(token) = self.identity.as_ref().and_then(|i| i.session_token.as_deref()) {
                out.push(HeaderModification::Set(http::header::AUTHORIZATION, value(&format!("Bearer {token}"), "authorization")?));
            }
            if self.forward_identity {
                if let Some(identity) = &self.identity {
                    out.push(HeaderModification::Set(http::HeaderName::from_static("x-auth-request-user"), value(&crate::auth::header_safe(&identity.subject), "identity subject")?));
                    let email = crate::auth::header_safe(&identity.email);
                    if !email.is_empty() { out.push(HeaderModification::Set(http::HeaderName::from_static("x-auth-request-email"), value(&email, "identity email")?)); }
                    if let Some(name) = &identity.name {
                        let name = crate::auth::header_safe(name);
                        if !name.is_empty() { out.push(HeaderModification::Set(http::HeaderName::from_static("x-auth-request-name"), value(&name, "identity name")?)); }
                    }
                }
            }
        }
        Ok(out)
    }
    /// Apply the deployment's backend admission policy once. The adapter owns
    /// header parsing/removal; this state owns the resulting regional
    /// assignment so it cannot be replayed against another backend generation.
    pub fn admit(
        &mut self,
        deployment: &Deployment,
        headers: &http::HeaderMap,
        secrets: &crate::secrets::SecretStore,
    ) -> Result<Option<String>, u16> {
        if let Some(router) = &deployment.regional {
            let discovery = deployment
                .spec
                .discovery
                .as_ref()
                .expect("regional discovery configured");
            let assignment = router.admit(
                discovery.regional.as_ref().unwrap(),
                &discovery.service_id,
                discovery.region.as_deref().unwrap(),
                headers,
                secrets,
            )?;
            self.regional_assignment = Some(assignment);
            Ok(None)
        } else if [crate::regional::GENERATION, crate::regional::ENVIRONMENT]
            .iter()
            .any(|header| headers.contains_key(*header))
        {
            Err(403)
        } else {
            crate::gateway::admit(deployment.spec.gateway.as_ref(), headers, secrets)
        }
    }
    #[cfg(test)]
    pub(crate) fn set_reserved_backend(&mut self, backend: Arc<VmBackend>) {
        self.backend = Some(backend);
    }

    /// Release the in-flight slot exactly once.
    pub fn release(&mut self) {
        if let Some(backend) = self.backend.take() {
            backend.release();
        }
    }

    /// End the whole request, including its generation-pinned assignment.
    /// An attempt failure releases only the backend; completion releases both.
    pub fn complete(&mut self) {
        self.release();
        self.regional_assignment.take();
    }

    /// Record a failed connection and return its backend for diagnostics.
    pub fn connection_failed(&mut self) -> Option<Arc<VmBackend>> {
        let backend = self.backend.as_ref().cloned();
        if let Some(backend) = &backend {
            backend.set_healthy(false);
            self.failed.push(backend.peer.clone());
        }
        self.release();
        backend
    }

    pub fn retry_allowed(&self) -> bool {
        self.regional_assignment.is_none() && self.attempts < MAX_ATTEMPTS
    }

    /// Select and reserve the next peer. Reservation happens before DNS awaits,
    /// preserving the cordon/drain admission boundary.
    pub async fn next_peer(
        &mut self,
        registry: &Registry,
        metrics: &Metrics,
        feed: &Feed,
    ) -> Result<Peer, RequestError> {
        let mut deployment = self
            .deployment
            .clone()
            .ok_or_else(|| RequestError::internal("no deployment in request state"))?;
        self.attempts += 1;
        if self.attempts > MAX_ATTEMPTS {
            return Err(RequestError::connect("exhausted upstream retries"));
        }
        self.release();

        if let Some(assignment) = &self.regional_assignment {
            if self.attempts != 1 || !assignment.backend.try_acquire() {
                return Err(RequestError::connect(
                    "regional assignment unavailable; replay forbidden",
                ));
            }
            let backend = assignment.backend.clone();
            self.backend = Some(backend.clone());
            let address = resolve_peer(&backend.address).await.ok_or_else(|| {
                RequestError::connect("regional assignment address did not resolve")
            })?;
            return Ok(peer(&backend, address));
        }

        let address = loop {
            let observed = deployment.clone();
            let changed = observed.ready_signal.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(current) = registry.get(&deployment.spec.id) {
                if !Arc::ptr_eq(&current, &deployment) {
                    check_flat_admission_refresh(&deployment, &current)?;
                    drop(changed);
                    deployment = current;
                    self.deployment = Some(deployment.clone());
                    continue;
                }
            }
            let backend = match deployment.select(&self.failed) {
                Some(backend) => backend,
                None => match tokio::select! {
                    result = wait_for_capacity(&deployment, &self.failed, metrics, feed) => result,
                    _ = &mut changed => continue,
                } {
                    Some(backend) => backend,
                    None => {
                        return Err(RequestError::connect(
                            "no healthy backend available for deployment",
                        ));
                    }
                },
            };
            if !backend.try_acquire() {
                self.failed.push(backend.peer.clone());
                continue;
            }
            self.backend = Some(backend.clone());
            match resolve_peer(&backend.address).await {
                Some(address) => break address,
                None => {
                    tracing::warn!(peer = %backend.peer, "upstream address did not resolve; marking unhealthy");
                    backend.set_healthy(false);
                    self.failed.push(backend.peer.clone());
                    self.release();
                }
            }
        };
        Ok(peer(
            self.backend
                .as_ref()
                .expect("selected backend remains in request state"),
            address,
        ))
    }
}

impl RequestControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(registry: Arc<Registry>, metrics: Arc<Metrics>, challenges: Arc<ChallengeTable>, auth: Arc<Authenticator>, guard: Arc<Guard>, feed: Arc<Feed>, auth_providers: Arc<crate::auth_providers::AuthProviderStore>, secrets: Arc<crate::secrets::SecretStore>) -> Self {
        Self { registry, metrics, challenges, auth, guard, feed, auth_providers, secrets, strip_cookies: Arc::from([]) }
    }

    /// Remove these cookies from every forwarded request (`APP_LB_STRIP_COOKIES`).
    pub fn with_stripped_cookies(mut self, names: Vec<String>) -> Self {
        self.strip_cookies = names.into();
        self
    }

    pub async fn next_peer(&self, state: &mut RequestState) -> Result<Peer, RequestError> {
        state.next_peer(&self.registry, &self.metrics, &self.feed).await
    }

    pub async fn decide(&self, head: &RequestHead, state: &mut RequestState) -> RequestDecision {
        let host = head.host();
        let path = head.uri.path().to_string();
        if let Some(answer) = head.uri.path().strip_prefix(ACME_CHALLENGE_PREFIX).and_then(|token| self.challenges.get(token)) {
            tracing::debug!(%path, "answering ACME http-01 challenge");
            return RequestDecision::Respond(ResponseData::plain(200, answer));
        }
        let routed = self.registry.route(host.as_deref(), &path);
        let facts = request_facts(head, host.as_deref(), &path, routed.as_deref());
        match self.guard.decide(&facts, crate::deployment::now_secs()) {
            GuardVerdict::Block(rule) => {
                tracing::info!(rule = %rule.id, matched = %rule.describe(), client = ?facts.client, %path, "refused by a guard rule");
                if let Some(d) = routed { state.set_deployment(d); }
                return RequestDecision::Respond(ResponseData::plain(403, "blocked\n"));
            }
            GuardVerdict::WouldBlock(rule) => tracing::warn!(rule = %rule.id, matched = %rule.describe(), client = ?facts.client, %path, "would have refused this request (APP_LB_GUARD_ENFORCE=0)"),
            GuardVerdict::Pass => {}
        }
        let Some(mut deployment) = routed else {
            tracing::debug!(?host, %path, "no deployment matches request");
            return RequestDecision::Respond(ResponseData::plain(404, "no deployment matches this request\n"));
        };
        let nominates = crate::gateway::HEADERS.iter().chain([crate::regional::GENERATION, crate::regional::ENVIRONMENT, crate::regional::PROBE, crate::regional::ACTIVE_PROBE].iter()).any(|n| head.headers.contains_key(*n));
        if nominates { if let Some(staged) = self.registry.staged(&deployment.spec.id) { deployment = staged; } }
        if head.headers.contains_key(crate::regional::PROBE) || head.headers.contains_key(crate::regional::ACTIVE_PROBE) {
            let result = if deployment.spec.maintenance { Err(503) } else if let (Some(router), Some(discovery)) = (&deployment.regional, &deployment.spec.discovery) {
                let regional = discovery.regional.as_ref().unwrap();
                if head.headers.contains_key(crate::regional::ACTIVE_PROBE) {
                    router.active_probe_local(regional, &discovery.service_id, discovery.region.as_deref().unwrap(), &head.headers, &head.method, &head.uri, host.as_deref().unwrap_or(""), &deployment.spec.health, &self.secrets).await
                        .map(|r| serde_json::to_string(&r).expect("active probe receipt serializes"))
                } else {
                    router.probe_local(regional, &discovery.service_id, discovery.region.as_deref().unwrap(), &head.headers, &head.method, &head.uri, host.as_deref().unwrap_or(""), &deployment.spec.health, &self.secrets).await
                        .map(|r| serde_json::to_string(&r).expect("probe receipt serializes"))
                }
            } else { Err(403) };
            state.set_deployment(deployment);
            return RequestDecision::Respond(match result { Ok(body) => ResponseData::plain(200, body), Err(status) => ResponseData::plain(status, "candidate probe refused or unhealthy\n") });
        }
        match state.admit(&deployment, &head.headers, &self.secrets) {
            Ok(token) => state.gateway_token = token,
            Err(status) => { state.set_deployment(deployment); return RequestDecision::Respond(ResponseData::plain(status, "gateway admission refused\n")); }
        }
        if deployment.spec.maintenance {
            state.set_deployment(deployment);
            return RequestDecision::Respond(ResponseData::plain(503, "deployment is under maintenance\n"));
        }
        state.route_prefix = matched_strip_prefix(&deployment, host.as_deref(), &path);
        state.cookie_rewrite = strip_cookies(&head.headers, &self.strip_cookies);
        if let Some(mut gate) = deployment.spec.auth.clone() {
            if let Some(name) = gate.provider_ref.as_deref() {
                match self.auth_providers.get(&deployment.spec.namespace, name) {
                    Some(provider) => gate = provider.resolve(&gate),
                    None => { tracing::warn!(deployment = %deployment.spec.id, namespace = %deployment.spec.namespace, "auth gate references an unresolvable provider; refusing the request"); state.set_deployment(deployment); return RequestDecision::Respond(ResponseData::plain(500, format!("this deployment's sign-in gate inherits the auth provider {name:?}, which is not declared in its namespace\n"))); }
                }
            }
            let Some(route_host) = host.as_deref() else { state.set_deployment(deployment); return RequestDecision::Respond(ResponseData::plain(400, "this deployment requires sign-in, which needs a Host header\n")); };
            let auth_host = if gate.jwt_policy().is_some_and(|p| p.login_endpoint.is_some()) { head.uri.authority().map(|a| a.as_str()).or_else(|| head.headers.get(http::header::HOST).and_then(|v| v.to_str().ok())).unwrap_or(route_host) } else { route_host };
            let info = owned_request_info(head, auth_host, &path, self.auth.fronts_admin_api(&deployment.spec));
            state.forward_identity = gate.forward_identity;
            if path == gate.login_path() && head.method == http::Method::POST && gate.jwt_policy().is_some_and(|p| p.login_endpoint.is_some()) {
                state.pending_login = Some(PendingLogin { gate, deployment_id: deployment.spec.id.clone(), info, origin: head.headers.get("origin").and_then(|v| v.to_str().ok()).map(str::to_string) });
                state.set_deployment(deployment);
                return RequestDecision::ReadLoginBody;
            }
            match self.auth.decide(&gate, &deployment.spec.id, &deployment.spec.namespace, &info.borrowed()).await {
                AuthDecision::Allow(identity) => state.identity = *identity,
                AuthDecision::Answered(response) => { state.set_deployment(deployment); return RequestDecision::Respond(ResponseData::auth(response)); }
            }
        }
        if let Some(expose) = deployment.spec.feed.as_ref().and_then(|f| f.expose.as_deref()) && path == expose {
            let link = match &host { Some(h) if head.secure() => format!("https://{h}{path}"), Some(h) => format!("http://{h}{path}"), None => path.clone() };
            let doc = crate::feed::rss(&deployment.spec.namespace, &link, &self.feed.recent(&deployment.spec.namespace, FEED_PAGE));
            state.set_deployment(deployment);
            return RequestDecision::Respond(ResponseData { status: 200, body: doc, content_type: "application/rss+xml; charset=utf-8", headers: vec![], cache_control: Some("public, max-age=300") });
        }
        if let Some(spec) = deployment.spec.site.clone() { state.set_deployment(deployment); return RequestDecision::ServeSite { spec, path }; }
        state.set_deployment(deployment);
        RequestDecision::Proxy
    }

    pub async fn continue_login(&self, state: &mut RequestState, body: &[u8]) -> RequestDecision {
        if body.len() > MAX_LOGIN_BODY { return RequestDecision::Respond(ResponseData::plain(413, "sign-in request is too large\n")); }
        let Some(pending) = state.pending_login.take() else { return RequestDecision::Respond(ResponseData::plain(500, "sign-in continuation is not pending\n")); };
        RequestDecision::Respond(ResponseData::auth(self.auth.heyo_login_submit(&pending.gate, &pending.deployment_id, &pending.info.borrowed(), pending.origin.as_deref(), body).await))
    }
}

fn request_facts<'a>(
    head: &'a RequestHead,
    host: Option<&'a str>,
    path: &'a str,
    deployment: Option<&'a Deployment>,
) -> RequestFacts<'a> {
    RequestFacts {
        client: head.peer.map(|peer| peer.ip()),
        host,
        path,
        method: head.method.as_str(),
        deployment: deployment.map(|deployment| deployment.spec.id.as_str()),
        user_agent: head.headers.get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.get(..MAX_SCANNED_UA).unwrap_or(value)),
    }
}

fn owned_request_info(head: &RequestHead, host: &str, path: &str, fronts_admin_api: bool) -> OwnedRequestInfo {
    OwnedRequestInfo { host: host.to_string(), path: path.to_string(), query: head.uri.query().map(str::to_string), cookies: head.headers.get_all(http::header::COOKIE).iter().filter_map(|v| v.to_str().ok()).map(str::to_string).collect(), secure: head.secure(), wants_html: head.headers.get(http::header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("text/html")), fronts_admin_api, bearer: head.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string), client: head.peer.map(|p| p.ip()) }
}

fn matched_strip_prefix(deployment: &Deployment, host: Option<&str>, path: &str) -> Option<String> {
    deployment.spec.routes.iter().filter(|r| r.strip_prefix && r.matches(host, path)).max_by_key(|r| r.specificity()).and_then(|r| r.path_prefix.clone())
}

fn strip_uri_prefix(uri: &http::Uri, prefix: &str) -> String {
    let suffix = uri.path().strip_prefix(prefix).unwrap_or(uri.path());
    let mut rewritten = if suffix.is_empty() { "/".to_string() } else if suffix.starts_with('/') { suffix.to_string() } else { format!("/{suffix}") };
    if let Some(query) = uri.query() { rewritten.push('?'); rewritten.push_str(query); }
    rewritten
}

impl Drop for RequestState {
    fn drop(&mut self) {
        self.release();
    }
}

fn peer(backend: &VmBackend, address: SocketAddr) -> Peer {
    Peer {
        address,
        tls: backend.tls,
        sni: backend.sni.clone(),
    }
}

fn check_flat_admission_refresh(
    previous: &Deployment,
    current: &Deployment,
) -> Result<(), RequestError> {
    if current.spec.gateway != previous.spec.gateway
        || current.regional.is_some()
        || previous.regional.is_some()
    {
        return Err(RequestError::connect(
            "gateway policy changed after admission",
        ));
    }
    Ok(())
}

async fn resolve_peer(peer: &str) -> Option<SocketAddr> {
    tokio::net::lookup_host(peer).await.ok()?.next()
}

pub async fn wait_for_capacity(
    deployment: &Arc<Deployment>,
    exclude: &[String],
    metrics: &Metrics,
    feed: &Feed,
) -> Option<Arc<VmBackend>> {
    if !deployment.can_grow() {
        return None;
    }
    let _waiter = deployment.track_waiter();
    metrics.record_cold_start_wait(&deployment.spec.id);
    deployment.scale_signal.notify_one();
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(deployment.spec.scaling.cold_start_timeout_secs);
    tracing::info!(deployment = %deployment.spec.id,
        timeout_secs = deployment.spec.scaling.cold_start_timeout_secs,
        "holding request for cold start");
    loop {
        let notified = deployment.ready_signal.notified();
        if let Some(backend) = deployment.select(exclude) {
            metrics.record_cold_start_hit(&deployment.spec.id);
            return Some(backend);
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            tracing::warn!(deployment = %deployment.spec.id, "cold start timed out with no VM available");
            metrics.record_cold_start_timeout(&deployment.spec.id);
            feed.issue(
                &deployment.spec,
                format!("{}: cold start timed out", deployment.spec.id),
                format!(
                    "a request waited {}s and no VM became available",
                    deployment.spec.scaling.cold_start_timeout_secs
                ),
                crate::deployment::now_secs(),
            );
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeploymentSpec;

    #[test]
    fn owned_request_head_prefers_authority_and_preserves_socket_and_tls_facts() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::HOST, "stale.example:8080".parse().unwrap());
        headers.append(http::header::COOKIE, "a=1".parse().unwrap());
        headers.append(http::header::COOKIE, "b=2".parse().unwrap());
        let head = RequestHead {
            method: http::Method::GET,
            uri: "https://User@Live.Example:443/path".parse().unwrap(),
            headers,
            peer: Some("127.0.0.1:4321".parse().unwrap()),
            tls_terminated: true,
        };
        assert_eq!(head.host().as_deref(), Some("live.example"));
        let info = owned_request_info(&head, "Live.Example:443", "/path", false);
        assert_eq!(info.cookies, ["a=1", "b=2"]);
        assert_eq!(info.client, Some("127.0.0.1".parse().unwrap()));
        assert!(info.secure);
    }

    #[test]
    fn forwarding_plan_rewrites_path_without_losing_query() {
        let mut state = RequestState::default();
        state.route_prefix = Some("/manager".into());
        let uri = "/manager/v1/read?name=a%2Fb".parse().unwrap();
        let modifications = state.forwarding_modifications(&uri).unwrap();
        assert!(matches!(
            modifications.as_slice(),
            [HeaderModification::RewriteUri(value)] if value == "/v1/read?name=a%2Fb"
        ));
    }

    #[test]
    fn guard_facts_trust_the_socket_peer_not_forwarding_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let head = RequestHead {
            method: http::Method::DELETE,
            uri: "/private".parse().unwrap(),
            headers,
            peer: Some("192.0.2.4:1234".parse().unwrap()),
            tls_terminated: false,
        };
        let facts = request_facts(&head, Some("app.example"), "/private", None);
        assert_eq!(facts.client, Some("192.0.2.4".parse().unwrap()));
        assert_eq!(facts.method, "DELETE");
        assert_eq!(facts.host, Some("app.example"));
    }

    #[test]
    fn auth_forwarding_sanitizes_identity_but_rejects_invalid_session_token() {
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}],
            "upstreams":["127.0.0.1:8000"],
            "auth":{"provider":"app-token", "forward_identity":true}
        })).unwrap();
        let mut state = RequestState::default();
        state.set_deployment(Arc::new(Deployment::new(spec)));
        state.forward_identity = true;
        state.identity = Some(Identity {
            subject: "user\nspoofed: yes".into(),
            email: String::new(),
            name: None,
            hosted_domain: None,
            session_token: Some("bad\ntoken".into()),
        });
        assert!(state.forwarding_modifications(&"/".parse().unwrap()).is_err());

        state.identity.as_mut().unwrap().session_token = Some("valid-token".into());
        let modifications = state.forwarding_modifications(&"/".parse().unwrap()).unwrap();
        assert!(modifications.iter().any(|modification| matches!(
            modification,
            HeaderModification::Set(name, value)
                if name == "x-auth-request-user" && value == "userspoofed: yes"
        )));
        assert!(!modifications.iter().any(|modification| matches!(
            modification,
            HeaderModification::Set(name, _) if name == "x-auth-request-email"
        )));
    }

    #[tokio::test]
    async fn request_decisions_preserve_acme_maintenance_and_auth_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(Registry::new(dir.path().join("state.json")));
        let secrets = Arc::new(crate::secrets::SecretStore::new(dir.path().join("secrets"), None));
        let challenges = Arc::new(ChallengeTable::new());
        challenges.publish("live".into(), "live.thumbprint".into());
        let control = RequestControl::new(
            registry.clone(), Arc::new(Metrics::new()), challenges,
            Arc::new(Authenticator::new(vec![7; 32], secrets.clone(), None, None)),
            Arc::new(Guard::new(dir.path().join("guard"), true)), Arc::new(Feed::new()),
            Arc::new(crate::auth_providers::AuthProviderStore::new(dir.path().join("providers"))),
            secrets,
        );
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}],
            "upstreams":["127.0.0.1:8000"], "maintenance":true,
            "auth":{"provider_ref":"missing"}
        })).unwrap();
        registry.upsert(spec.clone());
        let mut head = RequestHead {
            method: http::Method::GET,
            uri: "http://unrouted.example/.well-known/acme-challenge/live".parse().unwrap(),
            headers: http::HeaderMap::new(), peer: None, tls_terminated: false,
        };
        let mut state = RequestState::default();
        assert!(matches!(control.decide(&head, &mut state).await,
            RequestDecision::Respond(r) if r.status == 200 && r.body == "live.thumbprint"));
        assert!(state.deployment().is_none());
        head.uri = "http://unrouted.example/.well-known/acme-challenge/unknown".parse().unwrap();
        assert!(matches!(control.decide(&head, &mut RequestState::default()).await,
            RequestDecision::Respond(r) if r.status == 404));
        head.uri = "http://app.example/private".parse().unwrap();
        let mut state = RequestState::default();
        assert!(matches!(control.decide(&head, &mut state).await,
            RequestDecision::Respond(r) if r.status == 503));
        assert_eq!(state.deployment().unwrap().spec.id, "app");
        assert!(state.backend().is_none());
        let mut active = spec;
        active.maintenance = false;
        registry.upsert(active.clone());
        assert!(matches!(control.decide(&head, &mut RequestState::default()).await,
            RequestDecision::Respond(r) if r.status == 500 && r.body.contains("not declared")));
        active.auth = None;
        registry.upsert(active);
        assert!(matches!(control.decide(&head, &mut RequestState::default()).await,
            RequestDecision::Proxy));
    }

    #[test]
    fn host_and_prefix_edge_cases_survive_extraction() {
        for (raw, expected) in [(Some("Demo.Local:6188"), Some("demo.local")),
            (Some("[::1]:8080"), Some("[::1]")), (None, None)] {
            let mut head = RequestHead {
                method: http::Method::GET, uri: "/".parse().unwrap(),
                headers: http::HeaderMap::new(), peer: None, tls_terminated: false,
            };
            if let Some(raw) = raw { head.headers.insert(http::header::HOST, raw.parse().unwrap()); }
            assert_eq!(head.host().as_deref(), expected);
        }
        assert_eq!(strip_uri_prefix(&"/manager".parse().unwrap(), "/manager"), "/");
        assert_eq!(strip_uri_prefix(&"/manager?x=1".parse().unwrap(), "/manager"), "/?x=1");
    }

    #[tokio::test]
    async fn peer_resolution_is_async_and_fallible() {
        assert_eq!(
            resolve_peer("127.0.0.1:8080").await,
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert!(
            resolve_peer("localhost:8080")
                .await
                .is_some_and(|address| address.ip().is_loopback())
        );
        assert_eq!(resolve_peer("no-port").await, None);
        assert!(
            resolve_peer("definitely-not-a-real-host.invalid:80")
                .await
                .is_none()
        );
    }

    #[test]
    fn request_state_releases_once_and_on_drop() {
        let backend = Arc::new(VmBackend::new(
            "sb-1".into(),
            "10.0.0.1:80".parse().unwrap(),
        ));
        // A second request distinguishes exact-once release from a saturating
        // double release which would incorrectly erase someone else's work.
        backend.acquire();
        backend.acquire();
        let mut state = RequestState::default();
        state.set_reserved_backend(backend.clone());
        state.release();
        state.release();
        assert_eq!(backend.in_flight(), 1);
        backend.acquire();
        state.set_reserved_backend(backend.clone());
        drop(state);
        assert_eq!(
            backend.in_flight(),
            1,
            "cancellation must return the reservation"
        );
        backend.release();
    }

    #[tokio::test]
    async fn regional_completion_releases_assignment_but_failed_attempt_does_not() {
        let spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}],
            "discovery":{"service_id":"svc","region":"us3","regional":{
                "gateway_id":"us","backend_server_id":"host-us","environment":"test","auth":{"secret":"peer"}}}
        })).unwrap();
        let deployment = Arc::new(Deployment::new(spec));
        let router = deployment.regional.as_ref().unwrap();
        let regional = deployment.spec.discovery.as_ref().unwrap().regional.as_ref().unwrap();
        let backend = Arc::new(VmBackend::for_upstream("127.0.0.1:8888".into()));
        let snapshot = serde_json::from_value(serde_json::json!({
            "protocolVersion":1,"serviceId":"svc","environment":"test","region":"us3",
            "gatewayId":"us","bootId":router.boot_id,"version":1,"operationId":"op",
            "phase":"wait_policy_adopted","proposalGeneration":1,"activeGeneration":1,
            "drainTarget":"us3","closedThroughGeneration":0,"endpoints":[],"policies":[{
                "generation":1,"policy":{"version":1,"regions":[{"region":"us3","weight":1,
                    "gateways":[{"id":"us","backendServerId":"host-us","url":"https://us.example"}]}]}}]
        })).unwrap();
        router.apply(snapshot, regional, "svc", "us3", vec![backend.clone()]).unwrap();
        let secrets = crate::secrets::SecretStore::new("unused-request-control-test", None);
        let mut request = RequestState::default();
        request.set_deployment(deployment.clone());
        request.admit(&deployment, &http::HeaderMap::new(), &secrets).unwrap();
        let registry = Registry::new("unused-request-control-registry");
        let metrics = Metrics::new();
        let feed = Feed::new();
        request.next_peer(&registry, &metrics, &feed).await.unwrap();
        assert_eq!(backend.in_flight(), 1);
        request.connection_failed();
        assert_eq!(backend.in_flight(), 0);
        assert!(!request.retry_allowed());
        assert!(request.next_peer(&registry, &metrics, &feed).await.is_err());
        assert_eq!(router.status(regional, true)["report"]["localTarget"], 1);
        request.complete();
        assert_eq!(router.status(regional, true)["report"]["localTarget"], 0);
        assert_eq!(router.status(regional, true)["report"]["outgoingTarget"], 0);
        request.complete();
        drop(request);
    }

    #[test]
    fn stale_flat_admission_cannot_be_replayed_into_a_regional_route() {
        let flat: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}],
            "discovery":{"service_id":"svc"}, "upstreams":["127.0.0.1:8000"]
        }))
        .unwrap();
        let previous = Deployment::new(flat.clone());
        let mut refreshed = flat.clone();
        refreshed.upstreams = vec!["127.0.0.1:8001".into()];
        assert!(check_flat_admission_refresh(&previous, &Deployment::new(refreshed)).is_ok());
        let mut regional = flat;
        regional.discovery.as_mut().unwrap().region = Some("us3".into());
        regional.discovery.as_mut().unwrap().regional = Some(serde_json::from_value(serde_json::json!({
            "gateway_id":"us", "backend_server_id":"host-us", "environment":"prod", "auth":{"secret":"peer"}
        })).unwrap());
        let current = Deployment::new(regional);
        assert!(check_flat_admission_refresh(&previous, &current).is_err());
        assert!(check_flat_admission_refresh(&current, &previous).is_err());
    }

    fn cookies(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values { headers.append(http::header::COOKIE, v.parse().unwrap()); }
        headers
    }

    #[test]
    fn parse_cookie_names_trims_and_drops_empties() {
        assert_eq!(parse_cookie_names(" heyo_token , ,applb_session,"), ["heyo_token", "applb_session"]);
        assert!(parse_cookie_names("").is_empty());
    }

    #[test]
    fn strip_cookies_removes_only_named_cookies_across_headers() {
        let names = vec!["heyo_token".to_string()];
        let out = strip_cookies(&cookies(&["a=1; heyo_token=secret", "b=2"]), &names);
        assert_eq!(out, Some(Some(http::HeaderValue::from_static("a=1; b=2"))));
        // Exact, case-sensitive names: neither a prefix nor a different case matches.
        assert_eq!(strip_cookies(&cookies(&["heyo_token_x=1; Heyo_Token=2"]), &names), None);
        // A value may itself contain `=`; only the name decides.
        let out = strip_cookies(&cookies(&["x=a=b; heyo_token=c=d"]), &names);
        assert_eq!(out, Some(Some(http::HeaderValue::from_static("x=a=b"))));
    }

    #[test]
    fn strip_cookies_removes_the_header_when_nothing_survives() {
        let names = vec!["heyo_token".to_string()];
        assert_eq!(strip_cookies(&cookies(&["heyo_token=secret"]), &names), Some(None));
        assert_eq!(strip_cookies(&cookies(&[" heyo_token=a ;heyo_token=b;"]), &names), Some(None));
    }

    #[test]
    fn strip_cookies_leaves_requests_alone_without_a_match_or_a_list() {
        let names = vec!["heyo_token".to_string()];
        assert_eq!(strip_cookies(&cookies(&["a=1"]), &names), None);
        assert_eq!(strip_cookies(&http::HeaderMap::new(), &names), None);
        assert_eq!(strip_cookies(&cookies(&["heyo_token=secret"]), &[]), None);
    }

    #[test]
    fn strip_cookies_drops_an_unparseable_header_rather_than_forwarding_it() {
        let names = vec!["heyo_token".to_string()];
        let mut headers = cookies(&["a=1"]);
        headers.append(http::header::COOKIE, http::HeaderValue::from_bytes(b"heyo_token=\xff").unwrap());
        assert_eq!(strip_cookies(&headers, &names), Some(Some(http::HeaderValue::from_static("a=1"))));
    }

    #[tokio::test]
    async fn configured_cookies_never_reach_the_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(Registry::new(dir.path().join("state.json")));
        let secrets = Arc::new(crate::secrets::SecretStore::new(dir.path().join("secrets"), None));
        let control = RequestControl::new(
            registry.clone(), Arc::new(Metrics::new()), Arc::new(ChallengeTable::new()),
            Arc::new(Authenticator::new(vec![7; 32], secrets.clone(), None, None)),
            Arc::new(Guard::new(dir.path().join("guard"), true)), Arc::new(Feed::new()),
            Arc::new(crate::auth_providers::AuthProviderStore::new(dir.path().join("providers"))),
            secrets,
        ).with_stripped_cookies(vec!["heyo_token".into()]);
        registry.upsert(serde_json::from_value(serde_json::json!({
            "id":"app", "routes":[{"host":"app.example"}], "upstreams":["127.0.0.1:8000"]
        })).unwrap());
        let uri: http::Uri = "http://app.example/".parse().unwrap();
        let head = |values: &[&str]| RequestHead {
            method: http::Method::GET, uri: uri.clone(), headers: cookies(values), peer: None, tls_terminated: false,
        };
        let cookie_mods = |state: &RequestState| state.forwarding_modifications(&uri).unwrap().into_iter()
            .filter(|m| matches!(m, HeaderModification::Remove(n) | HeaderModification::Set(n, _) if n == http::header::COOKIE))
            .collect::<Vec<_>>();

        let mut state = RequestState::default();
        assert!(matches!(control.decide(&head(&["a=1; heyo_token=secret"]), &mut state).await, RequestDecision::Proxy));
        assert!(matches!(cookie_mods(&state).as_slice(),
            [HeaderModification::Set(_, v)] if v == "a=1"));

        let mut state = RequestState::default();
        assert!(matches!(control.decide(&head(&["heyo_token=secret"]), &mut state).await, RequestDecision::Proxy));
        assert!(matches!(cookie_mods(&state).as_slice(), [HeaderModification::Remove(_)]));

        let mut state = RequestState::default();
        assert!(matches!(control.decide(&head(&["a=1"]), &mut state).await, RequestDecision::Proxy));
        assert!(cookie_mods(&state).is_empty());
    }
}
