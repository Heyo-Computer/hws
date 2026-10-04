//! Federated admin auth: a bearer somebody else issued, turned into a set of
//! namespace grants by asking the Heyo auth API.
//!
//! The admin gate ([`crate::admin`]) knows two credentials of its own — the
//! startup Basic pair and app-tokens it minted itself. A managed fleet has a
//! third kind of caller: a Heyo customer, carrying the JWT (or `heyo_api_*`
//! key) the Heyo auth service gave them. app-lb never sees that user's
//! password and never mints them anything; it asks `GET /api/auth/scopes` what
//! that bearer is allowed to reach and enforces the answer with the same
//! namespace wall a local namespace token gets.
//!
//! What comes back is a list of scope strings. The grammar is the contract
//! with the auth service and is deliberately tiny:
//!
//! | scope | meaning |
//! | --- | --- |
//! | `namespace:<name>:admin` | admin tier on every deployment in `<name>` |
//! | `namespace:<name>:view` | view tier only — directory, `/metrics`, list, get |
//! | `fleet:admin` | unconfined, as the Basic operator is |
//!
//! Anything else is ignored with a debug log rather than refused, so the auth
//! service can grow new scopes without breaking an older app-lb.
//!
//! Answers are cached by the SHA-256 of the bearer for at most
//! `APP_LB_AUTH_CACHE_SECS` (and never past the token's own expiry), so a
//! dashboard polling `/metrics` costs one upstream round trip per minute rather
//! than one per poll. Refusals are cached too, briefly, so a bad token cannot
//! turn app-lb into an amplifier against the auth service. The cost of the
//! cache is revocation latency: a scope withdrawn upstream lingers here for
//! up to the TTL. That is the same trade every JWT makes, and shorter than most.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::tokens::AdminScope;

/// Bearers with this prefix are app-lb's own tokens and never leave the
/// process; the gate resolves them from the local store, not from here.
pub const LOCAL_TOKEN_PREFIX: &str = "applb_";

/// How long a refusal is remembered. Short: a token that has just been
/// created, or a transient auth-service outage, should not lock a caller out
/// for a whole cache period.
const MISS_TTL: Duration = Duration::from_secs(5);

/// Above this many cached entries the expired ones are swept on insert. A
/// bound rather than an LRU: the cache is keyed by token hash, and a caller
/// spraying fresh tokens would otherwise grow it without limit.
const MAX_ENTRIES: usize = 4096;

/// Who the auth service says the bearer is.
#[derive(Debug, Clone, Deserialize)]
pub struct Subject {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(rename = "accountId", default)]
    pub account_id: Option<String>,
    #[serde(rename = "platformRole", default)]
    pub platform_role: Option<String>,
}

/// What a federated bearer may do, as the gate consumes it.
#[derive(Debug)]
pub struct Grant {
    pub subject: Subject,
    /// Namespace → the strongest tier granted there.
    pub namespaces: BTreeMap<String, AdminScope>,
    /// Namespace → the heyo account that owns it, from the `namespaces[]`
    /// array beside the scopes. Kept apart from `namespaces` because the two
    /// answer different questions: that one is *what may this caller do
    /// here*, this one is *who pays for what is deployed here*.
    pub accounts: BTreeMap<String, String>,
    /// `fleet:admin` was present: this caller is not behind any wall.
    pub fleet: bool,
}

impl Grant {
    /// The account billed for deployments in `ns`.
    ///
    /// The namespace's owner when the auth service said who that is; otherwise
    /// the caller's own account, which is right for a user in one account and
    /// wrong for a user in several — hence the warning, so an auth service that
    /// predates `namespaces[]` is noticed rather than silently billing the
    /// wrong account.
    pub fn account_for(&self, ns: &str) -> Option<&str> {
        if let Some(owner) = self.accounts.get(ns) {
            return Some(owner.as_str());
        }
        if self.subject.account_id.is_some() {
            tracing::warn!(
                namespace = %ns,
                user = %self.subject.user_id,
                "auth service named no owner for this namespace; billing the caller's own account",
            );
        }
        self.subject.account_id.as_deref()
    }
}

enum Entry {
    Hit(Arc<Grant>, Instant),
    Miss(Instant),
}

impl Entry {
    fn expires_at(&self) -> Instant {
        match self {
            Entry::Hit(_, at) | Entry::Miss(at) => *at,
        }
    }
}

/// The resolver, one per process.
pub struct FederatedAuth {
    base_url: String,
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<[u8; 32], Entry>>,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    subject: Subject,
    #[serde(default)]
    scopes: Vec<String>,
    /// One entry per namespace the caller reaches, with its owning account.
    /// Optional on the wire: an older auth service sends only `scopes`.
    #[serde(default)]
    namespaces: Vec<NamespaceGrantWire>,
    #[serde(rename = "expiresIn", default)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct NamespaceGrantWire {
    name: String,
    #[serde(rename = "accountId", default)]
    account_id: Option<String>,
}

impl FederatedAuth {
    /// The auth service this fleet federates to. Read by the admin API to
    /// derive that service's key set URL for the `heyo-jwks` provider preset —
    /// the one place app-lb needs to name the auth service for something other
    /// than resolving a bearer.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn new(base_url: String, ttl_secs: u64, timeout_secs: u64) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs.max(1)))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            ttl: Duration::from_secs(ttl_secs.max(1)),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Exchange browser credentials only with the configured Heyo authority.
    /// The returned token still needs a current grant — `fleet:admin`, or at
    /// least one namespace; email and JWT role claims are not a second
    /// administrator list.
    pub async fn login(&self, email: &str, password: &str) -> Option<(String, u64)> {
        let url = reqwest::Url::parse(&self.base_url).ok()?;
        // Match the existing Heyo browser-login transport policy: loopback
        // Auth on this host is supported, but never plaintext remote login.
        if !(url.scheme() == "https"
            || url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let mut response = self
            .http
            .post(format!("{}/api/auth/login", self.base_url))
            .json(&serde_json::json!({"email":email,"password":password}))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len() + chunk.len() > 65536 {
                return None;
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        if value.get("success")?.as_bool()? != true {
            return None;
        }
        let token = value.pointer("/data/tokens/accessToken")?.as_str()?;
        if token.is_empty()
            || token.len() > 3800
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return None;
        }
        // The grant decides, not the login response's own claims: a fleet
        // admin gets the fleet console, and a caller with namespaces gets the
        // namespace rollup. A bearer that reaches nothing at all is still
        // refused — signing somebody in only to tell them they can see
        // nothing is worse than no sign-in.
        let grant = self.resolve(token).await?;
        if !grant.fleet && grant.namespaces.is_empty() {
            return None;
        }
        let lifetime = value
            .pointer("/data/tokens/expiresIn")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600)
            .min(86400);
        Some((token.to_owned(), lifetime))
    }

    /// The grant behind `bearer`, or `None` when the auth service refuses it
    /// (or cannot be reached — an outage fails closed).
    pub async fn resolve(&self, bearer: &str) -> Option<Arc<Grant>> {
        if bearer.is_empty() || bearer.starts_with(LOCAL_TOKEN_PREFIX) {
            return None;
        }
        let key: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let now = Instant::now();
        if let Some(cached) = self.cached(&key, now) {
            return cached;
        }
        let fetched = self.fetch(bearer).await;
        let entry = match &fetched {
            Some((grant, ttl)) => Entry::Hit(grant.clone(), now + *ttl),
            None => Entry::Miss(now + MISS_TTL.min(self.ttl)),
        };
        self.store(key, entry, now);
        fetched.map(|(g, _)| g)
    }

    /// `Some(answer)` when the cache has an unexpired entry, where `answer` is
    /// itself `None` for a remembered refusal.
    fn cached(&self, key: &[u8; 32], now: Instant) -> Option<Option<Arc<Grant>>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        match cache.get(key) {
            Some(e) if e.expires_at() > now => Some(match e {
                Entry::Hit(g, _) => Some(g.clone()),
                Entry::Miss(_) => None,
            }),
            _ => None,
        }
    }

    fn store(&self, key: [u8; 32], entry: Entry, now: Instant) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_ENTRIES {
            cache.retain(|_, e| e.expires_at() > now);
        }
        cache.insert(key, entry);
    }

    async fn fetch(&self, bearer: &str) -> Option<(Arc<Grant>, Duration)> {
        let url = format!("{}/api/auth/scopes", self.base_url);
        let resp = match self.http.get(&url).bearer_auth(bearer).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "auth service unreachable; refusing federated bearer");
                return None;
            }
        };
        let status = resp.status();
        if !status.is_success() {
            tracing::debug!(status = %status, "auth service refused federated bearer");
            return None;
        }
        let env: Envelope = match resp.json().await {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "auth service returned an unparseable scopes response");
                return None;
            }
        };
        let (Some(data), true) = (env.data, env.success) else {
            return None;
        };
        let (namespaces, fleet) = Self::parse_scopes(&data.scopes);
        let accounts: BTreeMap<String, String> = data
            .namespaces
            .into_iter()
            .filter_map(|n| n.account_id.map(|a| (n.name, a)))
            .collect();
        let ttl = data
            .expires_in
            .map(Duration::from_secs)
            .map_or(self.ttl, |e| e.min(self.ttl));
        tracing::debug!(
            user = %data.subject.user_id,
            namespaces = namespaces.len(),
            fleet,
            "resolved federated bearer"
        );
        Some((
            Arc::new(Grant {
                subject: data.subject,
                namespaces,
                accounts,
                fleet,
            }),
            ttl,
        ))
    }

    /// The scope grammar. Pure, so it is tested without a server.
    ///
    /// A namespace granted twice keeps the stronger tier. A namespace that
    /// would not validate as a spec's namespace is dropped: it could never
    /// match a deployment, and letting it into the map would only make the
    /// grant *look* wider than it is.
    pub fn parse_scopes(scopes: &[String]) -> (BTreeMap<String, AdminScope>, bool) {
        let mut namespaces: BTreeMap<String, AdminScope> = BTreeMap::new();
        let mut fleet = false;
        for scope in scopes {
            let parts: Vec<&str> = scope.split(':').collect();
            match parts.as_slice() {
                ["fleet", "admin"] => fleet = true,
                ["namespace", ns, tier] if crate::config::is_valid_namespace(ns) => {
                    let granted = match *tier {
                        "admin" => AdminScope::Admin,
                        "view" => AdminScope::View,
                        _ => {
                            tracing::debug!(scope = %scope, "ignoring scope with unknown tier");
                            continue;
                        }
                    };
                    let slot = namespaces
                        .entry((*ns).to_string())
                        .or_insert(AdminScope::None);
                    if granted.satisfies(*slot) {
                        *slot = granted;
                    }
                }
                _ => tracing::debug!(scope = %scope, "ignoring unrecognised scope"),
            }
        }
        (namespaces, fleet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn the_scope_grammar_is_parsed_and_the_rest_ignored() {
        let (ns, fleet) = FederatedAuth::parse_scopes(&s(&[
            "namespace:team-a:admin",
            "namespace:team-b:view",
            "namespace:team-b:admin",   // stronger duplicate wins
            "namespace:team-c:owner",   // unknown tier
            "namespace:bad name:admin", // invalid namespace
            "billing:read",             // not ours
        ]));
        assert!(!fleet);
        assert_eq!(ns.get("team-a"), Some(&AdminScope::Admin));
        assert_eq!(ns.get("team-b"), Some(&AdminScope::Admin));
        assert!(!ns.contains_key("team-c"));
        assert_eq!(ns.len(), 2);

        let (ns, fleet) = FederatedAuth::parse_scopes(&s(&["fleet:admin"]));
        assert!(fleet);
        assert!(ns.is_empty());
    }

    #[derive(Clone)]
    struct Mock {
        calls: Arc<AtomicUsize>,
        body: Arc<serde_json::Value>,
    }

    async fn scopes(
        State(m): State<Mock>,
        headers: HeaderMap,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        m.calls.fetch_add(1, Ordering::SeqCst);
        let ok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "Bearer good");
        if ok {
            (axum::http::StatusCode::OK, Json((*m.body).clone()))
        } else {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"success": false, "code": "INVALID_TOKEN"})),
            )
        }
    }

    async fn serve(body: serde_json::Value) -> (String, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Mock {
            calls: calls.clone(),
            body: Arc::new(body),
        };
        let app = Router::new()
            .route("/api/auth/scopes", get(scopes))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/"), calls)
    }

    fn good_body() -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "data": {
                "subject": {"userId": "u1", "email": "a@b", "accountId": "acc", "platformRole": "user"},
                "scopes": ["namespace:team-a:admin"],
                "namespaces": [{"name": "team-a", "accountId": "acc-team-a", "scope": "admin"}],
                "expiresIn": 3600
            }
        })
    }

    #[tokio::test]
    async fn browser_login_takes_fleet_or_namespace_scopes_not_email_or_claimed_role() {
        use axum::routing::post;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/api/auth/login", post(|Json(body): Json<serde_json::Value>| async move {
                assert_eq!(body["password"], "p&ss word");
                let token = match body["email"].as_str().unwrap() {
                    "first@example.com" => "first", "second@example.net" => "second",
                    "admin@heyo.computer" => "ordinary", _ => "nobody",
                };
                Json(serde_json::json!({"success":true,"data":{"tokens":{"accessToken":token,"expiresIn":123}}}))
            }))
            .route("/api/auth/scopes", get(|headers: HeaderMap| async move {
                let bearer = headers.get("authorization").and_then(|h| h.to_str().ok());
                let scopes = match bearer {
                    // Two fleet admins, by scope.
                    Some("Bearer first" | "Bearer second") => vec!["fleet:admin"],
                    // An administrator-looking email and platformRole with one
                    // namespace: a confined grant, not a fleet one — the claim
                    // never mattered, but the namespace is a real sign-in now.
                    Some("Bearer ordinary") => vec!["namespace:team-a:admin"],
                    // And a bearer that reaches nothing at all is nobody's
                    // sign-in, whatever the login response said.
                    _ => vec![] as Vec<&str>,
                };
                Json(serde_json::json!({"success":true,"data":{
                    "subject":{"userId":"u1","email":"admin@heyo.computer","platformRole":"admin"},
                    "scopes":scopes,"expiresIn":123}}))
            }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let auth = FederatedAuth::new(url, 60, 5);
        assert_eq!(
            auth.login("first@example.com", "p&ss word").await,
            Some(("first".into(), 123))
        );
        assert_eq!(
            auth.login("second@example.net", "p&ss word").await,
            Some(("second".into(), 123))
        );
        // The namespace-only caller signs in: the dashboard's client-side nudge
        // takes them to the rollup. Their `platformRole` claim did not make
        // them fleet — it simply is not a privilege here.
        assert_eq!(
            auth.login("admin@heyo.computer", "p&ss word").await,
            Some(("ordinary".into(), 123))
        );
        // A grant that reaches neither the fleet nor any namespace is a refusal.
        assert_eq!(auth.login("nobody@example.org", "p&ss word").await, None);
        server.abort();
    }

    #[tokio::test]
    async fn browser_login_never_redirects_passwords_or_uses_remote_plaintext() {
        use axum::routing::post;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let captured = calls.clone();
        let app = Router::new()
            .route(
                "/api/auth/login",
                post(|| async { axum::response::Redirect::temporary("/capture") }),
            )
            .route(
                "/capture",
                post(move || {
                    captured.fetch_add(1, Ordering::SeqCst);
                    async { "unexpected" }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        assert!(
            FederatedAuth::new(url, 60, 5)
                .login("a@b", "test")
                .await
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            FederatedAuth::new("http://auth.example.com".into(), 60, 1)
                .login("a@b", "test")
                .await
                .is_none()
        );
        server.abort();
    }

    #[tokio::test]
    async fn the_namespace_owner_is_taken_from_the_grant_and_falls_back_to_the_subject() {
        let (url, _) = serve(good_body()).await;
        let g = FederatedAuth::new(url, 60, 5)
            .resolve("good")
            .await
            .expect("resolved");
        assert_eq!(g.account_for("team-a"), Some("acc-team-a"));
        // A namespace the auth service named no owner for bills the caller.
        assert_eq!(g.account_for("team-b"), Some("acc"));

        // An auth service that predates `namespaces[]` still resolves; every
        // namespace then bills the caller's own account.
        let mut old = good_body();
        old["data"].as_object_mut().unwrap().remove("namespaces");
        let (url, _) = serve(old).await;
        let g = FederatedAuth::new(url, 60, 5)
            .resolve("good")
            .await
            .expect("resolved");
        assert!(g.accounts.is_empty());
        assert_eq!(g.account_for("team-a"), Some("acc"));
    }

    #[tokio::test]
    async fn a_good_bearer_is_resolved_once_and_then_served_from_cache() {
        let (url, calls) = serve(good_body()).await;
        let auth = FederatedAuth::new(url, 60, 5);
        let g = auth.resolve("good").await.expect("resolved");
        assert_eq!(g.subject.user_id, "u1");
        assert_eq!(g.namespaces.get("team-a"), Some(&AdminScope::Admin));
        assert!(!g.fleet);
        let again = auth.resolve("good").await.expect("cached");
        assert!(Arc::ptr_eq(&g, &again));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refused_bearer_is_remembered_briefly() {
        let (url, calls) = serve(good_body()).await;
        let auth = FederatedAuth::new(url, 60, 5);
        assert!(auth.resolve("bad").await.is_none());
        assert!(auth.resolve("bad").await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the refusal was cached");
    }

    #[tokio::test]
    async fn local_tokens_and_dead_servers_never_resolve() {
        let (url, calls) = serve(good_body()).await;
        let auth = FederatedAuth::new(url, 60, 5);
        assert!(auth.resolve("applb_abc_def").await.is_none());
        assert!(auth.resolve("").await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let dead = FederatedAuth::new("http://127.0.0.1:1".into(), 60, 1);
        assert!(
            dead.resolve("good").await.is_none(),
            "an outage fails closed"
        );
    }
}
