//! Who is calling, and what they may do.
//!
//! The provider model is app-lb's (`app-lb/src/admin.rs` `decide_access` and
//! `app-lb/src/federated.rs`). A bearer is resolved into a [`Principal`]: a
//! tier per namespace, optionally confined to some repos. Four kinds of
//! bearer are recognised, by shape:
//!
//! | bearer | resolved by |
//! | --- | --- |
//! | `REMOTE_ADMIN_TOKEN` | itself: the unconfined operator |
//! | `hrm_<id>_<secret>` | a token this service minted, in the control bucket |
//! | `applb_<id>_<secret>` | the app-lb admin API's `GET /whoami` (`REMOTE_APPLB_URL`) |
//! | anything else | the Heyo auth service's `GET /api/auth/scopes` (`REMOTE_AUTH_URL`) |
//!
//! Delegating `applb_*` tokens means an agent that already holds an app-lb
//! namespace token can create and push repos with it, with no second
//! credential to obtain. `hrm_*` tokens exist for the places a long-lived
//! broad token should not go: the `git` command line and an app-lb build's
//! `build.auth` secret. They are confined to one namespace, optionally to some
//! repos, and are read or write, never admin.
//!
//! Answers from the two upstreams are cached by the SHA-256 of the bearer, and
//! refusals briefly, exactly as app-lb does, so a polling client costs one
//! upstream round trip per TTL and a bad token cannot amplify against either
//! service. An unreachable upstream fails closed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::registry::valid_namespace;
use crate::sigv4;
use crate::store::{Cond, Put, Store, StoreError};

pub const TOKEN_PREFIX: &str = "hrm_";
pub const APPLB_TOKEN_PREFIX: &str = "applb_";
const MISS_TTL: Duration = Duration::from_secs(5);
/// How long a minted token's record is trusted before it is re-read, which is
/// also how long a revocation takes to reach the other region.
const TOKEN_TTL: Duration = Duration::from_secs(30);
const MAX_ENTRIES: usize = 4096;

/// Read: clone, fetch, list. Write: push and commit. Admin: create and delete
/// repos, mint and revoke tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Read,
    Write,
    Admin,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Read => "read",
            Tier::Write => "write",
            Tier::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Operator,
    Federated,
    AppToken,
    RepoToken,
}

#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    pub kind: Kind,
    pub subject: String,
    /// Unconfined at this tier, as `fleet:admin` or the operator is.
    pub fleet: Option<Tier>,
    pub namespaces: BTreeMap<String, Tier>,
    /// Namespace → owning Heyo account, when the credential says.
    #[serde(skip)]
    pub accounts: BTreeMap<String, String>,
    #[serde(skip)]
    pub own_account: Option<String>,
    /// `Some` confines a repo token to these repos; empty means all of the
    /// namespace's repos.
    pub repos: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// What a page calls this caller: an email when the credential carries
    /// one, else the subject.
    #[serde(skip)]
    pub display: Option<String>,
}

impl Principal {
    pub fn display(&self) -> &str {
        self.display.as_deref().unwrap_or(&self.subject)
    }

    pub fn tier_in(&self, ns: &str) -> Option<Tier> {
        self.fleet.max(self.namespaces.get(ns).copied())
    }

    /// Whether this caller reaches `want` in `ns` (and, for a repo-confined
    /// token, on `repo`; namespace-wide operations are refused to those).
    pub fn allows(&self, ns: &str, repo: Option<&str>, want: Tier) -> bool {
        if self.tier_in(ns).is_none_or(|t| t < want) {
            return false;
        }
        match (&self.repos, repo) {
            (Some(list), _) if list.is_empty() => true,
            (Some(list), Some(r)) => list.iter().any(|x| x == r),
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// The account a namespace's bucket belongs to, as far as this caller
    /// knows. Only consulted when a namespace is bound for the first time.
    pub fn account_for(&self, ns: &str) -> Option<String> {
        self.accounts
            .get(ns)
            .cloned()
            .or_else(|| self.own_account.clone())
    }
}

/// A minted `hrm_*` token, as stored. Only the hash of its secret is kept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub namespace: String,
    #[serde(default)]
    pub repos: Vec<String>,
    pub access: Tier,
    pub created_at: u64,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl TokenRecord {
    fn principal(&self) -> Principal {
        Principal {
            kind: Kind::RepoToken,
            subject: format!("token:{}", self.name),
            fleet: None,
            namespaces: BTreeMap::from([(self.namespace.clone(), self.access)]),
            accounts: BTreeMap::new(),
            own_account: None,
            repos: Some(self.repos.clone()),
            token_id: Some(self.id.clone()),
            display: None,
        }
    }

    /// What is safe to show: everything but the hash.
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id, "name": self.name, "namespace": self.namespace,
            "repos": self.repos, "access": self.access, "created_at": self.created_at,
            "created_by": self.created_by, "expires_at": self.expires_at,
        })
    }
}

/// The bearer a request carries: `Authorization: Bearer <t>`, or the password
/// of `Basic` (git's only way to send one; the username is ignored, or used
/// when the password is empty, as some clients put the token there).
pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?.trim();
    let (scheme, rest) = value.split_once(' ')?;
    let rest = rest.trim();
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.to_string()).filter(|t| !t.is_empty());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(rest)
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded.split_once(':').unwrap_or((decoded.as_str(), ""));
        let t = if pass.is_empty() { user } else { pass };
        return Some(t.to_string()).filter(|t| !t.is_empty());
    }
    None
}

/// A resolved principal (or a refusal) and when it stops being trusted.
type CacheEntry = (Option<Arc<Principal>>, Instant);

struct Cache {
    ttl: Duration,
    map: Mutex<HashMap<[u8; 32], CacheEntry>>,
}

impl Cache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<Option<Arc<Principal>>> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(key) {
            Some((p, at)) if *at > Instant::now() => Some(p.clone()),
            _ => None,
        }
    }

    fn put(&self, key: [u8; 32], p: Option<Arc<Principal>>) {
        let now = Instant::now();
        let until = now
            + if p.is_some() {
                self.ttl
            } else {
                MISS_TTL.min(self.ttl)
            };
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, (_, at)| *at > now);
        }
        map.insert(key, (p, until));
    }

    #[cfg(test)]
    fn forget(&self, key: &[u8; 32]) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

pub struct Authenticator {
    admin_token: Option<String>,
    auth_url: Option<String>,
    applb_url: Option<String>,
    default_account: Option<String>,
    http: reqwest::Client,
    upstream: Cache,
    tokens: Cache,
    store: Store,
    control_bucket: String,
}

#[derive(Debug)]
pub enum MintError {
    Forbidden(String),
    Invalid(String),
    Store(StoreError),
}

impl Authenticator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admin_token: Option<String>,
        auth_url: Option<String>,
        applb_url: Option<String>,
        default_account: Option<String>,
        cache_secs: u64,
        timeout_secs: u64,
        store: Store,
        control_bucket: String,
    ) -> Self {
        Self {
            admin_token,
            auth_url,
            applb_url,
            default_account,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs.max(1)))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            upstream: Cache::new(Duration::from_secs(cache_secs.max(1))),
            tokens: Cache::new(TOKEN_TTL),
            store,
            control_bucket,
        }
    }

    /// Which providers are configured, for `/healthz` and startup logs.
    pub fn providers(&self) -> Vec<&'static str> {
        let mut v = vec![TOKEN_PREFIX];
        if self.admin_token.is_some() {
            v.push("operator");
        }
        if self.applb_url.is_some() {
            v.push("applb");
        }
        if self.auth_url.is_some() {
            v.push("heyo");
        }
        v
    }

    pub async fn authenticate(&self, bearer: &str) -> Option<Arc<Principal>> {
        if bearer.is_empty() {
            return None;
        }
        if let Some(admin) = &self.admin_token
            && bool::from(admin.as_bytes().ct_eq(bearer.as_bytes()))
        {
            return Some(Arc::new(Principal {
                kind: Kind::Operator,
                subject: "operator".into(),
                fleet: Some(Tier::Admin),
                namespaces: BTreeMap::new(),
                accounts: BTreeMap::new(),
                own_account: self.default_account.clone(),
                repos: None,
                token_id: None,
                display: None,
            }));
        }
        let key: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        if bearer.starts_with(TOKEN_PREFIX) {
            if let Some(hit) = self.tokens.get(&key) {
                return hit;
            }
            let p = self.repo_token(bearer).await.map(Arc::new);
            self.tokens.put(key, p.clone());
            return p;
        }
        if let Some(hit) = self.upstream.get(&key) {
            return hit;
        }
        let p = if bearer.starts_with(APPLB_TOKEN_PREFIX) {
            self.applb(bearer).await
        } else {
            self.federated(bearer).await
        }
        .map(|mut p| {
            if p.own_account.is_none() {
                p.own_account = self.default_account.clone();
            }
            Arc::new(p)
        });
        self.upstream.put(key, p.clone());
        p
    }

    /// Whether a Heyo email/password sign-in is possible here.
    pub fn can_login(&self) -> bool {
        self.auth_url.is_some()
    }

    /// Exchange a Heyo email and password for an access token, as app-lb's
    /// dashboard sign-in does (`app-lb/src/federated.rs` `login`). The token
    /// is the session: every later request resolves it through
    /// `/api/auth/scopes`, so the namespaces it reaches are exactly the ones
    /// app-lb would grant it. Returns the token and its lifetime in seconds.
    pub async fn login(&self, email: &str, password: &str) -> Option<(String, u64)> {
        let base = self.auth_url.as_ref()?;
        let url = reqwest::Url::parse(base).ok()?;
        // Never send a password over plaintext to anything but loopback.
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback) {
            tracing::warn!("REMOTE_AUTH_URL is not https; refusing to send a password to it");
            return None;
        }
        let resp = self
            .http
            .post(format!("{base}/api/auth/login"))
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await
            .inspect_err(|e| tracing::warn!(error = %e, "auth service unreachable for sign-in"))
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return None;
        }
        let token = body.pointer("/data/tokens/accessToken")?.as_str()?;
        if !cookie_safe(token) {
            return None;
        }
        let lifetime = body
            .pointer("/data/tokens/expiresIn")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600)
            .min(86_400);
        Some((token.to_string(), lifetime))
    }

    async fn repo_token(&self, bearer: &str) -> Option<Principal> {
        let rest = bearer.strip_prefix(TOKEN_PREFIX)?;
        let (id, secret) = rest.split_once('_')?;
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let obj = match self
            .store
            .get(&self.control_bucket, &format!("tokens/{id}.json"))
            .await
        {
            Ok(Some(o)) => o,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read token record; refusing");
                return None;
            }
        };
        let rec: TokenRecord = serde_json::from_slice(&obj.bytes).ok()?;
        let presented = sigv4::sha256_hex(secret.as_bytes());
        if !bool::from(presented.as_bytes().ct_eq(rec.hash.as_bytes())) {
            return None;
        }
        if rec.expires_at.is_some_and(|e| e <= sigv4::now_unix()) {
            return None;
        }
        Some(rec.principal())
    }

    async fn applb(&self, bearer: &str) -> Option<Principal> {
        let base = self.applb_url.as_ref()?;
        let resp = self
            .http
            .get(format!("{base}/whoami"))
            .bearer_auth(bearer)
            .send()
            .await
            .inspect_err(|e| tracing::warn!(error = %e, "app-lb unreachable; refusing applb token"))
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        principal_from_whoami(&body)
    }

    async fn federated(&self, bearer: &str) -> Option<Principal> {
        let base = self.auth_url.as_ref()?;
        let url = format!("{base}/api/auth/scopes");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .inspect_err(|e| tracing::warn!(url = %url, error = %e, "auth service unreachable; refusing bearer"))
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        principal_from_scopes(&body)
    }

    /// Mint an `hrm_*` token. The caller must be an admin of `ns`, and a token
    /// is never stronger than write.
    #[allow(clippy::too_many_arguments)]
    pub async fn mint(
        &self,
        by: &Principal,
        ns: &str,
        name: &str,
        repos: Vec<String>,
        access: Tier,
        ttl_secs: Option<u64>,
        max_ttl_secs: u64,
    ) -> Result<(String, TokenRecord), MintError> {
        if !valid_namespace(ns) {
            return Err(MintError::Invalid(format!("invalid namespace {ns:?}")));
        }
        if !by.allows(ns, None, Tier::Admin) {
            return Err(MintError::Forbidden(format!(
                "minting tokens needs admin in namespace {ns}; this credential has {}",
                by.tier_in(ns).map_or("nothing", Tier::as_str)
            )));
        }
        if access == Tier::Admin {
            return Err(MintError::Invalid(
                "a repo token is read or write, never admin".into(),
            ));
        }
        let ttl = ttl_secs.unwrap_or(max_ttl_secs).min(max_ttl_secs);
        let now = sigv4::now_unix();
        let id = hex::encode(rand::random::<[u8; 8]>());
        let secret = hex::encode(rand::random::<[u8; 24]>());
        let rec = TokenRecord {
            id: id.clone(),
            name: if name.is_empty() {
                format!("token-{id}")
            } else {
                name.to_string()
            },
            hash: sigv4::sha256_hex(secret.as_bytes()),
            namespace: ns.to_string(),
            repos,
            access,
            created_at: now,
            created_by: Some(by.subject.clone()),
            expires_at: (ttl > 0).then_some(now + ttl),
        };
        let body = serde_json::to_vec_pretty(&rec).expect("serializable");
        match self
            .store
            .put(
                &self.control_bucket,
                &format!("tokens/{id}.json"),
                body,
                Cond::Absent,
            )
            .await
            .map_err(MintError::Store)?
        {
            Put::Written(_) => Ok((format!("{TOKEN_PREFIX}{id}_{secret}"), rec)),
            Put::PreconditionFailed => Err(MintError::Invalid("token id collision; retry".into())),
        }
    }

    pub async fn tokens(&self, ns: &str) -> Result<Vec<TokenRecord>, StoreError> {
        let keys = self.store.list(&self.control_bucket, "tokens/").await?;
        let mut out = Vec::new();
        for k in keys {
            if let Some(obj) = self.store.get(&self.control_bucket, &k).await?
                && let Ok(rec) = serde_json::from_slice::<TokenRecord>(&obj.bytes)
                && rec.namespace == ns
            {
                out.push(rec);
            }
        }
        Ok(out)
    }

    pub async fn token(&self, id: &str) -> Result<Option<TokenRecord>, StoreError> {
        if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None);
        }
        Ok(self
            .store
            .get(&self.control_bucket, &format!("tokens/{id}.json"))
            .await?
            .and_then(|o| serde_json::from_slice(&o.bytes).ok()))
    }

    pub async fn revoke(&self, id: &str) -> Result<(), StoreError> {
        self.store
            .delete(&self.control_bucket, &format!("tokens/{id}.json"))
            .await?;
        // Only this instance's cache can be cleared; the other region notices
        // within TOKEN_TTL.
        self.tokens
            .map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (p, _)| p.as_ref().and_then(|p| p.token_id.as_deref()) != Some(id));
        Ok(())
    }

    #[cfg(test)]
    fn forget(&self, bearer: &str) {
        let key: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        self.tokens.forget(&key);
        self.upstream.forget(&key);
    }
}

/// Whether a bearer can be a cookie value as-is: the alphabet of JWTs and of
/// every token shape here.
pub fn cookie_safe(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 3800
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Seconds until a JWT's `exp`, read without verifying it: only to size a
/// cookie, never to trust it. `None` for anything that is not a JWT.
pub fn jwt_remaining(token: &str, now: u64) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("exp")?.as_u64()?.checked_sub(now)
}

/// The Heyo auth service's `/api/auth/scopes` envelope, in the grammar app-lb
/// consumes: `namespace:<ns>:admin|view` and `fleet:admin`.
pub fn principal_from_scopes(body: &serde_json::Value) -> Option<Principal> {
    if body.get("success").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let data = body.get("data")?;
    let subject = data.pointer("/subject/userId")?.as_str()?.to_string();
    let mut namespaces = BTreeMap::new();
    let mut fleet = None;
    for scope in data
        .get("scopes")?
        .as_array()?
        .iter()
        .filter_map(|s| s.as_str())
    {
        match scope.split(':').collect::<Vec<_>>().as_slice() {
            ["fleet", "admin"] => fleet = Some(Tier::Admin),
            ["namespace", ns, tier] if valid_namespace(ns) => {
                let t = match *tier {
                    "admin" => Tier::Admin,
                    "view" => Tier::Read,
                    _ => continue,
                };
                let slot = namespaces.entry(ns.to_string()).or_insert(t);
                *slot = (*slot).max(t);
            }
            _ => {}
        }
    }
    let accounts = data
        .get("namespaces")
        .and_then(|n| n.as_array())
        .into_iter()
        .flatten()
        .filter_map(|n| {
            Some((
                n.get("name")?.as_str()?.to_string(),
                n.get("accountId")?.as_str()?.to_string(),
            ))
        })
        .collect();
    Some(Principal {
        kind: Kind::Federated,
        subject,
        fleet,
        namespaces,
        accounts,
        own_account: data
            .pointer("/subject/accountId")
            .and_then(|v| v.as_str())
            .map(String::from),
        repos: None,
        token_id: None,
        display: data
            .pointer("/subject/email")
            .and_then(|v| v.as_str())
            .filter(|e| !e.is_empty())
            .map(String::from),
    })
}

/// app-lb's `/whoami` for an `applb_*` token. Anything that is not an
/// app-token answer is refused, an `ungated` one most of all: an app-lb with
/// no gate admits every bearer, which says nothing about this one.
pub fn principal_from_whoami(body: &serde_json::Value) -> Option<Principal> {
    if body.get("caller")?.as_str()? != "app-token" {
        return None;
    }
    let mut tier = match body.get("admin_scope")?.as_str()? {
        "admin" => Tier::Admin,
        "view" => Tier::Read,
        _ => return None,
    };
    // A token confined to particular deployments was meant for those; it may
    // read repos in its namespace but not create or change them.
    let deployments: Vec<&str> = body
        .get("deployments")
        .and_then(|d| d.as_array())
        .map(|d| d.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !deployments.is_empty() && deployments != ["*"] {
        tier = tier.min(Tier::Read);
    }
    let subject = body
        .pointer("/token/name")
        .or_else(|| body.pointer("/token/id"))
        .and_then(|v| v.as_str())
        .map(|n| format!("applb:{n}"))
        .unwrap_or_else(|| "applb".into());
    let ns = body
        .get("namespace")
        .and_then(|n| n.as_str())
        .filter(|n| valid_namespace(n));
    let fleet = body.get("fleet").and_then(|f| f.as_bool()) == Some(true);
    let (fleet, namespaces) = match (fleet, ns) {
        (true, _) => (Some(tier), BTreeMap::new()),
        (false, Some(ns)) => (None, BTreeMap::from([(ns.to_string(), tier)])),
        (false, None) => return None,
    };
    Some(Principal {
        kind: Kind::AppToken,
        subject,
        fleet,
        namespaces,
        accounts: BTreeMap::new(),
        own_account: None,
        repos: None,
        token_id: None,
        display: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsStore;
    use serde_json::json;

    #[test]
    fn bearer_is_read_from_bearer_or_basic() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("abc"));
        let basic = base64::engine::general_purpose::STANDARD.encode("x-access-token:hrm_1_2");
        h.insert("authorization", format!("Basic {basic}").parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("hrm_1_2"));
        let basic = base64::engine::general_purpose::STANDARD.encode("hrm_1_2:");
        h.insert("authorization", format!("Basic {basic}").parse().unwrap());
        assert_eq!(bearer(&h).as_deref(), Some("hrm_1_2"));
        h.insert("authorization", "Digest x".parse().unwrap());
        assert_eq!(bearer(&h), None);
    }

    #[test]
    fn scopes_map_to_tiers_and_accounts() {
        let p = principal_from_scopes(&json!({"success": true, "data": {
            "subject": {"userId": "u1", "accountId": "acc"},
            "scopes": ["namespace:a:view", "namespace:a:admin", "namespace:b:view", "namespace:c:owner", "x"],
            "namespaces": [{"name": "a", "accountId": "acc-a"}]
        }}))
        .unwrap();
        assert_eq!(p.tier_in("a"), Some(Tier::Admin));
        assert_eq!(p.tier_in("b"), Some(Tier::Read));
        assert_eq!(p.tier_in("c"), None);
        assert_eq!(p.account_for("a").as_deref(), Some("acc-a"));
        assert_eq!(p.account_for("b").as_deref(), Some("acc"));
        assert!(p.allows("b", Some("r"), Tier::Read) && !p.allows("b", Some("r"), Tier::Write));
        assert!(principal_from_scopes(&json!({"success": false})).is_none());
    }

    #[test]
    fn whoami_maps_namespace_tokens_and_refuses_the_rest() {
        let ns = principal_from_whoami(&json!({
            "caller": "app-token", "admin_scope": "admin", "fleet": false,
            "namespace": "team-a", "deployments": [], "token": {"id": "t1", "name": "agent"}
        }))
        .unwrap();
        assert_eq!(ns.tier_in("team-a"), Some(Tier::Admin));
        assert_eq!(ns.tier_in("team-b"), None);
        assert_eq!(ns.subject, "applb:agent");

        let narrow = principal_from_whoami(&json!({
            "caller": "app-token", "admin_scope": "admin", "namespace": "team-a", "deployments": ["site"]
        }))
        .unwrap();
        assert_eq!(narrow.tier_in("team-a"), Some(Tier::Read));

        let fleet = principal_from_whoami(&json!({
            "caller": "app-token", "admin_scope": "admin", "fleet": true, "namespace": null, "deployments": ["*"]
        }))
        .unwrap();
        assert_eq!(fleet.tier_in("anything"), Some(Tier::Admin));

        for refused in [
            json!({"caller": "ungated", "admin_scope": "unchecked"}),
            json!({"caller": "operator", "admin_scope": "admin"}),
            json!({"caller": "app-token", "admin_scope": "none", "namespace": "a"}),
            json!({"caller": "app-token", "admin_scope": "admin", "deployments": ["x"]}),
        ] {
            assert!(principal_from_whoami(&refused).is_none(), "{refused}");
        }
    }

    #[tokio::test]
    async fn minted_tokens_are_confined_expire_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::Fs(FsStore::new(dir.path().into()));
        store.ensure_bucket("ctl").await.unwrap();
        let auth = Authenticator::new(
            Some("op".into()),
            None,
            None,
            None,
            60,
            5,
            store,
            "ctl".into(),
        );
        let op = auth.authenticate("op").await.unwrap();
        assert_eq!(op.kind, Kind::Operator);

        let (tok, rec) = auth
            .mint(
                &op,
                "team-a",
                "ci",
                vec!["site".into()],
                Tier::Write,
                Some(3600),
                86_400,
            )
            .await
            .unwrap();
        let p = auth.authenticate(&tok).await.unwrap();
        assert!(p.allows("team-a", Some("site"), Tier::Write));
        assert!(!p.allows("team-a", Some("other"), Tier::Read));
        assert!(
            !p.allows("team-a", None, Tier::Read),
            "namespace-wide ops refused"
        );
        assert!(!p.allows("team-b", Some("site"), Tier::Read));
        assert!(!p.allows("team-a", Some("site"), Tier::Admin));

        // A repo token cannot mint, and nothing mints admin.
        assert!(matches!(
            auth.mint(&p, "team-a", "", vec![], Tier::Read, None, 60)
                .await,
            Err(MintError::Forbidden(_))
        ));
        assert!(matches!(
            auth.mint(&op, "team-a", "", vec![], Tier::Admin, None, 60)
                .await,
            Err(MintError::Invalid(_))
        ));

        // A tampered secret is refused.
        let forged = format!("{}x", &tok[..tok.len() - 1]);
        assert!(auth.authenticate(&forged).await.is_none());

        assert_eq!(auth.tokens("team-a").await.unwrap().len(), 1);
        auth.revoke(&rec.id).await.unwrap();
        auth.forget(&tok);
        assert!(auth.authenticate(&tok).await.is_none());
    }
}
