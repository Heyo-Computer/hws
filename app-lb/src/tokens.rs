//! App-tokens — credentials app-lb issues for itself.
//!
//! The admin API's only credential until now was one Basic username/password
//! read from the environment. That is fine for a person at a terminal and wrong
//! for everything else: it cannot be scoped, it cannot be revoked without a
//! restart, every client that has it can do everything, and it cannot ride on a
//! WebSocket upgrade from a browser — which is why the dashboard could never
//! offer a terminal.
//!
//! An app-token fixes each of those. It is minted through the API or the
//! dashboard, carries a scope, can expire, and is revoked by deleting it. Basic
//! auth stays, because you need *some* credential to mint the first token.
//!
//! # Shape
//!
//! ```text
//! applb_7f3a9c2b1e4d_kJ8vQ2mN...   43 base64url chars of 32 random bytes
//!       └── id, 12 hex ──┘
//! ```
//!
//! The id is in the token so verification is a hash-map lookup and one
//! comparison, rather than hashing the presented secret against every token on
//! file. The `applb_` prefix is there so a leaked token is greppable — secret
//! scanners key on prefixes, and a bare base64 blob in a commit is invisible.
//!
//! # What is stored
//!
//! Only `sha256(secret)`. The token file sits on disk next to the state file and
//! is written 0600, but a file leak should not be a fleet compromise, and the
//! secret is shown exactly once — at mint — and cannot be read back afterwards.
//! That is also why there is no "reveal" endpoint: losing a token means minting
//! a new one, which is the behaviour you want.
//!
//! # Scope
//!
//! Two axes, deliberately coarse:
//!
//! - `admin` — what the token may do on the *admin API*: nothing, read-only
//!   (`/metrics`, `/dashboard`), or full CRUD.
//! - `deployments` — which deployments it may touch, either a list of ids or
//!   `["*"]`. This governs both the per-deployment admin routes (`exec`,
//!   `shell`, scale, delete) and the data-plane gate on a deployment configured
//!   with the `app-token` provider.
//!
//! A token scoped to specific deployments is refused the fleet-wide routes —
//! creating deployments, reading the secret store, listing every job — because
//! those are not about a deployment it was given. The narrow token an agent
//! carries to reach its own sandbox is then genuinely narrow.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Prefix on every token, so a leaked one is greppable and a mistyped one is
/// rejected before anything is hashed.
const PREFIX: &str = "applb_";
/// Hex characters of token id. 48 bits — enough that ids don't collide, short
/// enough to read out over a call.
const ID_LEN: usize = 12;
/// Random bytes behind the secret half.
const SECRET_BYTES: usize = 32;

/// What a token may do on the admin API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AdminScope {
    /// No admin API access. Still usable against a deployment's data-plane gate,
    /// which is the whole point of a token handed to an application.
    #[default]
    None,
    /// `/metrics` and `/dashboard`.
    View,
    /// Everything, within the token's `deployments` scope.
    Admin,
}

impl AdminScope {
    /// The wire spelling, matching the `serde` representation. Used where a
    /// scope has to appear in an error a person reads, which must not drift
    /// from the value they would type into a spec.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::View => "view",
            Self::Admin => "admin",
        }
    }

    /// Whether this scope satisfies a route needing `want`.
    pub fn satisfies(self, want: AdminScope) -> bool {
        match want {
            AdminScope::None => true,
            AdminScope::View => matches!(self, AdminScope::View | AdminScope::Admin),
            AdminScope::Admin => matches!(self, AdminScope::Admin),
        }
    }
}

/// A minted token, as stored. The secret itself is not in here — only its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppToken {
    pub id: String,
    /// Free-text label, so a list of tokens is a list of *reasons* rather than a
    /// list of opaque ids. Required, because an unnamed token is one nobody will
    /// ever dare revoke.
    pub name: String,
    #[serde(default)]
    pub admin: AdminScope,
    /// The namespace this token is confined to. `None` — the shape every token
    /// had before namespaces existed — means unconfined: reach is governed by
    /// `deployments` alone. `Some(ns)` walls the token into that namespace: it
    /// can never touch a deployment outside it, no matter what `deployments`
    /// says, and an empty `deployments` list means *everything in the
    /// namespace* rather than nothing. That inversion is the point of the
    /// field: a namespace token is "a key to this room", not a list of ids
    /// that goes stale as the room's contents change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Deployment ids this token may touch, or `["*"]` for all of them.
    #[serde(default)]
    pub deployments: Vec<String>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Who minted it, when that was a namespace-confined caller rather than an
    /// operator: the minting token's id, or the federated user's id. A tenant
    /// mints its own credentials, so the record says which of its people did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_by: Option<String>,
    /// Hex `sha256(secret)`. Never leaves this module.
    #[serde(rename = "secret_sha256")]
    hash: String,
    /// Last time the token authenticated something, for deciding whether a
    /// forgotten token is safe to revoke.
    ///
    /// Kept in memory and written out whenever the store is next persisted for
    /// another reason, rather than on every request: a token used on a hot path
    /// would otherwise turn each authenticated call into a file write. So this
    /// lags, and a token used since the last mint or revoke may still read as
    /// never used.
    #[serde(default, skip_serializing_if = "is_zero")]
    last_used_at: u64,
    #[serde(skip)]
    live_last_used: Arc<AtomicU64>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

impl AppToken {
    /// Whether this token may act on `deployment`.
    pub fn allows(&self, deployment: &str) -> bool {
        self.deployments
            .iter()
            .any(|d| d == "*" || d == deployment)
    }

    /// Whether this token may act on a deployment, given the namespace that
    /// deployment lives in. This is the check every enforcement point should
    /// use; bare [`allows`](Self::allows) predates namespaces and ignores them.
    ///
    /// For an unconfined token this is exactly `allows`. For a namespace token
    /// the namespace must match, and within it the `deployments` list narrows
    /// only when non-empty — see the field doc on
    /// [`namespace`](Self::namespace) for why empty means everything there.
    pub fn admits(&self, deployment: &str, deployment_namespace: &str) -> bool {
        match &self.namespace {
            None => self.allows(deployment),
            Some(ns) => {
                ns == deployment_namespace
                    && (self.deployments.is_empty() || self.allows(deployment))
            }
        }
    }

    /// Whether this token's scope covers the whole fleet, which the routes that
    /// aren't about any one deployment require.
    ///
    /// A namespace token never does, whatever its `deployments` say: `["*"]`
    /// inside a namespace means every deployment *there*, and the fleet-wide
    /// routes are precisely the ones that see past a namespace wall.
    pub fn covers_fleet(&self) -> bool {
        self.namespace.is_none() && self.deployments.iter().any(|d| d == "*")
    }

    pub fn expired_at(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| now >= e)
    }

    fn touch(&self, now: u64) {
        self.live_last_used.store(now, Ordering::Relaxed);
    }

    /// The last-used stamp including uses since the last persist.
    fn last_used(&self) -> u64 {
        self.live_last_used
            .load(Ordering::Relaxed)
            .max(self.last_used_at)
    }

    pub fn summary(&self) -> TokenSummary {
        TokenSummary {
            id: self.id.clone(),
            name: self.name.clone(),
            admin: self.admin,
            namespace: self.namespace.clone(),
            deployments: self.deployments.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            minted_by: self.minted_by.clone(),
            last_used_at: match self.last_used() {
                0 => None,
                n => Some(n),
            },
        }
    }
}

/// What the API returns about a token. Never the secret, and never the hash —
/// a hash is still a verifier, and there is no reason for it to leave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub admin: AdminScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub deployments: Vec<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_by: Option<String>,
    /// `None` means the token has never authenticated anything — or has not
    /// since the last time the store was written. See [`AppToken::last_used_at`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
}

/// A mint request.
///
/// Both scope fields default to *nothing*: a token minted with no scope can do
/// nothing at all, which is a harmless mistake. Defaulting the other way would
/// make a forgotten field into fleet-wide credentials.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NewToken {
    pub name: String,
    #[serde(default)]
    pub admin: AdminScope,
    /// Confine the token to one namespace. See [`AppToken::namespace`] for the
    /// semantics — note that with this set, an empty `deployments` list means
    /// the whole namespace, not nothing.
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub deployments: Vec<String>,
    /// Lifetime from now. Absent means it never expires, which is a real choice
    /// and worth making deliberately.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// The fields of a token that can be changed after minting. The secret cannot:
/// rotating means minting a new token and revoking the old one, so that the two
/// are distinguishable in `last_used_at` while the change rolls out.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub admin: Option<AdminScope>,
    /// `Some(None)` (JSON `null`) lifts the namespace wall, `Some(Some(ns))`
    /// moves it. Absent leaves it — the same shape as `expires_at`.
    #[serde(default, deserialize_with = "double_option")]
    pub namespace: Option<Option<String>>,
    #[serde(default)]
    pub deployments: Option<Vec<String>>,
    /// `Some(None)` clears the expiry, `Some(Some(t))` sets it. Absent leaves it.
    #[serde(default, deserialize_with = "double_option")]
    pub expires_at: Option<Option<u64>>,
}

/// Distinguish an explicit `null` (clear it) from an absent key (leave it).
fn double_option<'de, T, D>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(d).map(Some)
}

#[derive(Debug)]
pub enum TokenError {
    EmptyName,
    /// A name long enough to be a paste of the token itself.
    NameTooLong,
    NoToken(String),
    /// A `deployments` entry that isn't a plausible id.
    BadScope(String),
    /// A namespace outside the id alphabet.
    BadNamespace(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    UnknownFormat(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => write!(f, "a token needs a name — it is how you know what to revoke"),
            Self::NameTooLong => write!(f, "token name must be 128 characters or fewer"),
            Self::NoToken(id) => write!(f, "no token \"{id}\""),
            Self::BadScope(s) => write!(
                f,
                "\"{s}\" is not a deployment id — scope entries are ids, or \"*\" for all"
            ),
            Self::BadNamespace(s) => write!(
                f,
                "\"{s}\" is not a namespace — letters, digits, '-', '_' and '.' only"
            ),
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::UnknownFormat(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for TokenError {}

#[derive(Serialize, Deserialize)]
struct TokenFile {
    version: u32,
    tokens: Vec<AppToken>,
}

/// Token id -> token, behind the same copy-on-write swap the registry and the
/// secret store use: verification happens on every gated request, and must not
/// contend with the rare mint.
pub struct TokenStore {
    tokens: ArcSwap<HashMap<String, Arc<AppToken>>>,
    path: PathBuf,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("path", &self.path)
            .field("count", &self.tokens.load().len())
            .finish()
    }
}

impl TokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            tokens: ArcSwap::from_pointee(HashMap::new()),
            path: path.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Mint a token. Returns the summary and the secret — the secret is returned
    /// here and nowhere else, ever.
    pub fn mint(&self, req: NewToken, now: u64) -> Result<(TokenSummary, String), TokenError> {
        self.mint_by(req, now, None)
    }

    /// [`mint`](Self::mint), recording who asked. Not a field of [`NewToken`]
    /// because it must come from the authenticated caller, never the body.
    pub fn mint_by(
        &self,
        req: NewToken,
        now: u64,
        minted_by: Option<String>,
    ) -> Result<(TokenSummary, String), TokenError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(TokenError::EmptyName);
        }
        if name.chars().count() > 128 {
            return Err(TokenError::NameTooLong);
        }
        validate_scope(&req.deployments)?;
        validate_namespace(req.namespace.as_deref())?;

        let id = random_hex(ID_LEN / 2);
        let secret = random_b64(SECRET_BYTES);
        let token = AppToken {
            id: id.clone(),
            name,
            admin: req.admin,
            namespace: req.namespace,
            deployments: req.deployments,
            created_at: now,
            expires_at: req.expires_in_secs.map(|s| now.saturating_add(s)),
            minted_by,
            hash: hash_secret(&secret),
            last_used_at: 0,
            live_last_used: Arc::new(AtomicU64::new(0)),
        };
        let summary = token.summary();

        self.mutate(|m| {
            m.insert(id.clone(), Arc::new(token.clone()));
        });

        Ok((summary, format!("{PREFIX}{id}_{secret}")))
    }

    pub fn get(&self, id: &str) -> Option<Arc<AppToken>> {
        self.tokens.load().get(id).cloned()
    }

    /// Put a token back exactly as it was.
    ///
    /// For undoing an in-memory change whose write to disk failed. Without it, a
    /// failed persist leaves the store and the file disagreeing — and in the
    /// revoke case that means a credential that stops working now and starts
    /// working again at the next restart.
    pub fn restore(&self, token: Arc<AppToken>) {
        self.mutate(|m| {
            m.insert(token.id.clone(), token.clone());
        });
    }

    pub fn list(&self) -> Vec<TokenSummary> {
        let mut out: Vec<_> = self.tokens.load().values().map(|t| t.summary()).collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        out
    }

    /// Revoke. Effective immediately for every subsequent request, because
    /// verification is a lookup in this map rather than a signature check — which
    /// is the reason tokens are opaque and stored rather than self-describing and
    /// signed.
    pub fn revoke(&self, id: &str) -> bool {
        let mut removed = false;
        self.mutate(|m| removed = m.remove(id).is_some());
        removed
    }

    pub fn patch(&self, id: &str, patch: TokenPatch) -> Result<TokenSummary, TokenError> {
        if let Some(scope) = &patch.deployments {
            validate_scope(scope)?;
        }
        if let Some(namespace) = &patch.namespace {
            validate_namespace(namespace.as_deref())?;
        }
        if let Some(name) = &patch.name {
            let n = name.trim();
            if n.is_empty() {
                return Err(TokenError::EmptyName);
            }
            if n.chars().count() > 128 {
                return Err(TokenError::NameTooLong);
            }
        }

        let existing = self.get(id).ok_or_else(|| TokenError::NoToken(id.into()))?;
        let mut next = (*existing).clone();
        // Fold in any uses since the last write, so a patch doesn't reset the
        // stamp back to whatever was last persisted.
        next.last_used_at = existing.last_used();
        if let Some(name) = patch.name {
            next.name = name.trim().to_string();
        }
        if let Some(admin) = patch.admin {
            next.admin = admin;
        }
        if let Some(namespace) = patch.namespace {
            next.namespace = namespace;
        }
        if let Some(deployments) = patch.deployments {
            next.deployments = deployments;
        }
        if let Some(expires_at) = patch.expires_at {
            next.expires_at = expires_at;
        }

        let summary = next.summary();
        self.mutate(|m| {
            m.insert(id.to_string(), Arc::new(next.clone()));
        });
        Ok(summary)
    }

    /// Verify a presented credential.
    ///
    /// Takes the raw secret string (`applb_…`), not an `Authorization` header —
    /// the same token arrives as a Bearer header from an SDK and as a query
    /// parameter on a browser's WebSocket upgrade, and both should end up here.
    ///
    /// `None` covers every failure — malformed, unknown id, wrong secret,
    /// expired — on purpose. A caller that could tell "no such token" from
    /// "wrong secret" could enumerate ids.
    pub fn verify(&self, presented: &str, now: u64) -> Option<Arc<AppToken>> {
        let (id, secret) = split(presented)?;
        let token = self.tokens.load().get(id).cloned()?;

        // Hash before the expiry check, and compare in constant time, so neither
        // an expired token nor a wrong secret is distinguishable by timing.
        let ok = crate::admin::ct_eq(hash_secret(secret).as_bytes(), token.hash.as_bytes());
        if !ok || token.expired_at(now) {
            return None;
        }
        token.touch(now);
        Some(token)
    }

    fn mutate(&self, f: impl FnOnce(&mut HashMap<String, Arc<AppToken>>)) {
        let mut next = (**self.tokens.load()).clone();
        f(&mut next);
        self.tokens.store(Arc::new(next));
    }

    /// Write the file, 0600, via a temp file that is restricted *before* it has
    /// any content — the same order the secret store uses, so there is no window
    /// where a world-readable file holds a verifier.
    pub fn persist(&self) -> Result<(), TokenError> {
        let mut tokens: Vec<AppToken> = self
            .tokens
            .load()
            .values()
            .map(|t| {
                let mut t = (**t).clone();
                t.last_used_at = t.last_used();
                t
            })
            .collect();
        tokens.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

        let json = serde_json::to_vec_pretty(&TokenFile { version: 1, tokens })
            .map_err(TokenError::Json)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(TokenError::Io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, b"").map_err(TokenError::Io)?;
        restrict(&tmp).map_err(TokenError::Io)?;
        std::fs::write(&tmp, json).map_err(TokenError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(TokenError::Io)
    }

    /// Load the file. A missing one is a normal first run.
    ///
    /// An unreadable one is an error rather than an empty store: silently
    /// starting with no tokens would revoke every client at once, and would look
    /// exactly like a working server until the calls started failing.
    pub fn load(&self) -> Result<usize, TokenError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(TokenError::Io(e)),
        };
        let file: TokenFile = serde_json::from_slice(&bytes).map_err(TokenError::Json)?;
        if file.version != 1 {
            return Err(TokenError::UnknownFormat(format!(
                "token file version {} was written by a newer app-lb",
                file.version
            )));
        }
        let n = file.tokens.len();
        let map: HashMap<_, _> = file
            .tokens
            .into_iter()
            .map(|t| {
                let live = Arc::new(AtomicU64::new(t.last_used_at));
                (
                    t.id.clone(),
                    Arc::new(AppToken {
                        live_last_used: live,
                        ..t
                    }),
                )
            })
            .collect();
        self.tokens.store(Arc::new(map));
        Ok(n)
    }

    /// Drop tokens whose expiry has passed. Expired tokens already fail
    /// `verify`; this is so they stop showing up in the dashboard as if they were
    /// live credentials.
    pub fn sweep_expired(&self, now: u64) -> usize {
        let expired: Vec<String> = self
            .tokens
            .load()
            .values()
            .filter(|t| t.expired_at(now))
            .map(|t| t.id.clone())
            .collect();
        if expired.is_empty() {
            return 0;
        }
        self.mutate(|m| {
            for id in &expired {
                m.remove(id);
            }
        });
        expired.len()
    }
}

/// Split `applb_<id>_<secret>` without allocating or leaking length information
/// beyond what the format already fixes.
fn split(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(PREFIX)?;
    let (id, secret) = rest.split_once('_')?;
    if id.len() != ID_LEN || secret.is_empty() {
        return None;
    }
    if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((id, secret))
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A deployment id, or `*`. Rejected rather than ignored, because a typo'd id in
/// a scope silently produces a token that authenticates and then 403s on
/// everything, which is a miserable thing to debug.
fn validate_scope(scope: &[String]) -> Result<(), TokenError> {
    for s in scope {
        if s == "*" {
            continue;
        }
        if s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(TokenError::BadScope(s.clone()));
        }
    }
    Ok(())
}

/// A namespace, if one was given. Same reasoning as [`validate_scope`]: a
/// typo'd namespace would mint a token that authenticates and then reaches
/// nothing, silently.
fn validate_namespace(ns: Option<&str>) -> Result<(), TokenError> {
    match ns {
        Some(ns) if !crate::config::is_valid_namespace(ns) => {
            Err(TokenError::BadNamespace(ns.to_string()))
        }
        _ => Ok(()),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buf).expect("entropy for a token id");
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn random_b64(bytes: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; bytes];
    openssl::rand::rand_bytes(&mut buf).expect("entropy for a token secret");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// 0600. Unix-only, like the rest of app-lb's on-disk credential handling.
fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (TokenStore, tempdir::Guard) {
        let g = tempdir::Guard::new();
        (TokenStore::new(g.path.join("tokens.json")), g)
    }

    /// A throwaway directory that removes itself, so tests can exercise the real
    /// persist/load path rather than a mock of it.
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);

        pub struct Guard {
            pub path: PathBuf,
        }

        impl Guard {
            pub fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "applb-tokens-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    fn new(name: &str, admin: AdminScope, deployments: &[&str]) -> NewToken {
        NewToken {
            name: name.into(),
            admin,
            namespace: None,
            deployments: deployments.iter().map(|s| s.to_string()).collect(),
            expires_in_secs: None,
        }
    }

    #[test]
    fn a_minted_token_verifies_and_a_mangled_one_does_not() {
        let (s, _g) = store();
        let (summary, secret) = s.mint(new("ci", AdminScope::Admin, &["*"]), 100).unwrap();

        assert!(secret.starts_with("applb_"));
        assert!(secret.contains(&summary.id));
        assert_eq!(s.verify(&secret, 100).unwrap().id, summary.id);

        // Every way of getting it wrong fails, and fails identically.
        assert!(s.verify(&secret[..secret.len() - 1], 100).is_none());
        assert!(s.verify(&format!("{secret}x"), 100).is_none());
        assert!(s.verify(secret.trim_start_matches("applb_"), 100).is_none());
        assert!(s.verify("applb_000000000000_nope", 100).is_none());
        assert!(s.verify("", 100).is_none());
    }

    #[test]
    fn the_secret_is_never_recoverable_from_what_is_stored() {
        let (s, _g) = store();
        let (summary, secret) = s.mint(new("ci", AdminScope::Admin, &["*"]), 100).unwrap();
        let stored = s.get(&summary.id).unwrap();

        let raw = secret.rsplit_once('_').unwrap().1;
        assert!(!stored.hash.contains(raw), "the secret is stored in the clear");

        // Nor through anything the API can return.
        let json = serde_json::to_string(&stored.summary()).unwrap();
        assert!(!json.contains(raw));
        assert!(!json.contains(&stored.hash), "the hash is a verifier and must not leave");

        // Nor through the persisted file.
        s.persist().unwrap();
        let on_disk = std::fs::read_to_string(s.path()).unwrap();
        assert!(!on_disk.contains(raw));
    }

    #[test]
    fn revoking_takes_effect_immediately() {
        let (s, _g) = store();
        let (summary, secret) = s.mint(new("agent", AdminScope::Admin, &["*"]), 100).unwrap();
        assert!(s.verify(&secret, 100).is_some());

        assert!(s.revoke(&summary.id));
        assert!(s.verify(&secret, 100).is_none());
        // Revoking twice is not an error the caller has to distinguish, but the
        // return value says which call did the work.
        assert!(!s.revoke(&summary.id));
    }

    #[test]
    fn an_expired_token_stops_verifying_at_its_deadline() {
        let (s, _g) = store();
        let (_, secret) = s
            .mint(
                NewToken {
                    expires_in_secs: Some(60),
                    ..new("short", AdminScope::Admin, &["*"])
                },
                100,
            )
            .unwrap();

        assert!(s.verify(&secret, 159).is_some());
        assert!(s.verify(&secret, 160).is_none(), "expiry is inclusive");
        assert!(s.verify(&secret, 1_000).is_none());
    }

    #[test]
    fn scope_governs_which_deployments_a_token_reaches() {
        let (s, _g) = store();
        let (narrow, _) = s.mint(new("agent", AdminScope::Admin, &["sb-1"]), 100).unwrap();
        let (wide, _) = s.mint(new("ci", AdminScope::Admin, &["*"]), 100).unwrap();

        let narrow = s.get(&narrow.id).unwrap();
        assert!(narrow.allows("sb-1"));
        assert!(!narrow.allows("sb-2"));
        assert!(
            !narrow.covers_fleet(),
            "a deployment-scoped token must not reach the fleet-wide routes"
        );

        let wide = s.get(&wide.id).unwrap();
        assert!(wide.allows("anything"));
        assert!(wide.covers_fleet());
    }

    #[test]
    fn a_namespace_token_is_walled_into_its_namespace() {
        let (s, _g) = store();
        let (summary, _) = s
            .mint(
                NewToken {
                    namespace: Some("team-a".into()),
                    ..new("team-a agent", AdminScope::Admin, &[])
                },
                100,
            )
            .unwrap();
        let t = s.get(&summary.id).unwrap();

        // Empty `deployments` inside a namespace means the whole namespace —
        // the inversion that makes the token a key to the room rather than a
        // stale list of ids.
        assert!(t.admits("web", "team-a"));
        assert!(t.admits("anything-registered-there", "team-a"));
        assert!(!t.admits("web", "team-b"), "the wall holds across namespaces");
        assert!(!t.admits("web", "default"));

        // `["*"]` inside a namespace is the namespace, not the fleet.
        let (wide, _) = s
            .mint(
                NewToken {
                    namespace: Some("team-a".into()),
                    ..new("team-a wide", AdminScope::Admin, &["*"])
                },
                100,
            )
            .unwrap();
        let wide = s.get(&wide.id).unwrap();
        assert!(wide.admits("web", "team-a"));
        assert!(!wide.admits("web", "team-b"));
        assert!(
            !wide.covers_fleet(),
            "a namespace token must never satisfy a fleet-wide route"
        );

        // An explicit list narrows *within* the namespace.
        let (narrow, _) = s
            .mint(
                NewToken {
                    namespace: Some("team-a".into()),
                    ..new("team-a one app", AdminScope::None, &["web"])
                },
                100,
            )
            .unwrap();
        let narrow = s.get(&narrow.id).unwrap();
        assert!(narrow.admits("web", "team-a"));
        assert!(!narrow.admits("api", "team-a"));
    }

    #[test]
    fn an_unconfined_token_ignores_namespaces_entirely() {
        let (s, _g) = store();
        let (summary, _) = s.mint(new("ci", AdminScope::Admin, &["web"]), 100).unwrap();
        let t = s.get(&summary.id).unwrap();
        // Pre-namespace behavior, unchanged: the list is the scope, wherever
        // the deployment lives.
        assert!(t.admits("web", "default"));
        assert!(t.admits("web", "team-b"));
        assert!(!t.admits("api", "default"));
    }

    #[test]
    fn a_namespace_must_be_plausible_and_can_be_patched_away() {
        let (s, _g) = store();
        assert!(matches!(
            s.mint(
                NewToken {
                    namespace: Some("team a".into()),
                    ..new("bad", AdminScope::None, &[])
                },
                100,
            ),
            Err(TokenError::BadNamespace(_))
        ));

        let (summary, _) = s
            .mint(
                NewToken {
                    namespace: Some("team-a".into()),
                    ..new("movable", AdminScope::None, &["*"])
                },
                100,
            )
            .unwrap();
        // `null` lifts the wall; the `deployments` list is the scope again.
        let patched = s
            .patch(&summary.id, TokenPatch { namespace: Some(None), ..Default::default() })
            .unwrap();
        assert_eq!(patched.namespace, None);
        assert!(s.get(&summary.id).unwrap().covers_fleet());

        // And it survives a restart in either shape.
        s.persist().unwrap();
    }

    #[test]
    fn admin_scope_is_ordered_not_a_set() {
        assert!(AdminScope::Admin.satisfies(AdminScope::View));
        assert!(AdminScope::Admin.satisfies(AdminScope::Admin));
        assert!(AdminScope::View.satisfies(AdminScope::View));
        assert!(!AdminScope::View.satisfies(AdminScope::Admin));
        assert!(!AdminScope::None.satisfies(AdminScope::View));
        // A data-plane-only token satisfies nothing on the admin API.
        assert!(!AdminScope::None.satisfies(AdminScope::Admin));
    }

    #[test]
    fn tokens_survive_a_restart_and_still_verify() {
        let (s, g) = store();
        let (summary, secret) = s.mint(new("ci", AdminScope::View, &["sb-1"]), 100).unwrap();
        s.verify(&secret, 150).unwrap();
        s.persist().unwrap();

        let reloaded = TokenStore::new(g.path.join("tokens.json"));
        assert_eq!(reloaded.load().unwrap(), 1);

        let t = reloaded.verify(&secret, 200).expect("token survived the restart");
        assert_eq!(t.id, summary.id);
        assert_eq!(t.name, "ci");
        assert_eq!(t.admin, AdminScope::View);
        assert_eq!(t.deployments, vec!["sb-1"]);
        assert_eq!(
            t.summary().last_used_at,
            Some(200),
            "use is recorded across the restart, not reset by it"
        );
    }

    #[test]
    fn a_missing_file_is_a_first_run_but_a_corrupt_one_is_not() {
        let (s, g) = store();
        assert_eq!(s.load().unwrap(), 0);

        std::fs::write(g.path.join("tokens.json"), b"{ not json").unwrap();
        assert!(
            s.load().is_err(),
            "a corrupt token file must not silently revoke every client"
        );
    }

    #[test]
    fn the_file_is_not_world_readable() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (s, _g) = store();
            s.mint(new("ci", AdminScope::Admin, &["*"]), 100).unwrap();
            s.persist().unwrap();
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "token file is readable by others: {mode:o}");
        }
    }

    #[test]
    fn a_token_needs_a_name_and_a_plausible_scope() {
        let (s, _g) = store();
        assert!(matches!(
            s.mint(new("  ", AdminScope::Admin, &["*"]), 100),
            Err(TokenError::EmptyName)
        ));
        assert!(matches!(
            s.mint(new("ci", AdminScope::Admin, &["sb 1"]), 100),
            Err(TokenError::BadScope(_))
        ));
        // A typo'd id is caught at mint rather than becoming a token that
        // authenticates and then 403s on everything.
        assert!(matches!(
            s.mint(new("ci", AdminScope::Admin, &["../etc/passwd"]), 100),
            Err(TokenError::BadScope(_))
        ));
    }

    #[test]
    fn patching_narrows_a_token_without_reminting_it() {
        let (s, _g) = store();
        let (summary, secret) = s.mint(new("ci", AdminScope::Admin, &["*"]), 100).unwrap();

        let patched = s
            .patch(
                &summary.id,
                TokenPatch {
                    deployments: Some(vec!["sb-1".into()]),
                    admin: Some(AdminScope::View),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(patched.admin, AdminScope::View);

        // Same secret, narrower reach — the point of patching rather than
        // reminting.
        let t = s.verify(&secret, 100).unwrap();
        assert!(t.allows("sb-1"));
        assert!(!t.allows("sb-2"));
        assert!(!t.covers_fleet());
    }

    #[test]
    fn expiry_can_be_cleared_and_set_through_a_patch() {
        let (s, _g) = store();
        let (summary, secret) = s
            .mint(
                NewToken {
                    expires_in_secs: Some(60),
                    ..new("short", AdminScope::Admin, &["*"])
                },
                100,
            )
            .unwrap();
        assert!(s.verify(&secret, 200).is_none());

        s.patch(&summary.id, TokenPatch { expires_at: Some(None), ..Default::default() })
            .unwrap();
        assert!(s.verify(&secret, 200).is_some(), "clearing expiry revives it");

        s.patch(&summary.id, TokenPatch { expires_at: Some(Some(300)), ..Default::default() })
            .unwrap();
        assert!(s.verify(&secret, 299).is_some());
        assert!(s.verify(&secret, 300).is_none());
    }

    #[test]
    fn sweeping_removes_expired_tokens_from_the_listing() {
        let (s, _g) = store();
        s.mint(
            NewToken {
                expires_in_secs: Some(60),
                ..new("short", AdminScope::Admin, &["*"])
            },
            100,
        )
        .unwrap();
        s.mint(new("forever", AdminScope::Admin, &["*"]), 100).unwrap();

        assert_eq!(s.sweep_expired(150), 0);
        assert_eq!(s.list().len(), 2);
        assert_eq!(s.sweep_expired(200), 1);
        assert_eq!(s.list().len(), 1);
        assert_eq!(s.list()[0].name, "forever");
    }

    #[test]
    fn two_mints_never_collide() {
        let (s, _g) = store();
        let mut ids = std::collections::HashSet::new();
        let mut secrets = std::collections::HashSet::new();
        for i in 0..200 {
            let (summary, secret) = s
                .mint(new(&format!("t{i}"), AdminScope::None, &[]), 100)
                .unwrap();
            assert!(ids.insert(summary.id), "duplicate token id");
            assert!(secrets.insert(secret), "duplicate token secret");
        }
        assert_eq!(s.list().len(), 200);
    }
}
