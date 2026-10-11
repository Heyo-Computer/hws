//! Secrets: named bags of key/value strings, stored apart from deployments.
//!
//! Deployment specs are echoed back verbatim by the admin API and written to the
//! state file in the clear, which is fine for a port number and wrong for a git
//! token. A secret is the other half of that: values go in through the API,
//! never come back out of it, and live in their own file that only app-lb reads.
//!
//! Storage mirrors [`Registry`](crate::registry::Registry) — copy-on-write
//! behind an `ArcSwap`, persisted with write-then-rename — with two differences.
//! The file is `0600`, and when `APP_LB_SECRET_KEY` is set the whole payload is
//! sealed with AES-256-GCM before it is written, so a leaked backup of the state
//! directory is not a leaked credential. Encryption is opt-in because the key has
//! to come from somewhere, and an unavailable key would otherwise turn every
//! restart into an outage.

use crate::config::{DEFAULT_NAMESPACE, is_valid_namespace};
use crate::deployment::now_secs;
use crate::tls::restrict;
use arc_swap::ArcSwap;
use base64::Engine;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Bound into the AEAD as additional data, so a payload can't be replayed into a
/// different file format or a future version that means something else by it.
const AAD: &[u8] = b"app-lb-secrets-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A pointer to one value inside one secret, as a deployment spec spells it.
///
/// Deliberately not a value: a spec holding `{"secret": "github", "key":
/// "token"}` can be read, edited, backed up and diffed without ever carrying the
/// credential, and the indirection is what lets the token be rotated in one
/// place for every deployment that builds from that repo.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SecretRef {
    /// The secret's id.
    pub secret: String,
    /// Which key inside it. Defaults to `token`, the only key a git credential
    /// normally needs.
    #[serde(default = "default_secret_key")]
    pub key: String,
    /// Username to pair the value with, for the (rare) forge that wants a real
    /// one. GitHub, GitLab and Bitbucket all accept a placeholder next to a PAT,
    /// which is why this defaults rather than being asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The namespace the secret lives in.
    ///
    /// Stamped from the deployment's own namespace when a spec is registered
    /// (see `DeploymentSpec::normalize`), never taken from the client: a spec
    /// in `team-a` resolves `team-a`'s `github`, whatever the body said, which
    /// is the whole wall. Absent on state files written before namespaces
    /// existed and read as [`DEFAULT_NAMESPACE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

fn default_secret_key() -> String {
    "token".into()
}

impl SecretRef {
    pub fn validate(&self) -> Result<(), SecretError> {
        validate_id(&self.secret)?;
        validate_key(&self.key)
    }

    /// The namespace this reference resolves in.
    pub fn namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or(DEFAULT_NAMESPACE)
    }

    /// Bind the reference to `ns`. Overwrites, on purpose — see the field.
    pub fn scope_to(&mut self, ns: &str) {
        self.namespace = Some(ns.to_string());
    }
}

/// One stored secret.
///
/// `data` is a `BTreeMap` so the persisted file and the API's key listings have
/// a stable order — a secret that reserialized in a different order every write
/// would make the state directory impossible to diff.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecretSpec {
    pub id: String,
    /// The namespace wall this secret sits behind. Two namespaces may each
    /// hold a `github`; a deployment only ever sees its own. Omitted on the
    /// wire (and in the file) when it is the default, so a single-tenant
    /// app-lb's secrets look exactly as they did before namespaces.
    #[serde(default = "default_namespace", skip_serializing_if = "is_default_namespace")]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    /// Server-assigned, so a client can tell whether the rotation it did landed.
    /// Ignored on input.
    #[serde(default)]
    pub updated_at: u64,
}

/// What the API returns for a secret: everything except the values.
///
/// There is no endpoint that reveals a value. Reading one back would make the
/// admin API a credential store with a `GET`, and nothing app-lb does needs it —
/// the builder resolves references in-process.
#[derive(Debug, Clone, Serialize)]
pub struct SecretSummary {
    pub id: String,
    pub namespace: String,
    pub description: Option<String>,
    pub keys: Vec<String>,
    pub updated_at: u64,
    /// Whether this LB seals its secrets file (`APP_LB_SECRET_KEY` is set).
    pub encrypted_at_rest: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    EmptyId,
    BadId(String),
    /// A namespace outside the id alphabet. Same rule as a deployment's.
    BadNamespace(String),
    BadKey(String),
    NoData,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => write!(f, "secret id must not be empty"),
            Self::BadId(id) => write!(
                f,
                "secret id {id:?} is unusable: use up to 64 characters of \
                 [A-Za-z0-9._-] (it appears in admin API paths)"
            ),
            Self::BadNamespace(ns) => write!(
                f,
                "secret namespace {ns:?} is unusable: use characters of [A-Za-z0-9._-]"
            ),
            Self::BadKey(k) => write!(
                f,
                "secret key {k:?} is unusable: use up to 128 characters of [A-Za-z0-9._-]"
            ),
            Self::NoData => write!(f, "a secret must hold at least one key"),
        }
    }
}

impl std::error::Error for SecretError {}

fn validate_id(id: &str) -> Result<(), SecretError> {
    if id.trim().is_empty() {
        return Err(SecretError::EmptyId);
    }
    let ok = id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !id.contains("..");
    if ok {
        Ok(())
    } else {
        Err(SecretError::BadId(id.to_string()))
    }
}

/// Whether `id` could name a secret. For a caller that builds an id from parts
/// and would rather skip one that cannot exist than report it.
pub fn is_valid_id(id: &str) -> bool {
    validate_id(id).is_ok()
}

fn validate_key(key: &str) -> Result<(), SecretError> {
    let ok = !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(SecretError::BadKey(key.to_string()))
    }
}

fn default_namespace() -> String {
    DEFAULT_NAMESPACE.to_string()
}

fn is_default_namespace(ns: &String) -> bool {
    ns == DEFAULT_NAMESPACE
}

/// The map key: `<namespace>/<id>`. Unambiguous because neither half may
/// contain a slash.
fn store_key(namespace: &str, id: &str) -> String {
    format!("{namespace}/{id}")
}

impl SecretSpec {
    pub fn validate(&self) -> Result<(), SecretError> {
        validate_id(&self.id)?;
        if !is_valid_namespace(&self.namespace) {
            return Err(SecretError::BadNamespace(self.namespace.clone()));
        }
        if self.data.is_empty() {
            return Err(SecretError::NoData);
        }
        for key in self.data.keys() {
            validate_key(key)?;
        }
        Ok(())
    }

    fn summary(&self, encrypted_at_rest: bool) -> SecretSummary {
        SecretSummary {
            id: self.id.clone(),
            namespace: self.namespace.clone(),
            description: self.description.clone(),
            keys: self.data.keys().cloned().collect(),
            updated_at: self.updated_at,
            encrypted_at_rest,
        }
    }
}

/// The on-disk envelope. Either the secrets in the clear, or one sealed blob —
/// never a mix, so "is this file safe to copy?" has a single answer visible in
/// its first line.
#[derive(Deserialize, Serialize)]
struct SecretFile {
    version: u32,
    /// `"none"` or `"aes-256-gcm"`.
    encryption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secrets: Option<Vec<SecretSpec>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// The file is sealed and no key was configured. Fatal on purpose: starting
    /// with an empty store would let the first write overwrite secrets that are
    /// still perfectly good, just unreadable right now.
    KeyRequired,
    /// The key is set but does not open the file — a rotated or truncated
    /// `APP_LB_SECRET_KEY`, or a corrupted payload.
    Undecryptable,
    UnknownFormat(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "malformed secrets file: {e}"),
            Self::KeyRequired => write!(
                f,
                "the secrets file is encrypted but APP_LB_SECRET_KEY is not set; \
                 set the same key it was written with, or move the file aside to start over"
            ),
            Self::Undecryptable => write!(
                f,
                "the secrets file could not be decrypted with APP_LB_SECRET_KEY; \
                 the key does not match the one it was written with"
            ),
            Self::UnknownFormat(e) => write!(f, "unsupported secrets file: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Turn whatever `APP_LB_SECRET_KEY` holds into 32 bytes.
///
/// 64 hex characters are taken literally, so a key generated with `openssl rand
/// -hex 32` is used as-is; anything else is hashed, so a passphrase works too
/// without a silently-truncated key.
pub fn derive_key(material: &str) -> Vec<u8> {
    let material = material.trim();
    if material.len() == 64
        && let Ok(bytes) = hex_decode(material)
    {
        return bytes;
    }
    openssl::hash::hash(openssl::hash::MessageDigest::sha256(), material.as_bytes())
        .expect("sha256 of a byte string cannot fail")
        .to_vec()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Secret id -> secret, behind the same copy-on-write swap the registry uses.
pub struct SecretStore {
    secrets: ArcSwap<HashMap<String, Arc<SecretSpec>>>,
    path: PathBuf,
    /// 32 bytes, or `None` for plaintext-at-rest.
    key: Option<Vec<u8>>,
}

impl std::fmt::Debug for SecretStore {
    /// Hand-written so a `{:?}` of anything holding a store can't print the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("path", &self.path)
            .field("encrypted", &self.key.is_some())
            .field("count", &self.secrets.load().len())
            .finish()
    }
}

impl SecretStore {
    pub fn new(path: impl Into<PathBuf>, key: Option<Vec<u8>>) -> Self {
        Self {
            secrets: ArcSwap::from_pointee(HashMap::new()),
            path: path.into(),
            key,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }

    pub fn get(&self, namespace: &str, id: &str) -> Option<Arc<SecretSpec>> {
        self.secrets.load().get(&store_key(namespace, id)).cloned()
    }

    /// Resolve a reference to its value, in the reference's own namespace. The
    /// only path by which a stored value leaves this module, and it goes to the
    /// builder, never to a response.
    ///
    /// A reference that was never scoped resolves in the default namespace,
    /// which is where an un-namespaced app-lb keeps everything — so a
    /// single-tenant install behaves exactly as before.
    pub fn resolve(&self, r: &SecretRef) -> Result<String, ResolveError> {
        let secret = self
            .get(r.namespace(), &r.secret)
            .ok_or_else(|| ResolveError::NoSecret(r.secret.clone()))?;
        secret
            .data
            .get(&r.key)
            .cloned()
            .ok_or_else(|| ResolveError::NoKey(r.secret.clone(), r.key.clone()))
    }

    /// Every secret, or those of one namespace, id-ordered within namespace.
    pub fn list(&self, namespace: Option<&str>) -> Vec<SecretSummary> {
        let mut out: Vec<_> = self
            .secrets
            .load()
            .values()
            .filter(|s| namespace.is_none_or(|ns| s.namespace == ns))
            .map(|s| s.summary(self.is_encrypted()))
            .collect();
        out.sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
        out
    }

    pub fn summary(&self, namespace: &str, id: &str) -> Option<SecretSummary> {
        self.get(namespace, id)
            .map(|s| s.summary(self.is_encrypted()))
    }

    /// Create or replace a secret wholesale. Stamps `updated_at` server-side.
    pub fn put(&self, mut spec: SecretSpec) -> Arc<SecretSpec> {
        spec.updated_at = now_secs();
        let secret = Arc::new(spec);
        let key = store_key(&secret.namespace, &secret.id);
        self.mutate(|map| {
            map.insert(key, secret.clone());
        });
        secret
    }

    /// Merge keys into an existing secret: `Some(v)` sets, `None` removes.
    ///
    /// Rotating one key of a multi-key secret shouldn't require resending the
    /// others — a client that only knows the new value would otherwise have to
    /// read the old ones back, which is exactly what this store refuses to do.
    pub fn patch(
        &self,
        namespace: &str,
        id: &str,
        changes: BTreeMap<String, Option<String>>,
    ) -> Result<Arc<SecretSpec>, SecretError> {
        let Some(current) = self.get(namespace, id) else {
            return Err(SecretError::BadId(id.to_string()));
        };
        let mut next = (*current).clone();
        for (k, v) in changes {
            match v {
                Some(v) => {
                    validate_key(&k)?;
                    next.data.insert(k, v);
                }
                None => {
                    next.data.remove(&k);
                }
            }
        }
        if next.data.is_empty() {
            return Err(SecretError::NoData);
        }
        Ok(self.put(next))
    }

    pub fn remove(&self, namespace: &str, id: &str) -> Option<Arc<SecretSpec>> {
        let mut removed = None;
        let key = store_key(namespace, id);
        self.mutate(|map| {
            removed = map.remove(&key);
        });
        removed
    }

    fn mutate(&self, f: impl FnOnce(&mut HashMap<String, Arc<SecretSpec>>)) {
        let mut next = (**self.secrets.load()).clone();
        f(&mut next);
        self.secrets.store(Arc::new(next));
    }

    fn specs(&self) -> Vec<SecretSpec> {
        let mut out: Vec<_> = self
            .secrets
            .load()
            .values()
            .map(|s| (**s).clone())
            .collect();
        out.sort_by(|a, b| (&a.namespace, &a.id).cmp(&(&b.namespace, &b.id)));
        out
    }

    /// Serialize, seal if a key is configured, and write `0600`.
    ///
    /// The temp file is restricted *before* it is written to, not after: the
    /// window between `create` and `chmod` is short, but it is a window in which
    /// a world-readable file holds every credential this LB knows.
    pub fn persist(&self) -> Result<(), StoreError> {
        let specs = self.specs();
        let file = match &self.key {
            None => SecretFile {
                version: 1,
                encryption: "none".into(),
                secrets: Some(specs),
                nonce: None,
                tag: None,
                ciphertext: None,
            },
            Some(key) => {
                let plaintext = serde_json::to_vec(&specs).map_err(StoreError::Json)?;
                let mut nonce = [0u8; NONCE_LEN];
                openssl::rand::rand_bytes(&mut nonce).map_err(|e| {
                    StoreError::Io(std::io::Error::other(format!("no entropy: {e}")))
                })?;
                let mut tag = [0u8; TAG_LEN];
                let ciphertext = encrypt_aead(
                    Cipher::aes_256_gcm(),
                    key,
                    Some(&nonce),
                    AAD,
                    &plaintext,
                    &mut tag,
                )
                .map_err(|e| StoreError::Io(std::io::Error::other(format!("seal failed: {e}"))))?;
                SecretFile {
                    version: 1,
                    encryption: "aes-256-gcm".into(),
                    secrets: None,
                    nonce: Some(b64().encode(nonce)),
                    tag: Some(b64().encode(tag)),
                    ciphertext: Some(b64().encode(ciphertext)),
                }
            }
        };

        let json = serde_json::to_vec_pretty(&file).map_err(StoreError::Json)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, b"").map_err(StoreError::Io)?;
        restrict(&tmp).map_err(StoreError::Io)?;
        std::fs::write(&tmp, json).map_err(StoreError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(StoreError::Io)
    }

    /// Load the file. A missing one is a normal first run.
    ///
    /// Unlike the deployment registry, a secret that fails validation is *not*
    /// skipped — a half-loaded secret store would let a build run with a
    /// credential the operator thinks was rotated. Anything unreadable is an
    /// error the caller is expected to treat as fatal.
    pub fn load(&self) -> Result<usize, StoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StoreError::Io(e)),
        };
        let file: SecretFile = serde_json::from_slice(&bytes).map_err(StoreError::Json)?;
        if file.version != 1 {
            return Err(StoreError::UnknownFormat(format!(
                "version {} was written by a newer app-lb",
                file.version
            )));
        }

        let specs: Vec<SecretSpec> = match file.encryption.as_str() {
            "none" => {
                if self.key.is_some() {
                    tracing::info!(
                        path = %self.path.display(),
                        "secrets file is plaintext but APP_LB_SECRET_KEY is set; it will be \
                         encrypted on the next write"
                    );
                }
                file.secrets.unwrap_or_default()
            }
            "aes-256-gcm" => {
                let Some(key) = &self.key else {
                    return Err(StoreError::KeyRequired);
                };
                let decode = |v: Option<String>| -> Result<Vec<u8>, StoreError> {
                    let s = v.ok_or_else(|| {
                        StoreError::UnknownFormat("sealed file is missing a field".into())
                    })?;
                    b64().decode(s).map_err(|e| {
                        StoreError::UnknownFormat(format!("sealed field is not base64: {e}"))
                    })
                };
                let nonce = decode(file.nonce)?;
                let tag = decode(file.tag)?;
                let ciphertext = decode(file.ciphertext)?;
                let plaintext = decrypt_aead(
                    Cipher::aes_256_gcm(),
                    key,
                    Some(&nonce),
                    AAD,
                    &ciphertext,
                    &tag,
                )
                .map_err(|_| StoreError::Undecryptable)?;
                serde_json::from_slice(&plaintext).map_err(StoreError::Json)?
            }
            other => {
                return Err(StoreError::UnknownFormat(format!(
                    "unknown encryption {other:?}"
                )));
            }
        };

        let mut map = HashMap::new();
        for spec in specs {
            spec.validate().map_err(|e| StoreError::UnknownFormat(e.to_string()))?;
            map.insert(store_key(&spec.namespace, &spec.id), Arc::new(spec));
        }
        let count = map.len();
        self.secrets.store(Arc::new(map));
        Ok(count)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    NoSecret(String),
    NoKey(String, String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSecret(id) => write!(f, "no secret {id:?}"),
            Self::NoKey(id, key) => write!(f, "secret {id:?} has no key {key:?}"),
        }
    }
}

impl std::error::Error for ResolveError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "app-lb-secrets-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn secret(id: &str, key: &str, value: &str) -> SecretSpec {
        SecretSpec {
            namespace: crate::config::DEFAULT_NAMESPACE.to_string(),
            id: id.into(),
            description: None,
            data: BTreeMap::from([(key.to_string(), value.to_string())]),
            updated_at: 0,
        }
    }

    /// Two namespaces may each hold a `github`; a reference resolves in its
    /// own namespace and nowhere else, and an unscoped one means `default`.
    #[test]
    fn namespaces_wall_secrets_off_from_each_other() {
        let store = SecretStore::new(temp_dir("ns").join("s.json"), None);
        store.put(secret("github", "token", "default-token"));
        let mut b = secret("github", "token", "team-b-token");
        b.namespace = "team-b".into();
        store.put(b);

        let r = |ns: Option<&str>| SecretRef {
            secret: "github".into(),
            key: "token".into(),
            username: None,
            namespace: ns.map(str::to_string),
        };
        assert_eq!(store.resolve(&r(None)).unwrap(), "default-token");
        assert_eq!(store.resolve(&r(Some("default"))).unwrap(), "default-token");
        assert_eq!(store.resolve(&r(Some("team-b"))).unwrap(), "team-b-token");
        assert_eq!(
            store.resolve(&r(Some("team-c"))),
            Err(ResolveError::NoSecret("github".into()))
        );

        assert_eq!(store.list(None).len(), 2);
        let only_b = store.list(Some("team-b"));
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b[0].namespace, "team-b");
        assert!(store.list(Some("team-c")).is_empty());

        // Removing one leaves the other's alone.
        assert!(store.remove("team-b", "github").is_some());
        assert!(store.get("team-b", "github").is_none());
        assert!(store.get(DEFAULT_NAMESPACE, "github").is_some());

        // Round-trips through the file with the wall intact.
        let mut c = secret("github", "token", "c");
        c.namespace = "team-c".into();
        store.put(c);
        store.persist().unwrap();
        let reopened = SecretStore::new(store.path().to_path_buf(), None);
        assert_eq!(reopened.load().unwrap(), 2);
        assert_eq!(reopened.resolve(&r(Some("team-c"))).unwrap(), "c");
        assert!(reopened.get("team-c", "nope").is_none());

        let mut bad = secret("x", "token", "v");
        bad.namespace = "has/slash".into();
        assert!(matches!(bad.validate(), Err(SecretError::BadNamespace(_))));
    }

    #[test]
    fn a_summary_never_carries_a_value() {
        let store = SecretStore::new("unused.json", None);
        store.put(secret("github", "token", "ghp_supersecret"));
        let json = serde_json::to_string(&store.list(None)).unwrap();
        assert!(json.contains("token"), "keys are listed");
        assert!(!json.contains("ghp_supersecret"), "values are not: {json}");
    }

    #[test]
    fn resolve_finds_the_value_and_names_what_is_missing() {
        let store = SecretStore::new("unused.json", None);
        store.put(secret("github", "token", "ghp_1"));

        let r = SecretRef {
            namespace: None,
            secret: "github".into(),
            key: "token".into(),
            username: None,
        };
        assert_eq!(store.resolve(&r).unwrap(), "ghp_1");

        let missing_key = SecretRef {
            namespace: None,
            key: "other".into(),
            ..r.clone()
        };
        assert_eq!(
            store.resolve(&missing_key),
            Err(ResolveError::NoKey("github".into(), "other".into()))
        );

        let missing_secret = SecretRef {
            namespace: None,
            secret: "gitlab".into(),
            ..r
        };
        assert_eq!(
            store.resolve(&missing_secret),
            Err(ResolveError::NoSecret("gitlab".into()))
        );
    }

    #[test]
    fn patch_sets_and_removes_without_resending_the_rest() {
        let store = SecretStore::new("unused.json", None);
        let mut s = secret("forge", "token", "old");
        s.data.insert("username".into(), "bot".into());
        store.put(s);

        let updated = store
            .patch(crate::config::DEFAULT_NAMESPACE, "forge",
                BTreeMap::from([
                    ("token".to_string(), Some("new".to_string())),
                    ("username".to_string(), None),
                ]),
            )
            .unwrap();
        assert_eq!(updated.data.get("token").unwrap(), "new");
        assert!(!updated.data.contains_key("username"));

        // Emptying a secret is a delete, and delete has its own endpoint.
        assert!(matches!(
            store.patch(crate::config::DEFAULT_NAMESPACE, "forge", BTreeMap::from([("token".to_string(), None)])),
            Err(SecretError::NoData)
        ));
    }

    #[test]
    fn plaintext_round_trips() {
        let dir = temp_dir("plain");
        let path = dir.join("secrets.json");
        let store = SecretStore::new(&path, None);
        store.put(secret("github", "token", "ghp_1"));
        store.persist().unwrap();

        // Readable as-is, which is the documented cost of leaving the key unset.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("ghp_1"));

        let reopened = SecretStore::new(&path, None);
        assert_eq!(reopened.load().unwrap(), 1);
        assert_eq!(reopened.get(crate::config::DEFAULT_NAMESPACE, "github").unwrap().data["token"], "ghp_1");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn encrypted_round_trips_and_keeps_values_out_of_the_file() {
        let dir = temp_dir("sealed");
        let path = dir.join("secrets.json");
        let key = derive_key("correct horse battery staple");

        let store = SecretStore::new(&path, Some(key.clone()));
        store.put(secret("github", "token", "ghp_supersecret"));
        store.persist().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("ghp_supersecret"), "value leaked into the file");
        assert!(!raw.contains("github"), "even the id is sealed");
        assert!(raw.contains("aes-256-gcm"));

        let reopened = SecretStore::new(&path, Some(key));
        assert_eq!(reopened.load().unwrap(), 1);
        assert_eq!(reopened.get(crate::config::DEFAULT_NAMESPACE, "github").unwrap().data["token"], "ghp_supersecret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_sealed_file_will_not_open_without_or_with_the_wrong_key() {
        let dir = temp_dir("wrongkey");
        let path = dir.join("secrets.json");
        let store = SecretStore::new(&path, Some(derive_key("right")));
        store.put(secret("github", "token", "ghp_1"));
        store.persist().unwrap();

        // Refusing is the point: loading empty would let the next write destroy
        // secrets that are merely unreadable right now.
        assert!(matches!(
            SecretStore::new(&path, None).load(),
            Err(StoreError::KeyRequired)
        ));
        assert!(matches!(
            SecretStore::new(&path, Some(derive_key("wrong"))).load(),
            Err(StoreError::Undecryptable)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_plaintext_file_is_adopted_by_a_keyed_store() {
        let dir = temp_dir("migrate");
        let path = dir.join("secrets.json");
        SecretStore::new(&path, None)
            .tap_put(secret("github", "token", "ghp_1"))
            .persist()
            .unwrap();

        let key = derive_key("new-key");
        let store = SecretStore::new(&path, Some(key.clone()));
        assert_eq!(store.load().unwrap(), 1, "plaintext still loads");
        store.persist().unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("ghp_1"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_file_is_not_world_readable() {
        let dir = temp_dir("mode");
        let path = dir.join("secrets.json");
        let store = SecretStore::new(&path, None);
        store.put(secret("github", "token", "ghp_1"));
        store.persist().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "group/other bits set: {mode:o}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ids_and_keys_that_could_escape_a_url_or_a_path_are_rejected() {
        for bad in ["", "../etc", "a/b", "a b", "a?b"] {
            let mut s = secret("x", "token", "v");
            s.id = bad.into();
            assert!(s.validate().is_err(), "{bad:?} should be rejected");
        }
        let mut s = secret("ok", "token", "v");
        s.data.insert("bad key".into(), "v".into());
        assert!(matches!(s.validate(), Err(SecretError::BadKey(_))));
    }

    #[test]
    fn a_hex_key_is_used_verbatim_and_anything_else_is_hashed() {
        let hex = "0".repeat(64);
        assert_eq!(derive_key(&hex), vec![0u8; 32]);
        assert_eq!(derive_key("passphrase").len(), 32);
        assert_ne!(derive_key("passphrase"), derive_key("passphrase2"));
    }

    /// Test-only sugar so a store can be built, filled and persisted inline.
    impl SecretStore {
        fn tap_put(self, spec: SecretSpec) -> Self {
            self.put(spec);
            self
        }
    }
}
