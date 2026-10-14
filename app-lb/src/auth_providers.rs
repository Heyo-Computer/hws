//! Declared auth provider objects — reusable, namespace-scoped auth identity.
//!
//! An [`AuthProviderSpec`] is the identity half of an [`AuthGate`] on its own,
//! given a name and an owning namespace: who may enter and how they are
//! verified, without the route-scoped configuration each deployment supplies. A
//! deployment inherits one with `auth.provider_ref`, and the proxy resolves it
//! on every gated request — so editing a provider reaches every deployment that
//! names it at once.
//!
//! ## One file per object, keyed by (namespace, name)
//!
//! The same shape as [`crate::namespaces`] and `workflows.rs`, for the same
//! reasons: an unparseable object loses itself rather than the whole file, and
//! no write rewrites everything. A provider is unique within its namespace, not
//! across the fleet — two namespaces may each declare `google` — so the key is
//! the pair, and the filename encodes both.
//!
//! [`AuthGate`]: crate::config::AuthGate
//! [`AuthProviderSpec`]: crate::config::AuthProviderSpec

use crate::config::AuthProviderSpec;
use crate::fleet_store::{Collection, Expect, FileCollection, FileOptions};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The key an object is stored under: `(namespace, name)`.
type Key = (String, String);

#[derive(Debug)]
pub struct AuthProviderStore {
    providers: ArcSwap<HashMap<Key, Arc<AuthProviderSpec>>>,
    dir: PathBuf,
    records: Arc<dyn Collection>,
}

impl AuthProviderStore {
    /// `dir` is where one JSON file per object lives, derived from the state
    /// path the way the namespace store derives its directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let records = Arc::new(FileCollection::new(&dir, ".json", FileOptions::PLAIN));
        Self::with_collection(dir, records)
    }

    /// The same store over another backend. `dir` is only reported in logs.
    pub fn with_collection(dir: impl Into<PathBuf>, records: Arc<dyn Collection>) -> Self {
        Self {
            providers: ArcSwap::from_pointee(HashMap::new()),
            dir: dir.into(),
            records,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every provider declared in `namespace`, name-sorted.
    pub fn list(&self, namespace: &str) -> Vec<Arc<AuthProviderSpec>> {
        let mut out: Vec<_> = self
            .providers
            .load()
            .values()
            .filter(|p| p.namespace == namespace)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Every provider, in every namespace — for the fleet-scoped listing, which
    /// narrows itself in the handler.
    pub fn list_all(&self) -> Vec<Arc<AuthProviderSpec>> {
        let mut out: Vec<_> = self.providers.load().values().cloned().collect();
        out.sort_by(|a, b| (a.namespace.as_str(), a.name.as_str()).cmp(&(&b.namespace, &b.name)));
        out
    }

    pub fn get(&self, namespace: &str, name: &str) -> Option<Arc<AuthProviderSpec>> {
        self.providers
            .load()
            .get(&(namespace.to_string(), name.to_string()))
            .cloned()
    }

    /// Insert or replace, then persist. Validation is the caller's, so a handler
    /// can answer 400 before anything reaches the disk.
    pub fn upsert(&self, spec: AuthProviderSpec) -> Result<Arc<AuthProviderSpec>, std::io::Error> {
        let spec = Arc::new(spec);
        let mut next = (**self.providers.load()).clone();
        next.insert((spec.namespace.clone(), spec.name.clone()), spec.clone());
        self.providers.store(Arc::new(next));
        self.persist_one(&spec)?;
        Ok(spec)
    }

    /// Returns whether anything was removed, so a handler can answer 404. Any
    /// deployment still naming a removed provider is refused deletion by the
    /// handler, so this never orphans a live reference.
    pub fn remove(&self, namespace: &str, name: &str) -> Result<bool, std::io::Error> {
        let mut next = (**self.providers.load()).clone();
        let existed = next
            .remove(&(namespace.to_string(), name.to_string()))
            .is_some();
        self.providers.store(Arc::new(next));
        if existed {
            // Already gone is the desired end state.
            self.records.delete(&key(namespace, name), Expect::Any)?;
        }
        Ok(existed)
    }

    /// Write-then-rename, so a reader never sees a half-written object and a
    /// crash mid-write leaves the previous version intact.
    fn persist_one(&self, spec: &AuthProviderSpec) -> Result<(), std::io::Error> {
        let json = serde_json::to_vec_pretty(spec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.records.put(&key(&spec.namespace, &spec.name), &json, Expect::Any)?;
        Ok(())
    }

    /// Load every object from disk, skipping any that will not parse or validate.
    ///
    /// Returns `(loaded, skipped)`. A skipped object is not fatal — refusing to
    /// start over one bad file would take the load balancer down with it, and a
    /// gate that references it fails closed rather than open — but it is logged.
    pub fn load(&self) -> (usize, usize) {
        let mut loaded = HashMap::new();
        let mut skipped = 0usize;

        let entries = match self.records.list() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(dir = %self.dir.display(), error = %e, "could not list auth provider objects");
                return (0, 0);
            }
        };
        for entry in entries {
            match entry
                .body
                .ok()
                .and_then(|b| serde_json::from_slice::<AuthProviderSpec>(&b).ok())
                .map(|mut spec| {
                    // The same stamp the create path applies, so an object
                    // written before it existed resolves its secrets behind its
                    // own wall rather than in `default`.
                    spec.normalize();
                    spec
                })
            {
                Some(spec) if spec.validate().is_ok() => {
                    loaded.insert((spec.namespace.clone(), spec.name.clone()), Arc::new(spec));
                }
                _ => {
                    tracing::warn!(
                        "skipping unreadable auth provider object {}; it is still on disk",
                        entry.location
                    );
                    skipped += 1;
                }
            }
        }
        let count = loaded.len();
        self.providers.store(Arc::new(loaded));
        (count, skipped)
    }
}

/// A filename that cannot escape the directory whatever the namespace or name
/// contains. `namespace__name.json`; both are restricted to a safe alphabet by
/// validation, but a file may predate a validation change, so anything outside
/// it is encoded rather than trusted.
/// The store key: [`file_name`] without its `.json`.
fn key(namespace: &str, name: &str) -> String {
    let mut name = file_name(namespace, name);
    name.truncate(name.len() - ".json".len());
    name
}

fn file_name(namespace: &str, name: &str) -> String {
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
            .collect()
    };
    format!("{}__{}.json", safe(namespace), safe(name))
}

/// `app-lb-state.json` -> `app-lb-auth-providers.d`, beside it — the same
/// derivation `namespace_dir` uses.
pub fn auth_provider_dir(state_path: &str) -> PathBuf {
    crate::fleet_store::sibling_dir(state_path, "auth-providers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Providers;

    /// A minimal `TempDir`, copied in shape from `namespaces.rs`.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct TempDir(PathBuf);
        impl TempDir {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("app-lb-auth-providers-{}-{n}", std::process::id()));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    /// A valid Google provider in `namespace`.
    fn provider(namespace: &str, name: &str) -> AuthProviderSpec {
        AuthProviderSpec {
            name: name.into(),
            namespace: namespace.into(),
            description: None,
            created_at: 1,
            provider: Providers::default(),
            client_id: Some("cid.apps.googleusercontent.com".into()),
            client_secret: Some(crate::secrets::SecretRef {
                namespace: None,
                secret: "google".into(),
                key: "client_secret".into(),
                username: None,
            }),
            allowed_domains: vec!["example.com".into()],
            allowed_emails: vec![],
            jwt: None,
            cookie_domain: None,
        }
    }

    #[test]
    fn objects_survive_a_round_trip_through_disk() {
        let dir = tempdir::TempDir::new();
        let store = AuthProviderStore::new(dir.path());
        store.upsert(provider("team-a", "google")).unwrap();
        store.upsert(provider("team-b", "google")).unwrap();

        let reloaded = AuthProviderStore::new(dir.path());
        assert_eq!(reloaded.load(), (2, 0));
        // Same name, different namespaces, both kept and reachable by the pair.
        assert!(reloaded.get("team-a", "google").is_some());
        assert!(reloaded.get("team-b", "google").is_some());
        assert!(reloaded.get("team-a", "missing").is_none());
        assert_eq!(reloaded.list("team-a").len(), 1);
    }

    #[test]
    fn removing_takes_the_file_with_it_and_says_whether_it_was_there() {
        let dir = tempdir::TempDir::new();
        let store = AuthProviderStore::new(dir.path());
        store.upsert(provider("team-a", "google")).unwrap();
        assert!(dir.path().join("team-a__google.json").exists());

        assert!(store.remove("team-a", "google").unwrap());
        assert!(!dir.path().join("team-a__google.json").exists());
        assert!(!store.remove("team-a", "google").unwrap());
    }

    #[test]
    fn one_unreadable_object_does_not_lose_the_others() {
        let dir = tempdir::TempDir::new();
        let store = AuthProviderStore::new(dir.path());
        store.upsert(provider("team-a", "google")).unwrap();
        std::fs::write(dir.path().join("bad.json"), b"{ not json").unwrap();
        // Parses but fails validation (a Google provider with no allow-list).
        std::fs::write(
            dir.path().join("worse.json"),
            br#"{"name":"x","namespace":"team-a","provider":"google","client_id":"c"}"#,
        )
        .unwrap();

        let reloaded = AuthProviderStore::new(dir.path());
        assert_eq!(reloaded.load(), (1, 2));
        assert!(reloaded.get("team-a", "google").is_some());
    }

    #[test]
    fn the_directory_sits_beside_the_state_file() {
        assert_eq!(
            auth_provider_dir("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-auth-providers.d"),
        );
        assert_eq!(
            auth_provider_dir("state.json"),
            PathBuf::from("state-auth-providers.d")
        );
    }
}
