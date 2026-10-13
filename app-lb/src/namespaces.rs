//! Declared namespace objects.
//!
//! A namespace was a field before it was a thing: a deployment named one, and
//! that naming *was* its existence. That still works — an undeclared namespace
//! is not an error anywhere — but it left two ordinary acts impossible. You
//! could not make a room before putting something in it, and you could not say
//! what a room was for.
//!
//! So this store holds the namespaces somebody declared on purpose, and
//! `GET /namespaces` reports the union of those and the ones deployments merely
//! mention. Neither half is authoritative over the other: declaring `sam` does
//! not stop a deployment naming `bob`, and a deployment in `sam` does not
//! create the object.
//!
//! ## One file per object
//!
//! The same shape as `workflows.rs`, for the same reasons: an unparseable
//! object loses itself rather than the whole file, and no write rewrites
//! everything. Namespaces change even less often than workflows do, so this is
//! consistency rather than necessity — but the failure mode it avoids is one
//! somebody meets on their worst day.

use crate::config::NamespaceSpec;
use crate::fleet_store::{Collection, Expect, FileCollection, FileOptions};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub struct NamespaceStore {
    namespaces: ArcSwap<HashMap<String, Arc<NamespaceSpec>>>,
    dir: PathBuf,
    records: Arc<dyn Collection>,
}

impl NamespaceStore {
    /// `dir` is where one JSON file per namespace lives, derived from the state
    /// path the way the registry and the workflow store derive theirs.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let records = Arc::new(FileCollection::new(&dir, ".json", FileOptions::PLAIN));
        Self::with_collection(dir, records)
    }

    /// The same store over another backend. `dir` is only reported in logs.
    pub fn with_collection(dir: impl Into<PathBuf>, records: Arc<dyn Collection>) -> Self {
        Self {
            namespaces: ArcSwap::from_pointee(HashMap::new()),
            dir: dir.into(),
            records,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn list(&self) -> Vec<Arc<NamespaceSpec>> {
        let mut out: Vec<_> = self.namespaces.load().values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn get(&self, name: &str) -> Option<Arc<NamespaceSpec>> {
        self.namespaces.load().get(name).cloned()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.namespaces.load().contains_key(name)
    }

    /// Insert or replace, then persist. Validation is the caller's, so a handler
    /// can answer 400 before anything reaches the disk.
    pub fn upsert(&self, spec: NamespaceSpec) -> Result<Arc<NamespaceSpec>, std::io::Error> {
        let spec = Arc::new(spec);
        let mut next = (**self.namespaces.load()).clone();
        next.insert(spec.name.clone(), spec.clone());
        self.namespaces.store(Arc::new(next));
        self.persist_one(&spec)?;
        Ok(spec)
    }

    /// Returns whether anything was removed, so a handler can answer 404.
    ///
    /// Removing the *object* is all this does. Any deployment still naming it
    /// keeps working and keeps the namespace alive as an undeclared one, which
    /// is why the handler refuses a non-empty namespace rather than leaving a
    /// caller to discover that deleting it deleted nothing.
    pub fn remove(&self, name: &str) -> Result<bool, std::io::Error> {
        let mut next = (**self.namespaces.load()).clone();
        let existed = next.remove(name).is_some();
        self.namespaces.store(Arc::new(next));
        if existed {
            // Already gone is the desired end state.
            self.records.delete(&key(name), Expect::Any)?;
        }
        Ok(existed)
    }

    /// Write-then-rename, so a reader never sees a half-written object and a
    /// crash mid-write leaves the previous version intact.
    fn persist_one(&self, spec: &NamespaceSpec) -> Result<(), std::io::Error> {
        let json = serde_json::to_vec_pretty(spec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.records.put(&key(&spec.name), &json, Expect::Any)?;
        Ok(())
    }

    /// Load every object from disk, skipping any that will not parse.
    ///
    /// Returns `(loaded, skipped)`. A skipped object is not fatal — refusing to
    /// start over one bad file would take the load balancer down with it — but
    /// it is not nothing either, so the caller logs it.
    pub fn load(&self) -> (usize, usize) {
        let mut loaded = HashMap::new();
        let mut skipped = 0usize;

        let entries = match self.records.list() {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(dir = %self.dir.display(), error = %e, "could not list namespace objects");
                return (0, 0);
            }
        };
        for entry in entries {
            match entry
                .body
                .ok()
                .and_then(|b| serde_json::from_slice::<NamespaceSpec>(&b).ok())
            {
                Some(spec) if spec.validate().is_ok() => {
                    loaded.insert(spec.name.clone(), Arc::new(spec));
                }
                _ => {
                    tracing::warn!(
                        "skipping unreadable namespace object {}; it is still on disk",
                        entry.location
                    );
                    skipped += 1;
                }
            }
        }
        let count = loaded.len();
        self.namespaces.store(Arc::new(loaded));
        (count, skipped)
    }
}

/// A filename that cannot escape the directory whatever the name contains.
///
/// `is_valid_namespace` already restricts the alphabet to one that is safe
/// here, but a file on disk may predate a validation change, so anything
/// outside it is encoded rather than trusted.
fn file_name(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    format!("{safe}.json")
}

/// The store key: [`file_name`] without its `.json`.
fn key(name: &str) -> String {
    let mut name = file_name(name);
    name.truncate(name.len() - ".json".len());
    name
}

/// `app-lb-state.json` -> `app-lb-namespaces.d`, beside it.
pub fn namespace_dir(state_path: &str) -> PathBuf {
    crate::fleet_store::sibling_dir(state_path, "namespaces")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `TempDir`, copied in shape from `unpack.rs`: the repo declines
    /// to take a dependency for four lines, and this needs the same four.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct TempDir(PathBuf);
        impl TempDir {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                // Counter as well as pid: these tests run concurrently in one
                // process, and two sharing a directory is a load-only flake.
                static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("app-lb-namespaces-{}-{n}", std::process::id()));
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

    fn spec(name: &str) -> NamespaceSpec {
        NamespaceSpec { name: name.into(), description: None, created_at: 1 }
    }

    #[test]
    fn objects_survive_a_round_trip_through_disk() {
        let dir = tempdir::TempDir::new();
        let store = NamespaceStore::new(dir.path());
        store.upsert(spec("sam")).unwrap();
        store.upsert(NamespaceSpec {
            description: Some("Sam's things".into()),
            ..spec("sam-two")
        })
        .unwrap();

        let reloaded = NamespaceStore::new(dir.path());
        assert_eq!(reloaded.load(), (2, 0));
        assert_eq!(
            reloaded.list().iter().map(|n| n.name.clone()).collect::<Vec<_>>(),
            ["sam", "sam-two"],
        );
        assert_eq!(reloaded.get("sam-two").unwrap().description.as_deref(), Some("Sam's things"));
    }

    #[test]
    fn removing_takes_the_file_with_it_and_says_whether_it_was_there() {
        let dir = tempdir::TempDir::new();
        let store = NamespaceStore::new(dir.path());
        store.upsert(spec("sam")).unwrap();
        assert!(dir.path().join("sam.json").exists());

        assert!(store.remove("sam").unwrap());
        assert!(!dir.path().join("sam.json").exists());
        // Idempotent: a second delete is not an error, but it is a 404 for the
        // handler, so the boolean has to distinguish them.
        assert!(!store.remove("sam").unwrap());
    }

    #[test]
    fn one_unreadable_object_does_not_lose_the_others() {
        let dir = tempdir::TempDir::new();
        let store = NamespaceStore::new(dir.path());
        store.upsert(spec("good")).unwrap();
        std::fs::write(dir.path().join("bad.json"), b"{ not json").unwrap();
        // A file that parses but is not a legal namespace is skipped too: the
        // alphabet is what keeps these usable in a URL and a filename.
        std::fs::write(dir.path().join("worse.json"), br#"{"name":"has spaces"}"#).unwrap();

        let reloaded = NamespaceStore::new(dir.path());
        assert_eq!(reloaded.load(), (1, 2));
        assert!(reloaded.contains("good"));
    }

    #[test]
    fn the_directory_sits_beside_the_state_file() {
        assert_eq!(
            namespace_dir("/var/lib/app-lb/app-lb-state.json"),
            PathBuf::from("/var/lib/app-lb/app-lb-namespaces.d"),
        );
        assert_eq!(namespace_dir("state.json"), PathBuf::from("state-namespaces.d"));
    }
}
