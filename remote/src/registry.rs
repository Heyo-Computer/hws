//! Where things are: which bucket holds a namespace, and what a repo is made
//! of inside it.
//!
//! Layout:
//!
//! ```text
//! <control bucket>/namespaces/<ns>.json      → NamespaceBinding (account, bucket)
//! <control bucket>/tokens/<id>.json          → crate::auth::TokenRecord
//! <account bucket>/ns/<ns>/repos/<repo>/meta.json
//! <account bucket>/ns/<ns>/repos/<repo>/state.json   → RepoState, the authority
//! <account bucket>/ns/<ns>/repos/<repo>/packs/pack-<sha>.{pack,idx}
//! ```
//!
//! One bucket per Heyo **account**, named from a hash of the account id so the
//! name leaks nothing and is the same from every region. A namespace is bound
//! to its account the first time a repo is created in it, with a conditional
//! write, so the binding is decided once and every later caller (whatever kind
//! of credential it carries) finds the same bucket.
//!
//! `state.json` lists the refs *and* the packs. A pack is uploaded before the
//! state that names it, so a reader never sees a ref whose objects are missing;
//! a pack no state names is garbage from a push that lost its race.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::sigv4;
use crate::store::{Cond, Put, Store, StoreError};

pub const DEFAULT_BRANCH: &str = "main";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceBinding {
    pub namespace: String,
    pub account_id: String,
    pub bucket: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMeta {
    pub name: String,
    pub namespace: String,
    pub default_branch: String,
    pub created_at: u64,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoState {
    /// The symbolic HEAD, e.g. `refs/heads/main`.
    pub head: String,
    /// Ref name → object id.
    pub refs: BTreeMap<String, String>,
    /// Pack basenames (`pack-<sha>`), each with a `.pack` and `.idx` beside it.
    pub packs: Vec<String>,
    pub version: u64,
    pub updated_at: u64,
}

impl RepoState {
    pub fn empty(default_branch: &str) -> Self {
        Self {
            head: format!("refs/heads/{default_branch}"),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub enum RegistryError {
    Store(StoreError),
    Conflict(String),
    Invalid(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Store(e) => write!(f, "{e}"),
            RegistryError::Conflict(m) | RegistryError::Invalid(m) => f.write_str(m),
        }
    }
}

impl From<StoreError> for RegistryError {
    fn from(e: StoreError) -> Self {
        RegistryError::Store(e)
    }
}

pub type Result<T> = std::result::Result<T, RegistryError>;

/// Same rule as app-lb's `is_valid_namespace`, so a namespace there is one here.
pub fn valid_namespace(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 100
        && ns != "."
        && ns != ".."
        && ns != "api"
        && ns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub fn valid_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with(['.', '-'])
        && !name.ends_with(".git")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// `demo.git` and `demo` are the same repo in a URL.
pub fn repo_from_url(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

pub fn bucket_for_account(prefix: &str, account_id: &str) -> String {
    format!(
        "{prefix}-{}",
        &sigv4::sha256_hex(account_id.as_bytes())[..24]
    )
}

pub fn repo_prefix(ns: &str, repo: &str) -> String {
    format!("ns/{ns}/repos/{repo}/")
}

pub fn state_key(ns: &str, repo: &str) -> String {
    format!("{}state.json", repo_prefix(ns, repo))
}

pub fn pack_key(ns: &str, repo: &str, file: &str) -> String {
    format!("{}packs/{file}", repo_prefix(ns, repo))
}

fn meta_key(ns: &str, repo: &str) -> String {
    format!("{}meta.json", repo_prefix(ns, repo))
}

pub struct Registry {
    pub store: Store,
    bucket_prefix: String,
    control_bucket: String,
    bindings: Mutex<HashMap<String, NamespaceBinding>>,
    ensured: Mutex<HashSet<String>>,
}

impl Registry {
    pub fn new(store: Store, bucket_prefix: String, control_bucket: String) -> Self {
        Self {
            store,
            bucket_prefix,
            control_bucket,
            bindings: Mutex::new(HashMap::new()),
            ensured: Mutex::new(HashSet::new()),
        }
    }

    pub async fn ensure_bucket(&self, bucket: &str) -> Result<()> {
        if self.ensured.lock().unwrap().contains(bucket) {
            return Ok(());
        }
        self.store.ensure_bucket(bucket).await?;
        self.ensured.lock().unwrap().insert(bucket.to_string());
        Ok(())
    }

    /// The bucket `ns` lives in, if a repo was ever created there.
    pub async fn binding(&self, ns: &str) -> Result<Option<NamespaceBinding>> {
        if let Some(b) = self.bindings.lock().unwrap().get(ns) {
            return Ok(Some(b.clone()));
        }
        let Some(obj) = self
            .store
            .get(&self.control_bucket, &format!("namespaces/{ns}.json"))
            .await?
        else {
            return Ok(None);
        };
        let b: NamespaceBinding = serde_json::from_slice(&obj.bytes)
            .map_err(|e| RegistryError::Invalid(format!("namespace binding for {ns}: {e}")))?;
        self.bindings
            .lock()
            .unwrap()
            .insert(ns.to_string(), b.clone());
        Ok(Some(b))
    }

    /// Every namespace that has a binding, for an unconfined caller's view.
    pub async fn namespaces(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = self
            .store
            .list(&self.control_bucket, "namespaces/")
            .await?
            .iter()
            .filter_map(|k| k.strip_prefix("namespaces/")?.strip_suffix(".json"))
            .filter(|ns| valid_namespace(ns))
            .map(String::from)
            .collect();
        out.sort();
        Ok(out)
    }

    /// Bind `ns` to `account_id`'s bucket, creating the bucket, unless it is
    /// already bound, in which case the existing binding wins whoever asks.
    pub async fn bind(&self, ns: &str, account_id: &str) -> Result<NamespaceBinding> {
        if let Some(b) = self.binding(ns).await? {
            return Ok(b);
        }
        let binding = NamespaceBinding {
            namespace: ns.to_string(),
            account_id: account_id.to_string(),
            bucket: bucket_for_account(&self.bucket_prefix, account_id),
            created_at: sigv4::now_unix(),
        };
        self.ensure_bucket(&binding.bucket).await?;
        let body = serde_json::to_vec_pretty(&binding).expect("serializable");
        match self
            .store
            .put(
                &self.control_bucket,
                &format!("namespaces/{ns}.json"),
                body,
                Cond::Absent,
            )
            .await?
        {
            Put::Written(_) => {
                tracing::info!(namespace = ns, account = account_id, bucket = %binding.bucket, "bound namespace");
                self.bindings
                    .lock()
                    .unwrap()
                    .insert(ns.to_string(), binding.clone());
                Ok(binding)
            }
            // Somebody else bound it first; theirs stands.
            Put::PreconditionFailed => self.binding(ns).await?.ok_or_else(|| {
                RegistryError::Conflict(format!("namespace {ns} binding raced and vanished"))
            }),
        }
    }

    pub async fn create_repo(&self, b: &NamespaceBinding, meta: RepoMeta) -> Result<RepoMeta> {
        let (ns, name) = (meta.namespace.as_str(), meta.name.as_str());
        let body = serde_json::to_vec_pretty(&meta).expect("serializable");
        if self
            .store
            .put(&b.bucket, &meta_key(ns, name), body, Cond::Absent)
            .await?
            == Put::PreconditionFailed
        {
            return Err(RegistryError::Conflict(format!(
                "repo {ns}/{name} already exists"
            )));
        }
        let state = serde_json::to_vec_pretty(&RepoState::empty(&meta.default_branch))
            .expect("serializable");
        // Unconditional: a state left behind by a delete that crashed part-way
        // names packs that may be gone, and must not become this repo's.
        self.store
            .put(&b.bucket, &state_key(ns, name), state, Cond::None)
            .await?;
        Ok(meta)
    }

    pub async fn repo(
        &self,
        b: &NamespaceBinding,
        ns: &str,
        name: &str,
    ) -> Result<Option<RepoMeta>> {
        let Some(obj) = self.store.get(&b.bucket, &meta_key(ns, name)).await? else {
            return Ok(None);
        };
        serde_json::from_slice(&obj.bytes)
            .map(Some)
            .map_err(|e| RegistryError::Invalid(format!("repo {ns}/{name} meta: {e}")))
    }

    pub async fn list_repos(&self, b: &NamespaceBinding, ns: &str) -> Result<Vec<RepoMeta>> {
        let keys = self
            .store
            .list(&b.bucket, &format!("ns/{ns}/repos/"))
            .await?;
        let mut out = Vec::new();
        for key in keys.iter().filter(|k| k.ends_with("/meta.json")) {
            let name = key
                .trim_start_matches(&format!("ns/{ns}/repos/"))
                .trim_end_matches("/meta.json");
            if let Some(m) = self.repo(b, ns, name).await? {
                out.push(m);
            }
        }
        Ok(out)
    }

    pub async fn delete_repo(&self, b: &NamespaceBinding, ns: &str, name: &str) -> Result<usize> {
        // Meta first: once it is gone the repo is gone to every reader, and
        // a crash part-way leaves only unreachable objects behind.
        self.store.delete(&b.bucket, &meta_key(ns, name)).await?;
        Ok(self
            .store
            .delete_prefix(&b.bucket, &repo_prefix(ns, name))
            .await?
            + 1)
    }

    pub async fn state(
        &self,
        bucket: &str,
        ns: &str,
        name: &str,
    ) -> Result<(RepoState, Option<String>)> {
        state(&self.store, bucket, ns, name).await
    }
}

/// The authoritative state and its ETag (`None` when it does not exist yet).
pub async fn state(
    store: &Store,
    bucket: &str,
    ns: &str,
    name: &str,
) -> Result<(RepoState, Option<String>)> {
    match store.get(bucket, &state_key(ns, name)).await? {
        None => Ok((RepoState::empty(DEFAULT_BRANCH), None)),
        Some(obj) => {
            let s = serde_json::from_slice(&obj.bytes)
                .map_err(|e| RegistryError::Invalid(format!("repo {ns}/{name} state: {e}")))?;
            Ok((s, Some(obj.etag)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FsStore;

    #[test]
    fn names() {
        assert!(valid_namespace("team-a.prod_1"));
        assert!(!valid_namespace("api") && !valid_namespace("..") && !valid_namespace("a/b"));
        assert!(valid_repo_name("my-site.v2"));
        for bad in ["", ".hidden", "-x", "x.git", "a/b", "a b", &"x".repeat(101)] {
            assert!(!valid_repo_name(bad), "{bad:?}");
        }
        assert_eq!(repo_from_url("demo.git"), "demo");
        let b = bucket_for_account("heyo-git", "acct_123");
        assert_eq!(b.len(), "heyo-git-".len() + 24);
        assert_eq!(
            b,
            bucket_for_account("heyo-git", "acct_123"),
            "deterministic"
        );
        assert_ne!(b, bucket_for_account("heyo-git", "acct_124"));
    }

    #[tokio::test]
    async fn first_binding_wins_and_repos_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::Fs(FsStore::new(dir.path().into()));
        store.ensure_bucket("ctl").await.unwrap();
        let reg = Registry::new(store.clone(), "heyo-git".into(), "ctl".into());

        let b1 = reg.bind("team-a", "acct-1").await.unwrap();
        let b2 = reg.bind("team-a", "acct-2").await.unwrap();
        assert_eq!(b1, b2, "the first account to bind a namespace keeps it");
        // A second instance with a cold cache finds the same binding.
        let other = Registry::new(store, "heyo-git".into(), "ctl".into());
        assert_eq!(other.binding("team-a").await.unwrap(), Some(b1.clone()));

        let meta = RepoMeta {
            name: "site".into(),
            namespace: "team-a".into(),
            default_branch: DEFAULT_BRANCH.into(),
            created_at: 1,
            created_by: None,
            description: None,
        };
        reg.create_repo(&b1, meta.clone()).await.unwrap();
        assert!(matches!(
            reg.create_repo(&b1, meta).await,
            Err(RegistryError::Conflict(_))
        ));
        assert_eq!(reg.list_repos(&b1, "team-a").await.unwrap().len(), 1);
        let (s, etag) = reg.state(&b1.bucket, "team-a", "site").await.unwrap();
        assert_eq!(s.head, "refs/heads/main");
        assert!(etag.is_some());
        reg.delete_repo(&b1, "team-a", "site").await.unwrap();
        assert!(reg.repo(&b1, "team-a", "site").await.unwrap().is_none());
    }
}
