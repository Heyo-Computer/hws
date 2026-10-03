//! The store as the daemon serves it: the local [`Store`] as a cache, in front
//! of the remote tier when one is configured.
//!
//! Without a remote this is a thin pass-through and the daemon behaves exactly
//! as it always has. With one:
//!
//! - **Writes go to the remote first.** A blob upload returns only once the
//!   blob is in the bucket; a manifest is refused unless every blob it names
//!   is; a tag is refused unless what it points at is. The remote therefore
//!   never holds a pointer to nothing, and a store rebuilt from it is whole.
//! - **Blobs and manifests read through.** Both are named by their content, so
//!   a cached copy is never stale and a miss is fetched, verified against its
//!   digest, and kept. Concurrent misses on one digest share one download.
//! - **Tags revalidate.** A tag read older than `tag_ttl` asks the remote
//!   whether it changed (`If-None-Match`); a tag written in another region is
//!   therefore visible here within the TTL. If the remote cannot be reached the
//!   cached value is served and the failure logged: a boot that needs an image
//!   this region already holds should not fail because S3 is having a bad day.
//! - **Everything mutable is mirrored.** A background pass lists the remote's
//!   tags, labels, public markers and repositories and brings the local copies
//!   into line, so listings, the dashboard and the hub — which read the local
//!   store — show the global state.
//! - **The local disk is a cache.** When it runs short, blobs the remote holds
//!   and nothing has materialized are evicted, least recently used first. Real
//!   garbage collection happens against the remote, from `art s3 gc`, never
//!   here.
//!
//! The mirror only ever deletes a local object it previously copied from the
//! remote. A tag that exists only locally — written by the CLI, or left from
//! before this store had a remote — is left alone and reported, so turning the
//! remote on can never wipe a store that has not been backfilled yet.

use crate::digest::Digest;
use crate::error::{Error, Result};
use crate::labels::Label;
use crate::manifest::Manifest;
use crate::remote::{Cond, Fetched, Remote, keys};
use crate::repos::RepoMeta;
use crate::store::{BlobInfo, Store};
use crate::tags::{Ref, RepoName, TagName};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

pub const DEFAULT_TAG_TTL: Duration = Duration::from_secs(30);
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// The remote-state file under the store root: the ETag of every mutable
/// object the mirror has copied from the remote.
const STATE_FILE: &str = "remote-state.json";

#[derive(Debug, Clone)]
pub struct RegistryOptions {
    /// How long a tag read is trusted before it is revalidated.
    pub tag_ttl: Duration,
    /// How often the mirror, the public index and eviction run.
    pub sync_interval: Duration,
    /// Evict once cached blobs occupy more than this many bytes.
    pub cache_max_bytes: Option<u64>,
    /// Evict once the filesystem has less than this free.
    pub cache_min_free_bytes: u64,
    /// Never evict a blob younger than this — it may be on its way into a
    /// manifest, and the remote may not have it yet.
    pub min_age: Duration,
}

impl Default for RegistryOptions {
    fn default() -> Self {
        RegistryOptions {
            tag_ttl: DEFAULT_TAG_TTL,
            sync_interval: DEFAULT_SYNC_INTERVAL,
            cache_max_bytes: None,
            cache_min_free_bytes: 0,
            min_age: Duration::from_secs(600),
        }
    }
}

/// Which digests and repositories may be read without a credential.
///
/// Built from the local (mirrored) store: every tag in a public repository,
/// the manifest it names and every blob in that manifest. Rebuilt after every
/// write through this daemon and on every mirror pass, so checking a request
/// is a set lookup — no syscall and no remote call on the auth path.
#[derive(Debug, Clone, Default)]
pub struct PublicIndex {
    pub repos: HashSet<RepoName>,
    pub digests: HashSet<Digest>,
}

impl PublicIndex {
    pub fn repo_is_public(&self, r: &RepoName) -> bool {
        self.repos.contains(r)
    }

    pub fn tag_is_public(&self, t: &TagName) -> bool {
        t.repo().is_some_and(|r| self.repos.contains(&r))
    }
}

/// What the mirror did in one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub fetched: u64,
    pub removed: u64,
    pub local_only: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvictReport {
    pub evicted: u64,
    pub bytes_freed: u64,
}

#[derive(Clone)]
pub struct Registry {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    remote: Option<Remote>,
    opts: RegistryOptions,
    /// Remote key → ETag, for every mutable object copied from the remote.
    state: Mutex<BTreeMap<String, String>>,
    /// Remote key → when it was last confirmed current.
    checked: Mutex<HashMap<String, Instant>>,
    /// Blobs known to be in the remote.
    confirmed: Mutex<HashSet<Digest>>,
    /// One fill at a time per digest.
    fills: Mutex<HashMap<Digest, Arc<tokio::sync::Mutex<()>>>>,
    /// Last time each blob was served, for least-recently-used eviction.
    access: Mutex<HashMap<Digest, SystemTime>>,
    public: RwLock<Arc<PublicIndex>>,
}

impl Registry {
    /// A registry with no remote: the local store, served as it always was.
    pub fn local(store: Store) -> Registry {
        Registry::new(store, None, RegistryOptions::default())
    }

    pub fn new(store: Store, remote: Option<Remote>, opts: RegistryOptions) -> Registry {
        let state = load_state(&store);
        Registry {
            inner: Arc::new(Inner {
                store,
                remote,
                opts,
                state: Mutex::new(state),
                checked: Mutex::new(HashMap::new()),
                confirmed: Mutex::new(HashSet::new()),
                fills: Mutex::new(HashMap::new()),
                access: Mutex::new(HashMap::new()),
                public: RwLock::new(Arc::new(PublicIndex::default())),
            }),
        }
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    pub fn remote(&self) -> Option<&Remote> {
        self.inner.remote.as_ref()
    }

    pub fn public_index(&self) -> Arc<PublicIndex> {
        self.inner.public.read().expect("public index lock").clone()
    }

    /// Run the mirror, the public index and eviction every `sync_interval`
    /// for the life of the process. The first pass runs before this returns,
    /// so a daemon starts serving with a current index.
    pub async fn start_background(&self) {
        self.tick().await;
        let me = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(me.inner.opts.sync_interval);
            every.tick().await;
            loop {
                every.tick().await;
                me.tick().await;
            }
        });
    }

    async fn tick(&self) {
        if self.inner.remote.is_some() {
            match self.sync().await {
                Ok(r) if r.fetched > 0 || r.removed > 0 => {
                    tracing::info!(
                        fetched = r.fetched,
                        removed = r.removed,
                        "mirrored remote changes"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "mirroring the remote failed; serving the cache")
                }
            }
            if let Err(e) = self.evict().await {
                tracing::warn!(error = %e, "cache eviction failed");
            }
        }
        if let Err(e) = self.refresh_public_index().await {
            tracing::warn!(error = %e, "rebuilding the public index failed");
        }
    }

    // -- the public index --------------------------------------------------

    pub async fn refresh_public_index(&self) -> Result<()> {
        let store = &self.inner.store;
        let mut idx = PublicIndex::default();
        for (repo, meta) in store.list_repos().await? {
            if meta.public {
                idx.repos.insert(repo);
            }
        }
        if !idx.repos.is_empty() {
            for (tag, digest) in store.list_tags().await? {
                if !idx.tag_is_public(&tag) {
                    continue;
                }
                idx.digests.insert(digest.clone());
                if let Ok(m) = self.manifest(&digest).await {
                    for e in m.entries {
                        idx.digests.insert(e.digest);
                    }
                }
            }
        }
        *self.inner.public.write().expect("public index lock") = Arc::new(idx);
        Ok(())
    }

    // -- blobs -------------------------------------------------------------

    /// Make an uploaded blob durable in the remote. Called after the local
    /// insert has verified the bytes; returns once the remote holds them.
    pub async fn publish_blob(&self, d: &Digest) -> Result<()> {
        let Some(remote) = &self.inner.remote else {
            return Ok(());
        };
        if self.blob_in_remote(d).await? {
            return Ok(());
        }
        let enc = self.inner.store.encode_blob(d).await?;
        let len = enc.len();
        let started = Instant::now();
        remote.upload(&keys::blob(d), Box::new(enc), len).await?;
        tracing::info!(digest = %d, bytes = len, secs = started.elapsed().as_secs_f32(), "blob uploaded to the remote");
        self.confirm(d);
        Ok(())
    }

    fn confirm(&self, d: &Digest) {
        self.inner
            .confirmed
            .lock()
            .expect("confirmed lock")
            .insert(d.clone());
    }

    /// Whether the remote holds this blob. Cached once true — a blob, once
    /// there, only leaves through `art s3 gc`, which only takes unreachable
    /// content.
    pub async fn blob_in_remote(&self, d: &Digest) -> Result<bool> {
        let Some(remote) = &self.inner.remote else {
            return self.inner.store.has(d).await;
        };
        if self
            .inner
            .confirmed
            .lock()
            .expect("confirmed lock")
            .contains(d)
        {
            return Ok(true);
        }
        let found = remote.head(&keys::blob(d)).await?.is_some();
        if found {
            self.confirm(d);
        }
        Ok(found)
    }

    /// Make sure the blob is in the local cache, fetching it from the remote
    /// if need be. `NotFound` if neither has it.
    pub async fn ensure_blob(&self, d: &Digest) -> Result<BlobInfo> {
        self.touch(d);
        match self.inner.store.stat(d).await {
            Err(Error::NotFound(_)) if self.inner.remote.is_some() => {}
            other => return other,
        }
        let gate = {
            let mut fills = self.inner.fills.lock().expect("fills lock");
            fills.entry(d.clone()).or_default().clone()
        };
        let _one = gate.lock().await;
        // Someone else may have filled it while this request waited.
        let result = match self.inner.store.stat(d).await {
            Err(Error::NotFound(_)) => self.fill(d).await,
            other => other,
        };
        self.inner.fills.lock().expect("fills lock").remove(d);
        result
    }

    async fn fill(&self, d: &Digest) -> Result<BlobInfo> {
        let started = Instant::now();
        let info = match self.fill_once(d).await {
            Err(Error::NoSpace { .. }) => {
                // Make room and try once more; the stream is gone, so this is
                // a fresh download.
                let freed = self.evict_for(Some(d)).await?;
                tracing::info!(digest = %d, evicted = freed.evicted, "evicted to make room for a cache fill");
                self.fill_once(d).await?
            }
            other => other?,
        };
        self.confirm(d);
        tracing::info!(
            digest = %d,
            size = info.size,
            allocated = info.allocated,
            secs = started.elapsed().as_secs_f32(),
            "blob fetched from the remote"
        );
        Ok(info)
    }

    async fn fill_once(&self, d: &Digest) -> Result<BlobInfo> {
        let remote = self.inner.remote.as_ref().expect("fill needs a remote");
        let Some(reader) = remote.open(&keys::blob(d)).await? else {
            return Err(Error::NotFound(d.clone()));
        };
        let sync = tokio_util::io::SyncIoBridge::new_with_handle(
            reader,
            tokio::runtime::Handle::current(),
        );
        self.inner.store.insert_encoded(sync, d).await
    }

    fn touch(&self, d: &Digest) {
        self.inner
            .access
            .lock()
            .expect("access lock")
            .insert(d.clone(), SystemTime::now());
    }

    // -- manifests ---------------------------------------------------------

    /// A manifest by digest, reading through to the remote on a miss.
    pub async fn manifest(&self, d: &Digest) -> Result<Manifest> {
        match self.inner.store.get_manifest(d).await {
            Err(Error::NotFound(_)) if self.inner.remote.is_some() => {}
            other => return other,
        }
        self.fetch_manifest(d).await?;
        self.inner.store.get_manifest(d).await
    }

    /// Copy a manifest from the remote into the cache. `NotFound` if the
    /// remote has none by that digest.
    async fn fetch_manifest(&self, d: &Digest) -> Result<()> {
        let remote = self.inner.remote.as_ref().expect("fetch needs a remote");
        let body = match remote.get(&keys::manifest(d), None).await? {
            Fetched::Found { body, .. } => body,
            _ => return Err(Error::NotFound(d.clone())),
        };
        let actual = sha256(&body);
        if &actual != d {
            return Err(Error::DigestMismatch {
                expected: d.clone(),
                actual,
            });
        }
        // Parse before storing: an unreadable manifest is refused here rather
        // than cached and failed on every read after.
        Manifest::from_json(&body)?;
        self.inner.store.put_manifest_bytes(body).await?;
        Ok(())
    }

    async fn manifest_in_remote(&self, d: &Digest) -> Result<bool> {
        match &self.inner.remote {
            Some(remote) => Ok(remote.head(&keys::manifest(d)).await?.is_some()),
            None => Ok(self.inner.store.get_manifest(d).await.is_ok()),
        }
    }

    // -- promotion ---------------------------------------------------------
    //
    // A store that predates its remote holds content the remote has never
    // seen. Refusing every write that names such content would make the
    // first push after enabling S3 fail — a client that asks "do you have this
    // blob?" hears yes from the cache, skips the upload, and then has its
    // manifest refused. So a write that names content only this region holds
    // publishes that content first. The invariant is unchanged: the remote
    // still never holds a pointer to something it lacks.

    /// Make sure the remote holds blob `d`, publishing the local copy if only
    /// this region has it. `false` if neither does.
    async fn promote_blob(&self, d: &Digest) -> Result<bool> {
        if self.blob_in_remote(d).await? {
            return Ok(true);
        }
        if !self.inner.store.has(d).await? {
            return Ok(false);
        }
        tracing::info!(digest = %d, "publishing a blob only this region held");
        self.publish_blob(d).await?;
        Ok(true)
    }

    /// The same for a manifest, and every blob it names first.
    async fn promote_manifest(&self, d: &Digest) -> Result<bool> {
        let Some(remote) = &self.inner.remote else {
            return Ok(self.inner.store.get_manifest(d).await.is_ok());
        };
        if remote.head(&keys::manifest(d)).await?.is_some() {
            return Ok(true);
        }
        let m = match self.inner.store.get_manifest(d).await {
            Ok(m) => m,
            Err(Error::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        for e in &m.entries {
            if !self.promote_blob(&e.digest).await? {
                return Err(Error::Missing(e.digest.clone()));
            }
        }
        // The bytes on disk, not a re-serialization: they are what `d` names.
        let path = self.inner.store.inner().manifest_path_of(d);
        let bytes = tokio::fs::read(&path).await.map_err(|e| Error::Io {
            context: format!("read {}", path.display()),
            source: e,
        })?;
        tracing::info!(digest = %d, "publishing a manifest only this region held");
        match remote.put(&keys::manifest(d), bytes, Cond::IfAbsent).await {
            Ok(_) | Err(Error::PreconditionFailed(_)) => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// Whatever `d` names — manifest or blob — in the remote. `false` if
    /// neither the remote nor this region holds it.
    async fn promote(&self, d: &Digest) -> Result<bool> {
        if self.manifest_in_remote(d).await? || self.blob_in_remote(d).await? {
            return Ok(true);
        }
        Ok(self.promote_manifest(d).await? || self.promote_blob(d).await?)
    }

    /// Store a manifest — in the remote first, refusing it unless every blob
    /// it names is in the remote or can be published from this region.
    pub async fn put_manifest(&self, m: &Manifest) -> Result<Digest> {
        if let Some(remote) = &self.inner.remote {
            for e in &m.entries {
                if !self.promote_blob(&e.digest).await? {
                    return Err(Error::Missing(e.digest.clone()));
                }
            }
            let bytes = m.to_canonical_json();
            let d = sha256(&bytes);
            match remote.put(&keys::manifest(&d), bytes, Cond::IfAbsent).await {
                // Already there: content-addressed, so it is these bytes.
                Ok(_) | Err(Error::PreconditionFailed(_)) => {}
                Err(e) => return Err(e),
            }
        }
        let d = self.inner.store.put_manifest(m).await?;
        Ok(d)
    }

    // -- resolution --------------------------------------------------------

    /// A tag or digest to a digest. A tag is revalidated against the remote
    /// once its cached value is older than the TTL.
    pub async fn resolve(&self, r: &Ref) -> Result<Digest> {
        match r {
            Ref::Digest(d) => Ok(d.clone()),
            Ref::Tag(t) => self.get_tag(t).await.map(|(d, _)| d),
        }
    }

    /// Like [`Store::resolve_blob`], but reading through: a reference to a
    /// single-entry manifest resolves to its blob even when neither is cached.
    pub async fn resolve_blob(&self, r: &Ref) -> Result<Digest> {
        let d = self.resolve(r).await?;
        if self.inner.store.has(&d).await? || self.blob_in_remote(&d).await? {
            return Ok(d);
        }
        let m = match self.manifest(&d).await {
            Ok(m) => m,
            Err(Error::NotFound(_)) => return Err(Error::NotFound(d)),
            Err(e) => return Err(e),
        };
        match m.entries.len() {
            1 => Ok(m.entries[0].digest.clone()),
            _ => Err(Error::AmbiguousManifest {
                digest: d,
                entries: m.entries.iter().map(|e| e.name.clone()).collect(),
            }),
        }
    }

    // -- tags --------------------------------------------------------------

    /// What a tag points at, and its remote ETag when there is a remote.
    pub async fn get_tag(&self, t: &TagName) -> Result<(Digest, Option<String>)> {
        let store = &self.inner.store;
        let Some(remote) = &self.inner.remote else {
            return Ok((store.get_tag(t).await?, None));
        };
        let key = keys::tag(t);
        let known = self.known_etag(&key);
        let local = match store.get_tag(t).await {
            Ok(d) => Some(d),
            Err(Error::TagNotFound(_)) => None,
            Err(e) => return Err(e),
        };
        if let (Some(d), Some(etag)) = (&local, &known)
            && self.fresh(&key)
        {
            return Ok((d.clone(), Some(etag.clone())));
        }
        // Only ask "has it changed" about a copy that is actually on disk.
        let ask = if local.is_some() { known.clone() } else { None };
        match remote.get(&key, ask.as_deref()).await {
            Ok(Fetched::NotModified) => {
                self.mark_checked(&key);
                Ok((local.expect("asked only with a local copy"), known))
            }
            Ok(Fetched::Found { body, etag }) => {
                let d = crate::remote::parse_tag_body(&body)?;
                store.set_tag(t, &d).await?;
                self.remember(&key, &etag);
                Ok((d, Some(etag)))
            }
            Ok(Fetched::NotFound) => {
                if known.is_some() {
                    // It came from the remote and the remote has dropped it.
                    store.remove_tag(t).await?;
                    self.forget(&key);
                    return Err(Error::TagNotFound(t.to_string()));
                }
                // Only ever local: not backfilled yet. Serve it.
                match local {
                    Some(d) => Ok((d, None)),
                    None => Err(Error::TagNotFound(t.to_string())),
                }
            }
            Err(e) => match local {
                Some(d) => {
                    tracing::warn!(tag = %t, error = %e, "remote unreachable; serving the cached tag");
                    Ok((d, known))
                }
                None => Err(e),
            },
        }
    }

    /// Point a tag at a digest. With `if_match`, only if the tag is still at
    /// that ETag — a compare-and-swap across every region. Returns the new
    /// ETag when there is a remote.
    pub async fn set_tag(
        &self,
        t: &TagName,
        d: &Digest,
        if_match: Option<String>,
    ) -> Result<Option<String>> {
        let Some(remote) = &self.inner.remote else {
            self.inner.store.set_tag(t, d).await?;
            self.after_write().await;
            return Ok(None);
        };
        if !self.promote(d).await? {
            return Err(Error::Missing(d.clone()));
        }
        let key = keys::tag(t);
        let cond = match if_match {
            Some(etag) => Cond::IfMatch(etag),
            None => Cond::Always,
        };
        let etag = remote
            .put(&key, format!("{d}\n").into_bytes(), cond)
            .await?;
        self.inner.store.set_tag(t, d).await?;
        self.remember(&key, &etag);
        self.after_write().await;
        Ok(Some(etag))
    }

    /// Remove a tag everywhere. `false` if it existed nowhere.
    pub async fn remove_tag(&self, t: &TagName) -> Result<bool> {
        let mut existed = false;
        if let Some(remote) = &self.inner.remote {
            let key = keys::tag(t);
            existed |= remote.head(&key).await?.is_some();
            remote.delete(&key).await?;
            self.forget(&key);
        }
        existed |= self.inner.store.remove_tag(t).await?;
        self.after_write().await;
        Ok(existed)
    }

    // -- labels and public markers ----------------------------------------

    pub async fn set_label(&self, d: &Digest, label: &Label) -> Result<()> {
        label.validate()?;
        let Some(remote) = &self.inner.remote else {
            return self.inner.store.set_label(d, label).await;
        };
        if !self.promote(d).await? {
            return Err(Error::NotFound(d.clone()));
        }
        let key = keys::label(d);
        let etag = remote.put(&key, label.to_json(), Cond::Always).await?;
        self.inner.store.set_label_unchecked(d, label).await?;
        self.remember(&key, &etag);
        Ok(())
    }

    pub async fn remove_label(&self, d: &Digest) -> Result<bool> {
        let mut existed = false;
        if let Some(remote) = &self.inner.remote {
            let key = keys::label(d);
            existed |= remote.head(&key).await?.is_some();
            remote.delete(&key).await?;
            self.forget(&key);
        }
        existed |= self.inner.store.remove_label(d).await?;
        Ok(existed)
    }

    pub async fn set_public(&self, d: &Digest) -> Result<()> {
        let Some(remote) = &self.inner.remote else {
            self.inner.store.set_public(d).await?;
            return Ok(());
        };
        if !self.promote_blob(d).await? {
            return Err(Error::NotFound(d.clone()));
        }
        let key = keys::public(d);
        let etag = remote.put(&key, Vec::new(), Cond::Always).await?;
        self.inner.store.set_public_unchecked(d).await?;
        self.remember(&key, &etag);
        Ok(())
    }

    pub async fn remove_public(&self, d: &Digest) -> Result<bool> {
        let mut existed = false;
        if let Some(remote) = &self.inner.remote {
            let key = keys::public(d);
            existed |= remote.head(&key).await?.is_some();
            remote.delete(&key).await?;
            self.forget(&key);
        }
        existed |= self.inner.store.remove_public(d).await?;
        Ok(existed)
    }

    // -- repositories ------------------------------------------------------

    pub async fn set_repo(&self, r: &RepoName, meta: &RepoMeta) -> Result<()> {
        meta.validate()?;
        if let Some(remote) = &self.inner.remote {
            let key = keys::repo(r);
            let etag = remote.put(&key, meta.to_json(), Cond::Always).await?;
            self.remember(&key, &etag);
        }
        self.inner.store.set_repo(r, meta).await?;
        self.after_write().await;
        Ok(())
    }

    pub async fn remove_repo(&self, r: &RepoName) -> Result<bool> {
        let mut existed = false;
        if let Some(remote) = &self.inner.remote {
            let key = keys::repo(r);
            existed |= remote.head(&key).await?.is_some();
            remote.delete(&key).await?;
            self.forget(&key);
        }
        existed |= self.inner.store.remove_repo(r).await?;
        self.after_write().await;
        Ok(existed)
    }

    async fn after_write(&self) {
        if let Err(e) = self.refresh_public_index().await {
            tracing::warn!(error = %e, "rebuilding the public index failed");
        }
    }

    // -- the mirror --------------------------------------------------------

    /// Bring every local tag, label, public marker and repository into line
    /// with the remote.
    pub async fn sync(&self) -> Result<SyncReport> {
        let Some(remote) = &self.inner.remote else {
            return Ok(SyncReport::default());
        };
        let mut report = SyncReport::default();
        for prefix in [keys::REPOS, keys::TAGS, keys::LABELS, keys::PUBLIC] {
            let listed = remote.list(prefix).await?;
            let present: HashSet<&str> = listed.iter().map(|o| o.key.as_str()).collect();
            for obj in &listed {
                let unchanged = self.known_etag(&obj.key).as_deref() == Some(obj.etag.as_str());
                if unchanged && self.local_copy_exists(&obj.key).await {
                    self.mark_checked(&obj.key);
                    continue;
                }
                match self.pull_object(remote, &obj.key).await {
                    Ok(true) => report.fetched += 1,
                    Ok(false) => {}
                    Err(e) => tracing::warn!(key = %obj.key, error = %e, "could not mirror object"),
                }
            }
            // Objects this mirror copied that the remote no longer has.
            let stale: Vec<String> = self
                .inner
                .state
                .lock()
                .expect("state lock")
                .keys()
                .filter(|k| k.starts_with(prefix) && !present.contains(k.as_str()))
                .cloned()
                .collect();
            for key in stale {
                self.remove_local_copy(&key).await?;
                self.forget(&key);
                report.removed += 1;
            }
        }
        // Tags only this store has: not an error, but somebody should know.
        let state = self.inner.state.lock().expect("state lock").clone();
        for (t, _) in self.inner.store.list_tags().await? {
            if !state.contains_key(&keys::tag(&t)) {
                report.local_only += 1;
            }
        }
        if report.local_only > 0 {
            tracing::warn!(
                tags = report.local_only,
                "tags exist only in this region's cache; run `art s3 backfill` to publish them"
            );
        }
        self.save_state()?;
        Ok(report)
    }

    /// Copy one mutable object down. `false` if it vanished in between.
    async fn pull_object(&self, remote: &Remote, key: &str) -> Result<bool> {
        let (body, etag) = match remote.get(key, None).await? {
            Fetched::Found { body, etag } => (body, etag),
            _ => return Ok(false),
        };
        let store = &self.inner.store;
        if let Some(t) = keys::tag_of(key) {
            let d = crate::remote::parse_tag_body(&body)?;
            // The manifest comes with the tag, so a listing can describe it.
            if store.get_manifest(&d).await.is_err() && !store.has(&d).await? {
                match self.fetch_manifest(&d).await {
                    Ok(()) | Err(Error::NotFound(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            store.set_tag(&t, &d).await?;
        } else if let Some(r) = keys::repo_of(key) {
            let meta: RepoMeta =
                serde_json::from_slice(&body).map_err(|e| Error::Remote(format!("{key}: {e}")))?;
            store.set_repo(&r, &meta).await?;
        } else if key.starts_with(keys::LABELS) {
            let d = keys::digest_of(key).ok_or_else(|| Error::Remote(format!("bad key {key}")))?;
            let label: Label =
                serde_json::from_slice(&body).map_err(|e| Error::Remote(format!("{key}: {e}")))?;
            store.set_label_unchecked(&d, &label).await?;
        } else if key.starts_with(keys::PUBLIC) {
            let d = keys::digest_of(key).ok_or_else(|| Error::Remote(format!("bad key {key}")))?;
            store.set_public_unchecked(&d).await?;
        } else {
            return Ok(false);
        }
        self.remember(key, &etag);
        Ok(true)
    }

    async fn local_copy_exists(&self, key: &str) -> bool {
        let inner = self.inner.store.inner();
        let path = if let Some(t) = keys::tag_of(key) {
            inner.tag_path_of(&t)
        } else if let Some(r) = keys::repo_of(key) {
            inner.repo_path_of(&r)
        } else if let Some(d) = keys::digest_of(key) {
            if key.starts_with(keys::LABELS) {
                inner.label_path_of(&d)
            } else {
                inner.public_path_of(&d)
            }
        } else {
            return false;
        };
        tokio::fs::try_exists(path).await.unwrap_or(false)
    }

    async fn remove_local_copy(&self, key: &str) -> Result<()> {
        let store = &self.inner.store;
        if let Some(t) = keys::tag_of(key) {
            store.remove_tag(&t).await?;
        } else if let Some(r) = keys::repo_of(key) {
            store.remove_repo(&r).await?;
        } else if let Some(d) = keys::digest_of(key) {
            if key.starts_with(keys::LABELS) {
                store.remove_label(&d).await?;
            } else if key.starts_with(keys::PUBLIC) {
                store.remove_public(&d).await?;
            }
        }
        Ok(())
    }

    // -- eviction ----------------------------------------------------------

    /// Evict cached blobs if the cache is over its limits.
    pub async fn evict(&self) -> Result<EvictReport> {
        self.evict_for(None).await
    }

    /// Evict until the cache is within its limits — or, with `room_for`, until
    /// it is comfortably so, because a fill just failed for lack of space.
    async fn evict_for(&self, room_for: Option<&Digest>) -> Result<EvictReport> {
        let mut report = EvictReport::default();
        if self.inner.remote.is_none() {
            return Ok(report);
        }
        let opts = &self.inner.opts;
        let store = &self.inner.store;
        let usage = store.usage().await?;
        let mut allocated = usage.allocated;
        let mut available = usage.fs_available;

        // Evict down to 90% of the cap, and up to 125% of the free-space
        // floor, so one eviction buys more than one insert's worth of room.
        let target_alloc = opts.cache_max_bytes.map(|m| m / 10 * 9);
        let target_free = opts
            .cache_min_free_bytes
            .saturating_add(opts.cache_min_free_bytes / 4);
        let over = |allocated: u64, available: u64, slack: bool| {
            let cap = if slack {
                target_alloc
            } else {
                opts.cache_max_bytes
            };
            let floor = if slack {
                target_free
            } else {
                opts.cache_min_free_bytes
            };
            cap.is_some_and(|c| allocated > c) || available < floor
        };
        if room_for.is_none() && !over(allocated, available, false) {
            return Ok(report);
        }

        let now = SystemTime::now();
        let access = self.inner.access.lock().expect("access lock").clone();
        let mut candidates: Vec<_> = store
            .list_blobs()
            .await?
            .into_iter()
            .filter(|b| b.nlink == 1)
            .filter(|b| Some(&b.digest) != room_for)
            .filter(|b| now.duration_since(b.created).unwrap_or_default() >= opts.min_age)
            .collect();
        candidates.sort_by_key(|b| access.get(&b.digest).copied().unwrap_or(b.created));

        for b in candidates {
            if !over(allocated, available, true) {
                break;
            }
            // Never drop the only copy.
            if !self.blob_in_remote(&b.digest).await? {
                continue;
            }
            if let Some(freed) = store.evict_blob(&b.digest).await? {
                report.evicted += 1;
                report.bytes_freed += freed;
                allocated = allocated.saturating_sub(freed);
                available = available.saturating_add(freed);
                self.inner
                    .access
                    .lock()
                    .expect("access lock")
                    .remove(&b.digest);
            }
        }
        if report.evicted > 0 {
            tracing::info!(
                evicted = report.evicted,
                bytes_freed = report.bytes_freed,
                "evicted cached blobs the remote holds"
            );
        }
        Ok(report)
    }

    // -- remote state ------------------------------------------------------

    fn known_etag(&self, key: &str) -> Option<String> {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .get(key)
            .cloned()
    }

    fn fresh(&self, key: &str) -> bool {
        self.inner
            .checked
            .lock()
            .expect("checked lock")
            .get(key)
            .is_some_and(|at| at.elapsed() < self.inner.opts.tag_ttl)
    }

    fn mark_checked(&self, key: &str) {
        self.inner
            .checked
            .lock()
            .expect("checked lock")
            .insert(key.to_string(), Instant::now());
    }

    fn remember(&self, key: &str, etag: &str) {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .insert(key.to_string(), etag.to_string());
        self.mark_checked(key);
    }

    fn forget(&self, key: &str) {
        self.inner.state.lock().expect("state lock").remove(key);
        self.inner.checked.lock().expect("checked lock").remove(key);
    }

    fn save_state(&self) -> Result<()> {
        let state = self.inner.state.lock().expect("state lock").clone();
        let body = serde_json::to_vec_pretty(&state).expect("state always serializes");
        let path = self.inner.store.root().join(STATE_FILE);
        crate::store::write_replacing(&path, &body, "remote state")
    }
}

fn load_state(store: &Store) -> BTreeMap<String, String> {
    let path = store.root().join(STATE_FILE);
    match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
            tracing::warn!(error = %e, path = %path.display(), "ignoring unreadable remote state");
            BTreeMap::new()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "ignoring unreadable remote state");
            BTreeMap::new()
        }
    }
}

fn sha256(bytes: &[u8]) -> Digest {
    let out = Sha256::digest(bytes);
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    Digest::from_bytes(&b)
}

/// The remote, configured from the environment, or `None` for a local-only
/// store.
///
/// `ART_S3_BUCKET` selects S3; `ART_REMOTE_DIR` a directory standing in for
/// one. Setting both is an error rather than a precedence rule.
pub fn remote_from_env() -> Result<Option<Remote>> {
    let bucket = std::env::var("ART_S3_BUCKET")
        .ok()
        .filter(|v| !v.is_empty());
    let dir = std::env::var_os("ART_REMOTE_DIR").filter(|v| !v.is_empty());
    let bad = |m: String| Error::Io {
        context: m,
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad configuration"),
    };
    match (bucket, dir) {
        (Some(_), Some(_)) => Err(bad(
            "ART_S3_BUCKET and ART_REMOTE_DIR are both set; pick one".to_string(),
        )),
        (None, None) => Ok(None),
        (None, Some(dir)) => Ok(Some(Remote::fs(std::path::PathBuf::from(dir))?)),
        #[cfg(not(feature = "s3"))]
        (Some(_), None) => Err(bad(
            "ART_S3_BUCKET is set but this build has no S3 support (the `s3` feature)".into(),
        )),
        #[cfg(feature = "s3")]
        (Some(bucket), None) => {
            use crate::remote::s3::{DEFAULT_CONCURRENCY, DEFAULT_PART_SIZE, S3Settings};
            let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
            let need =
                |k: &str| var(k).ok_or_else(|| bad(format!("ART_S3_BUCKET is set but {k} is not")));
            let num = |k: &str, default: u64| -> Result<u64> {
                match var(k) {
                    None => Ok(default),
                    Some(v) => v
                        .parse()
                        .map_err(|_| bad(format!("{k} must be a whole number, got {v:?}"))),
                }
            };
            Ok(Some(Remote::s3(S3Settings {
                bucket,
                prefix: var("ART_S3_PREFIX").unwrap_or_else(|| "art/".into()),
                region: var("ART_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
                endpoint: var("ART_S3_ENDPOINT"),
                access_key_id: need("ART_S3_ACCESS_KEY_ID")?,
                secret_access_key: need("ART_S3_SECRET_ACCESS_KEY")?,
                part_size: num("ART_S3_PART_SIZE", DEFAULT_PART_SIZE)?,
                concurrency: num("ART_S3_CONCURRENCY", DEFAULT_CONCURRENCY as u64)? as usize,
            })?))
        }
    }
}

/// Registry tuning from the environment: `ART_TAG_TTL`, `ART_SYNC_INTERVAL`
/// (durations like `30s`), `ART_CACHE_MAX_BYTES`, `ART_CACHE_MIN_FREE_BYTES`.
pub fn options_from_env(config: &crate::Config) -> Result<RegistryOptions> {
    let bad = |m: String| Error::Io {
        context: m,
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad configuration"),
    };
    let dur = |k: &str, default: Duration| -> Result<Duration> {
        match std::env::var(k).ok().filter(|v| !v.is_empty()) {
            None => Ok(default),
            Some(v) => crate::config::parse_duration(&v).map_err(|e| bad(format!("{k}: {e}"))),
        }
    };
    let bytes = |k: &str| -> Result<Option<u64>> {
        match std::env::var(k).ok().filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| bad(format!("{k} must be a byte count, got {v:?}"))),
        }
    };
    Ok(RegistryOptions {
        tag_ttl: dur("ART_TAG_TTL", DEFAULT_TAG_TTL)?,
        sync_interval: dur("ART_SYNC_INTERVAL", DEFAULT_SYNC_INTERVAL)?,
        cache_max_bytes: bytes("ART_CACHE_MAX_BYTES")?,
        // Twice the hard floor by default: evict well before the store's own
        // guard starts refusing writes.
        cache_min_free_bytes: bytes("ART_CACHE_MIN_FREE_BYTES")?
            .unwrap_or(config.min_free_bytes.saturating_mul(2)),
        min_age: config.gc_min_age.min(Duration::from_secs(600)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    struct Region {
        _dir: tempfile::TempDir,
        reg: Registry,
    }

    fn region(remote: &Remote, opts: RegistryOptions) -> Region {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Config {
            root: dir.path().join("store"),
            min_free_bytes: 0,
            gc_min_age: Duration::ZERO,
            heyvm_images_dir: dir.path().join("images"),
        })
        .unwrap();
        Region {
            _dir: dir,
            reg: Registry::new(store, Some(remote.clone()), opts),
        }
    }

    fn opts() -> RegistryOptions {
        RegistryOptions {
            tag_ttl: Duration::ZERO,
            min_age: Duration::ZERO,
            ..Default::default()
        }
    }

    fn shared() -> (tempfile::TempDir, Remote) {
        let d = tempfile::tempdir().unwrap();
        let r = Remote::fs(d.path().join("bucket")).unwrap();
        (d, r)
    }

    /// Push the way the HTTP layer does: local insert, then publish.
    async fn push(reg: &Registry, bytes: &[u8]) -> Digest {
        let info = reg.store().insert_bytes(bytes.to_vec()).await.unwrap();
        reg.publish_blob(&info.digest).await.unwrap();
        info.digest
    }

    fn tag(s: &str) -> TagName {
        TagName::parse(s).unwrap()
    }

    #[tokio::test]
    async fn a_push_in_one_region_is_pullable_in_another() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());

        let blob = push(&us.reg, b"rootfs bytes").await;
        let m = Manifest::new(crate::KIND_ROOTFS).with_entry("rootfs.ext4", blob.clone(), 12);
        let md = us.reg.put_manifest(&m).await.unwrap();
        us.reg.set_tag(&tag("heyo/pg:16"), &md, None).await.unwrap();

        // eu has never seen any of it.
        assert!(!eu.reg.store().has(&blob).await.unwrap());
        let (d, etag) = eu.reg.get_tag(&tag("heyo/pg:16")).await.unwrap();
        assert_eq!(d, md);
        assert!(etag.is_some());
        assert_eq!(eu.reg.manifest(&md).await.unwrap(), m);
        let info = eu.reg.ensure_blob(&blob).await.unwrap();
        assert_eq!(info.size, 12);
        eu.reg.store().verify(&blob).await.unwrap();
    }

    #[tokio::test]
    async fn the_remote_never_holds_a_pointer_to_nothing() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        // In neither store.
        let nowhere = Digest::parse(&"0".repeat(64)).unwrap();
        let m = Manifest::new(crate::KIND_GENERIC).with_entry("x", nowhere.clone(), 11);
        assert!(matches!(
            us.reg.put_manifest(&m).await,
            Err(Error::Missing(_))
        ));
        assert!(matches!(
            us.reg.set_tag(&tag("x"), &nowhere, None).await,
            Err(Error::Missing(_))
        ));
        // A manifest this region holds whose blob is gone everywhere.
        let gone = us
            .reg
            .store()
            .insert_bytes(b"gone".to_vec())
            .await
            .unwrap()
            .digest;
        let md = us
            .reg
            .store()
            .put_manifest(&Manifest::new(crate::KIND_GENERIC).with_entry("g", gone.clone(), 4))
            .await
            .unwrap();
        us.reg.store().evict_blob(&gone).await.unwrap();
        assert!(matches!(
            us.reg.set_tag(&tag("g"), &md, None).await,
            Err(Error::Missing(_))
        ));
        assert!(remote.head(&keys::manifest(&md)).await.unwrap().is_none());
    }

    /// A store that predates its remote: content only it holds is published
    /// by the first write that names it, so a client that skipped an upload
    /// because the cache said "already here" still succeeds.
    #[tokio::test]
    async fn writes_naming_pre_remote_content_publish_it_first() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());
        // Written straight to the cache, as everything was before S3.
        let store = us.reg.store();
        let old = store
            .insert_bytes(b"old image".to_vec())
            .await
            .unwrap()
            .digest;
        let old_m = Manifest::new(crate::KIND_ROOTFS).with_entry("rootfs.ext4", old.clone(), 9);
        let old_md = store.put_manifest(&old_m).await.unwrap();
        let older = store.insert_bytes(b"older".to_vec()).await.unwrap().digest;

        // A push that deduplicated against the cache: manifest only.
        let m = Manifest::new(crate::KIND_GENERIC).with_entry("x", older.clone(), 5);
        us.reg.put_manifest(&m).await.unwrap();
        assert!(remote.head(&keys::blob(&older)).await.unwrap().is_some());

        // Tagging a manifest only this region had publishes it and its blobs.
        us.reg
            .set_tag(&tag("heyo/old:1"), &old_md, None)
            .await
            .unwrap();
        assert!(
            remote
                .head(&keys::manifest(&old_md))
                .await
                .unwrap()
                .is_some()
        );
        assert!(remote.head(&keys::blob(&old)).await.unwrap().is_some());

        // And another region can pull all of it.
        let (d, _) = eu.reg.get_tag(&tag("heyo/old:1")).await.unwrap();
        assert_eq!(eu.reg.manifest(&d).await.unwrap(), old_m);
        eu.reg.ensure_blob(&old).await.unwrap();

        // Labels and public markers promote too.
        let lone = store.insert_bytes(b"lone".to_vec()).await.unwrap().digest;
        us.reg.set_public(&lone).await.unwrap();
        assert!(remote.head(&keys::blob(&lone)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn tags_move_across_regions_and_compare_and_swap_holds() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());
        let a = push(&us.reg, b"a").await;
        let b = push(&us.reg, b"b").await;
        let t = tag("heyo/app:live");

        let e1 = us.reg.set_tag(&t, &a, None).await.unwrap().unwrap();
        assert_eq!(eu.reg.get_tag(&t).await.unwrap().0, a);
        let _e2 = eu.reg.set_tag(&t, &b, Some(e1.clone())).await.unwrap();
        // us still holds e1, which is now stale.
        assert!(matches!(
            us.reg.set_tag(&t, &a, Some(e1)).await,
            Err(Error::PreconditionFailed(_))
        ));
        assert_eq!(us.reg.get_tag(&t).await.unwrap().0, b);

        // A delete in one region is a 404 in the other once revalidated.
        assert!(us.reg.remove_tag(&t).await.unwrap());
        assert!(matches!(
            eu.reg.get_tag(&t).await,
            Err(Error::TagNotFound(_))
        ));
        assert!(eu.reg.store().get_tag(&t).await.is_err());
    }

    #[tokio::test]
    async fn a_fresh_tag_is_served_without_asking_and_a_dead_remote_serves_stale() {
        let (bucket, remote) = shared();
        let us = region(
            &remote,
            RegistryOptions {
                tag_ttl: Duration::from_secs(3600),
                ..opts()
            },
        );
        let a = push(&us.reg, b"a").await;
        us.reg.set_tag(&tag("t"), &a, None).await.unwrap();
        // Make the remote unreachable; within the TTL nothing notices.
        std::fs::rename(bucket.path().join("bucket"), bucket.path().join("gone")).unwrap();
        std::fs::write(bucket.path().join("bucket"), b"not a directory").unwrap();
        assert_eq!(us.reg.get_tag(&tag("t")).await.unwrap().0, a);
        // Past the TTL, the failure is logged and the cache still answers.
        us.reg.inner.checked.lock().unwrap().clear();
        assert_eq!(us.reg.get_tag(&tag("t")).await.unwrap().0, a);
    }

    #[tokio::test]
    async fn concurrent_cold_reads_fetch_once() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());
        let d = push(&us.reg, &vec![3u8; 3 * 1024 * 1024]).await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let reg = eu.reg.clone();
            let d = d.clone();
            tasks.push(tokio::spawn(async move { reg.ensure_blob(&d).await }));
        }
        let mut deduped = 0;
        for t in tasks {
            let info = t.await.unwrap().unwrap();
            deduped += info.deduped as u32;
        }
        // Every caller got the blob, and no second fill raced the first into
        // a dedup.
        assert_eq!(deduped, 0);
        eu.reg.store().verify(&d).await.unwrap();
    }

    #[tokio::test]
    async fn the_mirror_copies_remote_state_and_leaves_local_only_tags_alone() {
        let (_b, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());
        let d = push(&us.reg, b"x").await;
        us.reg.set_tag(&tag("heyo/x:1"), &d, None).await.unwrap();
        us.reg
            .set_repo(
                &RepoName::parse("heyo/x").unwrap(),
                &RepoMeta {
                    public: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        us.reg
            .set_label(&d, &Label::new(Some("x".into()), None).unwrap())
            .await
            .unwrap();
        // A tag only eu has: written straight to its cache.
        let own = eu.reg.store().insert_bytes(b"mine".to_vec()).await.unwrap();
        eu.reg
            .store()
            .set_tag(&tag("local-only"), &own.digest)
            .await
            .unwrap();

        let r = eu.reg.sync().await.unwrap();
        assert_eq!(r.fetched, 3);
        assert_eq!(r.local_only, 1);
        assert_eq!(eu.reg.store().get_tag(&tag("heyo/x:1")).await.unwrap(), d);
        assert!(eu.reg.store().get_label(&d).await.unwrap().is_some());
        eu.reg.refresh_public_index().await.unwrap();
        assert!(eu.reg.public_index().digests.contains(&d));

        // Removed remotely: removed here on the next pass. The local-only tag
        // survives every pass.
        us.reg.remove_tag(&tag("heyo/x:1")).await.unwrap();
        let r = eu.reg.sync().await.unwrap();
        assert_eq!(r.removed, 1);
        assert!(eu.reg.store().get_tag(&tag("heyo/x:1")).await.is_err());
        assert!(eu.reg.store().get_tag(&tag("local-only")).await.is_ok());

        // The state survives a restart: a new registry on the same root knows
        // what it mirrored.
        let again = Registry::new(eu.reg.store().clone(), Some(remote.clone()), opts());
        assert!(
            again
                .known_etag(&keys::repo(&RepoName::parse("heyo/x").unwrap()))
                .is_some()
        );
    }

    #[tokio::test]
    async fn eviction_drops_only_what_the_remote_holds_and_nothing_pinned() {
        let (_b, remote) = shared();
        let us = region(
            &remote,
            RegistryOptions {
                cache_max_bytes: Some(1),
                ..opts()
            },
        );
        let published = push(&us.reg, &vec![1u8; 64 * 1024]).await;
        let unpublished = us
            .reg
            .store()
            .insert_bytes(vec![2u8; 64 * 1024])
            .await
            .unwrap()
            .digest;
        let pinned = push(&us.reg, &vec![3u8; 64 * 1024]).await;
        let dest = us._dir.path().join("pin");
        us.reg
            .store()
            .materialize(&pinned, &dest, crate::Materialize::ReadOnly)
            .await
            .unwrap();

        let r = us.reg.evict().await.unwrap();
        assert_eq!(r.evicted, 1);
        assert!(!us.reg.store().has(&published).await.unwrap());
        assert!(us.reg.store().has(&unpublished).await.unwrap());
        assert!(us.reg.store().has(&pinned).await.unwrap());
        // And it comes back on demand.
        us.reg.ensure_blob(&published).await.unwrap();
    }

    #[tokio::test]
    async fn a_corrupt_remote_blob_is_never_cached() {
        let (bucket, remote) = shared();
        let us = region(&remote, opts());
        let eu = region(&remote, opts());
        let d = push(&us.reg, b"genuine").await;
        let path = bucket.path().join("bucket").join(keys::blob(&d));
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            eu.reg.ensure_blob(&d).await,
            Err(Error::DigestMismatch { .. })
        ));
        assert!(!eu.reg.store().has(&d).await.unwrap());
    }
}
