//! Blobs are immutable and mode `0444`; the only mutable object in the store is
//! a tag.
//!
//! Layout under the store root:
//!
//! ```text
//! .store.lock            flock, see crate::lock
//! blobs/<aa>/<64-hex>    mode 0444
//! manifests/<aa>/<64-hex>  canonical JSON, addressed by its own sha256
//! labels/<aa>/<64-hex>   a name and description for either of the above
//! tags/<name>            one digest and a newline; a namespaced tag's '/' is '~'
//! repos/<name>.json      what is said about a repository: public, description
//! tmp/                   incoming files, named only on the no-O_TMPFILE path
//! ```
//!
//! Two of those are mutable — `tags/` and `labels/` — and both are written the
//! same way: temp file in the same directory, `sync_all`, rename. A label is
//! keyed by digest and describes whatever that digest names, blob or manifest;
//! see [`crate::labels`] for why the name lives beside the content and not in
//! it.
//!
//! **Fanout is two hex characters — 256 shards, one level.** ext4 directories
//! are htree-indexed, so lookup was never the constraint; what the fanout
//! bounds is the size of the directory inode and the cost of the whole-store
//! `readdir` that garbage collection performs. Three levels would spend 65,536
//! directory inodes to hold a few thousand blobs.
//!
//! The filesystem is the only source of truth. There is no index to reconcile
//! with it, so crash recovery is nothing at all: a blob either has a directory
//! entry — and, by the ordering [`crate::sys::tmpfile`] enforces, correct
//! content — or it does not exist and the caller re-inserts the same bytes.

use crate::config::Config;
use crate::digest::Digest;
use crate::error::{Error, IoContext, Result};
use crate::labels::{Label, Labelled};
use crate::lock::{LockMode, StoreLock};
use crate::manifest::Manifest;
use crate::repos::RepoMeta;
use crate::sys::space::{self, FileStat};
use crate::sys::sparse::{self, Shape};
use crate::sys::tmpfile::{Incoming, LinkOutcome};
use crate::tags::{Ref, RepoName, TagName};
use sha2::{Digest as _, Sha256};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// How often the incremental free-space guard re-checks during a long write.
const GUARD_INTERVAL: u64 = 256 * 1024 * 1024;

/// What the store knows about one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    pub digest: Digest,
    /// Logical length — what a reader sees, and what the digest covers.
    pub size: u64,
    /// Physically allocated bytes. Far below `size` for a sparsified image;
    /// reporting only `size` would misstate what the store costs on disk.
    pub allocated: u64,
    /// Links to this inode. One means the store's own directory entry and
    /// nothing else.
    pub nlink: u64,
    pub created: SystemTime,
    /// True when the bytes were already present and this insert deduplicated.
    pub deduped: bool,
}

/// How a caller wants the bytes delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Materialize {
    /// A hardlink when the destination is on the same filesystem: no bytes
    /// copied, no space consumed, and `st_nlink` records the reference.
    ReadOnly,
    /// A private copy the caller may modify. Never a hardlink — Firecracker
    /// opens a rootfs read-write, and a hardlink would let a guest rewrite
    /// content whose name is a promise about what it contains.
    Writable { shape: Shape, mode: u32 },
}

/// Which mechanism [`Store::materialize`] actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Hardlink,
    /// Only allocated extents were copied.
    SparseCopy,
    DenseCopy,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Method::Hardlink => "hardlink",
            Method::SparseCopy => "sparse-copy",
            Method::DenseCopy => "dense-copy",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialized {
    pub path: PathBuf,
    pub digest: Digest,
    pub method: Method,
    /// Bytes actually written. Zero for a hardlink. Surfaced so a caller can
    /// log what a boot really cost instead of the image's nominal size.
    pub bytes_written: u64,
}

/// A repository as listed: its metadata and the tags in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub name: RepoName,
    pub meta: RepoMeta,
    pub tags: Vec<(TagName, Digest)>,
}

/// Aggregate accounting for `art usage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub blobs: u64,
    pub logical: u64,
    pub allocated: u64,
    pub manifests: u64,
    pub tags: u64,
    pub fs_available: u64,
    pub fs_total: u64,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

pub(crate) struct Inner {
    root: PathBuf,
    /// `st_dev` of the store root, so a hardlink is only ever attempted at a
    /// destination it can actually reach.
    dev: u64,
    min_free_bytes: u64,
    lock: StoreLock,
}

impl Store {
    /// Open (creating if needed) the store at `config.root`.
    pub fn open(config: &Config) -> Result<Store> {
        let root = config.root.clone();
        // All 256 shards up front. They cost 256 inodes each for blobs and
        // manifests, and their existence removes any mkdir race from the insert
        // path.
        for sub in ["blobs", "manifests", "labels", "public"] {
            for i in 0u16..256 {
                let d = root.join(sub).join(format!("{i:02x}"));
                std::fs::create_dir_all(&d).ctx(format!("create {}", d.display()))?;
            }
        }
        for sub in ["tags", "repos", "tmp"] {
            let d = root.join(sub);
            std::fs::create_dir_all(&d).ctx(format!("create {}", d.display()))?;
        }

        let dev = space::dev_of_dir(&root)?;
        let lock = StoreLock::open(&root)?;
        Ok(Store {
            inner: Arc::new(Inner {
                root,
                dev,
                min_free_bytes: config.min_free_bytes,
                lock,
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub fn blob_path(&self, d: &Digest) -> PathBuf {
        self.inner.blob_path(d)
    }

    /// The store's scratch directory.
    ///
    /// Exposed so a caller staging something it is about to insert — a packed
    /// build context, say — can put it on the store's own filesystem. Writing it
    /// to `/tmp` instead risks a `tmpfs` far smaller than the thing being
    /// packed, and makes the subsequent insert a cross-filesystem copy. Anything
    /// left here is the caller's to remove.
    pub fn tmp_dir(&self) -> PathBuf {
        self.inner.tmp_dir()
    }

    // -- blobs -------------------------------------------------------------

    /// Insert a file, hashing its full logical content and storing it as
    /// `shape` directs.
    pub async fn insert_path(&self, src: &Path, shape: Shape) -> Result<BlobInfo> {
        let inner = self.inner.clone();
        let src = src.to_path_buf();
        blocking(move || inner.insert_path(&src, shape)).await
    }

    /// Insert from a reader of unknown length.
    pub async fn insert_stream<R>(&self, reader: R, shape: Shape) -> Result<BlobInfo>
    where
        R: std::io::Read + Send + 'static,
    {
        let inner = self.inner.clone();
        blocking(move || inner.insert_stream(reader, shape)).await
    }

    pub async fn insert_bytes(&self, data: Vec<u8>) -> Result<BlobInfo> {
        self.insert_stream(std::io::Cursor::new(data), Shape::Dense)
            .await
    }

    /// Insert from an async reader — an HTTP request body, typically.
    ///
    /// Bridged onto the blocking insert rather than buffered: a blob may be
    /// twenty gigabytes, so holding the upload in memory is not an option, and
    /// spooling it to a temp file first would double the IO of every upload.
    #[cfg(feature = "daemon")]
    pub async fn insert_async<R>(&self, reader: R, shape: Shape) -> Result<BlobInfo>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        let inner = self.inner.clone();
        let handle = tokio::runtime::Handle::current();
        blocking(move || {
            // `new_with_handle`, not `new`: the bridge needs a runtime to drive
            // the reader, and a spawn_blocking thread has no ambient context.
            let sync = tokio_util::io::SyncIoBridge::new_with_handle(reader, handle);
            inner.insert_stream(sync, shape)
        })
        .await
    }

    /// Insert a blob from its [`crate::asp`] encoding — what the remote tier
    /// stores — refusing it unless the rebuilt bytes hash to `expected`.
    ///
    /// The holes come back as holes, so a cache fill costs what the blob
    /// occupies, not its logical length.
    pub async fn insert_encoded<R>(&self, reader: R, expected: &Digest) -> Result<BlobInfo>
    where
        R: std::io::Read + Send + 'static,
    {
        let inner = self.inner.clone();
        let expected = expected.clone();
        blocking(move || inner.insert_encoded(reader, &expected)).await
    }

    /// A blob as an [`crate::asp`] stream, and that stream's exact length.
    pub async fn encode_blob(&self, d: &Digest) -> Result<crate::asp::Encoder> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || {
            let p = inner.blob_path(&d);
            let st = space::stat_path(&p).map_err(|e| match e {
                Error::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                    Error::NotFound(d.clone())
                }
                other => other,
            })?;
            let f = sparse::open_for_read(&p)?;
            crate::asp::Encoder::new(f, st.size).ctx(format!("encode {}", p.display()))
        })
        .await
    }

    pub async fn has(&self, d: &Digest) -> Result<bool> {
        Ok(self.stat(d).await.is_ok())
    }

    pub async fn stat(&self, d: &Digest) -> Result<BlobInfo> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || inner.stat(&d)).await
    }

    pub async fn open_blob(&self, d: &Digest) -> Result<std::fs::File> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || {
            let p = inner.blob_path(&d);
            if !p.exists() {
                return Err(Error::NotFound(d));
            }
            sparse::open_for_read(&p)
        })
        .await
    }

    /// Re-hash a blob and confirm it still matches its name.
    pub async fn verify(&self, d: &Digest) -> Result<()> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || inner.verify(&d)).await
    }

    /// Place the blob's content at `dest`.
    pub async fn materialize(
        &self,
        d: &Digest,
        dest: &Path,
        how: Materialize,
    ) -> Result<Materialized> {
        let inner = self.inner.clone();
        let d = d.clone();
        let dest = dest.to_path_buf();
        blocking(move || inner.materialize(&d, &dest, how)).await
    }

    /// Drop a materialization. For a hardlink this is what returns the blob's
    /// `st_nlink` to 1 and makes it collectable again.
    pub async fn release(&self, m: &Materialized) -> Result<bool> {
        let path = m.path.clone();
        blocking(move || sparse::unlink_if_present(&path)).await
    }

    pub async fn list_blobs(&self) -> Result<Vec<BlobInfo>> {
        let inner = self.inner.clone();
        blocking(move || inner.list_blobs()).await
    }

    // -- manifests ---------------------------------------------------------

    pub async fn put_manifest(&self, m: &Manifest) -> Result<Digest> {
        let inner = self.inner.clone();
        let bytes = m.to_canonical_json();
        blocking(move || inner.put_manifest(bytes)).await
    }

    /// Store manifest bytes exactly as given — the remote's copy, which is
    /// already canonical. The returned digest is what those bytes hash to;
    /// the caller compares it with the one it asked for.
    #[cfg(feature = "daemon")]
    pub(crate) async fn put_manifest_bytes(&self, bytes: Vec<u8>) -> Result<Digest> {
        let inner = self.inner.clone();
        blocking(move || inner.put_manifest(bytes)).await
    }

    pub async fn get_manifest(&self, d: &Digest) -> Result<Manifest> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || {
            let p = inner.manifest_path(&d);
            let bytes = match std::fs::read(&p) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::NotFound(d));
                }
                Err(e) => return Err(e).ctx(format!("read {}", p.display())),
            };
            Manifest::from_json(&bytes)
        })
        .await
    }

    pub async fn list_manifests(&self) -> Result<Vec<Digest>> {
        let inner = self.inner.clone();
        blocking(move || inner.list_digests("manifests")).await
    }

    // -- labels ------------------------------------------------------------

    /// Give a digest a name and a description, replacing whatever it had.
    ///
    /// Refuses a digest the store does not hold. A label on absent content is
    /// metadata about nothing: it describes an address that resolves nowhere,
    /// and it sits there until a sweep notices. Enforced here rather than in the
    /// CLI and the HTTP layer separately, so the two cannot disagree about it —
    /// which they did, briefly.
    ///
    /// Takes no store lock. A label is referenced by nothing and nothing
    /// resolves through one, so the worst a concurrent write can do is decide
    /// which of two descriptions is current, and the rename makes that atomic.
    /// Locking here would make labelling contend with a garbage collection.
    ///
    /// The existence check is therefore not a guarantee: a sweep between the
    /// check and the rename leaves a label describing content that has just
    /// gone. That is exactly the orphan the sweep already knows how to remove,
    /// which is why this is a check against mistakes rather than a lock against
    /// races.
    pub async fn set_label(&self, d: &Digest, label: &Label) -> Result<()> {
        label.validate()?;
        let inner = self.inner.clone();
        let (d, label) = (d.clone(), label.clone());
        blocking(move || {
            if !(inner.blob_exists(&d) || inner.manifest_exists(&d)) {
                return Err(Error::NotFound(d));
            }
            inner.set_label(&d, &label)
        })
        .await
    }

    /// The label for a digest, or `None` if it has never been given one.
    ///
    /// `None` rather than an error, because "unlabelled" is the ordinary state
    /// of most of a store and every caller of this is rendering a row.
    pub async fn get_label(&self, d: &Digest) -> Result<Option<Label>> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || inner.get_label(&d)).await
    }

    /// [`Self::set_label`] without the existence check, for the remote tier:
    /// a label mirrored from the global store describes content this cache may
    /// not hold yet.
    #[cfg(feature = "daemon")]
    pub(crate) async fn set_label_unchecked(&self, d: &Digest, label: &Label) -> Result<()> {
        let inner = self.inner.clone();
        let (d, label) = (d.clone(), label.clone());
        blocking(move || inner.set_label(&d, &label)).await
    }

    /// [`Self::set_public`] without the existence check, for the same reason.
    #[cfg(feature = "daemon")]
    pub(crate) async fn set_public_unchecked(&self, d: &Digest) -> Result<()> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || inner.set_public(&d)).await
    }

    /// Drop a cached blob whose bytes live on elsewhere — the remote tier's
    /// eviction. Under the exclusive store lock, and only while nothing but the
    /// store links it: a materialization in use pins its blob here no matter
    /// what the remote holds. Returns the bytes freed, or `None` if it was kept.
    #[cfg(feature = "daemon")]
    pub(crate) async fn evict_blob(&self, d: &Digest) -> Result<Option<u64>> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || {
            let _guard = inner.lock().acquire(LockMode::Exclusive)?;
            let st = match space::stat_path(&inner.blob_path(&d)) {
                Ok(st) => st,
                Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            if st.nlink > 1 {
                return Ok(None);
            }
            sparse::unlink_if_present(&inner.blob_path(&d))?;
            Ok(Some(st.allocated))
        })
        .await
    }

    /// Remove a digest's label. `false` if it had none.
    pub async fn remove_label(&self, d: &Digest) -> Result<bool> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || sparse::unlink_if_present(&inner.label_path(&d))).await
    }

    // -- public ------------------------------------------------------------

    /// Mark a blob as public: downloadable (`GET`/`HEAD /blobs/{digest}`)
    /// without a credential. Nothing else about it becomes public — it does
    /// not appear in any listing without auth, and no mutating route is ever
    /// exempt.
    ///
    /// Blobs only, deliberately. A manifest made public would leak the names
    /// and digests of everything it references, which is a listing, not a
    /// download; and public exists for exactly one use — handing someone a
    /// link to bytes.
    ///
    /// Stored as a marker file beside the content (`public/<aa>/<64-hex>`),
    /// the same shape as a label: keyed by digest, load-bearing for nothing
    /// but the auth exemption, swept by GC when its subject goes. Refuses a
    /// digest the store holds no blob for — a public flag on nothing would
    /// exempt a 404.
    pub async fn set_public(&self, d: &Digest) -> Result<()> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || {
            if !inner.blob_exists(&d) {
                return Err(Error::NotFound(d));
            }
            inner.set_public(&d)
        })
        .await
    }

    /// Make a blob private again. `false` if it was not public.
    pub async fn remove_public(&self, d: &Digest) -> Result<bool> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || sparse::unlink_if_present(&inner.public_path(&d))).await
    }

    /// Whether this digest may be downloaded without a credential.
    ///
    /// On the request path of every unauthenticated download, so it is one
    /// `access(2)` and nothing more.
    pub async fn is_public(&self, d: &Digest) -> Result<bool> {
        let inner = self.inner.clone();
        let d = d.clone();
        blocking(move || Ok(inner.public_path(&d).exists())).await
    }

    /// Every label in the store, digest-ordered.
    ///
    /// One `readdir` of 256 shards rather than a `stat` per row: a listing page
    /// needs the label for every blob it shows, and asking per digest turns one
    /// page load into a thousand syscalls.
    pub async fn list_labels(&self) -> Result<Vec<Labelled>> {
        let inner = self.inner.clone();
        blocking(move || inner.list_labels()).await
    }

    /// Labels as a lookup, for a caller rendering many rows at once.
    pub async fn label_map(&self) -> Result<std::collections::HashMap<Digest, Label>> {
        Ok(self
            .list_labels()
            .await?
            .into_iter()
            .map(|l| (l.digest, l.label))
            .collect())
    }

    /// Which tags point at each digest.
    ///
    /// The inverse of [`Self::list_tags`], and the direction every listing
    /// actually asks in: a row knows its digest and wants the names. Several
    /// tags can name one digest, so the value is a list.
    pub async fn tags_by_digest(&self) -> Result<std::collections::HashMap<Digest, Vec<TagName>>> {
        let mut out: std::collections::HashMap<Digest, Vec<TagName>> =
            std::collections::HashMap::new();
        for (tag, digest) in self.list_tags().await? {
            out.entry(digest).or_default().push(tag);
        }
        Ok(out)
    }

    // -- tags --------------------------------------------------------------

    pub async fn set_tag(&self, t: &TagName, d: &Digest) -> Result<()> {
        let inner = self.inner.clone();
        let (t, d) = (t.clone(), d.clone());
        blocking(move || inner.set_tag(&t, &d)).await
    }

    pub async fn get_tag(&self, t: &TagName) -> Result<Digest> {
        let inner = self.inner.clone();
        let t = t.clone();
        blocking(move || inner.get_tag(&t)).await
    }

    pub async fn remove_tag(&self, t: &TagName) -> Result<bool> {
        let inner = self.inner.clone();
        let t = t.clone();
        blocking(move || sparse::unlink_if_present(&inner.tag_path(&t))).await
    }

    pub async fn list_tags(&self) -> Result<Vec<(TagName, Digest)>> {
        let inner = self.inner.clone();
        blocking(move || inner.list_tags()).await
    }

    // -- repositories ------------------------------------------------------

    /// Replace a repository's metadata wholesale.
    ///
    /// Needs no tag to exist yet: marking `heyo/postgres` public before its
    /// first push is how a publisher says what the repository will be.
    pub async fn set_repo(&self, r: &RepoName, meta: &RepoMeta) -> Result<()> {
        meta.validate()?;
        let inner = self.inner.clone();
        let (r, meta) = (r.clone(), meta.clone());
        blocking(move || inner.set_repo(&r, &meta)).await
    }

    /// A repository's metadata, or `None` if nothing has been said about it.
    pub async fn get_repo(&self, r: &RepoName) -> Result<Option<RepoMeta>> {
        let inner = self.inner.clone();
        let r = r.clone();
        blocking(move || inner.get_repo(&r)).await
    }

    pub async fn remove_repo(&self, r: &RepoName) -> Result<bool> {
        let inner = self.inner.clone();
        let r = r.clone();
        blocking(move || sparse::unlink_if_present(&inner.repo_path(&r))).await
    }

    /// Every repository with metadata, name-ordered.
    pub async fn list_repos(&self) -> Result<Vec<(RepoName, RepoMeta)>> {
        let inner = self.inner.clone();
        blocking(move || inner.list_repos()).await
    }

    /// Every repository that has a tag or metadata, with its tags. A
    /// repository nobody described still exists the moment something is
    /// tagged into it.
    pub async fn repositories(&self) -> Result<Vec<Repository>> {
        let mut by_name: std::collections::BTreeMap<RepoName, Repository> =
            std::collections::BTreeMap::new();
        for (name, meta) in self.list_repos().await? {
            by_name.insert(
                name.clone(),
                Repository {
                    name,
                    meta,
                    tags: Vec::new(),
                },
            );
        }
        for (tag, digest) in self.list_tags().await? {
            let Some(repo) = tag.repo() else { continue };
            by_name
                .entry(repo.clone())
                .or_insert_with(|| Repository {
                    name: repo,
                    meta: RepoMeta::default(),
                    tags: Vec::new(),
                })
                .tags
                .push((tag, digest));
        }
        Ok(by_name.into_values().collect())
    }

    /// Map a tag or literal digest to a digest. Does not check existence.
    pub async fn resolve(&self, r: &Ref) -> Result<Digest> {
        match r {
            Ref::Digest(d) => Ok(d.clone()),
            Ref::Tag(t) => self.get_tag(t).await,
        }
    }

    /// Resolve a reference all the way to a *blob*, stepping through a manifest
    /// when the reference names one.
    ///
    /// Tags point at manifests — that is what carries an image's annotations —
    /// so without this every command that wants bytes would have to know the
    /// difference, and `art get debian-hermes` would fail on the one input a
    /// person is most likely to type. A manifest with a single entry resolves
    /// to it; one with several is ambiguous and says so.
    pub async fn resolve_blob(&self, r: &Ref) -> Result<Digest> {
        let d = self.resolve(r).await?;
        if self.has(&d).await? {
            return Ok(d);
        }
        let m = match self.get_manifest(&d).await {
            Ok(m) => m,
            // Neither a blob nor a manifest: report it as the missing blob the
            // caller was asking for.
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

    pub async fn usage(&self) -> Result<Usage> {
        let inner = self.inner.clone();
        blocking(move || inner.usage()).await
    }

    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }
}

/// Run a blocking store operation off the runtime threads.
pub(crate) async fn run_blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    blocking(f).await
}

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(Error::Io {
            context: "store worker".into(),
            source: std::io::Error::other(e),
        }),
    }
}

impl Inner {
    fn blob_path(&self, d: &Digest) -> PathBuf {
        self.root.join("blobs").join(d.shard()).join(d.as_str())
    }

    fn manifest_path(&self, d: &Digest) -> PathBuf {
        self.root.join("manifests").join(d.shard()).join(d.as_str())
    }

    fn tag_path(&self, t: &TagName) -> PathBuf {
        self.root.join("tags").join(t.file_name())
    }

    fn repo_path(&self, r: &RepoName) -> PathBuf {
        self.root.join("repos").join(r.file_name())
    }

    fn label_path(&self, d: &Digest) -> PathBuf {
        self.root.join("labels").join(d.shard()).join(d.as_str())
    }

    fn public_path(&self, d: &Digest) -> PathBuf {
        self.root.join("public").join(d.shard()).join(d.as_str())
    }

    /// Create the public marker. An empty file whose existence is the whole
    /// message: there is no content to tear, so no tmp-and-rename dance — a
    /// crash leaves either a marker or none, both valid states.
    pub(crate) fn set_public(&self, d: &Digest) -> Result<()> {
        let dir = self.root.join("public").join(d.shard());
        let p = self.public_path(d);
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&p)
            .ctx(format!("create {}", p.display()))?;
        space::fsync_dir(&dir)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub(crate) fn lock(&self) -> &StoreLock {
        &self.lock
    }

    fn stat(&self, d: &Digest) -> Result<BlobInfo> {
        let p = self.blob_path(d);
        let st = space::stat_path(&p).map_err(|e| match e {
            Error::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                Error::NotFound(d.clone())
            }
            other => other,
        })?;
        Ok(BlobInfo {
            digest: d.clone(),
            size: st.size,
            allocated: st.allocated,
            nlink: st.nlink,
            created: st.created,
            deduped: false,
        })
    }

    // -- insert ------------------------------------------------------------

    fn insert_path(&self, src: &Path, shape: Shape) -> Result<BlobInfo> {
        let f = sparse::open_for_read(src)?;
        let st = space::stat_path(src)?;

        // For a shape that copies verbatim we know exactly what it will cost.
        // For ZeroSquash we cannot know until every zero run has been scanned,
        // so the upfront guard is skipped in favour of the incremental one
        // below — otherwise importing a 21 GB image that will occupy 1.2 GB
        // would be refused on a disk with 13 GB free, which is precisely the
        // case this store exists to handle.
        if shape.grain().is_none() {
            space::guard(&self.root, st.allocated, self.min_free_bytes)?;
        }

        let incoming = Incoming::create(&self.tmp_dir())?;
        let mut hasher = Sha256::new();
        let mut next_check = GUARD_INTERVAL;

        let written = sparse::copy_observing_guarded(
            f.as_raw_fd(),
            incoming.as_raw_fd(),
            st.size,
            shape,
            |b| hasher.update(b),
            |written| {
                if written >= next_check {
                    next_check = written + GUARD_INTERVAL;
                    space::guard(&self.root, 0, self.min_free_bytes)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                }
                Ok(())
            },
        )
        .ctx(format!("copy {}", src.display()))?;

        let digest = finish(hasher);
        let info = self.commit_blob(incoming, &digest, written)?;
        sparse::advise_dontneed(f.as_raw_fd(), st.size);
        Ok(info)
    }

    fn insert_stream<R: std::io::Read>(&self, mut reader: R, shape: Shape) -> Result<BlobInfo> {
        let incoming = Incoming::create(&self.tmp_dir())?;
        let fd = incoming.as_raw_fd();
        let grain = shape.grain();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut offset = 0u64;
        let mut written = 0u64;
        let mut next_check = GUARD_INTERVAL;

        loop {
            let n = read_full(&mut reader, &mut buf).ctx("read input")?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            hasher.update(chunk);
            written += match grain {
                Some(g) => write_nonzero(fd, chunk, offset, g)?,
                None => {
                    sparse::pwrite_all(fd, chunk, offset).ctx("write blob")?;
                    n as u64
                }
            };
            offset += n as u64;
            if written >= next_check {
                next_check = written + GUARD_INTERVAL;
                space::guard(&self.root, 0, self.min_free_bytes)?;
            }
        }
        // The length is only known now, and it is what makes any skipped tail
        // read back as zeros rather than truncating the blob.
        sparse::ftruncate(fd, offset).ctx("set blob length")?;

        let digest = finish(hasher);
        self.commit_blob(incoming, &digest, written)
    }

    fn insert_encoded<R: std::io::Read>(&self, mut r: R, expected: &Digest) -> Result<BlobInfo> {
        let header = crate::asp::read_header(&mut r).ctx("read remote blob header")?;
        // The header says exactly what the fill will allocate, so this guard is
        // the precise one rather than the incremental kind.
        space::guard(&self.root, header.data_len(), self.min_free_bytes)?;
        let incoming = Incoming::create(&self.tmp_dir())?;
        let mut hasher = Sha256::new();
        let (_, written) =
            crate::asp::decode_body(&header, r, incoming.as_raw_fd(), |b| hasher.update(b))
                .ctx(format!("decode remote blob {expected}"))?;
        let digest = finish(hasher);
        if &digest != expected {
            return Err(Error::DigestMismatch {
                expected: expected.clone(),
                actual: digest,
            });
        }
        self.commit_blob(incoming, &digest, written)
    }

    /// Sync, seal, and link a staged blob under the store lock.
    ///
    /// The lock is held only for the link and the directory fsync. Everything
    /// expensive already happened.
    fn commit_blob(&self, incoming: Incoming, digest: &Digest, written: u64) -> Result<BlobInfo> {
        let synced = incoming.sync()?;
        let dest = self.blob_path(digest);

        let outcome = {
            let _guard = self.lock.acquire(LockMode::Shared)?;
            let outcome = synced.link_into(&dest)?;
            if outcome == LinkOutcome::Created {
                space::fsync_dir(dest.parent().expect("blob path always has a shard"))?;
            }
            outcome
        };
        sparse::advise_dontneed(synced.as_raw_fd(), written);

        let mut info = self.stat(digest)?;
        info.deduped = outcome == LinkOutcome::AlreadyExists;
        Ok(info)
    }

    fn verify(&self, d: &Digest) -> Result<()> {
        let p = self.blob_path(d);
        if !p.exists() {
            return Err(Error::NotFound(d.clone()));
        }
        let f = sparse::open_for_read(&p)?;
        let st = space::stat_path(&p)?;
        let mut hasher = Sha256::new();
        // A hole reads as zeros, and the digest covers the logical stream, so
        // reading through the holes is exactly right here.
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut off = 0u64;
        while off < st.size {
            let want = ((st.size - off) as usize).min(buf.len());
            let n = sparse::pread(f.as_raw_fd(), &mut buf[..want], off).ctx("read blob")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            off += n as u64;
        }
        sparse::advise_dontneed(f.as_raw_fd(), st.size);

        let actual = finish(hasher);
        if &actual != d {
            return Err(Error::DigestMismatch {
                expected: d.clone(),
                actual,
            });
        }
        Ok(())
    }

    // -- materialize -------------------------------------------------------

    fn materialize(&self, d: &Digest, dest: &Path, how: Materialize) -> Result<Materialized> {
        let src = self.blob_path(d);
        let st = space::stat_path(&src).map_err(|e| match e {
            Error::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                Error::NotFound(d.clone())
            }
            other => other,
        })?;

        let parent = dest.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).ctx(format!("create {}", parent.display()))?;

        if how == Materialize::ReadOnly {
            // Decide before trying. Discovering EXDEV from a failed syscall
            // would mean unwinding a half-created file, and the caller would
            // never learn that its hardlink silently became a copy.
            let dest_dev = space::dev_of_dir(parent)?;
            if dest_dev == self.dev {
                match std::fs::hard_link(&src, dest) {
                    Ok(()) => {
                        return Ok(Materialized {
                            path: dest.to_path_buf(),
                            digest: d.clone(),
                            method: Method::Hardlink,
                            bytes_written: 0,
                        });
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EMLINK) => {
                        // Content is identical either way; only deduplication
                        // is lost, so warn and copy rather than fail.
                        tracing::warn!(
                            digest = %d,
                            nlink = st.nlink,
                            "blob has reached the filesystem hardlink limit; copying instead"
                        );
                    }
                    Err(e) => {
                        return Err(e).ctx(format!("link {} to {}", src.display(), dest.display()));
                    }
                }
            } else {
                tracing::debug!(
                    dest = %dest.display(),
                    "destination is on another filesystem; copying instead of linking"
                );
            }
        }

        let shape = match how {
            Materialize::Writable { shape, .. } => shape,
            // A read-only request that fell through to a copy still wants the
            // cheapest faithful copy.
            Materialize::ReadOnly => Shape::HoleAware,
        };
        let mode = match how {
            Materialize::Writable { mode, .. } => mode,
            Materialize::ReadOnly => 0o444,
        };

        space::guard(&self.root, st.allocated, self.min_free_bytes)?;

        let f = sparse::open_for_read(&src)?;
        let out = create_dest(dest, mode)?;
        let written = sparse::copy_shaped(f.as_raw_fd(), out.as_raw_fd(), st.size, shape)
            .ctx(format!("copy blob to {}", dest.display()))?;
        sparse::fdatasync(out.as_raw_fd()).ctx("fdatasync materialized file")?;
        sparse::advise_dontneed(out.as_raw_fd(), st.size);
        sparse::advise_dontneed(f.as_raw_fd(), st.size);

        Ok(Materialized {
            path: dest.to_path_buf(),
            digest: d.clone(),
            method: if written < st.size {
                Method::SparseCopy
            } else {
                Method::DenseCopy
            },
            bytes_written: written,
        })
    }

    // -- manifests and tags ------------------------------------------------

    fn put_manifest(&self, bytes: Vec<u8>) -> Result<Digest> {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = finish(hasher);

        let incoming = Incoming::create(&self.tmp_dir())?;
        sparse::pwrite_all(incoming.as_raw_fd(), &bytes, 0).ctx("write manifest")?;
        let synced = incoming.sync()?;
        let dest = self.manifest_path(&digest);

        let _guard = self.lock.acquire(LockMode::Shared)?;
        if synced.link_into(&dest)? == LinkOutcome::Created {
            space::fsync_dir(dest.parent().expect("manifest path always has a shard"))?;
        }
        Ok(digest)
    }

    /// Tags are the one mutable object, so they use temp + rename. `link`'s
    /// refusal to replace is exactly wrong here.
    pub(crate) fn set_tag(&self, t: &TagName, d: &Digest) -> Result<()> {
        let body = format!("{d}\n");
        write_replacing(&self.tag_path(t), body.as_bytes(), "tag")
    }

    pub(crate) fn set_repo(&self, r: &RepoName, meta: &RepoMeta) -> Result<()> {
        write_replacing(&self.repo_path(r), &meta.to_json(), "repository")
    }

    fn get_repo(&self, r: &RepoName) -> Result<Option<RepoMeta>> {
        let p = self.repo_path(r);
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).ctx(format!("read {}", p.display())),
        };
        // Unreadable metadata is a private, undescribed repository — the safe
        // reading of a file that no longer says "public".
        match serde_json::from_slice::<RepoMeta>(&bytes) {
            Ok(m) => Ok(Some(m)),
            Err(e) => {
                tracing::warn!(repo = %r, error = %e, "skipping unreadable repository metadata");
                Ok(Some(RepoMeta::default()))
            }
        }
    }

    fn list_repos(&self) -> Result<Vec<(RepoName, RepoMeta)>> {
        let dir = self.root.join("repos");
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).ctx(format!("read {}", dir.display())),
        };
        for entry in rd {
            let entry = entry.ctx("read repository entry")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') {
                continue;
            }
            let Ok(repo) = RepoName::from_file_name(name) else {
                continue;
            };
            if let Some(meta) = self.get_repo(&repo)? {
                out.push((repo, meta));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub(crate) fn set_label(&self, d: &Digest, label: &Label) -> Result<()> {
        let dir = self.root.join("labels").join(d.shard());
        let final_path = self.label_path(d);
        // Same directory as the destination, so the rename is within one
        // filesystem, and prefixed with a dot so a half-written label can never
        // be mistaken for one by `list_labels`.
        let tmp = dir.join(format!(".{}.{}.tmp", d.as_str(), std::process::id()));

        let body = label.to_json();
        let write = (|| -> Result<()> {
            let f = std::fs::File::create(&tmp).ctx(format!("create {}", tmp.display()))?;
            sparse::pwrite_all(f.as_raw_fd(), &body, 0).ctx("write label")?;
            f.sync_all().ctx("fsync label")?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).ctx(format!("rename label into {}", final_path.display()));
        }
        space::fsync_dir(&dir)
    }

    fn get_label(&self, d: &Digest) -> Result<Option<Label>> {
        let p = self.label_path(d);
        let bytes = match std::fs::read(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).ctx(format!("read {}", p.display())),
        };
        // A label that will not parse is reported as absent rather than as a
        // failure. It is metadata about content, so losing it costs a column;
        // failing the read would take the page that was rendering the row with
        // it, which is a strictly worse trade.
        match serde_json::from_slice::<Label>(&bytes) {
            Ok(label) => Ok(Some(label)),
            Err(e) => {
                tracing::warn!(digest = %d, error = %e, "skipping unreadable label");
                Ok(None)
            }
        }
    }

    fn list_labels(&self) -> Result<Vec<Labelled>> {
        let mut out = Vec::new();
        for digest in self.list_digests("labels")? {
            if let Some(label) = self.get_label(&digest)? {
                out.push(Labelled { digest, label });
            }
        }
        Ok(out)
    }

    fn get_tag(&self, t: &TagName) -> Result<Digest> {
        let p = self.tag_path(t);
        let body = match std::fs::read_to_string(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::TagNotFound(t.to_string()));
            }
            Err(e) => return Err(e).ctx(format!("read {}", p.display())),
        };
        Ok(Digest::parse(body.trim())?)
    }

    fn list_tags(&self) -> Result<Vec<(TagName, Digest)>> {
        let dir = self.root.join("tags");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).ctx(format!("read {}", dir.display()))? {
            let entry = entry.ctx("read tag entry")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Skip temp files and anything hidden.
            if name.starts_with('.') {
                continue;
            }
            let Ok(tag) = TagName::from_file_name(name) else {
                continue;
            };
            match self.get_tag(&tag) {
                Ok(d) => out.push((tag, d)),
                // A tag whose body is unreadable or malformed is skipped rather
                // than failing the whole listing.
                Err(e) => tracing::warn!(tag = %name, error = %e, "skipping unreadable tag"),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    // -- listing -----------------------------------------------------------

    /// Names in one shard, sorted by inode number.
    ///
    /// `readdir` on an htree directory returns entries in name-hash order,
    /// which is uncorrelated with inode number — but inode number *is* strongly
    /// correlated with position in the on-disk inode table. Sorting first turns
    /// a random walk of that table into a near-sequential one. `d_ino` comes
    /// free from `getdents64`, so this costs no extra syscall.
    fn shard_entries(&self, sub: &str, shard: &str) -> Result<Vec<(String, u64)>> {
        use std::os::unix::fs::DirEntryExt;
        let dir = self.root.join(sub).join(shard);
        let mut v = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(v),
            Err(e) => return Err(e).ctx(format!("read {}", dir.display())),
        };
        for entry in rd {
            let entry = entry.ctx("read shard entry")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('.') {
                continue;
            }
            v.push((name.to_string(), entry.ino()));
        }
        v.sort_by_key(|(_, ino)| *ino);
        Ok(v)
    }

    fn list_digests(&self, sub: &str) -> Result<Vec<Digest>> {
        let mut out = Vec::new();
        for i in 0u16..256 {
            let shard = format!("{i:02x}");
            for (name, _) in self.shard_entries(sub, &shard)? {
                if let Ok(d) = Digest::parse(&name) {
                    out.push(d);
                }
            }
        }
        Ok(out)
    }

    fn list_blobs(&self) -> Result<Vec<BlobInfo>> {
        let mut out = Vec::new();
        for i in 0u16..256 {
            let shard = format!("{i:02x}");
            for (name, _) in self.shard_entries("blobs", &shard)? {
                let Ok(d) = Digest::parse(&name) else {
                    continue;
                };
                match self.stat(&d) {
                    Ok(info) => out.push(info),
                    // Raced with a sweep; not an error for a listing.
                    Err(Error::NotFound(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        out.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.digest.cmp(&b.digest)));
        Ok(out)
    }

    fn usage(&self) -> Result<Usage> {
        let blobs = self.list_blobs()?;
        let fs = space::statfs(&self.root)?;
        Ok(Usage {
            blobs: blobs.len() as u64,
            logical: blobs.iter().map(|b| b.size).sum(),
            allocated: blobs.iter().map(|b| b.allocated).sum(),
            manifests: self.list_digests("manifests")?.len() as u64,
            tags: self.list_tags()?.len() as u64,
            fs_available: fs.available,
            fs_total: fs.total,
        })
    }
}

/// Access for sibling modules that need the raw stat without a `BlobInfo`.
impl Inner {
    pub(crate) fn blob_stat(&self, d: &Digest) -> Result<FileStat> {
        space::stat_path(&self.blob_path(d))
    }

    pub(crate) fn blob_path_of(&self, d: &Digest) -> PathBuf {
        self.blob_path(d)
    }

    pub(crate) fn manifest_path_of(&self, d: &Digest) -> PathBuf {
        self.manifest_path(d)
    }

    pub(crate) fn shard_names(&self, sub: &str, shard: &str) -> Result<Vec<(String, u64)>> {
        self.shard_entries(sub, shard)
    }

    pub(crate) fn all_tags(&self) -> Result<Vec<(TagName, Digest)>> {
        self.list_tags()
    }

    pub(crate) fn manifest_bytes(&self, d: &Digest) -> Result<Vec<u8>> {
        let p = self.manifest_path(d);
        std::fs::read(&p).ctx(format!("read {}", p.display()))
    }

    pub(crate) fn manifest_digests(&self) -> Result<Vec<Digest>> {
        self.list_digests("manifests")
    }

    pub(crate) fn label_digests(&self) -> Result<Vec<Digest>> {
        self.list_digests("labels")
    }

    pub(crate) fn label_path_of(&self, d: &Digest) -> PathBuf {
        self.label_path(d)
    }

    pub(crate) fn public_digests(&self) -> Result<Vec<Digest>> {
        self.list_digests("public")
    }

    pub(crate) fn public_path_of(&self, d: &Digest) -> PathBuf {
        self.public_path(d)
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn tag_path_of(&self, t: &TagName) -> PathBuf {
        self.tag_path(t)
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn repo_path_of(&self, r: &RepoName) -> PathBuf {
        self.repo_path(r)
    }

    /// Whether a digest still names a blob. A plain existence check — the
    /// garbage collector asks it about a label's subject, where the size and
    /// link count a `stat` would also return are of no interest.
    pub(crate) fn blob_exists(&self, d: &Digest) -> bool {
        self.blob_path(d).exists()
    }

    pub(crate) fn manifest_exists(&self, d: &Digest) -> bool {
        self.manifest_path(d).exists()
    }
}

/// Replace `path` with `body`: temp file in the same directory, `sync_all`,
/// rename, fsync the directory. The temp name is short and unique within the
/// process, so a long namespaced tag cannot push it past `NAME_MAX`, and it
/// starts with a dot so no listing mistakes it for the real thing.
pub(crate) fn write_replacing(path: &Path, body: &[u8], what: &str) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().expect("store paths always have a parent");
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let write = (|| -> Result<()> {
        let f = std::fs::File::create(&tmp).ctx(format!("create {}", tmp.display()))?;
        sparse::pwrite_all(f.as_raw_fd(), body, 0).ctx(format!("write {what}"))?;
        f.sync_all().ctx(format!("fsync {what}"))?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).ctx(format!("rename {what} into {}", path.display()));
    }
    space::fsync_dir(dir)
}

fn finish(h: Sha256) -> Digest {
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Digest::from_bytes(&bytes)
}

fn create_dest(dest: &Path, mode: u32) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // create_new, never truncate: silently replacing whatever was at the
    // destination is not this function's decision to make.
    std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(mode)
        .open(dest)
        .ctx(format!("create {}", dest.display()))
}

fn write_nonzero(fd: std::os::fd::RawFd, chunk: &[u8], base: u64, grain: usize) -> Result<u64> {
    let mut written = 0u64;
    let mut i = 0usize;
    while i < chunk.len() {
        let end = (i + grain).min(chunk.len());
        if sparse::is_zero(&chunk[i..end]) {
            i = end;
            continue;
        }
        let start = i;
        i = end;
        while i < chunk.len() {
            let e = (i + grain).min(chunk.len());
            if sparse::is_zero(&chunk[i..e]) {
                break;
            }
            i = e;
        }
        sparse::pwrite_all(fd, &chunk[start..i], base + start as u64).ctx("write blob")?;
        written += (i - start) as u64;
    }
    Ok(written)
}

/// Fill `buf` unless the reader ends first.
fn read_full<R: std::io::Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match r.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::KIND_GENERIC;

    fn tmpdir() -> tempfile::TempDir {
        match std::env::var_os("ART_TEST_DIR").map(PathBuf::from) {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn store_in(d: &tempfile::TempDir) -> Store {
        let cfg = Config {
            root: d.path().join("store"),
            min_free_bytes: 0,
            gc_min_age: std::time::Duration::ZERO,
            heyvm_images_dir: d.path().join("images"),
        };
        Store::open(&cfg).unwrap()
    }

    fn sha(data: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(data);
        finish(h)
    }

    #[tokio::test]
    async fn insert_is_addressed_by_content() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"hello world".to_vec()).await.unwrap();
        assert_eq!(info.digest, sha(b"hello world"));
        assert_eq!(info.size, 11);
        assert!(!info.deduped);
        assert!(s.has(&info.digest).await.unwrap());
    }

    #[tokio::test]
    async fn inserting_the_same_bytes_twice_dedups_without_raising_nlink() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"same".to_vec()).await.unwrap();
        let b = s.insert_bytes(b"same".to_vec()).await.unwrap();
        assert_eq!(a.digest, b.digest);
        assert!(!a.deduped);
        assert!(b.deduped, "second insert should report a dedup hit");
        // If a duplicate insert raised nlink, GC's "nlink == 1 means
        // unreferenced" rule would stop meaning anything.
        assert_eq!(s.stat(&a.digest).await.unwrap().nlink, 1);
    }

    #[tokio::test]
    async fn blobs_are_immutable_on_disk() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"sealed".to_vec()).await.unwrap();
        let p = s.blob_path(&info.digest);
        let e = std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn missing_blob_is_not_found() {
        let d = tmpdir();
        let s = store_in(&d);
        let e = s.stat(&sha(b"absent")).await.unwrap_err();
        assert!(matches!(e, Error::NotFound(_)), "{e:?}");
        assert!(!s.has(&sha(b"absent")).await.unwrap());
    }

    #[tokio::test]
    async fn insert_path_matches_insert_bytes() {
        let d = tmpdir();
        let s = store_in(&d);
        let f = d.path().join("f");
        std::fs::write(&f, b"from a file").unwrap();
        let a = s.insert_path(&f, Shape::Dense).await.unwrap();
        let b = s.insert_bytes(b"from a file".to_vec()).await.unwrap();
        assert_eq!(a.digest, b.digest);
    }

    #[tokio::test]
    async fn zero_squash_digest_matches_a_dense_digest() {
        // The digest must cover the full logical stream. If squashing changed
        // it, `art`'s addresses would stop matching `sha256sum` and mvm-ctrl's
        // BlobRef.sha256.
        let d = tmpdir();
        let s = store_in(&d);
        let mut data = vec![0u8; 1 << 20];
        data[..4096].fill(9);
        let f = d.path().join("img");
        std::fs::write(&f, &data).unwrap();

        let squashed = s.insert_path(&f, Shape::SQUASH).await.unwrap();
        assert_eq!(squashed.digest, sha(&data));
        assert_eq!(squashed.size, data.len() as u64);
        assert_eq!(std::fs::read(s.blob_path(&squashed.digest)).unwrap(), data);
    }

    #[tokio::test]
    async fn zero_squash_stores_less_than_it_addresses() {
        let d = tmpdir();
        let s = store_in(&d);
        if !sparse::supports_punch_hole(d.path()) {
            eprintln!("skipping zero_squash_stores_less: no sparse files here");
            return;
        }
        let mut data = vec![0u8; 4 << 20];
        data[..4096].fill(1);
        let f = d.path().join("img");
        std::fs::write(&f, &data).unwrap();

        let info = s.insert_path(&f, Shape::SQUASH).await.unwrap();
        assert_eq!(info.size, data.len() as u64);
        assert!(
            info.allocated < info.size / 2,
            "expected a sparse blob: {} allocated of {}",
            info.allocated,
            info.size
        );
    }

    #[tokio::test]
    async fn verify_detects_nothing_wrong_with_a_good_blob() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"trustworthy".to_vec()).await.unwrap();
        s.verify(&info.digest).await.unwrap();
    }

    #[tokio::test]
    async fn verify_reads_through_holes() {
        let d = tmpdir();
        let s = store_in(&d);
        let mut data = vec![0u8; 1 << 20];
        data[100..110].fill(5);
        let f = d.path().join("img");
        std::fs::write(&f, &data).unwrap();
        let info = s.insert_path(&f, Shape::SQUASH).await.unwrap();
        // A hole reads as zeros and the digest covers the logical stream, so a
        // sparsely-stored blob must still verify.
        s.verify(&info.digest).await.unwrap();
    }

    #[tokio::test]
    async fn read_only_materialize_is_a_hardlink() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"shared".to_vec()).await.unwrap();
        let dest = d.path().join("out/link");

        let m = s
            .materialize(&info.digest, &dest, Materialize::ReadOnly)
            .await
            .unwrap();
        assert_eq!(m.method, Method::Hardlink);
        assert_eq!(m.bytes_written, 0, "a hardlink costs no bytes");
        assert_eq!(std::fs::read(&dest).unwrap(), b"shared");

        // The kernel is now the refcount.
        assert_eq!(s.stat(&info.digest).await.unwrap().nlink, 2);
        assert_eq!(
            space::stat_path(&dest).unwrap().ino,
            space::stat_path(&s.blob_path(&info.digest)).unwrap().ino
        );

        assert!(s.release(&m).await.unwrap());
        assert_eq!(s.stat(&info.digest).await.unwrap().nlink, 1);
    }

    #[tokio::test]
    async fn writable_materialize_is_a_private_copy() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"base image".to_vec()).await.unwrap();
        let dest = d.path().join("vm/rootfs.ext4");

        let m = s
            .materialize(
                &info.digest,
                &dest,
                Materialize::Writable {
                    shape: Shape::HoleAware,
                    mode: 0o644,
                },
            )
            .await
            .unwrap();
        assert_ne!(m.method, Method::Hardlink);
        assert_eq!(std::fs::read(&dest).unwrap(), b"base image");

        // Distinct inode, and writable — a guest must be able to scribble on it
        // without touching the blob.
        assert_ne!(
            space::stat_path(&dest).unwrap().ino,
            space::stat_path(&s.blob_path(&info.digest)).unwrap().ino
        );
        assert_eq!(s.stat(&info.digest).await.unwrap().nlink, 1);
        std::fs::write(&dest, b"mutated!!!").unwrap();
        // The blob is untouched.
        s.verify(&info.digest).await.unwrap();
    }

    #[tokio::test]
    async fn writable_materialize_of_a_sparse_blob_writes_only_live_data() {
        let d = tmpdir();
        let s = store_in(&d);
        if !sparse::supports_punch_hole(d.path()) {
            eprintln!("skipping sparse materialize test: no sparse files here");
            return;
        }
        let mut data = vec![0u8; 8 << 20];
        data[..4096].fill(3);
        let f = d.path().join("img");
        std::fs::write(&f, &data).unwrap();
        let info = s.insert_path(&f, Shape::SQUASH).await.unwrap();

        let dest = d.path().join("vm/rootfs.ext4");
        let m = s
            .materialize(
                &info.digest,
                &dest,
                Materialize::Writable {
                    shape: Shape::HoleAware,
                    mode: 0o644,
                },
            )
            .await
            .unwrap();

        assert_eq!(m.method, Method::SparseCopy);
        assert!(
            m.bytes_written < info.size / 2,
            "materialize wrote {} of {}",
            m.bytes_written,
            info.size
        );
        // Content is still exact.
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn materialize_refuses_to_clobber() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"x".to_vec()).await.unwrap();
        let dest = d.path().join("out");
        std::fs::write(&dest, b"precious").unwrap();
        assert!(
            s.materialize(&info.digest, &dest, Materialize::ReadOnly)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"precious");
    }

    #[tokio::test]
    async fn materialize_of_a_missing_blob_is_not_found() {
        let d = tmpdir();
        let s = store_in(&d);
        let e = s
            .materialize(&sha(b"gone"), &d.path().join("out"), Materialize::ReadOnly)
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NotFound(_)), "{e:?}");
    }

    #[tokio::test]
    async fn public_is_a_per_blob_flag_that_round_trips() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"shareable".to_vec()).await.unwrap();

        assert!(!s.is_public(&a.digest).await.unwrap(), "private by default");
        s.set_public(&a.digest).await.unwrap();
        assert!(s.is_public(&a.digest).await.unwrap());
        // Idempotent: marking twice is not an error and changes nothing.
        s.set_public(&a.digest).await.unwrap();
        assert!(s.is_public(&a.digest).await.unwrap());

        assert!(s.remove_public(&a.digest).await.unwrap());
        assert!(
            !s.remove_public(&a.digest).await.unwrap(),
            "second removal reports none"
        );
        assert!(!s.is_public(&a.digest).await.unwrap());
    }

    /// A public flag on nothing would exempt a 404 from auth; a public flag on
    /// a manifest would leak a listing. Both are refused where labels allow
    /// the second, because public is a property of downloadable bytes only.
    #[tokio::test]
    async fn public_refuses_absent_digests_and_manifests() {
        let d = tmpdir();
        let s = store_in(&d);

        let absent = Digest::parse(&hex::encode([9u8; 32])).unwrap();
        assert!(matches!(
            s.set_public(&absent).await.unwrap_err(),
            Error::NotFound(_)
        ));

        let blob = s.insert_bytes(b"member".to_vec()).await.unwrap();
        let m = Manifest::new(KIND_GENERIC).with_entry("member", blob.digest.clone(), blob.size);
        let md = s.put_manifest(&m).await.unwrap();
        assert!(matches!(
            s.set_public(&md).await.unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn tags_resolve_and_are_replaceable() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"one".to_vec()).await.unwrap();
        let b = s.insert_bytes(b"two".to_vec()).await.unwrap();
        let t = TagName::parse("debian").unwrap();

        s.set_tag(&t, &a.digest).await.unwrap();
        assert_eq!(s.get_tag(&t).await.unwrap(), a.digest);
        // Last write wins — a tag is the one mutable object in the store.
        s.set_tag(&t, &b.digest).await.unwrap();
        assert_eq!(s.get_tag(&t).await.unwrap(), b.digest);

        assert_eq!(s.resolve(&Ref::Tag(t.clone())).await.unwrap(), b.digest);
        assert_eq!(
            s.resolve(&Ref::Digest(a.digest.clone())).await.unwrap(),
            a.digest
        );

        assert!(s.remove_tag(&t).await.unwrap());
        assert!(!s.remove_tag(&t).await.unwrap());
        assert!(matches!(
            s.get_tag(&t).await.unwrap_err(),
            Error::TagNotFound(_)
        ));
    }

    #[tokio::test]
    async fn setting_a_tag_leaves_no_temp_file() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"one".to_vec()).await.unwrap();
        let t = TagName::parse("img").unwrap();
        s.set_tag(&t, &a.digest).await.unwrap();
        s.set_tag(&t, &a.digest).await.unwrap();

        let names: Vec<_> = std::fs::read_dir(s.root().join("tags"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["img".to_string()]);
    }

    #[tokio::test]
    async fn list_tags_skips_temps_and_sorts() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"one".to_vec()).await.unwrap();
        for n in ["c", "a", "b"] {
            s.set_tag(&TagName::parse(n).unwrap(), &a.digest)
                .await
                .unwrap();
        }
        std::fs::write(s.root().join("tags").join(".x.tmp"), "junk").unwrap();

        let tags = s.list_tags().await.unwrap();
        let names: Vec<_> = tags.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn manifests_are_content_addressed_and_idempotent() {
        let d = tmpdir();
        let s = store_in(&d);
        let blob = s.insert_bytes(b"member".to_vec()).await.unwrap();
        let m = Manifest::new(KIND_GENERIC)
            .with_entry("member", blob.digest.clone(), blob.size)
            .annotate("note", "hi");

        let d1 = s.put_manifest(&m).await.unwrap();
        // Re-inserting an unchanged manifest must land at the same address —
        // this is why Manifest has no timestamp field.
        let d2 = s.put_manifest(&m).await.unwrap();
        assert_eq!(d1, d2);
        assert_eq!(s.list_manifests().await.unwrap().len(), 1);
        assert_eq!(s.get_manifest(&d1).await.unwrap(), m);
    }

    #[tokio::test]
    async fn resolve_blob_follows_a_tag_through_a_single_entry_manifest() {
        // A tag names a manifest, because that is what carries an image's
        // annotations. Without this step `art get <tag>` — the most likely
        // thing anyone types — would fail with "blob not found".
        let d = tmpdir();
        let s = store_in(&d);
        let blob = s.insert_bytes(b"rootfs bytes".to_vec()).await.unwrap();
        let m =
            Manifest::new(KIND_GENERIC).with_entry("rootfs.ext4", blob.digest.clone(), blob.size);
        let md = s.put_manifest(&m).await.unwrap();
        let tag = TagName::parse("debian").unwrap();
        s.set_tag(&tag, &md).await.unwrap();

        assert_eq!(
            s.resolve_blob(&Ref::Tag(tag.clone())).await.unwrap(),
            blob.digest
        );
        assert_eq!(s.resolve_blob(&Ref::Digest(md)).await.unwrap(), blob.digest);
        // A reference that already names a blob passes straight through.
        assert_eq!(
            s.resolve_blob(&Ref::Digest(blob.digest.clone()))
                .await
                .unwrap(),
            blob.digest
        );
    }

    #[tokio::test]
    async fn resolve_blob_reports_a_multi_entry_manifest_as_ambiguous() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"one".to_vec()).await.unwrap();
        let b = s.insert_bytes(b"two".to_vec()).await.unwrap();
        let m = Manifest::new(KIND_GENERIC)
            .with_entry("rootfs.ext4", a.digest.clone(), a.size)
            .with_entry("data.ext4", b.digest.clone(), b.size);
        let md = s.put_manifest(&m).await.unwrap();

        let e = s.resolve_blob(&Ref::Digest(md)).await.unwrap_err();
        match &e {
            Error::AmbiguousManifest { entries, .. } => {
                assert_eq!(
                    entries,
                    &["rootfs.ext4".to_string(), "data.ext4".to_string()]
                );
            }
            other => panic!("expected AmbiguousManifest, got {other:?}"),
        }
        // The message must name the entries, or the user cannot act on it.
        assert!(e.to_string().contains("data.ext4"), "{e}");
    }

    #[tokio::test]
    async fn resolve_blob_of_something_absent_is_not_found() {
        let d = tmpdir();
        let s = store_in(&d);
        let e = s
            .resolve_blob(&Ref::Digest(sha(b"nothing here")))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::NotFound(_)), "{e:?}");
    }

    #[tokio::test]
    async fn get_manifest_of_a_missing_digest_is_not_found() {
        let d = tmpdir();
        let s = store_in(&d);
        assert!(matches!(
            s.get_manifest(&sha(b"nope")).await.unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn usage_reports_logical_and_physical_separately() {
        let d = tmpdir();
        let s = store_in(&d);
        s.insert_bytes(b"abc".to_vec()).await.unwrap();
        s.insert_bytes(b"defgh".to_vec()).await.unwrap();
        let u = s.usage().await.unwrap();
        assert_eq!(u.blobs, 2);
        assert_eq!(u.logical, 8);
        assert!(u.fs_total > 0);
    }

    #[tokio::test]
    async fn list_blobs_covers_every_shard() {
        let d = tmpdir();
        let s = store_in(&d);
        let mut expected = Vec::new();
        for i in 0..40u8 {
            let info = s.insert_bytes(vec![i; (i as usize) + 1]).await.unwrap();
            expected.push(info.digest);
        }
        let listed = s.list_blobs().await.unwrap();
        assert_eq!(listed.len(), expected.len());
        for d in expected {
            assert!(listed.iter().any(|b| b.digest == d));
        }
    }

    #[tokio::test]
    async fn space_guard_refuses_before_writing() {
        let d = tmpdir();
        let cfg = Config {
            root: d.path().join("store"),
            min_free_bytes: u64::MAX,
            gc_min_age: std::time::Duration::ZERO,
            heyvm_images_dir: d.path().join("images"),
        };
        let s = Store::open(&cfg).unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, b"data").unwrap();

        let e = s.insert_path(&f, Shape::Dense).await.unwrap_err();
        assert!(matches!(e, Error::NoSpace { .. }), "{e:?}");
        assert!(s.list_blobs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_blob_round_trips() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(Vec::new()).await.unwrap();
        assert_eq!(info.size, 0);
        assert_eq!(
            info.digest.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        s.verify(&info.digest).await.unwrap();
    }

    #[tokio::test]
    async fn large_stream_spans_buffers() {
        let d = tmpdir();
        let s = store_in(&d);
        let data: Vec<u8> = (0..(9 << 20u32)).map(|i| (i % 251) as u8).collect();
        let info = s.insert_bytes(data.clone()).await.unwrap();
        assert_eq!(info.digest, sha(&data));
        assert_eq!(info.size, data.len() as u64);
        s.verify(&info.digest).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_inserts_of_identical_bytes_agree() {
        let d = tmpdir();
        let s = store_in(&d);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = s.clone();
                tokio::spawn(async move { s.insert_bytes(b"contended".to_vec()).await })
            })
            .collect();

        let mut digests = Vec::new();
        for h in handles {
            digests.push(h.await.unwrap().unwrap().digest);
        }
        assert!(digests.iter().all(|d| *d == digests[0]));
        // One blob, one link. `link` refusing to replace is what makes this
        // safe: the first writer wins permanently.
        assert_eq!(s.list_blobs().await.unwrap().len(), 1);
        assert_eq!(s.stat(&digests[0]).await.unwrap().nlink, 1);
        assert!(std::fs::read_dir(s.root().join("tmp")).unwrap().count() == 0);
    }

    // -- labels ------------------------------------------------------------

    #[tokio::test]
    async fn a_label_round_trips_and_replaces_wholesale() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"hello".to_vec()).await.unwrap();

        assert_eq!(s.get_label(&info.digest).await.unwrap(), None);

        let l = Label::new(Some("greeting".into()), Some("the usual".into())).unwrap();
        s.set_label(&info.digest, &l).await.unwrap();
        assert_eq!(s.get_label(&info.digest).await.unwrap(), Some(l));

        // A second write replaces both fields together — this is a PUT, not a
        // merge, so a label naming only a name has no description afterwards.
        let renamed = Label::new(Some("hello".into()), None).unwrap();
        s.set_label(&info.digest, &renamed).await.unwrap();
        let got = s.get_label(&info.digest).await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("hello"));
        assert_eq!(got.description, None, "the previous description is gone");
    }

    /// The property the whole design exists for: naming something does not
    /// move it. Every tag, manifest entry and materialization still resolves.
    #[tokio::test]
    async fn labelling_does_not_change_what_anything_resolves_to() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"rootfs".to_vec()).await.unwrap();
        let tag = TagName::parse("web-v2").unwrap();
        s.set_tag(&tag, &info.digest).await.unwrap();

        let before = s.get_tag(&tag).await.unwrap();
        s.set_label(
            &info.digest,
            &Label::new(Some("the web rootfs".into()), None).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(s.get_tag(&tag).await.unwrap(), before);
        assert_eq!(s.stat(&info.digest).await.unwrap().digest, info.digest);
    }

    /// One mechanism for both kinds. A manifest is addressed by a digest like
    /// anything else, so it is labelled the same way — and labelling it does not
    /// give it a new digest, which is what putting the name *inside* would.
    #[tokio::test]
    async fn a_manifest_is_labelled_like_a_blob() {
        let d = tmpdir();
        let s = store_in(&d);
        let blob = s.insert_bytes(b"entry".to_vec()).await.unwrap();
        let m = Manifest::new(KIND_GENERIC).with_entry("f", blob.digest.clone(), blob.size);
        let md = s.put_manifest(&m).await.unwrap();

        s.set_label(&md, &Label::new(Some("a bundle".into()), None).unwrap())
            .await
            .unwrap();

        assert_eq!(
            s.put_manifest(&m).await.unwrap(),
            md,
            "the manifest's own digest is unmoved by a label",
        );
        assert_eq!(
            s.get_label(&md).await.unwrap().unwrap().name.as_deref(),
            Some("a bundle"),
        );
        // ...and the blob it names is a different subject with its own label.
        assert_eq!(s.get_label(&blob.digest).await.unwrap(), None);
    }

    /// A label on content the store does not hold describes an address that
    /// resolves nowhere. Refused in the store itself, so the CLI and the HTTP
    /// route cannot disagree about it.
    #[tokio::test]
    async fn a_label_needs_something_to_describe() {
        let d = tmpdir();
        let s = store_in(&d);
        let absent = Digest::parse(&"0".repeat(64)).unwrap();

        let err = s
            .set_label(&absent, &Label::new(Some("nothing".into()), None).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
        assert_eq!(s.get_label(&absent).await.unwrap(), None);

        // Validation still comes first: an unusable label is refused before the
        // store is asked whether the digest exists, so the error names the thing
        // the caller can actually fix.
        let info = s.insert_bytes(b"real".to_vec()).await.unwrap();
        let err = s
            .set_label(&info.digest, &Label::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Label(_)), "{err}");
    }

    #[tokio::test]
    async fn removing_a_label_reports_whether_there_was_one() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"x".to_vec()).await.unwrap();

        assert!(!s.remove_label(&info.digest).await.unwrap());
        s.set_label(&info.digest, &Label::new(Some("x".into()), None).unwrap())
            .await
            .unwrap();
        assert!(s.remove_label(&info.digest).await.unwrap());
        assert_eq!(s.get_label(&info.digest).await.unwrap(), None);
    }

    #[tokio::test]
    async fn listing_labels_skips_the_unreadable_and_the_half_written() {
        let d = tmpdir();
        let s = store_in(&d);
        let a = s.insert_bytes(b"a".to_vec()).await.unwrap();
        let b = s.insert_bytes(b"b".to_vec()).await.unwrap();
        s.set_label(&a.digest, &Label::new(Some("A".into()), None).unwrap())
            .await
            .unwrap();
        s.set_label(&b.digest, &Label::new(Some("B".into()), None).unwrap())
            .await
            .unwrap();

        // Corrupt one, and drop a temp file beside it of the kind an
        // interrupted write leaves behind.
        let path = s
            .root()
            .join("labels")
            .join(b.digest.shard())
            .join(b.digest.as_str());
        std::fs::write(&path, b"{not json").unwrap();
        std::fs::write(path.with_file_name(format!(".{}.99.tmp", b.digest)), b"{}").unwrap();

        let listed = s.list_labels().await.unwrap();
        assert_eq!(
            listed.len(),
            1,
            "a broken label costs its own row and no more"
        );
        assert_eq!(listed[0].digest, a.digest);

        // And the map a listing page builds agrees with it.
        let map = s.label_map().await.unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&a.digest));
    }

    /// The direction a listing asks in: given a digest, what names it?
    #[tokio::test]
    async fn tags_are_indexable_by_what_they_point_at() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"shared".to_vec()).await.unwrap();
        let other = s.insert_bytes(b"lonely".to_vec()).await.unwrap();

        for name in ["latest", "web-v2"] {
            s.set_tag(&TagName::parse(name).unwrap(), &info.digest)
                .await
                .unwrap();
        }

        let by_digest = s.tags_by_digest().await.unwrap();
        let mut names: Vec<&str> = by_digest[&info.digest].iter().map(|t| t.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            ["latest", "web-v2"],
            "several tags can name one digest"
        );
        assert!(!by_digest.contains_key(&other.digest));
    }

    /// A label is metadata, and a label that will not parse must cost exactly
    /// one column — never the read of the thing it describes.
    #[tokio::test]
    async fn an_unreadable_label_does_not_fail_the_object() {
        let d = tmpdir();
        let s = store_in(&d);
        let info = s.insert_bytes(b"hello".to_vec()).await.unwrap();
        let path = s
            .root()
            .join("labels")
            .join(info.digest.shard())
            .join(info.digest.as_str());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"garbage").unwrap();

        assert_eq!(s.get_label(&info.digest).await.unwrap(), None);
        assert_eq!(s.stat(&info.digest).await.unwrap().size, 5);
    }
}
