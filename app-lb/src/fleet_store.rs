//! Where app-lb's records are kept.
//!
//! Every store that outlives a restart — deployments, namespaces, auth
//! providers, workflows, plugins, secrets, tokens, guard rules, the postgres
//! plugin's ownership map, the ACME account and certificates — reads and writes
//! through the two traits here instead of calling `std::fs` itself. A
//! [`Collection`] is a set of records under string keys (one file each today);
//! a [`Document`] is one record (one file).
//!
//! The file implementation here is exact: the same paths, the same bytes, the
//! same temp-file-then-rename, the same fsyncs where they were, the same
//! `0600`/`0700` modes. A single-server app-lb behaves as it always has and its
//! state directory stays readable by an older binary. The shared store
//! (`fleet_pg`, behind `APP_LB_FLEET_DATABASE_URL`) sits behind the same calls
//! and keeps these files as its local snapshot; see
//! `docs/design/fleet-shared-state.md`.
//!
//! Each store keeps its own serialization, validation and in-memory view.
//! This module moves bytes.
//!
//! **Revisions.** Every write returns a [`Revision`], and a write may demand
//! one with [`Expect`]. For files they are counted in memory and mean nothing
//! across processes or restarts; they exist so callers are written against
//! compare-and-swap from the start.
//!
//! The module depends on nothing but `std`, because the
//! `app-lb-fleet-import` binary compiles it too.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A record's version, as the store that holds it counts them.
pub type Revision = u64;

/// What a write requires of the record it replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Write whatever is there. Every store used this before revisions existed.
    Any,
    /// Only create: fail if the record exists.
    Absent,
    /// Only replace this exact version.
    Revision(Revision),
}

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    /// The [`Expect`] did not hold. `current` is what is there now, if anything.
    Conflict {
        key: String,
        current: Option<Revision>,
    },
    /// A write made under a lease this process no longer holds, or holds under
    /// an older epoch than the store's. Nothing was written.
    Fenced {
        lease: String,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Conflict {
                key,
                current: Some(r),
            } => {
                write!(
                    f,
                    "{key:?} changed underneath this write (now at revision {r})"
                )
            }
            Self::Conflict { key, current: None } => {
                write!(f, "{key:?} does not exist, or no longer does")
            }
            Self::Fenced { lease } => {
                write!(f, "this host no longer holds the {lease:?} lease")
            }
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// So a store whose callers speak `io::Result` can keep doing so.
impl From<StoreError> for io::Error {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Io(e) => e,
            fenced @ StoreError::Fenced { .. } => {
                io::Error::new(io::ErrorKind::PermissionDenied, fenced.to_string())
            }
            conflict => io::Error::new(io::ErrorKind::AlreadyExists, conflict.to_string()),
        }
    }
}

/// One record as a listing returns it.
#[derive(Debug)]
pub struct Entry {
    pub key: String,
    /// Where it lives, for log lines (a path, for files).
    pub location: String,
    /// The record, or why it could not be read. An unreadable record is
    /// returned rather than dropped: every store decides for itself whether
    /// that is a warning or a refusal to start.
    pub body: io::Result<Vec<u8>>,
}

/// A set of records under string keys.
///
/// Keys are opaque to the store but must be safe as part of a file name:
/// non-empty, with no `/` or NUL. (`.` and `..` are fine, since a suffix always
/// follows.) Every caller already encodes its ids into that alphabet.
pub trait Collection: Send + Sync + fmt::Debug {
    fn get(&self, key: &str) -> io::Result<Option<(Vec<u8>, Revision)>>;
    /// Every record. A collection that has never been written is empty, not an
    /// error. Order is unspecified.
    fn list(&self) -> io::Result<Vec<Entry>>;
    fn put(&self, key: &str, body: &[u8], expect: Expect) -> Result<Revision, StoreError>;
    /// Whether anything was removed. Removing a missing record succeeds with
    /// `false` under [`Expect::Any`].
    fn delete(&self, key: &str, expect: Expect) -> Result<bool, StoreError>;
    fn location(&self, key: &str) -> String;
}

/// One record's latest change, as a store with a change feed reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // the importer compiles this module without a shared store
pub struct Change {
    pub revision: Revision,
    pub kind: String,
    pub key: String,
    /// `None` when the change was a delete.
    pub body: Option<Vec<u8>>,
}

/// One write in a [`Transactional::transaction`]. `kind` names the
/// collection, as the shared store files records under it.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Write {
    Put {
        kind: String,
        key: String,
        body: Vec<u8>,
        expect: Expect,
    },
    Delete {
        kind: String,
        key: String,
        expect: Expect,
    },
}

/// What a store shared between hosts adds to [`Collection`]: writes to several
/// records that land together or not at all, and the feed of what changed.
///
/// Only the shared store implements it. A single server's files have no
/// other writer to hear from, and no caller relies on a multi-file write being
/// atomic.
#[allow(dead_code)]
pub trait Transactional: Send + Sync {
    /// Apply every write or none. With `fence`, the writes also require that
    /// the named lease is still held at that epoch ([`StoreError::Fenced`]
    /// otherwise). Returns each write's revision; a delete of nothing is `0`.
    fn transaction(
        &self,
        writes: &[Write],
        fence: Option<(&str, u64)>,
    ) -> Result<Vec<Revision>, StoreError>;

    /// Changes with a revision above `cursor`, oldest first, at most `limit`.
    /// A record changed twice appears once, at its latest revision.
    fn changes_since(&self, cursor: Revision, limit: usize) -> io::Result<Vec<Change>>;
}

/// The key a [`Document`] is filed under in a store of collections: a
/// document is a kind with one record.
#[allow(dead_code)]
pub const DOC_KEY: &str = "document";

/// A single record.
pub trait Document: Send + Sync + fmt::Debug {
    /// `None` when it has never been written.
    fn read(&self) -> io::Result<Option<(Vec<u8>, Revision)>>;
    fn write(&self, body: &[u8], expect: Expect) -> Result<Revision, StoreError>;
    fn location(&self) -> String;
}

// ---- files -------------------------------------------------------------------

/// How hard a file write tries to survive a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// Temp file, then rename. A crash leaves the old version or the new one,
    /// but a power loss may lose the latest write.
    Renamed,
    /// Also fsync the file before the rename and the directory after it, and
    /// make newly created directories durable in their parents. A completed
    /// write survives power loss. The deployment registry needs this: a drain
    /// must not silently reopen traffic after a host crash.
    Synced,
}

/// How a file-backed store writes.
#[derive(Debug, Clone, Copy)]
pub struct FileOptions {
    pub durability: Durability,
    /// Files are `0600`, restricted while still empty so no credential is ever
    /// readable by others, even briefly.
    pub private: bool,
    /// Set the containing directory to this mode on every write (`0o700` for
    /// the ACME directory, which holds private keys).
    pub dir_mode: Option<u32>,
}

impl FileOptions {
    pub const PLAIN: Self = Self {
        durability: Durability::Renamed,
        private: false,
        dir_mode: None,
    };
    pub const PRIVATE: Self = Self {
        durability: Durability::Renamed,
        private: true,
        dir_mode: None,
    };
    pub const SYNCED: Self = Self {
        durability: Durability::Synced,
        private: false,
        dir_mode: None,
    };

    pub const fn private_dir(mut self, mode: u32) -> Self {
        self.dir_mode = Some(mode);
        self
    }
}

/// In-memory revision counting for a file-backed store.
#[derive(Debug, Default)]
struct Revisions {
    next: Revision,
    by_key: HashMap<String, Revision>,
}

impl Revisions {
    fn bump(&mut self, key: &str) -> Revision {
        self.next += 1;
        self.by_key.insert(key.to_string(), self.next);
        self.next
    }

    /// The revision of a record known to exist, assigning one on first sight.
    fn seen(&mut self, key: &str) -> Revision {
        if let Some(r) = self.by_key.get(key) {
            return *r;
        }
        self.bump(key)
    }
}

/// A directory of files named `<key><suffix>`.
#[derive(Debug)]
pub struct FileCollection {
    dir: PathBuf,
    suffix: &'static str,
    opts: FileOptions,
    /// Held across check-and-write, so [`Expect`] is atomic within the process.
    revisions: Mutex<Revisions>,
    /// Fail a write after its rename and before the directory sync, the one
    /// point where the file is on disk but the write reports failure.
    #[cfg(test)]
    pub(crate) fail_after_rename: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FileCollection {
    /// `suffix` is the whole file-name ending, dot included (`.json`,
    /// `.crt.pem`). Nothing is created until the first write.
    pub fn new(dir: impl Into<PathBuf>, suffix: &'static str, opts: FileOptions) -> Self {
        Self {
            dir: dir.into(),
            suffix,
            opts,
            revisions: Mutex::new(Revisions::default()),
            #[cfg(test)]
            fail_after_rename: Default::default(),
        }
    }

    /// The directory the records live in.
    #[allow(dead_code)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, key: &str) -> io::Result<PathBuf> {
        check_key(key)?;
        Ok(self.dir.join(format!("{key}{}", self.suffix)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Revisions> {
        self.revisions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check(
        &self,
        revs: &mut Revisions,
        key: &str,
        path: &Path,
        expect: Expect,
    ) -> Result<(), StoreError> {
        let exists = path.exists();
        let current = exists.then(|| revs.seen(key));
        let ok = match expect {
            Expect::Any => true,
            Expect::Absent => !exists,
            Expect::Revision(r) => current == Some(r),
        };
        if ok {
            Ok(())
        } else {
            Err(StoreError::Conflict {
                key: key.to_string(),
                current,
            })
        }
    }
}

impl Collection for FileCollection {
    fn get(&self, key: &str) -> io::Result<Option<(Vec<u8>, Revision)>> {
        let path = self.path(key)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some((bytes, self.lock().seen(key)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn list(&self) -> io::Result<Vec<Entry>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            // A stray `<key><suffix>.tmp` from an interrupted write ends in
            // `.tmp`, so it never matches.
            let Some(key) = name.to_str().and_then(|n| n.strip_suffix(self.suffix)) else {
                continue;
            };
            if check_key(key).is_err() {
                continue;
            }
            let path = entry.path();
            let body = std::fs::read(&path);
            if body.is_ok() {
                self.lock().seen(key);
            }
            out.push(Entry {
                key: key.to_string(),
                location: path.display().to_string(),
                body,
            });
        }
        Ok(out)
    }

    fn put(&self, key: &str, body: &[u8], expect: Expect) -> Result<Revision, StoreError> {
        let path = self.path(key)?;
        let mut revs = self.lock();
        self.check(&mut revs, key, &path, expect)?;
        prepare_dir(&self.dir, &self.opts)?;
        #[cfg(test)]
        let hook = Some(&*self.fail_after_rename);
        #[cfg(not(test))]
        let hook = None;
        write_file(&path, body, &self.opts, hook)?;
        Ok(revs.bump(key))
    }

    fn delete(&self, key: &str, expect: Expect) -> Result<bool, StoreError> {
        let path = self.path(key)?;
        let mut revs = self.lock();
        self.check(&mut revs, key, &path, expect)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {
                revs.by_key.remove(key);
                if self.opts.durability == Durability::Synced {
                    sync_dir(&self.dir)?;
                }
                Ok(true)
            }
            // Already gone is the desired end state.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn location(&self, key: &str) -> String {
        self.dir
            .join(format!("{key}{}", self.suffix))
            .display()
            .to_string()
    }
}

/// One file.
#[derive(Debug)]
pub struct FileDocument {
    path: PathBuf,
    opts: FileOptions,
    revision: Mutex<Option<Revision>>,
}

impl FileDocument {
    pub fn new(path: impl Into<PathBuf>, opts: FileOptions) -> Self {
        Self {
            path: path.into(),
            opts,
            revision: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Revision>> {
        self.revision.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the file. Gone already is success. Only the shared store's
    /// snapshot needs this: no single-server store ever deletes its document.
    #[allow(dead_code)]
    pub fn remove(&self) -> io::Result<bool> {
        let mut rev = self.lock();
        match std::fs::remove_file(&self.path) {
            Ok(()) => {
                *rev = None;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

impl Document for FileDocument {
    fn read(&self) -> io::Result<Option<(Vec<u8>, Revision)>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let mut rev = self.lock();
                let r = *rev.get_or_insert(1);
                Ok(Some((bytes, r)))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write(&self, body: &[u8], expect: Expect) -> Result<Revision, StoreError> {
        let mut rev = self.lock();
        let exists = self.path.exists();
        let current = if exists {
            Some(*rev.get_or_insert(1))
        } else {
            None
        };
        let ok = match expect {
            Expect::Any => true,
            Expect::Absent => !exists,
            Expect::Revision(r) => current == Some(r),
        };
        if !ok {
            return Err(StoreError::Conflict {
                key: self.path.display().to_string(),
                current,
            });
        }
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            prepare_dir(parent, &self.opts)?;
        }
        write_file(&self.path, body, &self.opts, None)?;
        let next = current.unwrap_or(0) + 1;
        *rev = Some(next);
        Ok(next)
    }

    fn location(&self) -> String {
        self.path.display().to_string()
    }
}

fn check_key(key: &str) -> io::Result<()> {
    if key.is_empty() || key.contains('/') || key.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{key:?} is not a usable record key"),
        ));
    }
    Ok(())
}

/// Create `dir` as the options require.
fn prepare_dir(dir: &Path, opts: &FileOptions) -> io::Result<()> {
    if opts.durability == Durability::Synced {
        create_dir_durable(dir)?;
    } else {
        std::fs::create_dir_all(dir)?;
    }
    if let Some(_mode) = opts.dir_mode {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(_mode))?;
        }
    }
    Ok(())
}

/// `create_dir_all`, then sync each newly created directory into its parent,
/// from the highest one down: a directory entry is not crash-durable until its
/// parent is synced.
fn create_dir_durable(dir: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = dir;
    while !ancestor.as_os_str().is_empty() && !ancestor.exists() {
        missing.push(ancestor.to_path_buf());
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
    std::fs::create_dir_all(dir)?;
    for created in missing.iter().rev() {
        let parent = created
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// The temp name for `path`: `x.json` → `x.json.tmp`.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Write-then-rename, so a reader never sees a half-written record and a crash
/// mid-write leaves the previous version intact.
fn write_file(
    path: &Path,
    body: &[u8],
    opts: &FileOptions,
    fail_after_rename: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<()> {
    let tmp = tmp_path(path);
    match opts.durability {
        Durability::Renamed => {
            if opts.private {
                std::fs::write(&tmp, b"")?;
                restrict(&tmp)?;
            }
            std::fs::write(&tmp, body)?;
            std::fs::rename(&tmp, path)?;
        }
        Durability::Synced => {
            let mut file = std::fs::File::create(&tmp)?;
            if opts.private {
                restrict(&tmp)?;
            }
            io::Write::write_all(&mut file, body)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, path)?;
            if fail_after_rename.is_some_and(|f| f.swap(false, std::sync::atomic::Ordering::SeqCst))
            {
                return Err(io::Error::other("injected failure after rename"));
            }
            if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                sync_dir(dir)?;
            }
        }
    }
    Ok(())
}

/// `0600`. Unix-only, like the rest of app-lb's on-disk credential handling.
fn restrict(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

// ---- where things live --------------------------------------------------------

/// `app-lb-state.json` → `app-lb-<kind>.d`, beside it. The namespace, workflow,
/// auth-provider and plugin stores all derive their directories this way.
pub fn sibling_dir(state_path: &str, kind: &str) -> PathBuf {
    let path = Path::new(state_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app-lb-state");
    let name = match stem.strip_suffix("-state") {
        Some(prefix) => format!("{prefix}-{kind}.d"),
        None => format!("{stem}-{kind}.d"),
    };
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// `app-lb-state.json` → `app-lb-state.d`: the deployment registry's directory.
pub fn registry_dir(state_path: &Path) -> PathBuf {
    let stem = state_path
        .file_stem()
        .unwrap_or_else(|| std::ffi::OsStr::new("app-lb-state"));
    let mut name = stem.to_os_string();
    name.push(".d");
    match state_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

/// Every path app-lb keeps durable records under, from the same environment
/// variables and defaults `main` reads. `main` does not use this; it exists so
/// a tool that must not start app-lb can still find its state, and a test pins
/// it to `Config`'s defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // app-lb itself only uses it in a test; app-lb-fleet-import is its user
pub struct Layout {
    pub state_path: PathBuf,
    pub secrets_path: PathBuf,
    pub tokens_path: PathBuf,
    pub guard_path: PathBuf,
    pub acme_dir: PathBuf,
}

#[allow(dead_code)]
impl Layout {
    pub const DEFAULT_STATE_PATH: &'static str = "app-lb-state.json";
    pub const DEFAULT_SECRETS_PATH: &'static str = "app-lb-secrets.json";
    pub const DEFAULT_TOKENS_PATH: &'static str = "app-lb-tokens.json";
    pub const DEFAULT_GUARD_PATH: &'static str = "app-lb-guard.json";
    pub const DEFAULT_ACME_DIR: &'static str = "/var/lib/app-lb/acme";

    pub fn from_env() -> Self {
        let var =
            |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.to_string()));
        Self {
            state_path: var("APP_LB_STATE_PATH", Self::DEFAULT_STATE_PATH),
            secrets_path: var("APP_LB_SECRETS_PATH", Self::DEFAULT_SECRETS_PATH),
            tokens_path: var("APP_LB_TOKENS_PATH", Self::DEFAULT_TOKENS_PATH),
            guard_path: var("APP_LB_GUARD_PATH", Self::DEFAULT_GUARD_PATH),
            acme_dir: var("APP_LB_ACME_DIR", Self::DEFAULT_ACME_DIR),
        }
    }

    fn state(&self) -> String {
        self.state_path.to_string_lossy().into_owned()
    }

    pub fn registry_dir(&self) -> PathBuf {
        registry_dir(&self.state_path)
    }
    pub fn namespace_dir(&self) -> PathBuf {
        sibling_dir(&self.state(), "namespaces")
    }
    pub fn workflow_dir(&self) -> PathBuf {
        sibling_dir(&self.state(), "workflows")
    }
    pub fn auth_provider_dir(&self) -> PathBuf {
        sibling_dir(&self.state(), "auth-providers")
    }
    pub fn plugin_dir(&self) -> PathBuf {
        sibling_dir(&self.state(), "plugins")
    }
    /// The postgres plugin's ownership map.
    pub fn postgres_ownership_path(&self) -> PathBuf {
        self.plugin_dir().join("state").join("postgres.json")
    }
    pub fn acme_certs_dir(&self) -> PathBuf {
        self.acme_dir.join("certs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fleet-store-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn collection_round_trips_and_lists_only_its_suffix() {
        let dir = scratch("roundtrip");
        let c = FileCollection::new(&dir, ".json", FileOptions::PLAIN);
        assert!(c.list().unwrap().is_empty(), "a missing directory is empty");
        assert!(c.get("a").unwrap().is_none());

        c.put("a", b"{\"x\":1}", Expect::Any).unwrap();
        c.put("b", b"{}", Expect::Any).unwrap();
        std::fs::write(dir.join("c.json.tmp"), b"partial").unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignored").unwrap();
        std::fs::create_dir_all(dir.join("retired")).unwrap();

        assert_eq!(std::fs::read(dir.join("a.json")).unwrap(), b"{\"x\":1}");
        let mut keys: Vec<_> = c.list().unwrap().into_iter().map(|e| e.key).collect();
        keys.sort();
        assert_eq!(keys, ["a", "b"]);
        assert!(
            !dir.join("a.json.tmp").exists(),
            "no temp file is left behind"
        );

        assert!(c.delete("a", Expect::Any).unwrap());
        assert!(
            !c.delete("a", Expect::Any).unwrap(),
            "deleting twice is not an error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expectations_are_enforced() {
        let dir = scratch("cas");
        let c = FileCollection::new(&dir, ".json", FileOptions::SYNCED);
        let r1 = c.put("k", b"1", Expect::Absent).unwrap();
        assert!(matches!(
            c.put("k", b"2", Expect::Absent),
            Err(StoreError::Conflict { current: Some(r), .. }) if r == r1
        ));
        let r2 = c.put("k", b"2", Expect::Revision(r1)).unwrap();
        assert!(r2 > r1);
        assert!(matches!(
            c.put("k", b"3", Expect::Revision(r1)),
            Err(StoreError::Conflict { .. })
        ));
        assert!(matches!(
            c.delete("k", Expect::Revision(r1)),
            Err(StoreError::Conflict { .. })
        ));
        assert_eq!(c.get("k").unwrap().unwrap(), (b"2".to_vec(), r2));
        assert!(c.delete("k", Expect::Revision(r2)).unwrap());
        assert!(matches!(
            c.delete("k", Expect::Revision(r2)),
            Err(StoreError::Conflict { current: None, .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_keys_are_refused() {
        let dir = scratch("keys");
        let c = FileCollection::new(&dir, ".json", FileOptions::PLAIN);
        for key in ["", "a/b", "../x", "a\0b"] {
            assert!(c.put(key, b"x", Expect::Any).is_err(), "{key:?}");
        }
        assert!(!dir.exists(), "a refused key creates nothing");
    }

    #[test]
    fn an_unreadable_record_is_listed_not_dropped() {
        let dir = scratch("unreadable");
        std::fs::create_dir_all(dir.join("bad.json")).unwrap(); // a directory, so read fails
        let c = FileCollection::new(&dir, ".json", FileOptions::PLAIN);
        let entries = c.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].body.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_files_and_directories_get_their_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("modes");
        let c = FileCollection::new(&dir, ".key.pem", FileOptions::PRIVATE.private_dir(0o700));
        c.put("example.com", b"key", Expect::Any).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("example.com.key.pem")), 0o600);
        assert_eq!(mode(&dir), 0o700);

        let doc = FileDocument::new(dir.join("nested/secrets.json"), FileOptions::PRIVATE);
        doc.write(b"{}", Expect::Any).unwrap();
        assert_eq!(mode(&dir.join("nested/secrets.json")), 0o600);

        let synced = FileCollection::new(
            dir.join("synced"),
            ".json",
            FileOptions {
                private: true,
                ..FileOptions::SYNCED
            },
        );
        synced.put("s", b"{}", Expect::Any).unwrap();
        assert_eq!(mode(&dir.join("synced/s.json")), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn document_round_trips_with_revisions() {
        let dir = scratch("doc");
        let doc = FileDocument::new(dir.join("a/b/tokens.json"), FileOptions::PRIVATE);
        assert!(doc.read().unwrap().is_none());
        let r1 = doc.write(b"one", Expect::Absent).unwrap();
        assert!(matches!(
            doc.write(b"x", Expect::Absent),
            Err(StoreError::Conflict { .. })
        ));
        let r2 = doc.write(b"two", Expect::Revision(r1)).unwrap();
        assert_eq!(doc.read().unwrap().unwrap(), (b"two".to_vec(), r2));
        assert!(!dir.join("a/b/tokens.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn injected_failure_leaves_the_file_written() {
        let dir = scratch("hook");
        let c = FileCollection::new(&dir, ".json", FileOptions::SYNCED);
        c.fail_after_rename
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(c.put("k", b"v", Expect::Any).is_err());
        assert_eq!(std::fs::read(dir.join("k.json")).unwrap(), b"v");
        c.put("k", b"w", Expect::Any).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn directories_derive_like_they_always_have() {
        assert_eq!(
            sibling_dir("/var/lib/app-lb/app-lb-state.json", "namespaces"),
            PathBuf::from("/var/lib/app-lb/app-lb-namespaces.d")
        );
        assert_eq!(
            sibling_dir("app-lb-state.json", "plugins"),
            PathBuf::from("app-lb-plugins.d")
        );
        assert_eq!(
            sibling_dir("/srv/custom.json", "workflows"),
            PathBuf::from("/srv/custom-workflows.d")
        );
        assert_eq!(
            registry_dir(Path::new("/var/lib/app-lb/app-lb-state.json")),
            PathBuf::from("/var/lib/app-lb/app-lb-state.d")
        );
        assert_eq!(
            registry_dir(Path::new("app-lb-state.json")),
            PathBuf::from("app-lb-state.d")
        );
    }
}
