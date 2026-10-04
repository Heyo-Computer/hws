//! A blob acquires a name only after `fdatasync` has returned — enforced by the
//! type system, not by convention.
//!
//! [`Incoming`] is an anonymous, unnamed file. The only way to get a
//! [`SyncedTmp`], and therefore the only way to reach [`SyncedTmp::link_into`],
//! is through [`Incoming::sync`]. That ordering is not a stylistic preference:
//! under ext4's default `data=ordered`, journalling the *name* before the
//! *data* can survive a crash as a correctly-named blob containing the wrong
//! bytes — corruption the store cannot detect without rehashing everything.
//!
//! Two further decisions are load-bearing:
//!
//! - **`O_TMPFILE`, not a temp file.** A crash leaks nothing, because closing
//!   the descriptor reclaims the blocks. No name ever enters the shard's htree,
//!   so there is no `.tmp` residue to filter out of listings and no
//!   cleanup-on-every-error-path dance.
//! - **`link`, not `rename`.** `rename` would silently replace an existing
//!   blob, so two concurrent writers of the same digest each replace the
//!   other's inode — and any hardlink already handed to a running VM would then
//!   point at a different inode than the store's own directory entry, which is
//!   exactly the divergence `st_nlink`-as-refcount cannot tolerate. `link`'s
//!   `EEXIST` makes the first writer win permanently, and *is* the dedup hit:
//!   "we already have this" is the same syscall as the insert, with no
//!   pre-check race.

use super::{check, cpath};
use crate::error::{IoContext, Result};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Blobs are immutable, so they are stored read-only. This is the last line of
/// defence against a caller hardlinking a blob and handing it to something that
/// opens it read-write: that caller gets `EACCES` instead of rewriting content
/// whose name is a promise about what it contains.
const BLOB_MODE: libc::mode_t = 0o444;

/// Keeps fallback temp names unique within a process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// What `link_into` found at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The name did not exist; this call created it.
    Created,
    /// Another writer got there first. For a content-addressed store the bytes
    /// are necessarily identical, so this is a successful deduplication.
    AlreadyExists,
}

/// An unnamed file being written into a shard directory.
pub struct Incoming {
    file: File,
    /// `Some` only on the fallback path, where a real name exists and must be
    /// cleaned up.
    tmp_path: Option<PathBuf>,
}

impl Incoming {
    /// Create an unnamed file in `dir`, falling back to a hidden temp file when
    /// the filesystem has no `O_TMPFILE` (NFS, some overlay and FUSE mounts).
    pub fn create(dir: &Path) -> Result<Incoming> {
        Incoming::create_inner(dir, force_no_tmpfile())
    }

    /// [`Incoming::create`], with the fallback path forced.
    ///
    /// Exists so tests can cover both implementations on a filesystem that
    /// supports `O_TMPFILE`, without mutating process-wide environment that
    /// concurrently-running tests would see.
    pub fn create_fallback(dir: &Path) -> Result<Incoming> {
        Incoming::create_inner(dir, true)
    }

    fn create_inner(dir: &Path, force_fallback: bool) -> Result<Incoming> {
        if !force_fallback {
            match open_tmpfile(dir) {
                Ok(file) => {
                    return Ok(Incoming {
                        file,
                        tmp_path: None,
                    });
                }
                Err(e) if is_unsupported(&e) => {
                    tracing::debug!(
                        dir = %dir.display(),
                        error = %e,
                        "O_TMPFILE unsupported here; using a named temp file"
                    );
                }
                Err(e) => {
                    return Err(e).ctx(format!("create temp file in {}", dir.display()));
                }
            }
        }

        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".incoming.{}.{}.tmp", std::process::id(), seq));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&tmp)
            .ctx(format!("create {}", tmp.display()))?;
        Ok(Incoming {
            file,
            tmp_path: Some(tmp),
        })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Make the bytes durable and seal the file read-only.
    ///
    /// `fdatasync`, not `fsync`: the inode has no name yet, so its timestamps
    /// are irrelevant to recovery, and skipping them saves a journal
    /// transaction per blob.
    pub fn sync(self) -> Result<SyncedTmp> {
        super::sparse::fdatasync(self.as_raw_fd()).ctx("fdatasync blob")?;
        // SAFETY: the descriptor is live for the duration of the call.
        let rc = unsafe { libc::fchmod(self.as_raw_fd(), BLOB_MODE) };
        check(rc).ctx("seal blob read-only")?;
        Ok(SyncedTmp { inner: self })
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // The O_TMPFILE path has nothing to clean: closing the descriptor
        // releases the blocks.
        if let Some(p) = &self.tmp_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// An [`Incoming`] whose bytes are on disk. Only this type can be linked into
/// the store.
pub struct SyncedTmp {
    inner: Incoming,
}

impl SyncedTmp {
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Give the blob its name.
    ///
    /// `EEXIST` is reported as [`LinkOutcome::AlreadyExists`], not an error.
    pub fn link_into(&self, dest: &Path) -> Result<LinkOutcome> {
        let dest_c = cpath(dest).ctx(format!("link to {}", dest.display()))?;

        let rc = match &self.inner.tmp_path {
            // Fallback path: a real name exists, so link it directly.
            Some(tmp) => {
                let src_c = cpath(tmp).ctx(format!("link from {}", tmp.display()))?;
                // SAFETY: both paths are NUL-terminated C strings.
                unsafe { libc::link(src_c.as_ptr(), dest_c.as_ptr()) }
            }
            // O_TMPFILE path. `AT_EMPTY_PATH` would be the obvious spelling but
            // requires CAP_DAC_READ_SEARCH, which an unprivileged process does
            // not have; linking through /proc/self/fd is the documented
            // unprivileged recipe. AT_SYMLINK_FOLLOW is required because that
            // entry is a symlink.
            None => {
                let proc_path = CString::new(format!("/proc/self/fd/{}", self.as_raw_fd()))
                    .expect("fd path never contains a NUL");
                // SAFETY: both paths are NUL-terminated C strings and the
                // descriptor is live.
                unsafe {
                    libc::linkat(
                        libc::AT_FDCWD,
                        proc_path.as_ptr(),
                        libc::AT_FDCWD,
                        dest_c.as_ptr(),
                        libc::AT_SYMLINK_FOLLOW,
                    )
                }
            }
        };

        if rc == 0 {
            return Ok(LinkOutcome::Created);
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::AlreadyExists {
            return Ok(LinkOutcome::AlreadyExists);
        }
        Err(e).ctx(format!("link blob into {}", dest.display()))
    }
}

fn open_tmpfile(dir: &Path) -> io::Result<File> {
    let c = cpath(dir)?;
    // O_EXCL must NOT be set: combined with O_TMPFILE it makes the file
    // permanently unlinkable, which is the exact opposite of what we need.
    // SAFETY: `c` is a NUL-terminated directory path; the mode is only
    // consulted because O_TMPFILE creates a file.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::c_int,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn is_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EOPNOTSUPP) | Some(libc::EISDIR) | Some(libc::EINVAL) | Some(libc::ENOSYS)
    )
}

/// Test hook: exercise the named-temp-file path on a filesystem that does
/// support `O_TMPFILE`.
fn force_no_tmpfile() -> bool {
    matches!(std::env::var("ART_FORCE_NO_TMPFILE").as_deref(), Ok("1"))
}

/// Whether `O_TMPFILE` works in this directory.
pub fn supports_tmpfile(dir: &Path) -> bool {
    open_tmpfile(dir).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::space;
    use crate::sys::sparse::pwrite_all;

    fn tmpdir() -> tempfile::TempDir {
        match std::env::var_os("ART_TEST_DIR").map(PathBuf::from) {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn insert(dir: &Path, name: &str, data: &[u8]) -> LinkOutcome {
        insert_via(Incoming::create, dir, name, data)
    }

    fn insert_via(
        create: fn(&Path) -> Result<Incoming>,
        dir: &Path,
        name: &str,
        data: &[u8],
    ) -> LinkOutcome {
        let inc = create(dir).unwrap();
        pwrite_all(inc.as_raw_fd(), data, 0).unwrap();
        let synced = inc.sync().unwrap();
        synced.link_into(&dir.join(name)).unwrap()
    }

    #[test]
    fn writes_then_links_a_blob() {
        let d = tmpdir();
        assert_eq!(insert(d.path(), "blob", b"hello"), LinkOutcome::Created);
        assert_eq!(std::fs::read(d.path().join("blob")).unwrap(), b"hello");
    }

    #[test]
    fn blob_is_sealed_read_only() {
        let d = tmpdir();
        insert(d.path(), "blob", b"hello");
        let p = d.path().join("blob");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o444, "blobs must be immutable on disk");

        // The structural guard: nothing can open a blob for writing, so a
        // caller cannot corrupt content whose name promises what it contains.
        let e = std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn second_link_reports_already_exists_and_keeps_the_first_inode() {
        let d = tmpdir();
        assert_eq!(insert(d.path(), "blob", b"same"), LinkOutcome::Created);
        let first_ino = space::stat_path(&d.path().join("blob")).unwrap().ino;

        // A second writer of identical content must not replace the inode —
        // that is the difference between `link` and `rename`, and the reason
        // hardlinks already handed out stay valid.
        assert_eq!(
            insert(d.path(), "blob", b"same"),
            LinkOutcome::AlreadyExists
        );
        let second_ino = space::stat_path(&d.path().join("blob")).unwrap().ino;
        assert_eq!(first_ino, second_ino);
        assert_eq!(std::fs::read(d.path().join("blob")).unwrap(), b"same");
    }

    #[test]
    fn dedup_does_not_raise_nlink() {
        let d = tmpdir();
        insert(d.path(), "blob", b"x");
        insert(d.path(), "blob", b"x");
        // Storing the same bytes twice must leave one directory entry, or GC's
        // "nlink == 1 means unreferenced" rule stops meaning anything.
        assert_eq!(space::stat_path(&d.path().join("blob")).unwrap().nlink, 1);
    }

    #[test]
    fn abandoned_incoming_leaves_no_trace() {
        // Both implementations: O_TMPFILE reclaims on close, and the fallback
        // must actively clean up after itself.
        for create in [
            Incoming::create as fn(&Path) -> Result<Incoming>,
            Incoming::create_fallback,
        ] {
            let d = tmpdir();
            {
                let inc = create(d.path()).unwrap();
                pwrite_all(inc.as_raw_fd(), b"abandoned", 0).unwrap();
            }
            assert_eq!(
                std::fs::read_dir(d.path()).unwrap().count(),
                0,
                "a crashed or abandoned write must leave nothing behind"
            );
        }
    }

    #[test]
    fn synced_but_unlinked_also_leaves_no_trace() {
        let d = tmpdir();
        {
            let inc = Incoming::create(d.path()).unwrap();
            pwrite_all(inc.as_raw_fd(), b"abandoned", 0).unwrap();
            let _synced = inc.sync().unwrap();
        }
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn fallback_path_behaves_identically() {
        // Forced directly rather than through the environment: mutating process
        // env would be visible to every other test running in parallel.
        let d = tmpdir();
        let seq_before = TMP_SEQ.load(Ordering::Relaxed);
        let outcome = insert_via(Incoming::create_fallback, d.path(), "blob", b"fallback");

        assert_eq!(outcome, LinkOutcome::Created);
        assert_eq!(std::fs::read(d.path().join("blob")).unwrap(), b"fallback");
        assert!(
            TMP_SEQ.load(Ordering::Relaxed) > seq_before,
            "the fallback path should have been taken"
        );
        // The temp file must be gone, leaving only the blob.
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["blob".to_string()]);
    }

    #[test]
    fn empty_blob_round_trips() {
        let d = tmpdir();
        assert_eq!(insert(d.path(), "empty", b""), LinkOutcome::Created);
        assert_eq!(std::fs::metadata(d.path().join("empty")).unwrap().len(), 0);
    }
}
