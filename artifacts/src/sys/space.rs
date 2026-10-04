//! No write begins that could take the store's filesystem below
//! `ART_MIN_FREE_BYTES`.
//!
//! The guard uses `f_bavail`, **not** `f_bfree`: the latter includes the
//! root-reserved blocks (5% by default on ext4) that an unprivileged process
//! cannot allocate, so budgeting against it would let a write proceed that the
//! kernel then refuses partway through.
//!
//! This matters more than a normal disk-full check. The store root here lives
//! on a filesystem mounted `errors=remount-ro`; exhausting it does not produce
//! a clean `ENOSPC` for the caller to handle, it produces a read-only root
//! filesystem for the whole machine.

use super::{check, cpath};
use crate::error::{Error, IoContext, Result};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Free-space and free-inode snapshot of a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceInfo {
    /// Bytes allocatable by an unprivileged process (`f_bavail * f_bsize`).
    pub available: u64,
    /// Total bytes (`f_blocks * f_bsize`).
    pub total: u64,
    pub free_inodes: u64,
    pub total_inodes: u64,
}

impl SpaceInfo {
    /// True when inodes, not bytes, are the binding constraint. ext4 fixes the
    /// inode count at mkfs time, so a store of many tiny blobs can exhaust
    /// inodes with terabytes still free.
    pub fn inodes_low(&self) -> bool {
        self.total_inodes > 0 && (self.free_inodes * 100 / self.total_inodes) < 5
    }
}

pub fn statfs(path: &Path) -> Result<SpaceInfo> {
    let c = cpath(path).ctx(format!("statfs {}", path.display()))?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path and `buf` is a live, correctly-sized
    // `struct statfs` that the kernel only writes.
    let rc = unsafe { libc::statfs(c.as_ptr(), &mut buf) };
    check(rc).ctx(format!("statfs {}", path.display()))?;

    let bsize = buf.f_bsize.max(0) as u64;
    Ok(SpaceInfo {
        available: buf.f_bavail as u64 * bsize,
        total: buf.f_blocks as u64 * bsize,
        free_inodes: buf.f_ffree as u64,
        total_inodes: buf.f_files as u64,
    })
}

/// Refuse `needed` bytes unless `needed + reserve` fits in the available space.
///
/// Call this *before* the first byte is written, and again periodically for a
/// stream of unknown length — knowing at byte zero that a 3 GB import will not
/// fit is the entire point.
pub fn guard(path: &Path, needed: u64, reserve: u64) -> Result<()> {
    let info = statfs(path)?;
    if needed.saturating_add(reserve) > info.available {
        return Err(Error::NoSpace {
            needed,
            available: info.available,
            reserve,
        });
    }
    if info.inodes_low() {
        tracing::warn!(
            free_inodes = info.free_inodes,
            total_inodes = info.total_inodes,
            "filesystem is low on inodes; the store cannot create new blobs once they run out"
        );
    }
    Ok(())
}

/// What GC and `ls` need about a blob, in one syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub size: u64,
    /// Physically allocated bytes (`stx_blocks * 512`). For a sparsified image
    /// this is far below `size`; reporting only `size` would misrepresent what
    /// the store actually costs on disk.
    pub allocated: u64,
    pub nlink: u64,
    pub ino: u64,
    pub dev: u64,
    /// Birth time when the filesystem records it, else ctime. ext4 only carries
    /// a btime with 256-byte inodes. ctime for a blob is its link time, which
    /// is never *older* than its birth, so a GC grace window computed from it
    /// is only ever more conservative.
    pub created: SystemTime,
}

/// `statx` on an already-open file descriptor.
pub fn fstat(fd: RawFd) -> io::Result<FileStat> {
    statx_at(fd, c"", libc::AT_EMPTY_PATH)
}

/// `statx` on a path, without following a final symlink.
pub fn stat_path(path: &Path) -> Result<FileStat> {
    let c = cpath(path).ctx(format!("stat {}", path.display()))?;
    statx_at(libc::AT_FDCWD, &c, libc::AT_SYMLINK_NOFOLLOW).ctx(format!("stat {}", path.display()))
}

fn statx_at(dirfd: RawFd, path: &std::ffi::CStr, flags: libc::c_int) -> io::Result<FileStat> {
    let mask = libc::STATX_SIZE
        | libc::STATX_BLOCKS
        | libc::STATX_NLINK
        | libc::STATX_INO
        | libc::STATX_BTIME
        | libc::STATX_CTIME;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // AT_STATX_DONT_SYNC: this is a local filesystem, so there is no server to
    // round-trip to for freshness, and GC statting 20k blobs should not pay for
    // one.
    // SAFETY: `path` is NUL-terminated and `stx` is a live `struct statx` the
    // kernel only writes.
    let rc = unsafe {
        libc::statx(
            dirfd,
            path.as_ptr(),
            flags | libc::AT_STATX_DONT_SYNC,
            mask,
            &mut stx,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    // stx_mask reports what the kernel actually filled in; btime is optional.
    let ts = if stx.stx_mask & libc::STATX_BTIME != 0 {
        stx.stx_btime
    } else {
        stx.stx_ctime
    };
    let created = if ts.tv_sec >= 0 {
        UNIX_EPOCH + Duration::new(ts.tv_sec as u64, ts.tv_nsec)
    } else {
        UNIX_EPOCH
    };

    Ok(FileStat {
        size: stx.stx_size,
        allocated: stx.stx_blocks * 512,
        nlink: stx.stx_nlink as u64,
        ino: stx.stx_ino,
        dev: libc::makedev(stx.stx_dev_major, stx.stx_dev_minor),
        created,
    })
}

/// The `st_dev` of a directory, used to decide whether a hardlink can reach a
/// destination at all.
///
/// `linkat` returns `EXDEV` across filesystems. Checking first — rather than
/// discovering it from a failed syscall — means `materialize` never has to
/// unwind a partially-created file, and lets the caller be told which method
/// was actually used.
pub fn dev_of_dir(dir: &Path) -> Result<u64> {
    stat_path(dir).map(|s| s.dev)
}

/// `fsync` a directory, making a rename or link durable.
///
/// The step most often forgotten: on ext4 the entry itself is not durable until
/// its parent directory is synced, no matter how many times the file was.
pub fn fsync_dir(dir: &Path) -> Result<()> {
    let f = std::fs::File::open(dir).ctx(format!("open {} for fsync", dir.display()))?;
    // SAFETY: `f` is a live descriptor for the duration of the call.
    let rc = unsafe { libc::fsync(f.as_raw_fd()) };
    check(rc).ctx(format!("fsync {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn statfs_reports_plausible_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let info = statfs(dir.path()).unwrap();
        assert!(info.total > 0);
        assert!(info.available <= info.total);
    }

    #[test]
    fn guard_refuses_before_writing_anything() {
        let dir = tempfile::tempdir().unwrap();
        // An impossible reserve must fail even for a zero-byte write, and must
        // fail *without* having touched the filesystem.
        let e = guard(dir.path(), 0, u64::MAX).unwrap_err();
        assert!(matches!(e, Error::NoSpace { .. }), "{e:?}");
        assert_eq!(e.slug(), "no_space");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn guard_allows_a_small_write() {
        let dir = tempfile::tempdir().unwrap();
        guard(dir.path(), 1024, 0).unwrap();
    }

    #[test]
    fn stat_reports_size_nlink_and_dev() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"hello").unwrap();
        f.sync_all().unwrap();

        let s = stat_path(&p).unwrap();
        assert_eq!(s.size, 5);
        assert_eq!(s.nlink, 1);
        assert_eq!(s.dev, dev_of_dir(dir.path()).unwrap());
        assert!(s.ino > 0);

        // A hardlink is visible in nlink immediately — this is the refcount the
        // whole store depends on.
        let l = dir.path().join("g");
        std::fs::hard_link(&p, &l).unwrap();
        assert_eq!(stat_path(&p).unwrap().nlink, 2);
        std::fs::remove_file(&l).unwrap();
        assert_eq!(stat_path(&p).unwrap().nlink, 1);
    }

    #[test]
    fn fstat_matches_stat_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abcd").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        let a = fstat(f.as_raw_fd()).unwrap();
        let b = stat_path(&p).unwrap();
        assert_eq!(a.ino, b.ino);
        assert_eq!(a.size, b.size);
    }

    #[test]
    fn missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let e = stat_path(&dir.path().join("nope")).unwrap_err();
        match e {
            Error::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound)
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn fsync_dir_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        fsync_dir(dir.path()).unwrap();
    }
}
