//! Copies preserve logical content exactly and physical allocation minimally.
//!
//! Two independent notions of "empty" matter here, and conflating them is the
//! trap this whole module exists to avoid:
//!
//! - A **hole** is unallocated. `SEEK_DATA`/`SEEK_HOLE` find them, they cost
//!   nothing to skip, and copying around them is free.
//! - A **zero run** is allocated storage that happens to contain zeros. Only a
//!   userspace scan finds it, and only [`punch_zero_runs`] reclaims it.
//!
//! heyvm's base images are entirely the second kind: measured on this host,
//! every `~/.heyo/images/firecracker/*.ext4` has `stx_blocks * 512 == stx_size`
//! — fully allocated, no holes at all — while `debian-hermes.ext4` is 94% free
//! space *inside* the guest filesystem. A `SEEK_DATA`-only implementation would
//! pass its tests and reclaim exactly zero bytes on the corpus that matters, so
//! [`Shape::HoleAware`] alone is never the right default for an import.
//!
//! **The digest always covers the full logical stream.** Every function that
//! skips reading or writing a region still feeds the corresponding zeros to the
//! `observe` callback. Hashing the sparse representation instead would give
//! digests that no longer match `sha256sum` or mvm-ctrl's `BlobRef.sha256`.

use super::{check, cpath};
use crate::error::{Error, IoContext, Result};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

/// Self-imposed cap on a single `copy_file_range` request. The kernel clamps at
/// `MAX_RW_COUNT` (~2 GiB) anyway; capping lower keeps progress accounting
/// honest and short returns unremarkable.
const MAX_CFR: u64 = 1 << 30;

/// IO buffer for the read-and-hash paths. A multiple of every supported grain.
const BUF_LEN: usize = 4 * 1024 * 1024;

/// Source of zeros for holes we skip reading but must still hash.
static ZEROS: [u8; 65536] = [0u8; 65536];

/// How much of a file's logical content is worth touching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Every byte. One segment.
    Dense,
    /// Only allocated extents, found with `SEEK_DATA`/`SEEK_HOLE`. Free, but
    /// finds nothing in a fully-allocated file.
    HoleAware,
    /// `HoleAware`, and additionally scan the allocated regions for aligned
    /// runs of zeros and decline to write them. Costs a full read; this is the
    /// only shape that shrinks heyvm's base images.
    ZeroSquash { grain: usize },
}

impl Shape {
    /// The default import shape: 4 KiB grain, matching the ext4 block size.
    pub const SQUASH: Shape = Shape::ZeroSquash {
        grain: crate::config::BLOCK_SIZE,
    };

    /// The grain size when this shape scans for zero runs, else `None`. Callers
    /// use it to distinguish shapes whose written size is predictable from
    /// those whose is not.
    pub fn grain(&self) -> Option<usize> {
        match self {
            Shape::ZeroSquash { grain } => Some(*grain),
            _ => None,
        }
    }
}

/// A half-open byte range `[off, off + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub off: u64,
    pub len: u64,
}

/// Allocated extents of `fd`, in ascending order.
///
/// `SEEK_DATA` returning `ENXIO` means "no data at or after this offset" and is
/// the normal loop terminator, not an error. There is always an implicit hole
/// at EOF, so a segment is never emitted past `size`.
pub fn data_segments(fd: RawFd, size: u64) -> io::Result<Vec<Segment>> {
    let mut out = Vec::new();
    let mut off: i64 = 0;
    while (off as u64) < size {
        let data = unsafe { libc::lseek(fd, off, libc::SEEK_DATA) };
        if data == -1 {
            let e = io::Error::last_os_error();
            // ENXIO: no more data. EINVAL/EOPNOTSUPP: filesystem has no hole
            // reporting, so treat the remainder as one dense segment.
            return match e.raw_os_error() {
                Some(libc::ENXIO) => Ok(out),
                Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) => {
                    out.push(Segment {
                        off: off as u64,
                        len: size - off as u64,
                    });
                    Ok(out)
                }
                _ => Err(e),
            };
        }
        if data as u64 >= size {
            break;
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole == -1 {
            return Err(io::Error::last_os_error());
        }
        let end = (hole as u64).min(size);
        if end > data as u64 {
            out.push(Segment {
                off: data as u64,
                len: end - data as u64,
            });
        }
        off = end as i64;
    }
    Ok(out)
}

/// The regions of `fd` that `shape` says to touch.
pub fn segments(fd: RawFd, size: u64, shape: Shape) -> io::Result<Vec<Segment>> {
    match shape {
        Shape::Dense => Ok(if size == 0 {
            Vec::new()
        } else {
            vec![Segment { off: 0, len: size }]
        }),
        // ZeroSquash starts from the hole map too — no reason to read a region
        // the filesystem already says is empty.
        Shape::HoleAware | Shape::ZeroSquash { .. } => data_segments(fd, size),
    }
}

// ---------------------------------------------------------------------------
// copy_file_range
// ---------------------------------------------------------------------------

/// The one syscall the copy loop makes, behind a function pointer so the loop's
/// short-return handling can be tested against a shim that copies one byte at a
/// time. That handling is the most bug-prone code in the crate: `copy_file_range`
/// is *documented* to return less than requested, and a loop that forgets to
/// advance both offsets corrupts data in a way small-file tests never catch.
pub type CfrFn = fn(RawFd, &mut i64, RawFd, &mut i64, usize) -> io::Result<usize>;

fn cfr_real(
    src: RawFd,
    in_off: &mut i64,
    dst: RawFd,
    out_off: &mut i64,
    len: usize,
) -> io::Result<usize> {
    // SAFETY: both fds are live, and the offsets are live `loff_t`s the kernel
    // advances by the number of bytes it copied.
    let n = unsafe { libc::copy_file_range(src, in_off, dst, out_off, len, 0) };
    if n == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Copy `[off, off+len)` from `src` to the same offset in `dst`.
///
/// Falls back to `pread`/`pwrite` when `copy_file_range` is unavailable or
/// refuses the pair (`EXDEV` on older kernels, `EINVAL`, `ENOSYS`,
/// `EOPNOTSUPP`, `EPERM` under some seccomp filters), resuming from wherever
/// the syscall stopped rather than restarting the range.
pub fn copy_range(src: RawFd, dst: RawFd, off: u64, len: u64) -> io::Result<u64> {
    copy_range_with(cfr_real, src, dst, off, len)
}

fn copy_range_with(cfr: CfrFn, src: RawFd, dst: RawFd, off: u64, len: u64) -> io::Result<u64> {
    let mut in_off = off as i64;
    let mut out_off = off as i64;
    let mut remaining = len;
    let mut copied = 0u64;

    while remaining > 0 {
        let want = remaining.min(MAX_CFR) as usize;
        match cfr(src, &mut in_off, dst, &mut out_off, want) {
            // Short returns are normal: loop, and trust the kernel to have
            // advanced both offsets by exactly `n`.
            Ok(n) if n > 0 => {
                remaining -= n as u64;
                copied += n as u64;
            }
            // Zero means the source has fewer bytes than we were told.
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source shrank during copy",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let fall_back = matches!(
                    e.raw_os_error(),
                    Some(libc::EXDEV)
                        | Some(libc::EINVAL)
                        | Some(libc::ENOSYS)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::EPERM)
                        | Some(libc::EBADF)
                );
                if !fall_back {
                    return Err(e);
                }
                // Resume from where copy_file_range stopped, not from `off`.
                let n = copy_range_rw(src, dst, in_off as u64, remaining)?;
                copied += n;
                return Ok(copied);
            }
        }
    }
    Ok(copied)
}

/// Portable read/write copy of a range. The fallback path, and the only path
/// when the bytes must reach userspace anyway.
fn copy_range_rw(src: RawFd, dst: RawFd, off: u64, len: u64) -> io::Result<u64> {
    let mut buf = vec![0u8; BUF_LEN];
    let mut done = 0u64;
    while done < len {
        let want = ((len - done) as usize).min(BUF_LEN);
        let n = pread(src, &mut buf[..want], off + done)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source shrank during copy",
            ));
        }
        pwrite_all(dst, &buf[..n], off + done)?;
        done += n as u64;
    }
    Ok(done)
}

// ---------------------------------------------------------------------------
// The read-and-hash copy
// ---------------------------------------------------------------------------

/// Copy `src` into `dst`, feeding every logical byte to `observe` in order and
/// writing only what `shape` says is worth storing. Returns bytes written.
///
/// `observe` receives the full logical stream — including zeros standing in for
/// regions that were never read and never written — so a hash built from it is
/// the hash of the file's contents, not of its representation.
pub fn copy_observing<F>(
    src: RawFd,
    dst: RawFd,
    size: u64,
    shape: Shape,
    observe: F,
) -> io::Result<u64>
where
    F: FnMut(&[u8]),
{
    copy_observing_guarded(src, dst, size, shape, observe, |_| Ok(()))
}

/// [`copy_observing`], with `check` called after each buffer with the running
/// count of bytes actually written.
///
/// This is how a `ZeroSquash` import stays within a free-space budget it cannot
/// predict: the destination's final size is unknowable until the last zero run
/// has been scanned, so the only honest guard is an incremental one.
pub fn copy_observing_guarded<F, G>(
    src: RawFd,
    dst: RawFd,
    size: u64,
    shape: Shape,
    mut observe: F,
    mut check: G,
) -> io::Result<u64>
where
    F: FnMut(&[u8]),
    G: FnMut(u64) -> io::Result<()>,
{
    // First, not last: this is what preserves a trailing hole, and it means a
    // crash mid-copy leaves a correctly-sized but incomplete file that the
    // digest check rejects, rather than a silently short one.
    ftruncate(dst, size)?;

    let segs = segments(src, size, shape)?;
    let grain = shape.grain();
    let mut buf = vec![0u8; BUF_LEN];
    let mut cursor = 0u64;
    let mut written = 0u64;

    for seg in segs {
        feed_zeros(&mut observe, seg.off - cursor);
        cursor = seg.off;

        let end = seg.off + seg.len;
        while cursor < end {
            let want = ((end - cursor) as usize).min(BUF_LEN);
            let n = pread_full(src, &mut buf[..want], cursor)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source shrank during copy",
                ));
            }
            let chunk = &buf[..n];
            observe(chunk);
            written += match grain {
                Some(g) => write_nonzero_grains(dst, chunk, cursor, g)?,
                None => {
                    pwrite_all(dst, chunk, cursor)?;
                    n as u64
                }
            };
            cursor += n as u64;
            check(written)?;
        }
    }
    feed_zeros(&mut observe, size - cursor);
    Ok(written)
}

/// Copy `src` into `dst` without reading the bytes into userspace.
///
/// Used by materialization, where the digest is already known and there is
/// nothing to hash. `Dense` and `HoleAware` go through `copy_file_range`;
/// `ZeroSquash` cannot, because deciding what to skip requires looking at the
/// bytes.
pub fn copy_shaped(src: RawFd, dst: RawFd, size: u64, shape: Shape) -> io::Result<u64> {
    if shape.grain().is_some() {
        return copy_observing(src, dst, size, shape, |_| {});
    }
    ftruncate(dst, size)?;
    let mut written = 0u64;
    for seg in segments(src, size, shape)? {
        written += copy_range(src, dst, seg.off, seg.len)?;
    }
    Ok(written)
}

/// Write only the grains of `chunk` that contain a non-zero byte. Runs of
/// zero grains are simply not written; the destination's `ftruncate` already
/// established the size, so they read back as zeros from a hole.
fn write_nonzero_grains(dst: RawFd, chunk: &[u8], base: u64, grain: usize) -> io::Result<u64> {
    let mut written = 0u64;
    let mut i = 0usize;
    while i < chunk.len() {
        let end = (i + grain).min(chunk.len());
        if is_zero(&chunk[i..end]) {
            i = end;
            continue;
        }
        // Coalesce the run of non-zero grains into a single pwrite.
        let start = i;
        i = end;
        while i < chunk.len() {
            let e = (i + grain).min(chunk.len());
            if is_zero(&chunk[i..e]) {
                break;
            }
            i = e;
        }
        pwrite_all(dst, &chunk[start..i], base + start as u64)?;
        written += (i - start) as u64;
    }
    Ok(written)
}

fn feed_zeros<F: FnMut(&[u8])>(observe: &mut F, mut n: u64) {
    while n > 0 {
        let k = n.min(ZEROS.len() as u64) as usize;
        observe(&ZEROS[..k]);
        n -= k as u64;
    }
}

/// True when every byte is zero.
///
/// The `u64` prefix check rejects almost every non-zero block in one branch;
/// the `iter().all()` tail is autovectorized at `opt-level = 3`. Hand-rolled
/// SIMD here would be slower to maintain and no faster to run.
#[inline]
pub fn is_zero(buf: &[u8]) -> bool {
    if buf.len() >= 8 {
        if u64::from_ne_bytes(buf[..8].try_into().unwrap()) != 0 {
            return false;
        }
        return buf[8..].iter().all(|&b| b == 0);
    }
    buf.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// In-place sparsification
// ---------------------------------------------------------------------------

/// Punch out aligned runs of zeros in `fd`, feeding every logical byte to
/// `observe` so the caller can prove the content did not change. Returns bytes
/// freed.
///
/// The caller must have already established that this inode has exactly one
/// link — see [`crate::sys::sparse::ensure_unshared`]. Punching is an operation
/// on the inode, so it is visible through every name and every open descriptor,
/// including a running VM's disk.
pub fn punch_zero_runs<F>(fd: RawFd, size: u64, grain: usize, mut observe: F) -> io::Result<u64>
where
    F: FnMut(&[u8]),
{
    let mut buf = vec![0u8; BUF_LEN];
    let mut cursor = 0u64;
    let mut freed = 0u64;
    // Start of the current run of zero grains, if we are in one.
    let mut run: Option<u64> = None;

    while cursor < size {
        let want = ((size - cursor) as usize).min(BUF_LEN);
        let n = pread_full(fd, &mut buf[..want], cursor)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        observe(chunk);

        let mut i = 0usize;
        while i < chunk.len() {
            let end = (i + grain).min(chunk.len());
            let at = cursor + i as u64;
            let full_grain = end - i == grain;
            if is_zero(&chunk[i..end]) && full_grain {
                run.get_or_insert(at);
            } else if let Some(start) = run.take() {
                freed += punch_if_worthwhile(fd, start, at - start, grain)?;
            }
            i = end;
        }
        cursor += n as u64;
    }
    if let Some(start) = run.take() {
        freed += punch_if_worthwhile(fd, start, cursor - start, grain)?;
    }
    Ok(freed)
}

/// Punch `[off, off+len)` when it is a whole number of grains. A partial block
/// is not worth punching: ext4 zeroes it in place rather than freeing it.
fn punch_if_worthwhile(fd: RawFd, off: u64, len: u64, grain: usize) -> io::Result<u64> {
    if len < grain as u64 {
        return Ok(0);
    }
    punch_hole(fd, off, len)?;
    Ok(len)
}

/// Refuse to modify an inode that more than one name or store reference points
/// at. This is an assertion, not a caution: punching a shared inode silently
/// rewrites content that another path — possibly a booted VM's disk — is
/// currently reading.
pub fn ensure_unshared(path: &Path) -> Result<()> {
    let st = super::space::stat_path(path)?;
    if st.nlink > 1 {
        return Err(Error::SharedInode {
            path: path.to_path_buf(),
            nlink: st.nlink,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Thin syscall wrappers
// ---------------------------------------------------------------------------

/// `FALLOC_FL_KEEP_SIZE` is mandatory — without it `PUNCH_HOLE` returns
/// `EINVAL`. Offsets should be block-aligned; ext4 accepts unaligned ranges but
/// zeroes the partial head and tail blocks instead of freeing them.
pub fn punch_hole(fd: RawFd, off: u64, len: u64) -> io::Result<()> {
    // SAFETY: `fd` is live; fallocate reads no user memory.
    let rc = unsafe {
        libc::fallocate(
            fd,
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            off as libc::off_t,
            len as libc::off_t,
        )
    };
    check(rc)
}

/// Mode-0 `fallocate`: allocate `len` bytes up front.
///
/// Its value on a nearly-full filesystem is an early, honest `ENOSPC` — you
/// learn before streaming three gigabytes, not after. Never call it on a
/// sparse-intent import: preallocating a 20 GiB nominal image destroys the very
/// saving the import exists to capture.
pub fn preallocate(fd: RawFd, len: u64) -> io::Result<()> {
    // SAFETY: `fd` is live; fallocate reads no user memory.
    let rc = unsafe { libc::fallocate(fd, 0, 0, len as libc::off_t) };
    check(rc)
}

pub fn ftruncate(fd: RawFd, len: u64) -> io::Result<()> {
    // SAFETY: `fd` is live.
    check(unsafe { libc::ftruncate(fd, len as libc::off_t) })
}

pub fn fdatasync(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is live.
    check(unsafe { libc::fdatasync(fd) })
}

pub fn pread(fd: RawFd, buf: &mut [u8], off: u64) -> io::Result<usize> {
    // SAFETY: `buf` is a live, writable slice of exactly `buf.len()` bytes.
    let n = unsafe {
        libc::pread(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            off as libc::off_t,
        )
    };
    if n == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// `pread` until the buffer is full or EOF. Returning a short read only at EOF
/// is what keeps grain boundaries aligned in [`write_nonzero_grains`].
fn pread_full(fd: RawFd, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        match pread(fd, &mut buf[done..], off + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

pub fn pwrite_all(fd: RawFd, buf: &[u8], off: u64) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        // SAFETY: `buf` is a live slice; we pass a length within it.
        let n = unsafe {
            libc::pwrite(
                fd,
                buf[done..].as_ptr() as *const libc::c_void,
                buf.len() - done,
                (off + done as u64) as libc::off_t,
            )
        };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        done += n as usize;
    }
    Ok(())
}

/// Hint that a large file will be read start to finish. Roughly doubles the
/// readahead window; free.
pub fn advise_sequential(fd: RawFd, size: u64) {
    if size < 16 * 1024 * 1024 {
        return;
    }
    // SAFETY: `fd` is live; fadvise reads no user memory. Advice is advisory,
    // so a failure is not worth propagating.
    unsafe {
        libc::posix_fadvise(fd, 0, size as libc::off_t, libc::POSIX_FADV_SEQUENTIAL);
    }
}

/// Drop this file's pages from the cache.
///
/// Must be called *after* `fdatasync`: `DONTNEED` only evicts clean pages, so
/// before the sync it silently does nothing. Streaming a multi-gigabyte image
/// through the cache otherwise evicts everything else on the machine.
pub fn advise_dontneed(fd: RawFd, size: u64) {
    if size < 16 * 1024 * 1024 {
        return;
    }
    // SAFETY: as above.
    unsafe {
        libc::posix_fadvise(fd, 0, size as libc::off_t, libc::POSIX_FADV_DONTNEED);
    }
}

/// Whether this filesystem can actually free blocks with `PUNCH_HOLE`.
///
/// Probed by capability rather than by `f_type`: a store root can be bind
/// mounted onto anything, and the answer decides whether sparsification is
/// worth attempting.
pub fn supports_punch_hole(dir: &Path) -> bool {
    let path = dir.join(".art-probe-punch");
    let res = (|| -> io::Result<bool> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)?;
        let fd = f.as_raw_fd();
        ftruncate(fd, 1 << 20)?;
        pwrite_all(fd, &[1u8; 4096], 0)?;
        match punch_hole(fd, 0, 4096) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(false),
            Err(e) => Err(e),
        }
    })();
    let _ = std::fs::remove_file(&path);
    res.unwrap_or(false)
}

/// Open a path read-only, hinting sequential access for large files.
pub fn open_for_read(path: &Path) -> Result<std::fs::File> {
    let f = std::fs::File::open(path).ctx(format!("open {}", path.display()))?;
    if let Ok(md) = f.metadata() {
        advise_sequential(f.as_raw_fd(), md.len());
    }
    Ok(f)
}

/// `unlink`, mapping a missing file to `Ok(false)`.
pub fn unlink_if_present(path: &Path) -> Result<bool> {
    let c = cpath(path).ctx(format!("unlink {}", path.display()))?;
    // SAFETY: `c` is a NUL-terminated path.
    let rc = unsafe { libc::unlink(c.as_ptr()) };
    if rc == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(e).ctx(format!("unlink {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    fn tmpdir() -> tempfile::TempDir {
        let base = std::env::var_os("ART_TEST_DIR").map(std::path::PathBuf::from);
        match base {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn write_file(dir: &Path, name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
        p
    }

    fn rw(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    // -- is_zero -----------------------------------------------------------

    #[test]
    fn is_zero_handles_short_and_long_buffers() {
        assert!(is_zero(&[]));
        assert!(is_zero(&[0u8; 3]));
        assert!(is_zero(&[0u8; 4096]));
        assert!(!is_zero(&[1u8]));
        assert!(!is_zero(&[0, 0, 0, 1]));
        // Non-zero beyond the u64 prefix must still be caught.
        let mut b = [0u8; 4096];
        b[4095] = 1;
        assert!(!is_zero(&b));
        // Non-zero inside the u64 prefix.
        let mut c = [0u8; 4096];
        c[3] = 1;
        assert!(!is_zero(&c));
    }

    // -- segments ----------------------------------------------------------

    #[test]
    fn dense_shape_is_one_segment() {
        let d = tmpdir();
        let p = write_file(d.path(), "f", &[1u8; 100]);
        let f = std::fs::File::open(&p).unwrap();
        let s = segments(f.as_raw_fd(), 100, Shape::Dense).unwrap();
        assert_eq!(s, vec![Segment { off: 0, len: 100 }]);
    }

    #[test]
    fn empty_file_has_no_segments() {
        let d = tmpdir();
        let p = write_file(d.path(), "f", b"");
        let f = std::fs::File::open(&p).unwrap();
        assert!(segments(f.as_raw_fd(), 0, Shape::Dense).unwrap().is_empty());
        assert!(
            segments(f.as_raw_fd(), 0, Shape::HoleAware)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hole_aware_finds_data_around_a_hole() {
        let d = tmpdir();
        if !supports_punch_hole(d.path()) {
            eprintln!("skipping hole_aware_finds_data_around_a_hole: no hole punching here");
            return;
        }
        let size = 3 * 65536u64;
        let p = write_file(d.path(), "f", &vec![7u8; size as usize]);
        let f = rw(&p);
        punch_hole(f.as_raw_fd(), 65536, 65536).unwrap();

        let segs = data_segments(f.as_raw_fd(), size).unwrap();
        assert!(segs.len() >= 2, "expected data on both sides: {segs:?}");
        assert_eq!(segs[0].off, 0);
        assert_eq!(segs.last().unwrap().off + segs.last().unwrap().len, size);
        // The hole itself is not in any segment.
        assert!(
            !segs
                .iter()
                .any(|s| s.off <= 65536 && s.off + s.len > 65536 + 4096)
        );
    }

    #[test]
    fn trailing_hole_is_not_emitted_as_a_segment() {
        let d = tmpdir();
        let p = d.path().join("f");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        pwrite_all(f.as_raw_fd(), &[1u8; 4096], 0).unwrap();
        ftruncate(f.as_raw_fd(), 1 << 20).unwrap();

        let segs = data_segments(f.as_raw_fd(), 1 << 20).unwrap();
        // Whatever the filesystem reports, no segment may run past EOF.
        for s in &segs {
            assert!(s.off + s.len <= 1 << 20, "segment past EOF: {s:?}");
        }
    }

    // -- the copy_file_range loop -----------------------------------------

    /// Copies exactly one byte per call, via pread/pwrite, and advances both
    /// offsets the way the real syscall does. Exercises the loop's short-return
    /// handling without needing a gigabyte of data.
    fn cfr_one_byte(
        src: RawFd,
        in_off: &mut i64,
        dst: RawFd,
        out_off: &mut i64,
        len: usize,
    ) -> io::Result<usize> {
        if len == 0 {
            return Ok(0);
        }
        let mut b = [0u8; 1];
        let n = pread(src, &mut b, *in_off as u64)?;
        if n == 0 {
            return Ok(0);
        }
        pwrite_all(dst, &b[..n], *out_off as u64)?;
        *in_off += n as i64;
        *out_off += n as i64;
        Ok(n)
    }

    fn cfr_unsupported(
        _: RawFd,
        _: &mut i64,
        _: RawFd,
        _: &mut i64,
        _: usize,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn cfr_half_then_unsupported(
        src: RawFd,
        in_off: &mut i64,
        dst: RawFd,
        out_off: &mut i64,
        len: usize,
    ) -> io::Result<usize> {
        // Copy half, then behave like a filesystem that refuses the pair, so
        // the fallback has to resume from a non-zero offset.
        if len > 1 {
            let half = len / 2;
            let mut buf = vec![0u8; half];
            let n = pread(src, &mut buf, *in_off as u64)?;
            pwrite_all(dst, &buf[..n], *out_off as u64)?;
            *in_off += n as i64;
            *out_off += n as i64;
            return Ok(n);
        }
        Err(io::Error::from_raw_os_error(libc::EXDEV))
    }

    fn copy_loop_case(cfr: CfrFn) {
        let d = tmpdir();
        let data: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let src = write_file(d.path(), "src", &data);
        let dstp = d.path().join("dst");

        let sf = std::fs::File::open(&src).unwrap();
        let df = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&dstp)
            .unwrap();
        ftruncate(df.as_raw_fd(), data.len() as u64).unwrap();

        let n = copy_range_with(cfr, sf.as_raw_fd(), df.as_raw_fd(), 0, data.len() as u64).unwrap();
        assert_eq!(n, data.len() as u64);
        df.sync_all().unwrap();
        assert_eq!(std::fs::read(&dstp).unwrap(), data);
    }

    #[test]
    fn copy_loop_survives_one_byte_at_a_time() {
        copy_loop_case(cfr_one_byte);
    }

    #[test]
    fn copy_loop_falls_back_when_unsupported() {
        copy_loop_case(cfr_unsupported);
    }

    #[test]
    fn copy_loop_resumes_fallback_from_partial_progress() {
        copy_loop_case(cfr_half_then_unsupported);
    }

    #[test]
    fn copy_loop_uses_the_real_syscall_correctly() {
        copy_loop_case(cfr_real);
    }

    #[test]
    fn copy_range_at_a_nonzero_offset() {
        let d = tmpdir();
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
        let src = write_file(d.path(), "src", &data);
        let dstp = d.path().join("dst");
        let sf = std::fs::File::open(&src).unwrap();
        let df = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&dstp)
            .unwrap();
        ftruncate(df.as_raw_fd(), 4096).unwrap();

        copy_range(sf.as_raw_fd(), df.as_raw_fd(), 1000, 2000).unwrap();
        df.sync_all().unwrap();
        let got = std::fs::read(&dstp).unwrap();
        assert_eq!(&got[1000..3000], &data[1000..3000]);
        assert!(got[..1000].iter().all(|&b| b == 0));
    }

    // -- copy_observing ----------------------------------------------------

    fn observed(src: &Path, dst: &Path, size: u64, shape: Shape) -> (Vec<u8>, u64) {
        let sf = std::fs::File::open(src).unwrap();
        let df = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(dst)
            .unwrap();
        let mut seen = Vec::new();
        let w = copy_observing(sf.as_raw_fd(), df.as_raw_fd(), size, shape, |b| {
            seen.extend_from_slice(b)
        })
        .unwrap();
        df.sync_all().unwrap();
        (seen, w)
    }

    #[test]
    fn copy_observing_sees_every_logical_byte() {
        let d = tmpdir();
        let mut data = vec![0u8; 3 * 4096];
        data[..4096].fill(9);
        data[2 * 4096..].fill(8);
        let src = write_file(d.path(), "src", &data);
        let dst = d.path().join("dst");

        for shape in [Shape::Dense, Shape::HoleAware, Shape::SQUASH] {
            let (seen, _) = observed(&src, &dst, data.len() as u64, shape);
            assert_eq!(seen, data, "logical stream differs for {shape:?}");
            assert_eq!(
                std::fs::read(&dst).unwrap(),
                data,
                "content differs for {shape:?}"
            );
        }
    }

    #[test]
    fn zero_squash_writes_less_than_it_hashes() {
        let d = tmpdir();
        // 1 MiB: one live block at the front, the rest zeros.
        let mut data = vec![0u8; 1 << 20];
        data[..4096].fill(7);
        let src = write_file(d.path(), "src", &data);
        let dst = d.path().join("dst");

        let (seen, written) = observed(&src, &dst, data.len() as u64, Shape::SQUASH);
        assert_eq!(seen.len(), data.len(), "must hash the full logical stream");
        assert_eq!(seen, data);
        assert_eq!(written, 4096, "only the live grain should be written");
        assert_eq!(std::fs::read(&dst).unwrap(), data);

        // And a dense copy of the same file writes everything.
        let (_, dense) = observed(&src, &dst, data.len() as u64, Shape::Dense);
        assert_eq!(dense, data.len() as u64);
    }

    #[test]
    fn zero_squash_preserves_a_trailing_zero_tail() {
        let d = tmpdir();
        let mut data = vec![0u8; 8192];
        data[..10].fill(3);
        let src = write_file(d.path(), "src", &data);
        let dst = d.path().join("dst");
        let (seen, _) = observed(&src, &dst, data.len() as u64, Shape::SQUASH);
        assert_eq!(seen, data);
        // The file must still be 8192 bytes even though the tail was never written.
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), 8192);
        assert_eq!(std::fs::read(&dst).unwrap(), data);
    }

    #[test]
    fn zero_squash_handles_a_size_not_divisible_by_grain() {
        let d = tmpdir();
        let mut data = vec![0u8; 4096 + 17];
        data[4096..].fill(5);
        let src = write_file(d.path(), "src", &data);
        let dst = d.path().join("dst");
        let (seen, _) = observed(&src, &dst, data.len() as u64, Shape::SQUASH);
        assert_eq!(seen, data);
        assert_eq!(std::fs::read(&dst).unwrap(), data);
    }

    #[test]
    fn copy_observing_handles_an_empty_file() {
        let d = tmpdir();
        let src = write_file(d.path(), "src", b"");
        let dst = d.path().join("dst");
        let (seen, w) = observed(&src, &dst, 0, Shape::SQUASH);
        assert!(seen.is_empty());
        assert_eq!(w, 0);
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), 0);
    }

    #[test]
    fn copy_observing_spans_multiple_buffers() {
        let d = tmpdir();
        // Larger than BUF_LEN, with live data straddling the boundary.
        let n = BUF_LEN + 8192;
        let mut data = vec![0u8; n];
        for (i, b) in data.iter_mut().enumerate() {
            if i % 8192 < 16 {
                *b = (i % 251) as u8;
            }
        }
        let src = write_file(d.path(), "src", &data);
        let dst = d.path().join("dst");
        let (seen, _) = observed(&src, &dst, n as u64, Shape::SQUASH);
        assert_eq!(seen.len(), n);
        assert_eq!(seen, data);
        assert_eq!(std::fs::read(&dst).unwrap(), data);
    }

    // -- punching ----------------------------------------------------------

    #[test]
    fn punch_zero_runs_frees_blocks_without_changing_content() {
        let d = tmpdir();
        if !supports_punch_hole(d.path()) {
            eprintln!("skipping punch_zero_runs_frees_blocks: no hole punching here");
            return;
        }
        let mut data = vec![0u8; 1 << 20];
        data[..4096].fill(4);
        data[(1 << 20) - 4096..].fill(6);
        let p = write_file(d.path(), "img", &data);

        let before = super::super::space::stat_path(&p).unwrap();
        assert_eq!(before.size, data.len() as u64);

        let f = rw(&p);
        let mut seen = Vec::new();
        let freed = punch_zero_runs(f.as_raw_fd(), before.size, 4096, |b| {
            seen.extend_from_slice(b)
        })
        .unwrap();
        f.sync_all().unwrap();

        assert_eq!(seen, data, "must observe the full logical stream");
        assert!(freed > 0, "expected to free something");

        let after = super::super::space::stat_path(&p).unwrap();
        assert_eq!(after.size, before.size, "size must not change");
        assert!(
            after.allocated < before.allocated,
            "allocation should shrink: {} -> {}",
            before.allocated,
            after.allocated
        );
        // The whole point: content is byte-identical afterwards.
        assert_eq!(std::fs::read(&p).unwrap(), data);
    }

    #[test]
    fn punch_zero_runs_leaves_a_dense_file_alone() {
        let d = tmpdir();
        let data = vec![3u8; 1 << 16];
        let p = write_file(d.path(), "img", &data);
        let f = rw(&p);
        let freed = punch_zero_runs(f.as_raw_fd(), data.len() as u64, 4096, |_| {}).unwrap();
        assert_eq!(freed, 0);
        assert_eq!(std::fs::read(&p).unwrap(), data);
    }

    #[test]
    fn ensure_unshared_rejects_a_hardlinked_file() {
        let d = tmpdir();
        let p = write_file(d.path(), "a", b"x");
        ensure_unshared(&p).unwrap();

        let l = d.path().join("b");
        std::fs::hard_link(&p, &l).unwrap();
        let e = ensure_unshared(&p).unwrap_err();
        assert!(matches!(e, Error::SharedInode { nlink: 2, .. }), "{e:?}");
        assert_eq!(e.slug(), "shared_inode");
    }

    #[test]
    fn preallocate_allocates_blocks() {
        let d = tmpdir();
        let p = d.path().join("f");
        let f = std::fs::File::create(&p).unwrap();
        if preallocate(f.as_raw_fd(), 1 << 20).is_err() {
            eprintln!("skipping preallocate_allocates_blocks: fallocate unsupported here");
            return;
        }
        f.sync_all().unwrap();
        let st = super::super::space::stat_path(&p).unwrap();
        assert!(st.allocated >= 1 << 20, "allocated {}", st.allocated);
    }

    #[test]
    fn unlink_if_present_reports_whether_it_did_anything() {
        let d = tmpdir();
        let p = write_file(d.path(), "f", b"x");
        assert!(unlink_if_present(&p).unwrap());
        assert!(!unlink_if_present(&p).unwrap());
    }
}
