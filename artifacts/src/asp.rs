//! `artsparse v1` — how a blob travels to and from the remote tier without
//! its holes.
//!
//! A heyvm rootfs is twenty gigabytes long and a few hundred megabytes of
//! data; the store keeps it that way on disk by punching out its zero runs.
//! Object storage has no holes, so uploading the logical bytes would cost the
//! full twenty gigabytes in transfer and storage per image, and every cache
//! fill would have to rediscover the holes by scanning zeros. Instead a blob
//! is shipped as its allocated extents and nothing else:
//!
//! ```text
//! "ASP1"                      4 bytes, magic
//! header length               u32, little-endian
//! header                      JSON: {"size": <logical length>,
//!                                    "extents": [[offset, length], ...]}
//! extent bytes                each extent's data, concatenated, in order
//! ```
//!
//! Extents are ascending and disjoint, and everything outside them reads as
//! zeros. The blob's digest still covers the full logical stream — holes
//! included — so a decoder proves what it rebuilt by re-hashing, never by
//! trusting the header. That also means the format needs no checksum of its
//! own: a corrupt object fails the digest check and is never linked into the
//! store.
//!
//! Every blob uses this format, dense ones included (one extent covering the
//! whole file), so a reader never has to guess which encoding an object is in.
//! The format is deliberately simple enough to decode with a few lines of any
//! language, because a store that can only be rebuilt by the program that
//! wrote it is not a backup.

use crate::sys::sparse::{self, Segment};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};

pub const MAGIC: &[u8; 4] = b"ASP1";

/// Refuse a header claiming to be bigger than this. A 20 GiB image fragmented
/// into 4 KiB extents would still fit; anything larger is corruption.
const MAX_HEADER: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub size: u64,
    pub extents: Vec<(u64, u64)>,
}

impl Header {
    /// Bytes of extent data that follow the header.
    pub fn data_len(&self) -> u64 {
        self.extents.iter().map(|(_, len)| len).sum()
    }

    fn validate(&self) -> io::Result<()> {
        let mut end = 0u64;
        for &(off, len) in &self.extents {
            let stop = off
                .checked_add(len)
                .ok_or_else(|| bad("extent overflows u64"))?;
            if off < end || stop > self.size || len == 0 {
                return Err(bad(
                    "extents must be ascending, disjoint and within the blob",
                ));
            }
            end = stop;
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("header always serializes");
        let mut out = Vec::with_capacity(8 + json.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(&json);
        out
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("artsparse: {msg}"))
}

/// An encoded blob as a byte stream: the header, then each extent read
/// straight from the file with `pread`. Holds nothing but one extent's cursor,
/// so encoding a twenty-gigabyte image costs no memory.
pub struct Encoder {
    file: std::fs::File,
    head: Vec<u8>,
    head_pos: usize,
    extents: Vec<Segment>,
    index: usize,
    within: u64,
    total: u64,
}

impl Encoder {
    /// Encode `file`, a store blob of logical length `size`.
    pub fn new(file: std::fs::File, size: u64) -> io::Result<Encoder> {
        let extents: Vec<Segment> = sparse::data_segments(file.as_raw_fd(), size)?
            .into_iter()
            .filter(|s| s.len > 0)
            .collect();
        let header = Header {
            size,
            extents: extents.iter().map(|s| (s.off, s.len)).collect(),
        };
        let head = header.encode();
        let total = head.len() as u64 + header.data_len();
        Ok(Encoder {
            file,
            head,
            head_pos: 0,
            extents,
            index: 0,
            within: 0,
            total,
        })
    }

    /// The exact encoded length. Known before a byte is read, which is what a
    /// multipart upload needs to plan its parts.
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl Read for Encoder {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.head_pos < self.head.len() {
            let n = (self.head.len() - self.head_pos).min(buf.len());
            buf[..n].copy_from_slice(&self.head[self.head_pos..self.head_pos + n]);
            self.head_pos += n;
            return Ok(n);
        }
        while self.index < self.extents.len() {
            let seg = self.extents[self.index];
            if self.within >= seg.len {
                self.index += 1;
                self.within = 0;
                continue;
            }
            let want = ((seg.len - self.within) as usize).min(buf.len());
            let n = sparse::pread(
                self.file.as_raw_fd(),
                &mut buf[..want],
                seg.off + self.within,
            )?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "blob shrank while being encoded",
                ));
            }
            self.within += n as u64;
            return Ok(n);
        }
        Ok(0)
    }
}

/// Read and validate the header at the front of an encoded stream, leaving
/// `r` at the first extent's data.
pub fn read_header<R: Read>(r: &mut R) -> io::Result<Header> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(bad("not an artsparse object"));
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_HEADER {
        return Err(bad("header too large"));
    }
    let mut head = vec![0u8; len as usize];
    r.read_exact(&mut head)?;
    let header: Header = serde_json::from_slice(&head).map_err(|e| bad(&format!("header: {e}")))?;
    header.validate()?;
    Ok(header)
}

/// Decode a whole encoded stream into `fd`; see [`decode_body`].
pub fn decode_into<R: Read, F: FnMut(&[u8])>(
    mut r: R,
    fd: RawFd,
    observe: F,
) -> io::Result<(u64, u64)> {
    let header = read_header(&mut r)?;
    decode_body(&header, r, fd, observe)
}

/// Write the extents that follow `header` into `fd`, which must be empty,
/// calling `observe` with every byte of the **logical** stream — holes as
/// zeros — in order, so the caller can hash exactly what the digest covers.
/// Returns the logical size and the bytes written.
pub fn decode_body<R: Read, F: FnMut(&[u8])>(
    header: &Header,
    mut r: R,
    fd: RawFd,
    mut observe: F,
) -> io::Result<(u64, u64)> {
    let zeros = vec![0u8; 1024 * 1024];
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut pos = 0u64;
    let mut written = 0u64;
    let feed_zeros = |from: u64, to: u64, observe: &mut F| {
        let mut left = to - from;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            observe(&zeros[..n]);
            left -= n as u64;
        }
    };
    for &(off, len) in &header.extents {
        feed_zeros(pos, off, &mut observe);
        let mut done = 0u64;
        while done < len {
            let want = ((len - done) as usize).min(buf.len());
            r.read_exact(&mut buf[..want])?;
            observe(&buf[..want]);
            sparse::pwrite_all(fd, &buf[..want], off + done)?;
            done += want as u64;
        }
        written += len;
        pos = off + len;
    }
    feed_zeros(pos, header.size, &mut observe);
    // Trailing bytes mean the object is not what its header says.
    let mut extra = [0u8; 1];
    if r.read(&mut extra)? != 0 {
        return Err(bad("trailing bytes after the last extent"));
    }
    sparse::ftruncate(fd, header.size)?;
    Ok((header.size, written))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn tmpdir() -> tempfile::TempDir {
        match std::env::var_os("ART_TEST_DIR") {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn sparse_file(dir: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
        let p = dir.join("src");
        let f = std::fs::File::create(&p).unwrap();
        let size = 8 * 1024 * 1024u64;
        sparse::ftruncate(f.as_raw_fd(), size).unwrap();
        sparse::pwrite_all(f.as_raw_fd(), &[7u8; 4096], 0).unwrap();
        sparse::pwrite_all(f.as_raw_fd(), &[9u8; 8192], 4 * 1024 * 1024).unwrap();
        f.sync_all().unwrap();
        (p.clone(), std::fs::read(&p).unwrap())
    }

    #[test]
    fn round_trips_and_ships_only_the_extents() {
        let d = tmpdir();
        let (src, logical) = sparse_file(d.path());
        let enc = Encoder::new(std::fs::File::open(&src).unwrap(), logical.len() as u64).unwrap();
        let encoded_len = enc.len();
        let mut encoded = Vec::new();
        let mut enc = enc;
        enc.read_to_end(&mut encoded).unwrap();
        assert_eq!(encoded.len() as u64, encoded_len);
        // Far below the logical 8 MiB, whatever the filesystem's block size.
        assert!(encoded.len() < 2 * 1024 * 1024, "{}", encoded.len());

        let out = d.path().join("out");
        let f = std::fs::File::create(&out).unwrap();
        let mut h = Sha256::new();
        let (size, written) =
            decode_into(encoded.as_slice(), f.as_raw_fd(), |b| h.update(b)).unwrap();
        assert_eq!(size, logical.len() as u64);
        assert!(written < size);
        assert_eq!(std::fs::read(&out).unwrap(), logical);
        assert_eq!(h.finalize().to_vec(), Sha256::digest(&logical).to_vec());
    }

    #[test]
    fn an_empty_blob_round_trips() {
        let d = tmpdir();
        let p = d.path().join("empty");
        std::fs::write(&p, b"").unwrap();
        let mut enc = Encoder::new(std::fs::File::open(&p).unwrap(), 0).unwrap();
        let mut encoded = Vec::new();
        enc.read_to_end(&mut encoded).unwrap();
        let out = std::fs::File::create(d.path().join("out")).unwrap();
        assert_eq!(
            decode_into(encoded.as_slice(), out.as_raw_fd(), |_| {}).unwrap(),
            (0, 0)
        );
    }

    #[test]
    fn rejects_garbage_and_lies() {
        let d = tmpdir();
        let out = std::fs::File::create(d.path().join("out")).unwrap();
        assert!(decode_into(&b"PK\x03\x04"[..], out.as_raw_fd(), |_| {}).is_err());

        // Overlapping extents.
        let h = Header {
            size: 10,
            extents: vec![(0, 5), (3, 2)],
        };
        let mut enc = h.encode();
        enc.extend_from_slice(&[1u8; 7]);
        assert!(decode_into(enc.as_slice(), out.as_raw_fd(), |_| {}).is_err());

        // An extent past the end.
        let h = Header {
            size: 4,
            extents: vec![(2, 5)],
        };
        let mut enc = h.encode();
        enc.extend_from_slice(&[1u8; 5]);
        assert!(decode_into(enc.as_slice(), out.as_raw_fd(), |_| {}).is_err());

        // Truncated data.
        let h = Header {
            size: 10,
            extents: vec![(0, 10)],
        };
        let mut enc = h.encode();
        enc.extend_from_slice(&[1u8; 3]);
        assert!(decode_into(enc.as_slice(), out.as_raw_fd(), |_| {}).is_err());

        // Trailing bytes.
        let h = Header {
            size: 2,
            extents: vec![(0, 2)],
        };
        let mut enc = h.encode();
        enc.extend_from_slice(&[1u8; 3]);
        assert!(decode_into(enc.as_slice(), out.as_raw_fd(), |_| {}).is_err());
    }
}
