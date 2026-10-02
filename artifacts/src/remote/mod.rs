//! The remote tier: the global store every regional daemon reads through and
//! writes through.
//!
//! Each region keeps its local store as a cache. The remote — an S3 bucket in
//! production, a directory in tests — is the system of record for everything:
//! blobs, manifests, tags, labels, public markers and repository metadata. A
//! store can be rebuilt from it alone, which makes it the backup as well.
//!
//! Layout under the configured prefix (see [`keys`]):
//!
//! ```text
//! blobs/<aa>/<64-hex>.asp     the blob, in crate::asp encoding (holes elided)
//! manifests/<aa>/<64-hex>     canonical JSON, byte-identical to the local copy
//! labels/<aa>/<64-hex>        label JSON
//! public/<aa>/<64-hex>        empty marker: this blob downloads anonymously
//! tags/<name>                 "<digest>\n"; a namespaced tag keeps its '/'
//! repos/<name>.json           repository metadata
//! locks/gc                    the lease `art s3 gc` holds while it sweeps
//! ```
//!
//! Blobs and manifests are named by content and never change, so a cache of
//! them is never stale. Tags, labels and repository metadata are mutable and
//! are revalidated by ETag. Writes that must not race — a tag compare-and-swap,
//! the GC lease — use S3's conditional `PUT` (`If-None-Match: *`, `If-Match`),
//! which the daemon checks the bucket honours before it serves anything.

pub mod fs;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "s3")]
pub mod sigv4;

use crate::digest::Digest;
use crate::error::{Error, Result};
use std::sync::Arc;

/// One object, as a listing or a `HEAD` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// Relative to the remote's prefix — the same spelling [`keys`] produces.
    pub key: String,
    pub size: u64,
    /// Opaque; compared for equality and sent back in `If-Match` /
    /// `If-None-Match`, never parsed.
    pub etag: String,
    /// Seconds since the epoch, when the remote reports it.
    pub modified: Option<u64>,
}

/// A precondition on a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// Last writer wins.
    Always,
    /// Only if nothing is at the key yet (`If-None-Match: *`).
    IfAbsent,
    /// Only if the object is still the one with this ETag (`If-Match`).
    IfMatch(String),
}

/// What a small-object `GET` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    NotFound,
    /// The caller's ETag still matches; nothing was transferred.
    NotModified,
    Found {
        body: Vec<u8>,
        etag: String,
    },
}

/// A streaming download.
pub type Reader = Box<dyn tokio::io::AsyncRead + Send + Unpin>;

/// Small objects are read whole. Anything claiming to be bigger is not a tag,
/// a label or a manifest.
pub const SMALL_OBJECT_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct Remote {
    backend: Arc<Backend>,
}

enum Backend {
    Fs(fs::FsRemote),
    #[cfg(feature = "s3")]
    S3(s3::S3Remote),
}

macro_rules! dispatch {
    ($self:ident, $b:ident => $e:expr) => {
        match &*$self.backend {
            Backend::Fs($b) => $e,
            #[cfg(feature = "s3")]
            Backend::S3($b) => $e,
        }
    };
}

impl Remote {
    pub fn fs(root: impl Into<std::path::PathBuf>) -> Result<Remote> {
        Ok(Remote {
            backend: Arc::new(Backend::Fs(fs::FsRemote::new(root.into())?)),
        })
    }

    #[cfg(feature = "s3")]
    pub fn s3(config: s3::S3Settings) -> Result<Remote> {
        Ok(Remote {
            backend: Arc::new(Backend::S3(s3::S3Remote::new(config)?)),
        })
    }

    /// Where this remote is, for logs: `s3://bucket/prefix` or a path.
    pub fn describe(&self) -> String {
        dispatch!(self, b => b.describe())
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectInfo>> {
        dispatch!(self, b => b.head(key).await)
    }

    /// Read a small object whole. With `if_none_match`, an unchanged object
    /// answers [`Fetched::NotModified`] without its body.
    pub async fn get(&self, key: &str, if_none_match: Option<&str>) -> Result<Fetched> {
        dispatch!(self, b => b.get(key, if_none_match).await)
    }

    /// Stream an object of any size. `None` if it does not exist.
    pub async fn open(&self, key: &str) -> Result<Option<Reader>> {
        dispatch!(self, b => b.open(key).await)
    }

    /// Write a small object. Returns its new ETag, or
    /// [`Error::PreconditionFailed`] if `cond` did not hold.
    pub async fn put(&self, key: &str, body: Vec<u8>, cond: Cond) -> Result<String> {
        dispatch!(self, b => b.put(key, body, cond).await)
    }

    /// Write an object of any size from a blocking reader of exactly `len`
    /// bytes — multipart on S3 when it is large. Unconditional: only used for
    /// content-addressed keys, where every writer writes the same bytes.
    pub async fn upload(
        &self,
        key: &str,
        reader: Box<dyn std::io::Read + Send>,
        len: u64,
    ) -> Result<()> {
        dispatch!(self, b => b.upload(key, reader, len).await)
    }

    /// Remove an object. Removing one that is already gone succeeds.
    pub async fn delete(&self, key: &str) -> Result<()> {
        dispatch!(self, b => b.delete(key).await)
    }

    /// Every object whose key starts with `prefix`, in key order.
    pub async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>> {
        let mut out = dispatch!(self, b => b.list(prefix).await)?;
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// Prove the remote is reachable, the credentials work, and conditional
    /// writes are honoured.
    ///
    /// Run once at startup. Tag compare-and-swap and the GC lease are only as
    /// sound as `If-None-Match`, and a store that silently ignores it would
    /// turn both into last-writer-wins with no error anywhere — so a remote
    /// that does not refuse the second write below is refused instead.
    pub async fn probe(&self) -> Result<()> {
        let key = format!(
            "probe/{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        self.put(&key, b"probe\n".to_vec(), Cond::IfAbsent).await?;
        let second = self.put(&key, b"probe\n".to_vec(), Cond::IfAbsent).await;
        let _ = self.delete(&key).await;
        match second {
            Err(Error::PreconditionFailed(_)) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(Error::Remote(format!(
                "{} accepted a second If-None-Match: * write to {key}; conditional writes \
                 are required (tag compare-and-swap and the GC lease depend on them)",
                self.describe()
            ))),
        }
    }
}

/// Object keys, relative to the remote's prefix. One place, so the daemon,
/// the backfill and the collector cannot disagree about where anything lives.
pub mod keys {
    use crate::digest::Digest;
    use crate::tags::{RepoName, TagName};

    pub const BLOBS: &str = "blobs/";
    pub const MANIFESTS: &str = "manifests/";
    pub const LABELS: &str = "labels/";
    pub const PUBLIC: &str = "public/";
    pub const TAGS: &str = "tags/";
    pub const REPOS: &str = "repos/";
    pub const GC_LEASE: &str = "locks/gc";

    pub fn blob(d: &Digest) -> String {
        format!("{BLOBS}{}/{}.asp", d.shard(), d)
    }
    pub fn manifest(d: &Digest) -> String {
        format!("{MANIFESTS}{}/{}", d.shard(), d)
    }
    pub fn label(d: &Digest) -> String {
        format!("{LABELS}{}/{}", d.shard(), d)
    }
    pub fn public(d: &Digest) -> String {
        format!("{PUBLIC}{}/{}", d.shard(), d)
    }
    pub fn tag(t: &TagName) -> String {
        format!("{TAGS}{}", t.as_str())
    }
    pub fn repo(r: &RepoName) -> String {
        format!("{REPOS}{}.json", r.as_str())
    }

    /// The digest a content key names: `blobs/aa/<hex>.asp`,
    /// `manifests/aa/<hex>` and so on.
    pub fn digest_of(key: &str) -> Option<Digest> {
        let name = key.rsplit('/').next()?;
        let name = name.strip_suffix(".asp").unwrap_or(name);
        Digest::parse(name).ok()
    }

    pub fn tag_of(key: &str) -> Option<TagName> {
        TagName::parse(key.strip_prefix(TAGS)?).ok()
    }

    pub fn repo_of(key: &str) -> Option<RepoName> {
        RepoName::parse(key.strip_prefix(REPOS)?.strip_suffix(".json")?).ok()
    }
}

/// Parse a tag object's body: one digest and a newline.
pub fn parse_tag_body(body: &[u8]) -> Result<Digest> {
    let s =
        std::str::from_utf8(body).map_err(|_| Error::Remote("tag object is not UTF-8".into()))?;
    Ok(Digest::parse(s.trim())?)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn unix_of(y: i64, mo: u32, d: u32, h: u64, mi: u64, s: u64) -> Option<u64> {
    let days = days_from_civil(y, mo, d);
    u64::try_from(days)
        .ok()
        .map(|days| days * 86_400 + h * 3600 + mi * 60 + s)
}

/// `2024-01-02T03:04:05.000Z`, as ListObjectsV2 reports `LastModified`.
pub fn parse_iso8601(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<u64>().ok();
    unix_of(
        n(0..4)? as i64,
        n(5..7)? as u32,
        n(8..10)? as u32,
        n(11..13)?,
        n(14..16)?,
        n(17..19)?,
    )
}

/// `Tue, 02 Jan 2024 03:04:05 GMT`, as a `Last-Modified` header carries it.
pub fn parse_http_date(s: &str) -> Option<u64> {
    let mut it = s.split_whitespace().skip(1);
    let day: u32 = it.next()?.parse().ok()?;
    let month = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let h = hms.next()?.parse().ok()?;
    let m = hms.next()?.parse().ok()?;
    let sec = hms.next()?.parse().ok()?;
    unix_of(year, month, day, h, m, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_parse_in_both_spellings() {
        assert_eq!(
            parse_iso8601("2024-02-29T13:37:11.000Z"),
            Some(1_709_213_831)
        );
        assert_eq!(
            parse_http_date("Thu, 29 Feb 2024 13:37:11 GMT"),
            Some(1_709_213_831)
        );
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601("garbage"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }

    #[test]
    fn keys_round_trip() {
        let d = Digest::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        assert_eq!(
            keys::blob(&d),
            "blobs/e3/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.asp"
        );
        assert_eq!(keys::digest_of(&keys::blob(&d)), Some(d.clone()));
        assert_eq!(keys::digest_of(&keys::manifest(&d)), Some(d));
        let t = crate::tags::TagName::parse("heyo/postgres:16").unwrap();
        assert_eq!(keys::tag(&t), "tags/heyo/postgres:16");
        assert_eq!(keys::tag_of(&keys::tag(&t)), Some(t.clone()));
        let r = t.repo().unwrap();
        assert_eq!(keys::repo(&r), "repos/heyo/postgres.json");
        assert_eq!(keys::repo_of(&keys::repo(&r)), Some(r));
    }
}
