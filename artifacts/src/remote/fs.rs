//! A directory that behaves like an S3 bucket.
//!
//! The test double for the remote tier, and usable for real where the "remote"
//! is a mounted network filesystem (`ART_REMOTE_DIR`). It honours the same
//! contract S3 does — atomic object replacement, conditional writes, ETags
//! that change whenever the content does — so the code above it cannot tell
//! the two apart.
//!
//! Conditional writes are serialised with an `flock` on `.remote.lock` at the
//! root, which covers every process sharing the directory, not only this one.
//! Two daemons pointed at one directory — two "regions" in a test — therefore
//! see exactly the compare-and-swap behaviour they would against a bucket.

use super::{Cond, Fetched, ObjectInfo, Reader, SMALL_OBJECT_LIMIT};
use crate::error::{Error, IoContext, Result};
use fs2::FileExt;
use sha2::{Digest as _, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub struct FsRemote {
    root: PathBuf,
}

/// Objects at most this large get a content-hash ETag; larger ones a
/// size-and-mtime one, so a listing never re-reads a twenty-gigabyte blob.
const HASHED_ETAG_LIMIT: u64 = 1024 * 1024;

impl FsRemote {
    pub fn new(root: PathBuf) -> Result<FsRemote> {
        std::fs::create_dir_all(&root).ctx(format!("create {}", root.display()))?;
        Ok(FsRemote { root })
    }

    pub fn describe(&self) -> String {
        format!("dir://{}", self.root.display())
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        // Keys come from `remote::keys`, which only ever builds them from
        // validated names; this is the belt to that pair of braces.
        if key.is_empty()
            || key.starts_with('/')
            || key
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
        {
            return Err(Error::Remote(format!("invalid object key {key:?}")));
        }
        Ok(self.root.join(key))
    }

    pub async fn head(&self, key: &str) -> Result<Option<ObjectInfo>> {
        let p = self.path(key)?;
        let key = key.to_string();
        blocking(move || info_of(&p, key)).await
    }

    pub async fn get(&self, key: &str, if_none_match: Option<&str>) -> Result<Fetched> {
        let p = self.path(key)?;
        let key = key.to_string();
        let inm = if_none_match.map(str::to_string);
        blocking(move || {
            let Some(info) = info_of(&p, key)? else {
                return Ok(Fetched::NotFound);
            };
            if inm.as_deref() == Some(info.etag.as_str()) {
                return Ok(Fetched::NotModified);
            }
            if info.size > SMALL_OBJECT_LIMIT {
                return Err(Error::Remote(format!(
                    "{} is too large to read whole",
                    p.display()
                )));
            }
            match std::fs::read(&p) {
                Ok(body) => {
                    let etag = etag_of(&p, &body)?;
                    Ok(Fetched::Found { body, etag })
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fetched::NotFound),
                Err(e) => Err(e).ctx(format!("read {}", p.display())),
            }
        })
        .await
    }

    pub async fn open(&self, key: &str) -> Result<Option<Reader>> {
        let p = self.path(key)?;
        match tokio::fs::File::open(&p).await {
            Ok(f) => Ok(Some(Box::new(f))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).ctx(format!("open {}", p.display())),
        }
    }

    pub async fn put(&self, key: &str, body: Vec<u8>, cond: Cond) -> Result<String> {
        let p = self.path(key)?;
        let root = self.root.clone();
        let key = key.to_string();
        blocking(move || {
            let lock = lock_root(&root)?;
            let current = info_of(&p, key.clone())?;
            match (&cond, &current) {
                (Cond::IfAbsent, Some(_)) => {
                    return Err(Error::PreconditionFailed(format!("{key} already exists")));
                }
                (Cond::IfMatch(want), Some(have)) if &have.etag != want => {
                    return Err(Error::PreconditionFailed(format!("{key} has changed")));
                }
                (Cond::IfMatch(_), None) => {
                    return Err(Error::PreconditionFailed(format!("{key} does not exist")));
                }
                _ => {}
            }
            write_atomic(&p, &mut body.as_slice())?;
            drop(lock);
            etag_of(&p, &body)
        })
        .await
    }

    pub async fn upload(
        &self,
        key: &str,
        mut reader: Box<dyn Read + Send>,
        len: u64,
    ) -> Result<()> {
        let p = self.path(key)?;
        blocking(move || {
            let mut limited = (&mut reader).take(len);
            let written = write_atomic(&p, &mut limited)?;
            if written != len {
                let _ = std::fs::remove_file(&p);
                return Err(Error::Remote(format!(
                    "upload of {} ended after {written} of {len} bytes",
                    p.display()
                )));
            }
            Ok(())
        })
        .await
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        let p = self.path(key)?;
        blocking(move || crate::sys::sparse::unlink_if_present(&p).map(|_| ())).await
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>> {
        let root = self.root.clone();
        let prefix = prefix.to_string();
        blocking(move || {
            let mut out = Vec::new();
            walk(&root, &root, &prefix, &mut out)?;
            Ok(out)
        })
        .await
    }
}

fn walk(root: &Path, dir: &Path, prefix: &str, out: &mut Vec<ObjectInfo>) -> Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).ctx(format!("read {}", dir.display())),
    };
    for entry in rd {
        let entry = entry.ctx("read remote entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let key = path
            .strip_prefix(root)
            .expect("walk stays under the root")
            .to_string_lossy()
            .into_owned();
        let ft = entry.file_type().ctx("stat remote entry")?;
        if ft.is_dir() {
            // Only descend where something under the prefix could live.
            let as_dir = format!("{key}/");
            if as_dir.starts_with(prefix) || prefix.starts_with(&as_dir) {
                walk(root, &path, prefix, out)?;
            }
        } else if key.starts_with(prefix)
            && let Some(info) = info_of(&path, key)?
        {
            out.push(info);
        }
    }
    Ok(())
}

fn info_of(p: &Path, key: String) -> Result<Option<ObjectInfo>> {
    let md = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).ctx(format!("stat {}", p.display())),
    };
    let etag = if md.len() <= HASHED_ETAG_LIMIT {
        match std::fs::read(p) {
            Ok(b) => etag_of(p, &b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).ctx(format!("read {}", p.display())),
        }
    } else {
        stat_etag(&md)
    };
    Ok(Some(ObjectInfo {
        key,
        size: md.len(),
        etag,
        modified: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    }))
}

fn etag_of(p: &Path, body: &[u8]) -> Result<String> {
    if body.len() as u64 <= HASHED_ETAG_LIMIT {
        return Ok(format!("\"{}\"", hex::encode(Sha256::digest(body))));
    }
    let md = std::fs::metadata(p).ctx(format!("stat {}", p.display()))?;
    Ok(stat_etag(&md))
}

fn stat_etag(md: &std::fs::Metadata) -> String {
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("\"{:x}-{:x}\"", md.len(), mtime)
}

/// Write to a temp file beside `p`, then rename over it: a reader sees the old
/// object or the new one, never half of either.
fn write_atomic(p: &Path, r: &mut dyn Read) -> Result<u64> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = p.parent().expect("object paths have a parent");
    std::fs::create_dir_all(dir).ctx(format!("create {}", dir.display()))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let res = (|| -> Result<u64> {
        let mut f = std::fs::File::create(&tmp).ctx(format!("create {}", tmp.display()))?;
        let n = std::io::copy(r, &mut f).ctx(format!("write {}", tmp.display()))?;
        f.sync_all().ctx("fsync object")?;
        std::fs::rename(&tmp, p).ctx(format!("rename into {}", p.display()))?;
        Ok(n)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn lock_root(root: &Path) -> Result<std::fs::File> {
    let p = root.join(".remote.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&p)
        .ctx(format!("open {}", p.display()))?;
    f.lock_exclusive().ctx(format!("lock {}", p.display()))?;
    Ok(f)
}

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    crate::store::run_blocking(f).await
}

#[cfg(test)]
mod tests {
    use super::super::Remote;
    use super::*;

    fn remote() -> (tempfile::TempDir, Remote) {
        let d = tempfile::tempdir().unwrap();
        let r = Remote::fs(d.path().join("remote")).unwrap();
        (d, r)
    }

    #[tokio::test]
    async fn conditional_writes_behave_like_s3() {
        let (_d, r) = remote();
        let e1 = r
            .put("tags/x", b"a\n".to_vec(), Cond::IfAbsent)
            .await
            .unwrap();
        assert!(matches!(
            r.put("tags/x", b"b\n".to_vec(), Cond::IfAbsent).await,
            Err(Error::PreconditionFailed(_))
        ));
        let e2 = r
            .put("tags/x", b"b\n".to_vec(), Cond::IfMatch(e1.clone()))
            .await
            .unwrap();
        assert_ne!(e1, e2);
        // A stale ETag loses.
        assert!(matches!(
            r.put("tags/x", b"c\n".to_vec(), Cond::IfMatch(e1)).await,
            Err(Error::PreconditionFailed(_))
        ));
        assert!(matches!(
            r.put("tags/none", b"c\n".to_vec(), Cond::IfMatch(e2.clone()))
                .await,
            Err(Error::PreconditionFailed(_))
        ));
        assert_eq!(
            r.get("tags/x", Some(&e2)).await.unwrap(),
            Fetched::NotModified
        );
        r.probe().await.unwrap();
    }

    #[tokio::test]
    async fn listing_is_by_prefix_and_skips_temp_files() {
        let (d, r) = remote();
        for k in ["tags/a", "tags/heyo/pg:16", "repos/heyo/pg.json", "tagsx"] {
            r.put(k, b"x".to_vec(), Cond::Always).await.unwrap();
        }
        std::fs::write(d.path().join("remote/tags/.123.0.tmp"), b"half").unwrap();
        let keys: Vec<_> = r
            .list("tags/")
            .await
            .unwrap()
            .into_iter()
            .map(|o| o.key)
            .collect();
        assert_eq!(keys, ["tags/a", "tags/heyo/pg:16"]);
        r.delete("tags/a").await.unwrap();
        r.delete("tags/a").await.unwrap();
        assert_eq!(r.list("tags/").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn keys_cannot_escape_the_root() {
        let (_d, r) = remote();
        for k in ["../x", "a/../../x", "/etc/passwd", "a//b", ""] {
            assert!(r.put(k, vec![], Cond::Always).await.is_err(), "{k}");
        }
    }
}
