//! Every failure has one typed cause and one machine-readable slug.
//!
//! Two errno values get their own variants rather than being folded into
//! [`Error::Io`], because the correct operator response to each is completely
//! different and neither is recoverable by retrying:
//!
//! - `ENOSPC` — the store root is on a filesystem mounted `errors=remount-ro`.
//!   Filling it yields a read-only root filesystem, not an error return, so the
//!   guard in [`crate::sys::space`] must refuse *before* the write begins.
//! - `EMLINK` — ext4 caps a file at `LINK_MAX` (65000) hardlinks. The fix is to
//!   sweep stale materializations, which has nothing in common with freeing
//!   disk space.

use crate::digest::{Digest, DigestError};
use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("blob {0} not found")]
    NotFound(Digest),

    #[error("tag '{0}' not found")]
    TagNotFound(String),

    #[error("invalid digest: {0}")]
    Digest(#[from] DigestError),

    #[error("invalid tag name: {0}")]
    TagName(#[from] crate::tags::TagError),

    #[error("invalid label: {0}")]
    Label(#[from] crate::labels::LabelError),

    #[error("invalid repository metadata: {0}")]
    Repo(#[from] crate::repos::RepoError),

    #[error("repository '{0}' not found")]
    RepoNotFound(String),

    /// The remote tier (S3) failed or could not be reached. Distinct from
    /// [`Error::Io`]: the local disk is fine, and the answer is to retry or to
    /// look at the bucket, not at this host.
    #[error("remote store: {0}")]
    Remote(String),

    /// A conditional write lost: someone else changed the object first.
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    /// A manifest or tag names content the global store does not hold. Upload
    /// the blobs first; the remote must never hold a pointer to nothing.
    #[error("{0} is not in the store; upload it first")]
    Missing(Digest),

    #[error(
        "refusing to write {needed} bytes: only {available} free, and {reserve} is reserved \
         (ART_MIN_FREE_BYTES)"
    )]
    NoSpace {
        needed: u64,
        available: u64,
        reserve: u64,
    },

    #[error("blob {digest} has reached the filesystem hardlink limit ({nlink})")]
    LinkLimit { digest: Digest, nlink: u64 },

    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },

    #[error("source file shrank while being read: {0}")]
    SourceShrank(PathBuf),

    #[error(
        "refusing to punch holes in {path}: it has {nlink} links, so the change would be visible to every one of them"
    )]
    SharedInode { path: PathBuf, nlink: u64 },

    #[error("manifest schema version {0} is newer than this build understands")]
    ManifestVersion(u32),

    #[error(
        "{digest} is a manifest with {} entries ({}); name one directly, or use `art heyvm bundle export`",
        entries.len(),
        entries.join(", ")
    )]
    AmbiguousManifest {
        digest: Digest,
        entries: Vec<String>,
    },

    /// Missing or wrong API key. Distinct from [`Error::ReadOnly`]: this one
    /// means "prove who you are", which is what makes a `WWW-Authenticate`
    /// header the right response.
    #[error("unauthorized")]
    Unauthorized,

    /// The credentials were fine; the operation is disabled. A different answer
    /// from [`Error::Unauthorized`], and retrying with a better key will not
    /// help.
    #[error("this daemon is read-only (ART_READ_ONLY)")]
    ReadOnly,

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl Error {
    /// Machine-readable slug, for the v2 JSON API and for `--json` CLI output.
    pub fn slug(&self) -> &'static str {
        match self {
            Error::NotFound(_) => "not_found",
            Error::TagNotFound(_) => "tag_not_found",
            Error::Digest(_) => "invalid_digest",
            Error::TagName(_) => "invalid_tag",
            Error::Label(_) => "invalid_label",
            Error::Repo(_) => "invalid_repo",
            Error::RepoNotFound(_) => "repo_not_found",
            Error::Remote(_) => "remote_error",
            Error::PreconditionFailed(_) => "precondition_failed",
            Error::Missing(_) => "missing_content",
            Error::NoSpace { .. } => "no_space",
            Error::LinkLimit { .. } => "link_limit",
            Error::DigestMismatch { .. } => "digest_mismatch",
            Error::SourceShrank(_) => "source_shrank",
            Error::SharedInode { .. } => "shared_inode",
            Error::ManifestVersion(_) => "manifest_version",
            Error::AmbiguousManifest { .. } => "ambiguous_manifest",
            Error::Unauthorized => "unauthorized",
            Error::ReadOnly => "read_only",
            Error::Io { .. } => "io_error",
        }
    }
}

/// Attach context to an `io::Error` without losing the errno.
pub trait IoContext<T> {
    fn ctx(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for std::result::Result<T, io::Error> {
    fn ctx(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: context.into(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_distinct_per_variant() {
        let d = Digest::parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();
        let errs = [
            Error::NotFound(d.clone()),
            Error::TagNotFound("x".into()),
            Error::NoSpace {
                needed: 1,
                available: 0,
                reserve: 0,
            },
            Error::LinkLimit {
                digest: d.clone(),
                nlink: 65000,
            },
        ];
        let slugs: Vec<_> = errs.iter().map(|e| e.slug()).collect();
        let mut sorted = slugs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(slugs.len(), sorted.len(), "slugs must be distinct");
    }

    #[test]
    fn no_space_message_names_the_reserve_knob() {
        let e = Error::NoSpace {
            needed: 100,
            available: 10,
            reserve: 5,
        };
        // The operator needs to know which env var to turn, not just that the
        // disk is full.
        assert!(e.to_string().contains("ART_MIN_FREE_BYTES"));
    }

    #[test]
    fn io_context_preserves_errno() {
        let r: std::result::Result<(), io::Error> = Err(io::Error::from_raw_os_error(libc::ENOSPC));
        let e = r.ctx("writing blob").unwrap_err();
        match e {
            Error::Io { source, context } => {
                assert_eq!(source.raw_os_error(), Some(libc::ENOSPC));
                assert_eq!(context, "writing blob");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }
}
