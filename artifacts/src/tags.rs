//! A tag file holds exactly one digest and is replaced only by rename.
//!
//! Tags are the one mutable object in the store, so unlike blobs they use the
//! temp-in-same-directory + `sync_all` + rename pattern from
//! `vault/src/store.rs:111-136`.
//!
//! They are **regular files, not symlinks**. A symlink target is a path you
//! must re-parse and re-validate, which would reintroduce the traversal
//! boundary [`crate::digest::Digest::parse`] just removed; the kernel does not
//! validate symlink targets, so a dangling tag would be indistinguishable from
//! a typo; symlinks do not affect the target's `st_nlink`, so they contribute
//! nothing to the refcount; and replacing one atomically still needs
//! symlink-to-temp + rename anyway.
//!
//! [`TagName`] uses the same charset as `vault/src/ids.rs` and is a
//! path-traversal boundary for exactly the same reason.

use crate::digest::Digest;
use serde::{Deserialize, Deserializer};
use std::fmt;

const MAX_LEN: usize = 64;

/// A repository path is at most this long, so a namespaced tag's file name —
/// repo, `:`, tag — stays under ext4's 255-byte `NAME_MAX`.
const MAX_REPO_LEN: usize = 180;
const MAX_REPO_SEGMENTS: usize = 4;
const MAX_SEGMENT_LEN: usize = 64;

/// The tag a bare repository name means: `heyo/postgres` is
/// `heyo/postgres:latest`, as it is everywhere else people type image names.
pub const DEFAULT_TAG: &str = "latest";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    #[error("tag must not be empty")]
    Empty,
    #[error("tag must be at most {MAX_LEN} characters")]
    TooLong,
    #[error("tag may only contain letters, digits, '_', '-' and '.'")]
    BadChar,
    #[error("tag must not start with '-' or '.'")]
    BadStart,
    #[error("tag is a reserved name")]
    Reserved,
    #[error(
        "repository must be 1-{MAX_REPO_SEGMENTS} '/'-separated segments of lowercase letters, \
         digits, '.', '_' and '-', each starting with a letter or digit, at most \
         {MAX_REPO_LEN} characters in all"
    )]
    BadRepo,
}

/// Case-insensitive reserved names (dot entries plus Windows devices, so a
/// store directory stays copyable to a non-Unix filesystem).
const RESERVED: &[&str] = &[
    ".", "..", "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "lpt1", "lpt2", "lpt3",
    "lpt4",
];

/// A tag: either a **flat** name (`debian-hermes`) or a **namespaced** one
/// (`heyo/postgres:16`), held in its canonical spelling.
///
/// The two never collide. A flat name cannot contain `/` or `:`, and a
/// namespaced one always contains `:` once canonical, so every tag that existed
/// before namespaces parses to exactly the same value it always did.
///
/// A namespaced tag is a [`RepoName`] and a flat tag joined by `:`. The repo is
/// what the hub lists and what is public or private; the tag after the colon
/// follows the flat grammar, so `heyo/ubuntu:24.04` works.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TagName(String);

impl TagName {
    pub fn parse(s: &str) -> Result<TagName, TagError> {
        if s.contains('/') || s.contains(':') {
            let (repo, tag) = match s.split_once(':') {
                Some((repo, tag)) => (repo, tag),
                None => (s, DEFAULT_TAG),
            };
            let repo = RepoName::parse(repo)?;
            parse_flat(tag)?;
            return Ok(TagName(format!("{}:{tag}", repo.as_str())));
        }
        parse_flat(s)?;
        Ok(TagName(s.to_string()))
    }

    /// The tag `tag` in `repo`.
    pub fn in_repo(repo: &RepoName, tag: &str) -> Result<TagName, TagError> {
        parse_flat(tag)?;
        Ok(TagName(format!("{}:{tag}", repo.as_str())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The repository a namespaced tag belongs to. `None` for a flat tag.
    pub fn repo(&self) -> Option<RepoName> {
        let (repo, _) = self.0.split_once(':')?;
        Some(RepoName(repo.to_string()))
    }

    /// The part after the colon for a namespaced tag; the whole name otherwise.
    pub fn short(&self) -> &str {
        match self.0.split_once(':') {
            Some((_, tag)) => tag,
            None => &self.0,
        }
    }

    /// The name of this tag's file under `tags/`.
    ///
    /// A namespaced tag's `/` becomes `~`, which no tag may contain, so the
    /// mapping reverses exactly and `tags/` stays one flat directory: the store
    /// and the garbage collector keep listing it with a single `readdir`, and
    /// no tag can name a subdirectory.
    pub fn file_name(&self) -> String {
        self.0.replace('/', "~")
    }

    /// The inverse of [`Self::file_name`]. Re-validates, so a stray file under
    /// `tags/` can never become a tag that escapes it.
    pub fn from_file_name(name: &str) -> Result<TagName, TagError> {
        let t = TagName::parse(&name.replace('~', "/"))?;
        if t.file_name() != name {
            // Not canonical — `heyo~postgres` without its `:latest`, say.
            return Err(TagError::BadRepo);
        }
        Ok(t)
    }
}

fn parse_flat(s: &str) -> Result<(), TagError> {
    if s.is_empty() {
        return Err(TagError::Empty);
    }
    if s.len() > MAX_LEN {
        return Err(TagError::TooLong);
    }
    let first = s.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return Err(TagError::BadStart);
    }
    // '.' is allowed after the first byte so image names like
    // "ubuntu-24.04" survive a round trip. It cannot form ".." because a
    // leading '.' is rejected and no separator is in the charset.
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(TagError::BadChar);
    }
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(s)) {
        return Err(TagError::Reserved);
    }
    Ok(())
}

impl fmt::Display for TagName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TagName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        TagName::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A repository: `heyo/postgres`, `acme/web`, or a single segment like
/// `postgres`.
///
/// Lowercase only, as image registries are, so two people typing the same
/// name with different capitalisation reach the same repository. Every segment
/// starts with a letter or digit, which rules out `.`, `..` and empty segments
/// (`a//b`, a leading or trailing `/`) in one check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoName(String);

impl RepoName {
    pub fn parse(s: &str) -> Result<RepoName, TagError> {
        if s.is_empty() || s.len() > MAX_REPO_LEN {
            return Err(TagError::BadRepo);
        }
        let segments: Vec<&str> = s.split('/').collect();
        if segments.len() > MAX_REPO_SEGMENTS {
            return Err(TagError::BadRepo);
        }
        for seg in segments {
            let b = seg.as_bytes();
            if b.is_empty() || b.len() > MAX_SEGMENT_LEN {
                return Err(TagError::BadRepo);
            }
            if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
                return Err(TagError::BadRepo);
            }
            if !b.iter().all(|&c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-'
            }) {
                return Err(TagError::BadRepo);
            }
        }
        Ok(RepoName(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first path segment — `heyo` for `heyo/postgres`. The hub groups by
    /// it.
    pub fn namespace(&self) -> &str {
        self.0.split('/').next().unwrap_or(&self.0)
    }

    /// The repository's metadata file name under `repos/`, `/` as `~` for the
    /// same reason as [`TagName::file_name`].
    pub fn file_name(&self) -> String {
        format!("{}.json", self.0.replace('/', "~"))
    }

    pub fn from_file_name(name: &str) -> Result<RepoName, TagError> {
        let stem = name.strip_suffix(".json").ok_or(TagError::BadRepo)?;
        RepoName::parse(&stem.replace('~', "/"))
    }

    /// Whether `tag` lives in this repository.
    pub fn contains(&self, tag: &TagName) -> bool {
        tag.repo().is_some_and(|r| &r == self)
    }
}

impl fmt::Display for RepoName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepoName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        RepoName::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for RepoName {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl serde::Serialize for TagName {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Something that resolves to a digest: either a tag or a literal digest.
///
/// Parsed digest-first, so a 64-hex tag name can never shadow a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ref {
    Digest(Digest),
    Tag(TagName),
}

impl Ref {
    pub fn parse(s: &str) -> Result<Ref, TagError> {
        if let Ok(d) = Digest::parse(s) {
            return Ok(Ref::Digest(d));
        }
        TagName::parse(s).map(Ref::Tag)
    }
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ref::Digest(d) => write!(f, "{d}"),
            Ref::Tag(t) => write!(f, "{t}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn accepts_reasonable_tags() {
        for good in [
            "debian",
            "debian-hermes",
            "ubuntu-24.04",
            "agents_v1",
            "x",
            "N0de",
        ] {
            assert!(TagName::parse(good).is_ok(), "should accept {good}");
        }
    }

    #[test]
    fn rejects_traversal_and_tricks() {
        let long = "x".repeat(65);
        let bad: [&str; 14] = [
            "",
            "..",
            ".",
            "../../etc/passwd",
            "/etc/passwd",
            "a//b",
            "a\\b",
            ".hidden",
            "-flag",
            "a b",
            "café",
            "nul",
            "CON",
            &long,
        ];
        for b in bad {
            assert!(TagName::parse(b).is_err(), "should reject {b:?}");
        }
    }

    #[test]
    fn rejects_embedded_nul() {
        assert!(TagName::parse("with\0null").is_err());
    }

    #[test]
    fn dotted_tag_cannot_form_parent_directory() {
        // ".." is Reserved and a leading '.' is BadStart, so no accepted tag
        // can traverse even though '.' is in the charset.
        assert!(TagName::parse("..").is_err());
        assert!(TagName::parse(".").is_err());
        assert!(TagName::parse("a..b").is_ok());
        assert!(!TagName::parse("a..b").unwrap().as_str().contains('/'));
    }

    #[test]
    fn ref_prefers_digest_over_tag() {
        // A 64-hex string is a digest, never a tag, so a tag can't shadow a blob.
        assert!(matches!(Ref::parse(OK_DIGEST), Ok(Ref::Digest(_))));
        assert!(matches!(Ref::parse("debian"), Ok(Ref::Tag(_))));
    }

    #[test]
    fn ref_rejects_what_neither_accepts() {
        assert!(Ref::parse("../etc").is_err());
    }

    #[test]
    fn namespaced_tags_parse_to_a_canonical_spelling() {
        let t = TagName::parse("heyo/postgres:16").unwrap();
        assert_eq!(t.as_str(), "heyo/postgres:16");
        assert_eq!(t.repo().unwrap().as_str(), "heyo/postgres");
        assert_eq!(t.short(), "16");
        // A bare repository means :latest.
        assert_eq!(
            TagName::parse("heyo/postgres").unwrap().as_str(),
            "heyo/postgres:latest"
        );
        // A single-segment repository needs the colon to be one.
        assert_eq!(
            TagName::parse("postgres:16")
                .unwrap()
                .repo()
                .unwrap()
                .as_str(),
            "postgres"
        );
        assert_eq!(
            TagName::parse("heyo/ubuntu:24.04").unwrap().short(),
            "24.04"
        );
        assert_eq!(
            TagName::parse("a/b/c/d:x")
                .unwrap()
                .repo()
                .unwrap()
                .namespace(),
            "a"
        );
    }

    #[test]
    fn flat_tags_are_unchanged_by_namespaces() {
        for flat in ["debian", "debian-hermes", "ubuntu-24.04", "N0de"] {
            let t = TagName::parse(flat).unwrap();
            assert_eq!(t.as_str(), flat);
            assert_eq!(t.repo(), None);
            assert_eq!(t.short(), flat);
            assert_eq!(t.file_name(), flat);
        }
    }

    #[test]
    fn namespaced_tags_reject_traversal_and_tricks() {
        let long_repo = format!("{}/x", "a".repeat(200));
        let bad: [&str; 16] = [
            "a/../b",
            "a/./b",
            "../a:x",
            "a//b",
            "/a",
            "a/",
            "a/b:",
            "a/b:.x",
            "a/b:c:d",
            "A/b",
            "a/b~c",
            "a/b/c/d/e",
            "a/-b",
            "a/b:x/y",
            ":x",
            &long_repo,
        ];
        for b in bad {
            assert!(TagName::parse(b).is_err(), "should reject {b:?}");
        }
    }

    #[test]
    fn file_names_round_trip_and_stay_in_one_directory() {
        for name in [
            "debian",
            "heyo/postgres:16",
            "a/b/c/d:ubuntu-24.04",
            "postgres:16",
        ] {
            let t = TagName::parse(name).unwrap();
            let f = t.file_name();
            assert!(!f.contains('/'), "{f}");
            assert!(f.len() <= 255, "{f}");
            assert_eq!(TagName::from_file_name(&f).unwrap(), t);
        }
        assert_eq!(
            TagName::parse("heyo/postgres:16").unwrap().file_name(),
            "heyo~postgres:16"
        );
        // Not canonical: refused rather than silently re-spelled.
        assert!(TagName::from_file_name("heyo~postgres").is_err());
        let longest = format!("{}:{}", vec!["a".repeat(44); 4].join("/"), "t".repeat(64));
        assert!(TagName::parse(&longest).unwrap().file_name().len() <= 255);
    }

    #[test]
    fn repo_names_round_trip_through_their_file_names() {
        let r = RepoName::parse("heyo/postgres").unwrap();
        assert_eq!(r.file_name(), "heyo~postgres.json");
        assert_eq!(RepoName::from_file_name(&r.file_name()).unwrap(), r);
        assert!(r.contains(&TagName::parse("heyo/postgres:16").unwrap()));
        assert!(!r.contains(&TagName::parse("heyo/postgres-old:16").unwrap()));
        assert!(!r.contains(&TagName::parse("postgres").unwrap()));
    }

    #[test]
    fn ref_parses_namespaced_tags() {
        assert!(matches!(Ref::parse("heyo/postgres:16"), Ok(Ref::Tag(_))));
    }
}
