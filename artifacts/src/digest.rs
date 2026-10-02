//! Blob names and their validation — the path-traversal boundary.
//!
//! A [`Digest`] can only be built through [`Digest::parse`], which accepts
//! exactly 64 lowercase hex characters. Because that charset excludes `/`, `\`,
//! `.` and every other separator, joining a `Digest` onto the store root can
//! never escape it. No canonicalization or component-walking is required
//! anywhere in this crate.
//!
//! The digest is always sha256 over the blob's full *logical* byte stream —
//! including runs of zeros that the store chose not to allocate. See
//! [`crate::sys::sparse`] for why that distinction has teeth.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Hex characters in a sha256 digest.
pub const DIGEST_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest must be exactly {DIGEST_HEX_LEN} characters, got {0}")]
    BadLength(usize),
    #[error("digest must be lowercase hex")]
    BadChar,
}

/// A sha256 content address, guaranteed to be 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    pub fn parse(s: &str) -> Result<Digest, DigestError> {
        if s.len() != DIGEST_HEX_LEN {
            return Err(DigestError::BadLength(s.len()));
        }
        // Lowercase only. Accepting uppercase would make two spellings of one
        // address, and therefore two directory entries for one blob.
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DigestError::BadChar);
        }
        Ok(Digest(s.to_string()))
    }

    /// Build from a raw sha256 output. Infallible by construction.
    pub fn from_bytes(bytes: &[u8; 32]) -> Digest {
        Digest(hex::encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The shard directory this digest lives in — the first two hex chars.
    ///
    /// 256 shards, one level. ext4 directories are htree-indexed so lookup was
    /// never the bottleneck; what this bounds is the directory inode's size and
    /// the cost of the whole-store `readdir` that GC performs.
    pub fn shard(&self) -> &str {
        &self.0[..2]
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// Deserialize goes through `parse`, so a digest arriving in a manifest gets
/// the same rule as one arriving on the command line.
impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn accepts_lowercase_hex() {
        let d = Digest::parse(OK).unwrap();
        assert_eq!(d.as_str(), OK);
        assert_eq!(d.shard(), "e3");
    }

    #[test]
    fn rejects_traversal_and_tricks() {
        let long = "a".repeat(65);
        let short = "a".repeat(63);
        let upper = OK.to_uppercase();
        let bad: [&str; 11] = [
            "",
            "..",
            ".",
            "../../etc/passwd",
            "/etc/passwd",
            "a/b",
            "a\\b",
            &long,
            &short,
            &upper,
            // Right length, wrong alphabet ('g' is not hex).
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ];
        for b in bad {
            assert!(Digest::parse(b).is_err(), "should reject {b:?}");
        }
    }

    #[test]
    fn rejects_embedded_nul() {
        // 63 hex chars plus a NUL is still 64 bytes; the charset check is what
        // catches it, not the length check.
        let mut s = "a".repeat(63);
        s.push('\0');
        assert_eq!(s.len(), DIGEST_HEX_LEN);
        assert!(Digest::parse(&s).is_err());
    }

    #[test]
    fn from_bytes_matches_parse() {
        let empty_sha256 = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            Digest::from_bytes(&empty_sha256),
            Digest::parse(OK).unwrap()
        );
    }

    #[test]
    fn round_trips_through_json() {
        let d = Digest::parse(OK).unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{OK}\""));
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
    }

    #[test]
    fn deserialize_rejects_bad_digest() {
        assert!(serde_json::from_str::<Digest>("\"nope\"").is_err());
    }
}
