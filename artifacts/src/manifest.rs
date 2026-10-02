//! A manifest's digest is a pure function of its content.
//!
//! Annotations are a [`BTreeMap`] so serialization order does not depend on
//! insertion order, and there is deliberately **no timestamp field**. A
//! creation time would make the same logical manifest hash differently on every
//! write, so re-importing an unchanged image would accumulate a fresh manifest
//! each time instead of deduplicating to the one already stored. When a caller
//! genuinely wants a time recorded they put it in `annotations` and accept that
//! it changes the address; the blob's own birth time already answers "when did
//! this enter the store".
//!
//! [`BlobRef`] mirrors mvm-ctrl's type at heyo/mvm-ctrl/src/driver/sync.rs:79-85
//! field for field, so a sync bundle's `manifest.json` round-trips through this
//! crate unchanged. The types are redeclared rather than imported: `heyvm` is
//! edition 2021 with a large dependency tree, and the dependency would become
//! circular the moment mvm-ctrl adopts this store.

use crate::digest::Digest;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bumped on incompatible changes. Readers reject unknown majors, matching
/// `BUNDLE_VERSION` at heyo/mvm-ctrl/src/driver/sync.rs:33.
pub const SCHEMA_VERSION: u32 = 1;

/// Kind string for an imported heyvm rootfs image.
pub const KIND_ROOTFS: &str = "heyvm.rootfs.v1";
/// Kind string for an imported heyvm sync bundle.
pub const KIND_BUNDLE: &str = "heyvm.bundle.v1";
/// Kind string for a Dockerfile that *defines* a rootfs, rather than a rootfs.
///
/// The one manifest kind whose entries are a build input instead of a build
/// output: nothing here is bootable, and a consumer is expected to run a build
/// over it. See [`crate::dockerfile`].
pub const KIND_DOCKERFILE: &str = "heyvm.dockerfile.v1";
/// Kind string for a plain collection of files.
pub const KIND_GENERIC: &str = "generic";

/// One member of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Name this entry had outside the store — a bundle filename, a path inside
    /// an archive. Never used to build a path in the store itself.
    pub name: String,
    pub digest: Digest,
    pub size: u64,
}

/// An ordered set of blobs plus metadata, itself content-addressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub kind: String,
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

impl Manifest {
    pub fn new(kind: impl Into<String>) -> Manifest {
        Manifest {
            schema: SCHEMA_VERSION,
            kind: kind.into(),
            entries: Vec::new(),
            annotations: BTreeMap::new(),
        }
    }

    pub fn with_entry(mut self, name: impl Into<String>, digest: Digest, size: u64) -> Manifest {
        self.entries.push(Entry {
            name: name.into(),
            digest,
            size,
        });
        self
    }

    pub fn annotate(mut self, k: impl Into<String>, v: impl Into<String>) -> Manifest {
        self.annotations.insert(k.into(), v.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.annotations.get(key).map(String::as_str)
    }

    /// Total logical size of every entry.
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    /// The exact bytes this manifest is addressed by.
    ///
    /// `to_vec` on a struct with a `BTreeMap` is already canonical: struct
    /// fields serialize in declaration order and map keys in sorted order.
    pub fn to_canonical_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a Manifest is always serializable")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Manifest> {
        let m: Manifest = serde_json::from_slice(bytes).map_err(|e| Error::Io {
            context: "parse manifest".into(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        if m.schema > SCHEMA_VERSION {
            return Err(Error::ManifestVersion(m.schema));
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// heyvm sync-bundle wire types
// ---------------------------------------------------------------------------

/// Content reference for one file in a heyvm sync bundle.
///
/// Field names and types match heyo/mvm-ctrl/src/driver/sync.rs:79-85 exactly;
/// changing them here silently breaks bundle interoperability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub filename: String,
    pub size_bytes: u64,
    /// Lowercase hex sha256.
    pub sha256: String,
}

impl BlobRef {
    pub fn digest(&self) -> Result<Digest> {
        Ok(Digest::parse(&self.sha256)?)
    }
}

impl From<&Entry> for BlobRef {
    fn from(e: &Entry) -> BlobRef {
        BlobRef {
            filename: e.name.clone(),
            size_bytes: e.size,
            sha256: e.digest.to_string(),
        }
    }
}

impl TryFrom<&BlobRef> for Entry {
    type Error = Error;
    fn try_from(b: &BlobRef) -> Result<Entry> {
        Ok(Entry {
            name: b.filename.clone(),
            digest: b.digest()?,
            size: b.size_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::parse(&hex::encode([n; 32])).unwrap()
    }

    #[test]
    fn canonical_json_ignores_annotation_insertion_order() {
        let a = Manifest::new(KIND_GENERIC)
            .annotate("z", "1")
            .annotate("a", "2")
            .annotate("m", "3");
        let b = Manifest::new(KIND_GENERIC)
            .annotate("m", "3")
            .annotate("a", "2")
            .annotate("z", "1");
        // This is the entire reason annotations are a BTreeMap: otherwise the
        // same manifest would land at two different addresses.
        assert_eq!(a.to_canonical_json(), b.to_canonical_json());
    }

    #[test]
    fn canonical_json_is_stable_across_repeated_serialization() {
        let m = Manifest::new(KIND_ROOTFS)
            .with_entry("rootfs.ext4", d(1), 100)
            .annotate("heyvm.primitive", "ext4_raw");
        assert_eq!(m.to_canonical_json(), m.to_canonical_json());
    }

    #[test]
    fn entry_order_is_significant() {
        // Entries are a Vec, not a set: a bundle's drive order is meaningful,
        // so reordering must produce a different manifest.
        let a = Manifest::new(KIND_BUNDLE)
            .with_entry("rootfs.ext4", d(1), 1)
            .with_entry("data.ext4", d(2), 2);
        let b = Manifest::new(KIND_BUNDLE)
            .with_entry("data.ext4", d(2), 2)
            .with_entry("rootfs.ext4", d(1), 1);
        assert_ne!(a.to_canonical_json(), b.to_canonical_json());
    }

    #[test]
    fn round_trips_through_json() {
        let m = Manifest::new(KIND_ROOTFS)
            .with_entry("rootfs.ext4", d(7), 4096)
            .annotate("heyvm.nominal_size", "21474836480");
        let back = Manifest::from_json(&m.to_canonical_json()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.get("heyvm.nominal_size"), Some("21474836480"));
        assert_eq!(back.total_size(), 4096);
    }

    #[test]
    fn rejects_a_newer_schema() {
        let mut m = Manifest::new(KIND_GENERIC);
        m.schema = SCHEMA_VERSION + 1;
        let e = Manifest::from_json(&m.to_canonical_json()).unwrap_err();
        assert!(matches!(e, Error::ManifestVersion(_)), "{e:?}");
    }

    #[test]
    fn accepts_a_manifest_without_annotations() {
        // `annotations` is #[serde(default)], so an older writer's output loads.
        let json = br#"{"schema":1,"kind":"generic","entries":[]}"#;
        let m = Manifest::from_json(json).unwrap();
        assert!(m.annotations.is_empty());
    }

    #[test]
    fn rejects_a_manifest_with_an_invalid_digest() {
        let json =
            br#"{"schema":1,"kind":"generic","entries":[{"name":"x","digest":"nope","size":1}]}"#;
        assert!(Manifest::from_json(json).is_err());
    }

    #[test]
    fn blob_ref_round_trips_through_entry() {
        let e = Entry {
            name: "rootfs.ext4".into(),
            digest: d(3),
            size: 512,
        };
        let b = BlobRef::from(&e);
        assert_eq!(b.filename, "rootfs.ext4");
        assert_eq!(b.size_bytes, 512);
        assert_eq!(b.sha256, d(3).to_string());
        assert_eq!(Entry::try_from(&b).unwrap(), e);
    }

    #[test]
    fn blob_ref_deserializes_mvm_ctrl_field_names() {
        // Guards the wire contract with heyo/mvm-ctrl/src/driver/sync.rs:79-85.
        let json = br#"{"filename":"rootfs.ext4","size_bytes":42,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
        let b: BlobRef = serde_json::from_slice(json).unwrap();
        assert_eq!(b.filename, "rootfs.ext4");
        assert_eq!(b.size_bytes, 42);
        assert!(b.digest().is_ok());
    }

    #[test]
    fn blob_ref_with_a_bad_sha_is_rejected_at_use() {
        let b = BlobRef {
            filename: "x".into(),
            size_bytes: 0,
            sha256: "not-a-digest".into(),
        };
        assert!(b.digest().is_err());
    }
}
