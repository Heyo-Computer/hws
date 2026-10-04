//! heyvm's on-disk conventions are translated here and nowhere else;
//! [`crate::store`] never learns what an ext4 rootfs is.
//!
//! Three operations, in the order they are useful:
//!
//! 1. [`sparsify`] — punch the zero runs out of the images already sitting in
//!    `~/.heyo/images/firecracker`. On the host this was built for that is
//!    ~21 GiB across the image set, and it must run *before* an import: the
//!    images total 30 G and the filesystem has 13 G free.
//! 2. [`import`] — take an image into the store, hashed over its full logical
//!    content but stored sparsely.
//! 3. [`materialize_rootfs`] — the replacement for the per-boot full copy at
//!    heyo/mvm-ctrl/src/driver/firecracker.rs:2596-2638. Firecracker opens a
//!    rootfs read-write, so this is always a private copy — but of a blob that
//!    is already sparse, so it moves live data only.
//!
//! Deliberately absent: writing into an ext4 image with `debugfs -w`. That is
//! boot policy, it happens after materialization on the writable copy, and
//! shipping the primitive here would invite calling it on a hardlinked blob —
//! rewriting content whose name is a promise about what it contains. It stays
//! at heyo/mvm-ctrl/src/driver/ssh_bootstrap.rs:191-270.

use crate::config::BLOCK_SIZE;
use crate::digest::Digest;
use crate::error::{Error, IoContext, Result};
use crate::manifest::{BlobRef, KIND_BUNDLE, KIND_ROOTFS, Manifest};
use crate::store::{BlobInfo, Materialize, Materialized, Store};
use crate::sys::space;
use crate::sys::sparse::{self, Shape};
use crate::tags::{Ref, TagName};
use sha2::{Digest as _, Sha256};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Canonical filename of a rootfs inside a manifest or bundle. Matches
/// `ROOTFS_FILENAME` at heyo/mvm-ctrl/src/driver/sync.rs:24.
pub const ROOTFS_FILENAME: &str = "rootfs.ext4";
/// Manifest filename inside a heyvm sync bundle
/// (`MANIFEST_FILENAME`, sync.rs:22).
pub const BUNDLE_MANIFEST: &str = "manifest.json";

/// Annotation keys. Everything heyvm-specific rides here so the manifest type
/// itself stays generic.
pub const ANN_PRIMITIVE: &str = "heyvm.primitive";
pub const ANN_IMAGE: &str = "heyvm.image";
/// The image's full logical size. heyvm can compare this against its target
/// disk size and skip the `e2fsck -fp` + `resize2fs` pair at
/// heyo/mvm-ctrl/src/driver/kvm.rs:1367-1444 when no growth is needed.
pub const ANN_NOMINAL_SIZE: &str = "heyvm.nominal_size";

/// `RootfsPrimitive::Ext4Raw` from heyo/mvm-ctrl/src/driver/sync.rs:43.
pub const PRIMITIVE_EXT4_RAW: &str = "ext4_raw";

// ---------------------------------------------------------------------------
// Sparsify
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsifyReport {
    pub path: PathBuf,
    pub size: u64,
    pub allocated_before: u64,
    pub allocated_after: u64,
    /// sha256 of the content, which the operation must not change.
    pub digest: Digest,
    pub dry_run: bool,
}

impl SparsifyReport {
    pub fn freed(&self) -> u64 {
        self.allocated_before.saturating_sub(self.allocated_after)
    }
}

/// Punch the aligned zero runs out of `path`, in place.
///
/// Every byte is read, so hashing the content costs nothing extra and gives a
/// free proof that the operation preserved it. With `verify` the file is read a
/// second time afterwards and the digests compared — the difference between
/// believing the code and knowing.
pub async fn sparsify(path: &Path, dry_run: bool, verify: bool) -> Result<SparsifyReport> {
    let path = path.to_path_buf();
    crate::store::run_blocking(move || sparsify_sync(&path, dry_run, verify)).await
}

fn sparsify_sync(path: &Path, dry_run: bool, verify: bool) -> Result<SparsifyReport> {
    // Punching is an operation on the inode, so it is visible through every
    // name and every open descriptor — including a booted VM's disk.
    sparse::ensure_unshared(path)?;

    let before = space::stat_path(path)?;
    let mut hasher = Sha256::new();

    if dry_run {
        let (digest, would_free) = scan_zero_runs(path, &mut hasher)?;
        return Ok(SparsifyReport {
            path: path.to_path_buf(),
            size: before.size,
            allocated_before: before.allocated,
            allocated_after: before.allocated.saturating_sub(would_free),
            digest,
            dry_run: true,
        });
    }

    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .ctx(format!("open {} for writing", path.display()))?;
    sparse::advise_sequential(f.as_raw_fd(), before.size);

    sparse::punch_zero_runs(f.as_raw_fd(), before.size, BLOCK_SIZE, |b| hasher.update(b))
        .ctx(format!("sparsify {}", path.display()))?;
    sparse::fdatasync(f.as_raw_fd()).ctx("fdatasync sparsified image")?;
    sparse::advise_dontneed(f.as_raw_fd(), before.size);
    drop(f);

    let digest = finish(hasher);
    if verify {
        let mut check = Sha256::new();
        let (after_digest, _) = scan_zero_runs(path, &mut check)?;
        if after_digest != digest {
            return Err(Error::DigestMismatch {
                expected: digest,
                actual: after_digest,
            });
        }
    }

    let after = space::stat_path(path)?;
    Ok(SparsifyReport {
        path: path.to_path_buf(),
        size: before.size,
        allocated_before: before.allocated,
        allocated_after: after.allocated,
        digest,
        dry_run: false,
    })
}

/// Read `path`, hashing it and counting the bytes a punch would free.
fn scan_zero_runs(path: &Path, hasher: &mut Sha256) -> Result<(Digest, u64)> {
    let f = sparse::open_for_read(path)?;
    let st = space::stat_path(path)?;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut off = 0u64;
    let mut zero_grains = 0u64;

    while off < st.size {
        let want = ((st.size - off) as usize).min(buf.len());
        let n = sparse::pread(f.as_raw_fd(), &mut buf[..want], off).ctx("read image")?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        let mut i = 0usize;
        while i < chunk.len() {
            let end = (i + BLOCK_SIZE).min(chunk.len());
            if end - i == BLOCK_SIZE && sparse::is_zero(&chunk[i..end]) {
                zero_grains += 1;
            }
            i = end;
        }
        off += n as u64;
    }
    sparse::advise_dontneed(f.as_raw_fd(), st.size);

    let out = hasher.clone().finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    // Only already-allocated zero blocks can be freed; a block that is already
    // a hole costs nothing to punch again.
    let freeable = (zero_grains * BLOCK_SIZE as u64).min(st.allocated);
    Ok((Digest::from_bytes(&bytes), freeable))
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub name: TagName,
    pub blob: BlobInfo,
    pub manifest: Digest,
}

/// Every `*.ext4` in heyvm's Firecracker image directory, sorted by name.
pub fn list_images(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).ctx(format!("read {}", dir.display())),
    };
    for entry in rd {
        let entry = entry.ctx("read image dir entry")?;
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ext4")
            && entry.file_type().map(|t| t.is_file()).unwrap_or(false)
        {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// The tag an image file gets: its filename without `.ext4`.
pub fn image_tag(path: &Path) -> Result<TagName> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::Io {
            context: format!("image path has no usable name: {}", path.display()),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad image filename"),
        })?;
    Ok(TagName::parse(stem)?)
}

/// Import one image: hashed over its full logical bytes, stored sparsely,
/// described by a manifest, and tagged by name.
///
/// This supersedes the name-keyed cache whose entire deduplication logic is
/// `if dest_path.exists()` at heyo/mvm-ctrl/src/linux_vm_image.rs:78.
pub async fn import(store: &Store, path: &Path, name: Option<TagName>) -> Result<Imported> {
    let name = match name {
        Some(n) => n,
        None => image_tag(path)?,
    };

    // ZeroSquash, not HoleAware: heyvm's images are fully allocated on disk, so
    // a hole-based import would store every zero byte it was meant to elide.
    let blob = store.insert_path(path, Shape::SQUASH).await?;

    let manifest = Manifest::new(KIND_ROOTFS)
        .with_entry(ROOTFS_FILENAME, blob.digest.clone(), blob.size)
        .annotate(ANN_PRIMITIVE, PRIMITIVE_EXT4_RAW)
        .annotate(ANN_IMAGE, name.as_str())
        .annotate(ANN_NOMINAL_SIZE, blob.size.to_string());
    let manifest_digest = store.put_manifest(&manifest).await?;
    store.set_tag(&name, &manifest_digest).await?;

    Ok(Imported {
        name,
        blob,
        manifest: manifest_digest,
    })
}

// ---------------------------------------------------------------------------
// Materialize
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootfsOptions {
    /// Extend the image to this many gigabytes after copying. heyvm still owns
    /// the `e2fsck -fp` + `resize2fs` that makes the *filesystem* use the extra
    /// room; this only sets the file length.
    pub grow_gb: Option<u64>,
    pub mode: u32,
}

impl Default for RootfsOptions {
    fn default() -> Self {
        RootfsOptions {
            grow_gb: None,
            mode: 0o644,
        }
    }
}

/// Resolve a reference to the rootfs blob behind it.
///
/// Accepts a blob digest, a manifest digest, or a tag naming either, so callers
/// can say `debian-hermes` and get the rootfs rather than the manifest. Adds one
/// rule to [`Store::resolve_blob`]: a manifest with several entries — a sync
/// bundle, say — still resolves if exactly one of them is the rootfs.
pub async fn resolve_rootfs(store: &Store, r: &Ref) -> Result<Digest> {
    match store.resolve_blob(r).await {
        Ok(d) => Ok(d),
        Err(Error::AmbiguousManifest { digest, entries }) => {
            let m = store.get_manifest(&digest).await?;
            m.entries
                .iter()
                .find(|e| e.name == ROOTFS_FILENAME)
                .map(|e| e.digest.clone())
                .ok_or(Error::AmbiguousManifest { digest, entries })
        }
        Err(e) => Err(e),
    }
}

/// Produce a writable rootfs at `dest`.
///
/// Replaces the copy at heyo/mvm-ctrl/src/driver/firecracker.rs:2596-2638.
/// Always a private copy — never a hardlink — because Firecracker opens the
/// rootfs read-write. `HoleAware` is the right shape here precisely because
/// [`import`] already squashed the zeros: the blob's holes are exactly the
/// regions worth skipping, and finding them costs two `lseek`s per extent
/// rather than a full read.
pub async fn materialize_rootfs(
    store: &Store,
    r: &Ref,
    dest: &Path,
    opts: RootfsOptions,
) -> Result<Materialized> {
    let digest = resolve_rootfs(store, r).await?;
    let m = store
        .materialize(
            &digest,
            dest,
            Materialize::Writable {
                shape: Shape::HoleAware,
                mode: opts.mode,
            },
        )
        .await?;

    if let Some(gb) = opts.grow_gb {
        let target = gb * 1024 * 1024 * 1024;
        let current = space::stat_path(dest)?.size;
        if target > current {
            let dest = dest.to_path_buf();
            crate::store::run_blocking(move || {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&dest)
                    .ctx(format!("open {} to grow", dest.display()))?;
                // Extend sparsely: the guest filesystem does not use the new
                // space until resize2fs tells it to, so allocating now would
                // consume disk for nothing.
                sparse::ftruncate(f.as_raw_fd(), target).ctx("grow rootfs")?;
                Ok(())
            })
            .await?;
        }
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// Sync bundles
// ---------------------------------------------------------------------------

/// Import a heyvm sync-bundle directory.
///
/// Rather than reimplementing mvm-ctrl's `SyncManifest` struct — which would go
/// stale the moment it gains a field — this walks the bundle's `manifest.json`
/// for anything shaped like a `BlobRef` (`filename` + `size_bytes` + `sha256`,
/// heyo/mvm-ctrl/src/driver/sync.rs:79-85) and verifies each one. Storing a
/// blob and checking its digest are the same pass here, which is strictly
/// stronger than the bundle's own `blob_ref_for()` + `verify_blob()` at
/// sync.rs:500 and :530 — and reads each file once instead of twice.
pub async fn bundle_import(store: &Store, dir: &Path) -> Result<(Digest, Vec<BlobInfo>)> {
    let manifest_path = dir.join(BUNDLE_MANIFEST);
    let raw = std::fs::read(&manifest_path).ctx(format!("read {}", manifest_path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| Error::Io {
        context: format!("parse {}", manifest_path.display()),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;

    let refs = collect_blob_refs(&json);
    if refs.is_empty() {
        return Err(Error::Io {
            context: format!("no blob references found in {}", manifest_path.display()),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "empty bundle"),
        });
    }

    let mut manifest = Manifest::new(KIND_BUNDLE).annotate(ANN_PRIMITIVE, PRIMITIVE_EXT4_RAW);
    let mut infos = Vec::new();

    for r in &refs {
        let expected = r.digest()?;
        let path = dir.join(&r.filename);
        // Bundle filenames come from another machine, so a path with a
        // separator or a parent component must not be able to reach outside the
        // bundle directory.
        if r.filename.contains('/') || r.filename.contains('\\') || r.filename.starts_with('.') {
            return Err(Error::Io {
                context: format!("unsafe bundle entry name: {:?}", r.filename),
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad entry name"),
            });
        }
        let info = store.insert_path(&path, Shape::SQUASH).await?;
        if info.digest != expected {
            return Err(Error::DigestMismatch {
                expected,
                actual: info.digest,
            });
        }
        manifest = manifest.with_entry(r.filename.clone(), info.digest.clone(), info.size);
        infos.push(info);
    }

    // Keep the original manifest verbatim: it carries the backend's own view of
    // the VM, which this crate deliberately does not interpret.
    let raw_info = store.insert_bytes(raw).await?;
    manifest = manifest.with_entry(BUNDLE_MANIFEST, raw_info.digest.clone(), raw_info.size);
    infos.push(raw_info);

    let digest = store.put_manifest(&manifest).await?;
    Ok((digest, infos))
}

/// Write a stored bundle back out as a directory.
///
/// Entries are hardlinked when `dir` is on the store's filesystem, so an export
/// costs no space and shares storage with the store until it is shipped.
pub async fn bundle_export(store: &Store, r: &Ref, dir: &Path) -> Result<Vec<Materialized>> {
    let d = store.resolve(r).await?;
    let manifest = store.get_manifest(&d).await?;
    std::fs::create_dir_all(dir).ctx(format!("create {}", dir.display()))?;

    let mut out = Vec::new();
    for e in &manifest.entries {
        let dest = dir.join(&e.name);
        out.push(
            store
                .materialize(&e.digest, &dest, Materialize::ReadOnly)
                .await?,
        );
    }
    Ok(out)
}

/// Walk a JSON tree for objects shaped like a `BlobRef`.
fn collect_blob_refs(v: &serde_json::Value) -> Vec<BlobRef> {
    let mut out = Vec::new();
    walk(v, &mut out);
    // A blob may be named more than once (a snapshot's drive list repeats the
    // rootfs); import each file once.
    out.sort_by(|a, b| a.filename.cmp(&b.filename));
    out.dedup_by(|a, b| a.filename == b.filename);
    out
}

fn walk(v: &serde_json::Value, out: &mut Vec<BlobRef>) {
    match v {
        serde_json::Value::Object(map) => {
            if let (Some(f), Some(s), Some(h)) = (
                map.get("filename").and_then(|x| x.as_str()),
                map.get("size_bytes").and_then(|x| x.as_u64()),
                map.get("sha256").and_then(|x| x.as_str()),
            ) {
                out.push(BlobRef {
                    filename: f.to_string(),
                    size_bytes: s,
                    sha256: h.to_string(),
                });
            }
            for child in map.values() {
                walk(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                walk(child, out);
            }
        }
        _ => {}
    }
}

fn finish(h: Sha256) -> Digest {
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    Digest::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::time::Duration;

    fn tmpdir() -> tempfile::TempDir {
        match std::env::var_os("ART_TEST_DIR").map(PathBuf::from) {
            Some(b) => tempfile::tempdir_in(b).unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }

    fn store_in(d: &tempfile::TempDir) -> Store {
        Store::open(&Config {
            root: d.path().join("store"),
            min_free_bytes: 0,
            gc_min_age: Duration::ZERO,
            heyvm_images_dir: d.path().join("images"),
        })
        .unwrap()
    }

    /// A stand-in for a heyvm base image: mostly-zero, fully allocated.
    fn fake_image(dir: &Path, name: &str, mb: usize, live_kb: usize) -> (PathBuf, Vec<u8>) {
        let mut data = vec![0u8; mb * 1024 * 1024];
        for (i, b) in data.iter_mut().take(live_kb * 1024).enumerate() {
            *b = (i % 251) as u8;
        }
        let p = dir.join(name);
        std::fs::write(&p, &data).unwrap();
        (p, data)
    }

    fn sha(data: &[u8]) -> Digest {
        let mut h = Sha256::new();
        h.update(data);
        finish(h)
    }

    #[tokio::test]
    async fn sparsify_frees_space_without_changing_content() {
        let d = tmpdir();
        if !sparse::supports_punch_hole(d.path()) {
            eprintln!("skipping sparsify test: no hole punching here");
            return;
        }
        let (p, data) = fake_image(d.path(), "img.ext4", 8, 64);
        let before = space::stat_path(&p).unwrap();

        let r = sparsify(&p, false, true).await.unwrap();
        assert_eq!(r.digest, sha(&data), "sparsify must preserve content");
        assert_eq!(r.size, before.size, "logical size must not change");
        assert!(r.freed() > 0, "expected to free something");
        assert!(
            r.allocated_after < before.allocated / 2,
            "{} -> {}",
            before.allocated,
            r.allocated_after
        );
        // The proof that matters: the bytes on disk are identical.
        assert_eq!(std::fs::read(&p).unwrap(), data);
    }

    #[tokio::test]
    async fn sparsify_dry_run_changes_nothing() {
        let d = tmpdir();
        let (p, data) = fake_image(d.path(), "img.ext4", 4, 32);
        let before = space::stat_path(&p).unwrap();

        let r = sparsify(&p, true, false).await.unwrap();
        assert!(r.dry_run);
        assert_eq!(r.digest, sha(&data));
        assert!(r.freed() > 0, "should predict a saving");
        assert_eq!(
            space::stat_path(&p).unwrap().allocated,
            before.allocated,
            "dry run must not touch the file"
        );
    }

    #[tokio::test]
    async fn sparsify_refuses_a_hardlinked_image() {
        // Punching is per-inode, so doing it to a shared image would rewrite a
        // running VM's disk.
        let d = tmpdir();
        let (p, _) = fake_image(d.path(), "img.ext4", 1, 8);
        std::fs::hard_link(&p, d.path().join("in-use.ext4")).unwrap();
        let e = sparsify(&p, false, false).await.unwrap_err();
        assert!(matches!(e, Error::SharedInode { .. }), "{e:?}");
    }

    #[tokio::test]
    async fn import_tags_by_name_and_addresses_by_content() {
        let d = tmpdir();
        let s = store_in(&d);
        let (p, data) = fake_image(d.path(), "debian-hermes.ext4", 4, 32);

        let imported = import(&s, &p, None).await.unwrap();
        assert_eq!(imported.name.as_str(), "debian-hermes");
        // The digest must equal a plain sha256sum of the file, or the store
        // stops interoperating with BlobRef.sha256.
        assert_eq!(imported.blob.digest, sha(&data));

        let m = s.get_manifest(&imported.manifest).await.unwrap();
        assert_eq!(m.kind, KIND_ROOTFS);
        assert_eq!(m.get(ANN_PRIMITIVE), Some(PRIMITIVE_EXT4_RAW));
        assert_eq!(m.get(ANN_IMAGE), Some("debian-hermes"));
        assert_eq!(
            m.get(ANN_NOMINAL_SIZE),
            Some(data.len().to_string().as_str())
        );
        assert_eq!(s.get_tag(&imported.name).await.unwrap(), imported.manifest);
    }

    #[tokio::test]
    async fn importing_the_same_image_twice_is_idempotent() {
        let d = tmpdir();
        let s = store_in(&d);
        let (p, _) = fake_image(d.path(), "img.ext4", 2, 16);

        let a = import(&s, &p, None).await.unwrap();
        let b = import(&s, &p, None).await.unwrap();
        assert_eq!(a.blob.digest, b.blob.digest);
        assert_eq!(a.manifest, b.manifest, "manifests must be stable");
        assert!(b.blob.deduped);
        assert_eq!(s.list_blobs().await.unwrap().len(), 1);
        assert_eq!(s.list_manifests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn import_stores_a_mostly_zero_image_sparsely() {
        let d = tmpdir();
        let s = store_in(&d);
        if !sparse::supports_punch_hole(d.path()) {
            eprintln!("skipping sparse import test: no sparse files here");
            return;
        }
        let (p, data) = fake_image(d.path(), "img.ext4", 16, 64);
        let imported = import(&s, &p, None).await.unwrap();

        assert_eq!(imported.blob.size, data.len() as u64);
        assert!(
            imported.blob.allocated < imported.blob.size / 4,
            "stored {} of {}",
            imported.blob.allocated,
            imported.blob.size
        );
        s.verify(&imported.blob.digest).await.unwrap();
    }

    #[tokio::test]
    async fn materialize_rootfs_round_trips_by_tag() {
        let d = tmpdir();
        let s = store_in(&d);
        let (p, data) = fake_image(d.path(), "debian.ext4", 8, 32);
        let imported = import(&s, &p, None).await.unwrap();

        let dest = d.path().join("run/vm/rootfs.ext4");
        let m = materialize_rootfs(
            &s,
            &Ref::parse("debian").unwrap(),
            &dest,
            RootfsOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(m.digest, imported.blob.digest);
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        // Writable, and a different inode from the blob.
        assert_ne!(
            space::stat_path(&dest).unwrap().ino,
            space::stat_path(&s.blob_path(&imported.blob.digest))
                .unwrap()
                .ino
        );
        std::fs::write(&dest, b"guest scribbled here").unwrap();
        s.verify(&imported.blob.digest).await.unwrap();
    }

    #[tokio::test]
    async fn materialize_rootfs_writes_only_live_data() {
        let d = tmpdir();
        let s = store_in(&d);
        if !sparse::supports_punch_hole(d.path()) {
            eprintln!("skipping sparse materialize test: no sparse files here");
            return;
        }
        let (p, _) = fake_image(d.path(), "big.ext4", 32, 64);
        let imported = import(&s, &p, None).await.unwrap();

        let dest = d.path().join("rootfs.ext4");
        let m = materialize_rootfs(
            &s,
            &Ref::Digest(imported.blob.digest.clone()),
            &dest,
            RootfsOptions::default(),
        )
        .await
        .unwrap();

        // The whole point: a boot moves live data, not the nominal size.
        assert!(
            m.bytes_written < imported.blob.size / 4,
            "wrote {} of {}",
            m.bytes_written,
            imported.blob.size
        );
        assert_eq!(
            std::fs::metadata(&dest).unwrap().len(),
            imported.blob.size,
            "the materialized image must still be its full logical size"
        );
    }

    #[tokio::test]
    async fn grow_extends_the_file_without_allocating() {
        let d = tmpdir();
        let s = store_in(&d);
        let (p, _) = fake_image(d.path(), "small.ext4", 2, 8);
        import(&s, &p, None).await.unwrap();

        let dest = d.path().join("grown.ext4");
        materialize_rootfs(
            &s,
            &Ref::parse("small").unwrap(),
            &dest,
            RootfsOptions {
                grow_gb: Some(1),
                mode: 0o644,
            },
        )
        .await
        .unwrap();

        let st = space::stat_path(&dest).unwrap();
        assert_eq!(st.size, 1024 * 1024 * 1024);
        // Sparse growth: the guest has not used the room yet, so neither should
        // the host.
        assert!(
            st.allocated < 16 * 1024 * 1024,
            "allocated {}",
            st.allocated
        );
    }

    #[tokio::test]
    async fn resolve_rootfs_accepts_tag_manifest_or_blob() {
        let d = tmpdir();
        let s = store_in(&d);
        let (p, _) = fake_image(d.path(), "alpine.ext4", 1, 8);
        let i = import(&s, &p, None).await.unwrap();

        for r in [
            Ref::parse("alpine").unwrap(),
            Ref::Digest(i.manifest.clone()),
            Ref::Digest(i.blob.digest.clone()),
        ] {
            assert_eq!(resolve_rootfs(&s, &r).await.unwrap(), i.blob.digest);
        }
    }

    #[tokio::test]
    async fn resolve_rootfs_picks_the_rootfs_out_of_a_bundle() {
        // A bundle manifest is ambiguous to the generic resolver, but a rootfs
        // is exactly what this layer knows how to pick.
        let d = tmpdir();
        let s = store_in(&d);
        let bundle = d.path().join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        let rootfs = vec![1u8; 4096];
        let data = vec![2u8; 4096];
        std::fs::write(bundle.join(ROOTFS_FILENAME), &rootfs).unwrap();
        std::fs::write(bundle.join("data.ext4"), &data).unwrap();
        std::fs::write(
            bundle.join(BUNDLE_MANIFEST),
            serde_json::to_vec(&serde_json::json!({
                "rootfs": {"filename": ROOTFS_FILENAME, "size_bytes": 4096, "sha256": sha(&rootfs).to_string()},
                "data_disk": {"filename":"data.ext4","size_bytes":4096,"sha256":sha(&data).to_string()},
            }))
            .unwrap(),
        )
        .unwrap();

        let (md, _) = bundle_import(&s, &bundle).await.unwrap();
        // The generic resolver cannot choose...
        assert!(matches!(
            s.resolve_blob(&Ref::Digest(md.clone())).await,
            Err(Error::AmbiguousManifest { .. })
        ));
        // ...but this one can.
        assert_eq!(
            resolve_rootfs(&s, &Ref::Digest(md)).await.unwrap(),
            sha(&rootfs)
        );
    }

    #[test]
    fn list_images_finds_only_ext4_files() {
        let d = tmpdir();
        std::fs::write(d.path().join("a.ext4"), b"x").unwrap();
        std::fs::write(d.path().join("b.ext4"), b"x").unwrap();
        std::fs::write(d.path().join("vmlinux.bin"), b"x").unwrap();
        std::fs::create_dir(d.path().join("nested.ext4")).unwrap();

        let found = list_images(d.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, vec!["a.ext4", "b.ext4"]);
    }

    #[test]
    fn list_images_of_a_missing_directory_is_empty() {
        let d = tmpdir();
        assert!(list_images(&d.path().join("nope")).unwrap().is_empty());
    }

    #[test]
    fn collect_blob_refs_finds_nested_and_dedups() {
        // Shaped like a heyvm sync manifest: a rootfs, a data disk, mounts, and
        // a memory snapshot that names the rootfs again.
        let json: serde_json::Value = serde_json::from_str(
            r#"{
                "bundle_version": 1,
                "rootfs": {"filename":"rootfs.ext4","size_bytes":10,"sha256":"aa"},
                "data_disk": {"filename":"data.ext4","size_bytes":20,"sha256":"bb"},
                "mounts": [{"filename":"mount0.ext4","size_bytes":30,"sha256":"cc"}],
                "memory": {
                    "state": {"filename":"snapshot-state","size_bytes":40,"sha256":"dd"},
                    "memory": {"filename":"snapshot-mem","size_bytes":50,"sha256":"ee"},
                    "vm_format": "firecracker_v2"
                },
                "again": {"filename":"rootfs.ext4","size_bytes":10,"sha256":"aa"}
            }"#,
        )
        .unwrap();

        let refs = collect_blob_refs(&json);
        let names: Vec<_> = refs.iter().map(|r| r.filename.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "data.ext4",
                "mount0.ext4",
                "rootfs.ext4",
                "snapshot-mem",
                "snapshot-state"
            ],
            "should find every BlobRef exactly once, however nested"
        );
    }

    #[tokio::test]
    async fn bundle_round_trips() {
        let d = tmpdir();
        let s = store_in(&d);
        let bundle = d.path().join("bundle");
        std::fs::create_dir(&bundle).unwrap();

        let rootfs = vec![1u8; 4096];
        let data = vec![2u8; 8192];
        std::fs::write(bundle.join("rootfs.ext4"), &rootfs).unwrap();
        std::fs::write(bundle.join("data.ext4"), &data).unwrap();
        let manifest = serde_json::json!({
            "bundle_version": 1,
            "rootfs": {"filename":"rootfs.ext4","size_bytes":rootfs.len(),"sha256":sha(&rootfs).to_string()},
            "data_disk": {"filename":"data.ext4","size_bytes":data.len(),"sha256":sha(&data).to_string()},
        });
        std::fs::write(
            bundle.join(BUNDLE_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let (digest, infos) = bundle_import(&s, &bundle).await.unwrap();
        assert_eq!(infos.len(), 3, "two blobs plus the original manifest");

        let out = d.path().join("exported");
        let mats = bundle_export(&s, &Ref::Digest(digest), &out).await.unwrap();
        assert_eq!(mats.len(), 3);
        assert_eq!(std::fs::read(out.join("rootfs.ext4")).unwrap(), rootfs);
        assert_eq!(std::fs::read(out.join("data.ext4")).unwrap(), data);
        // Export on the same filesystem costs nothing.
        assert!(
            mats.iter()
                .all(|m| m.method == crate::store::Method::Hardlink)
        );
    }

    #[tokio::test]
    async fn bundle_import_rejects_a_wrong_digest() {
        let d = tmpdir();
        let s = store_in(&d);
        let bundle = d.path().join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join("rootfs.ext4"), b"actual content").unwrap();
        let manifest = serde_json::json!({
            "rootfs": {"filename":"rootfs.ext4","size_bytes":14,"sha256":sha(b"different content").to_string()},
        });
        std::fs::write(
            bundle.join(BUNDLE_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let e = bundle_import(&s, &bundle).await.unwrap_err();
        assert!(matches!(e, Error::DigestMismatch { .. }), "{e:?}");
    }

    #[tokio::test]
    async fn bundle_import_rejects_a_traversing_entry_name() {
        let d = tmpdir();
        let s = store_in(&d);
        let bundle = d.path().join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        let manifest = serde_json::json!({
            "rootfs": {"filename":"../../etc/passwd","size_bytes":1,"sha256":sha(b"x").to_string()},
        });
        std::fs::write(
            bundle.join(BUNDLE_MANIFEST),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        // A bundle arrives from another machine; its filenames are untrusted.
        assert!(bundle_import(&s, &bundle).await.is_err());
    }

    #[tokio::test]
    async fn bundle_import_rejects_a_manifest_with_no_blobs() {
        let d = tmpdir();
        let s = store_in(&d);
        let bundle = d.path().join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        std::fs::write(bundle.join(BUNDLE_MANIFEST), br#"{"bundle_version":1}"#).unwrap();
        assert!(bundle_import(&s, &bundle).await.is_err());
    }
}
