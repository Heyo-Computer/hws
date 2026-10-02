//! End-to-end: the path a heyvm image actually takes through the store.
//!
//! sparsify → import → materialize → gc, on a synthetic image shaped like the
//! real ones: fully allocated on disk, mostly zero inside.

use artifacts::config::Config;
use artifacts::gc::{GcPolicy, GcReport};
use artifacts::heyvm::{self, RootfsOptions};
use artifacts::store::{Materialize, Method, Store};
use artifacts::sys::space;
use artifacts::sys::sparse;
use artifacts::tags::Ref;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn tmpdir() -> tempfile::TempDir {
    match std::env::var_os("ART_TEST_DIR").map(PathBuf::from) {
        Some(b) => tempfile::tempdir_in(b).unwrap(),
        None => tempfile::tempdir().unwrap(),
    }
}

fn store_in(d: &Path) -> Store {
    Store::open(&Config {
        root: d.join("store"),
        min_free_bytes: 0,
        gc_min_age: Duration::ZERO,
        heyvm_images_dir: d.join("images"),
    })
    .unwrap()
}

/// A stand-in for `debian-hermes.ext4`: 32 MiB nominal, ~256 KiB live, written
/// densely so the filesystem allocates every block — exactly what the real
/// images look like (`stx_blocks * 512 == stx_size` for all of them).
fn fake_image(dir: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    let mut data = vec![0u8; 32 * 1024 * 1024];
    for (i, b) in data.iter_mut().take(256 * 1024).enumerate() {
        *b = (i % 251) as u8;
    }
    // A second live region past the middle, so a hole-aware copy has to handle
    // more than one extent.
    for (i, b) in data
        .iter_mut()
        .skip(20 * 1024 * 1024)
        .take(64 * 1024)
        .enumerate()
    {
        *b = (i % 199) as u8;
    }
    let images = dir.join("images");
    std::fs::create_dir_all(&images).unwrap();
    let p = images.join(name);
    std::fs::write(&p, &data).unwrap();
    (p, data)
}

fn no_sparse(dir: &Path) -> bool {
    if sparse::supports_punch_hole(dir) {
        return false;
    }
    eprintln!(
        "skipping: {} is on a filesystem without hole punching",
        dir.display()
    );
    true
}

#[tokio::test]
async fn image_survives_sparsify_import_materialize_and_gc() {
    let d = tmpdir();
    if no_sparse(d.path()) {
        return;
    }
    let s = store_in(d.path());
    let (image, data) = fake_image(d.path(), "debian-hermes.ext4");

    // -- 1. sparsify in place, on disk, before anything else -----------------
    let dense = space::stat_path(&image).unwrap();
    // `>=`, not `==`: `st_blocks` counts the extent-tree blocks as well as the
    // data, so a dense file measures slightly *larger* than its logical size
    // once the tree spills out of the inode. The real images show the same
    // thing — debian-hermes.ext4 is 21,474,836,480 bytes of data against
    // 21,475,020,800 allocated. What matters here is only that the fixture
    // starts with no holes, like they do.
    assert!(
        dense.allocated >= dense.size,
        "the fixture must start fully allocated, like the real images: {} allocated of {}",
        dense.allocated,
        dense.size
    );

    let report = heyvm::sparsify(&image, false, true).await.unwrap();
    assert_eq!(report.size, dense.size, "logical size must not change");
    assert!(report.freed() > 0);
    assert!(
        report.allocated_after < dense.allocated / 4,
        "expected a large reclaim: {} -> {}",
        dense.allocated,
        report.allocated_after
    );
    // The proof that matters.
    assert_eq!(std::fs::read(&image).unwrap(), data);

    // -- 2. import ----------------------------------------------------------
    let imported = heyvm::import(&s, &image, None).await.unwrap();
    assert_eq!(imported.name.as_str(), "debian-hermes");
    assert_eq!(imported.blob.size, data.len() as u64);
    assert_eq!(imported.blob.digest, report.digest);
    assert!(
        imported.blob.allocated < imported.blob.size / 4,
        "the stored blob should be sparse: {} of {}",
        imported.blob.allocated,
        imported.blob.size
    );
    s.verify(&imported.blob.digest).await.unwrap();

    // -- 3. materialize a writable rootfs -----------------------------------
    let rootfs = d.path().join("run/sb-1/rootfs.ext4");
    let m = heyvm::materialize_rootfs(
        &s,
        &Ref::parse("debian-hermes").unwrap(),
        &rootfs,
        RootfsOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(m.method, Method::SparseCopy);
    assert!(
        m.bytes_written < imported.blob.size / 4,
        "a boot should move live data, not the nominal size: {} of {}",
        m.bytes_written,
        imported.blob.size
    );
    assert_eq!(
        std::fs::read(&rootfs).unwrap(),
        data,
        "content must be exact"
    );
    assert_eq!(
        std::fs::metadata(&rootfs).unwrap().len(),
        imported.blob.size,
        "the guest still sees a full-size disk"
    );

    // Writable, and private: a guest scribbling on it must not reach the blob.
    std::fs::write(&rootfs, b"guest wrote here").unwrap();
    s.verify(&imported.blob.digest).await.unwrap();

    // -- 4. gc keeps it, because a tag points at its manifest ----------------
    let r = collect(&s).await;
    assert!(
        r.removed.is_empty(),
        "a tagged image must survive: {:?}",
        r.removed
    );
    assert!(s.has(&imported.blob.digest).await.unwrap());

    // Untagged, it goes.
    s.remove_tag(&imported.name).await.unwrap();
    let r = collect(&s).await;
    assert!(r.removed.contains(&imported.blob.digest));
    assert!(!s.has(&imported.blob.digest).await.unwrap());
}

#[tokio::test]
async fn a_read_only_materialization_pins_a_blob_through_gc() {
    let d = tmpdir();
    let s = store_in(d.path());
    let (image, _) = fake_image(d.path(), "alpine.ext4");
    let imported = heyvm::import(&s, &image, None).await.unwrap();
    s.remove_tag(&imported.name).await.unwrap();

    // Nothing references it by name, but something on disk does.
    let pinned = d.path().join("in-use.ext4");
    let m = s
        .materialize(&imported.blob.digest, &pinned, Materialize::ReadOnly)
        .await
        .unwrap();
    assert_eq!(m.method, Method::Hardlink);
    assert_eq!(m.bytes_written, 0);

    let r = collect(&s).await;
    assert!(r.removed.is_empty(), "removed a blob that is still in use");
    assert_eq!(r.pinned.len(), 1);
    assert_eq!(r.pinned[0].links, 1);
    assert!(s.has(&imported.blob.digest).await.unwrap());

    // Release, and it becomes collectable.
    s.release(&m).await.unwrap();
    let r = collect(&s).await;
    assert_eq!(r.removed, vec![imported.blob.digest.clone()]);
}

#[tokio::test]
async fn two_images_with_identical_content_are_stored_once() {
    let d = tmpdir();
    let s = store_in(d.path());
    let (a, _) = fake_image(d.path(), "nginx.ext4");
    let b = d.path().join("images/nginx-fc.ext4");
    std::fs::copy(&a, &b).unwrap();

    let ia = heyvm::import(&s, &a, None).await.unwrap();
    let ib = heyvm::import(&s, &b, None).await.unwrap();

    assert_eq!(ia.blob.digest, ib.blob.digest);
    assert!(ib.blob.deduped);
    assert_eq!(s.list_blobs().await.unwrap().len(), 1);
    // Two tags, one blob, one link — a duplicate insert must not inflate the
    // count GC reads as a reference.
    assert_eq!(s.list_tags().await.unwrap().len(), 2);
    assert_eq!(s.stat(&ia.blob.digest).await.unwrap().nlink, 1);
}

#[tokio::test]
async fn importing_every_image_in_a_directory_works() {
    let d = tmpdir();
    let s = store_in(d.path());
    for n in ["debian.ext4", "ubuntu.ext4", "alpine.ext4"] {
        fake_image(d.path(), n);
    }
    // A non-image in the same directory must be ignored.
    std::fs::write(d.path().join("images/vmlinux.bin"), b"kernel").unwrap();

    let found = heyvm::list_images(&d.path().join("images")).unwrap();
    assert_eq!(found.len(), 3);
    for p in &found {
        heyvm::import(&s, p, None).await.unwrap();
    }
    let tags = s.list_tags().await.unwrap();
    let names: Vec<_> = tags.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(names, vec!["alpine", "debian", "ubuntu"]);
    // All three fixtures have identical content, so one blob backs them all.
    assert_eq!(s.list_blobs().await.unwrap().len(), 1);
}

async fn collect(s: &Store) -> GcReport {
    artifacts::gc::collect(
        s,
        GcPolicy {
            min_age: Duration::ZERO,
            dry_run: false,
        },
    )
    .await
    .unwrap()
}
