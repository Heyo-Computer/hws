//! A Dockerfile that *defines* a rootfs, stored as a manifest instead of an
//! image.
//!
//! Every other manifest kind in this store describes a build **output** — bytes
//! that are already the thing you wanted. This one describes a build **input**:
//! the recipe plus the files it copies from, addressed by content so that
//! "which recipe produced this image" has an answer that a tag cannot quietly
//! change underneath.
//!
//! ```text
//! kind: heyvm.dockerfile.v1
//! entries:
//!   Dockerfile        <- required
//!   context.tar.gz    <- optional; the `docker build` context
//! annotations:
//!   heyvm.image       <- default name for the image this builds
//!   heyvm.size_mb     <- default `heyvm mvm build --size-mb`
//!   dockerfile.source <- where it came from, informational
//! ```
//!
//! ## Why the context is one blob and not many entries
//!
//! A manifest could list every file in the context separately and deduplicate
//! them individually, which is what a layered registry does. It is the wrong
//! trade here. A build context is consumed whole and exactly once — `heyvm mvm
//! build` hands the entire directory to the daemon — so per-file addressing buys
//! nothing at read time, and it costs a blob, an inode and a `link` syscall per
//! file at write time. A twelve-thousand-file `node_modules` would turn one
//! insert into twelve thousand.
//!
//! The cost of the choice is honest and worth stating: changing one byte of the
//! context re-uploads all of it, because the tarball's digest changed. That is
//! the same bargain [`crate::heyvm::import`] makes with a rootfs, and for the
//! same reason.
//!
//! ## What this module deliberately does not do
//!
//! **It does not build anything.** The store has no Docker, no heyvm and no
//! opinion about what a `RUN` line means; it holds the bytes and names them.
//! Building is app-lb's `image-build` job, which fetches this manifest, unpacks
//! it and drives `heyvm mvm build` — see the `build.store` half of app-lb's
//! `BuildSpec`.
//!
//! **It does not interpret the Dockerfile.** No `FROM` parsing, no `COPY`
//! validation. A Dockerfile whose `COPY` names a path outside the context is a
//! build failure at build time, where the error can name the line; a rejection
//! here would be a store second-guessing a tool it does not run.

use crate::digest::Digest;
use crate::error::{Error, IoContext, Result};
use crate::heyvm::ANN_IMAGE;
use crate::manifest::{Entry, KIND_DOCKERFILE, Manifest};
use crate::store::{BlobInfo, Materialize, Materialized, Store};
use crate::sys::sparse::Shape;
use crate::tags::{Ref, TagName};
use std::path::{Path, PathBuf};

/// Entry name of the recipe itself. Capitalised as Docker spells it, so a
/// manifest exported to a directory is one `docker build .` away from working.
pub const DOCKERFILE_ENTRY: &str = "Dockerfile";
/// Entry name of the build context. Always gzipped tar, always this name — the
/// entry name is the contract with app-lb's puller, which looks it up by name
/// rather than by position.
pub const CONTEXT_ENTRY: &str = "context.tar.gz";

/// Default `heyvm mvm build --size-mb` for the image this builds. A string,
/// like every annotation; the store does not know it is a number.
pub const ANN_SIZE_MB: &str = "heyvm.size_mb";
/// Where the Dockerfile came from — a path, a repo, a note. Informational, and
/// part of the address: changing it changes the manifest digest, which is the
/// point when the same recipe is pushed from two places for two reasons.
pub const ANN_SOURCE: &str = "dockerfile.source";

/// Ceiling on the Dockerfile itself. A recipe is kilobytes; something claiming
/// otherwise is a mistake — most often a whole build context passed where the
/// Dockerfile was meant — and catching it here beats storing it and failing at
/// build time on a different host.
const MAX_DOCKERFILE_BYTES: u64 = 1 << 20;

/// The optional halves of a Dockerfile manifest's annotations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Default name for the image this builds. A consumer may override it;
    /// recording it is what lets `art dockerfile show` say what this is *for*.
    pub image_name: Option<String>,
    /// Default rootfs size in megabytes.
    pub size_mb: Option<u64>,
    /// Provenance, free-form.
    pub source: Option<String>,
}

/// What [`put`] stored.
#[derive(Debug, Clone)]
pub struct Stored {
    pub manifest: Digest,
    pub dockerfile: BlobInfo,
    /// `None` when the manifest has no context — a self-contained recipe that
    /// copies nothing in.
    pub context: Option<BlobInfo>,
    pub tag: Option<TagName>,
}

/// What [`export`] wrote.
#[derive(Debug, Clone)]
pub struct Exported {
    pub manifest: Digest,
    pub dockerfile: Materialized,
    pub context: Option<Materialized>,
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Store a Dockerfile — and optionally an already-packed context archive — as a
/// [`KIND_DOCKERFILE`] manifest, and point `tag` at the manifest.
///
/// `context` is an *archive*, not a directory: packing is [`pack_context`], kept
/// separate so a caller that already has a tarball does not pay to unpack and
/// repack it, and so the temp file the packing needs is the caller's to place.
///
/// The tag lands on the manifest rather than on either blob, for the reason
/// every tag in this store does: the manifest is the thing that carries the
/// annotations, and a tag on the Dockerfile blob alone would resolve to a recipe
/// with no context and no image name.
pub async fn put(
    store: &Store,
    dockerfile: &Path,
    context: Option<&Path>,
    tag: Option<TagName>,
    opts: &Options,
) -> Result<Stored> {
    let st = crate::sys::space::stat_path(dockerfile)?;
    if st.size > MAX_DOCKERFILE_BYTES {
        return Err(Error::Io {
            context: format!(
                "{} is {} bytes; a Dockerfile is expected to be under {MAX_DOCKERFILE_BYTES}. \
                 Did you mean --context?",
                dockerfile.display(),
                st.size
            ),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "dockerfile too large"),
        });
    }

    // Dense, not SQUASH: a Dockerfile is text and a context is gzip, so there
    // are no aligned zero runs to find and the scan would be pure cost.
    let df = store.insert_path(dockerfile, Shape::Dense).await?;
    let ctx = match context {
        Some(p) => Some(store.insert_path(p, Shape::Dense).await?),
        None => None,
    };

    let manifest = manifest_for(&df, ctx.as_ref(), opts);
    let digest = store.put_manifest(&manifest).await?;
    if let Some(t) = &tag {
        store.set_tag(t, &digest).await?;
    }

    Ok(Stored {
        manifest: digest,
        dockerfile: df,
        context: ctx,
        tag,
    })
}

/// The manifest for a Dockerfile blob and an optional context blob.
///
/// Entry order is fixed — Dockerfile first — because [`Manifest`] addresses its
/// entries as a sequence, so emitting them in insertion order would give the
/// same logical recipe two addresses.
pub fn manifest_for(dockerfile: &BlobInfo, context: Option<&BlobInfo>, opts: &Options) -> Manifest {
    let mut m = Manifest::new(KIND_DOCKERFILE).with_entry(
        DOCKERFILE_ENTRY,
        dockerfile.digest.clone(),
        dockerfile.size,
    );
    if let Some(c) = context {
        m = m.with_entry(CONTEXT_ENTRY, c.digest.clone(), c.size);
    }
    if let Some(name) = &opts.image_name {
        m = m.annotate(ANN_IMAGE, name);
    }
    if let Some(mb) = opts.size_mb {
        m = m.annotate(ANN_SIZE_MB, mb.to_string());
    }
    if let Some(src) = &opts.source {
        m = m.annotate(ANN_SOURCE, src);
    }
    m
}

/// Pack `dir` into a gzipped tar at `dest`, and report its size.
///
/// **Blocking**, and potentially for a while: this reads the whole directory.
///
/// Every regular file under `dir` is included, with no `.dockerignore` handling
/// and no built-in exclusions. That is deliberate. A context that silently
/// dropped files would produce a build that fails on a host nobody is looking
/// at, with an error (`COPY failed`) pointing at the Dockerfile rather than at
/// the packer; and a store that quietly reinterprets what it was handed is a
/// store whose digests stop describing what somebody thinks they pushed. Point
/// `--context` at a clean directory, or pack it yourself and pass the archive.
///
/// Symlinks are followed and stored as their content, which is what makes an
/// archive from here safe to unpack under the "no links" rule app-lb applies to
/// everything it extracts.
pub fn pack_context(dir: &Path, dest: &Path) -> Result<u64> {
    if !dir.is_dir() {
        return Err(Error::Io {
            context: format!("build context {} is not a directory", dir.display()),
            source: std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a directory"),
        });
    }

    let out = std::fs::File::create(dest).ctx(format!("create {}", dest.display()))?;
    let gz = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    // Content, not metadata: a build context's ownership and mtimes are facts
    // about the machine that packed it, and including them would give the same
    // files a different digest on every host.
    builder.mode(tar::HeaderMode::Deterministic);
    builder
        .append_dir_all(".", dir)
        .ctx(format!("pack {}", dir.display()))?;
    let gz = builder.into_inner().ctx("finish the context archive")?;
    let mut out = gz.finish().ctx("compress the context archive")?;
    // The digest is taken from this file immediately afterwards, so a buffered
    // tail that never reached the kernel would be a manifest naming bytes that
    // are not the ones on disk.
    std::io::Write::flush(&mut out).ctx("flush the context archive")?;
    out.sync_all().ctx("fsync the context archive")?;

    Ok(crate::sys::space::stat_path(dest)?.size)
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Whether a manifest is a Dockerfile manifest.
pub fn is_dockerfile(m: &Manifest) -> bool {
    m.kind == KIND_DOCKERFILE
}

/// The Dockerfile entry, by name.
///
/// By name and never by position: a manifest holding a context but no recipe is
/// malformed, and picking `entries[0]` would hand a caller a gzip file to run
/// `docker build -f` against.
pub fn dockerfile_entry(m: &Manifest) -> Result<&Entry> {
    m.entries
        .iter()
        .find(|e| e.name == DOCKERFILE_ENTRY)
        .ok_or_else(|| Error::Io {
            context: format!(
                "this manifest has no {DOCKERFILE_ENTRY} entry (it holds: {})",
                entry_names(m)
            ),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a dockerfile manifest",
            ),
        })
}

/// The context entry, if there is one.
pub fn context_entry(m: &Manifest) -> Option<&Entry> {
    m.entries.iter().find(|e| e.name == CONTEXT_ENTRY)
}

/// The default image name recorded on the manifest.
pub fn image_name(m: &Manifest) -> Option<&str> {
    m.get(ANN_IMAGE)
}

/// The default rootfs size in megabytes, if it was recorded and is a number.
///
/// An unparseable value is `None` rather than an error: annotations are free
/// text by construction, and a build that refused to start over a malformed
/// *default* would be worse than one that lets heyvm size the image itself.
pub fn size_mb(m: &Manifest) -> Option<u64> {
    m.get(ANN_SIZE_MB)?.trim().parse().ok()
}

/// Write a Dockerfile manifest's entries into `dir` under their entry names.
///
/// Hardlinks where it can, exactly as [`Store::materialize`] does elsewhere: a
/// Dockerfile is a few kilobytes and a context is read once, so nothing here
/// wants a private copy. The caller gets `<dir>/Dockerfile` and, when the
/// manifest has one, `<dir>/context.tar.gz` — unpacking that archive is the
/// caller's business, because the rules for what an archive may contain belong
/// to whoever is going to run it.
pub async fn export(store: &Store, r: &Ref, dir: &Path) -> Result<Exported> {
    let digest = store.resolve(r).await?;
    let m = store.get_manifest(&digest).await?;
    if !is_dockerfile(&m) {
        return Err(Error::Io {
            context: format!(
                "{digest} is a {:?} manifest, not {KIND_DOCKERFILE:?}",
                m.kind
            ),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "wrong manifest kind"),
        });
    }

    std::fs::create_dir_all(dir).ctx(format!("create {}", dir.display()))?;

    let df = dockerfile_entry(&m)?;
    let dockerfile = store
        .materialize(
            &df.digest,
            &dir.join(DOCKERFILE_ENTRY),
            Materialize::ReadOnly,
        )
        .await?;

    let context = match context_entry(&m) {
        Some(c) => Some(
            store
                .materialize(&c.digest, &dir.join(CONTEXT_ENTRY), Materialize::ReadOnly)
                .await?,
        ),
        None => None,
    };

    Ok(Exported {
        manifest: digest,
        dockerfile,
        context,
    })
}

/// Where [`export`] would put each entry, without doing any work. For a caller
/// that wants to clear the destination first.
pub fn export_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(DOCKERFILE_ENTRY), dir.join(CONTEXT_ENTRY))
}

fn entry_names(m: &Manifest) -> String {
    if m.entries.is_empty() {
        return "nothing".to_string();
    }
    m.entries
        .iter()
        .map(|e| e.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
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

    const RECIPE: &[u8] = b"FROM debian:bookworm-slim\nRUN apt-get update\nCOPY app /srv/app\n";

    fn write_recipe(d: &tempfile::TempDir) -> PathBuf {
        let p = d.path().join("Dockerfile");
        std::fs::write(&p, RECIPE).unwrap();
        p
    }

    #[tokio::test]
    async fn a_dockerfile_becomes_a_tagged_manifest() {
        let d = tmpdir();
        let s = store_in(&d);
        let tag = TagName::parse("web-rootfs").unwrap();

        let stored = put(
            &s,
            &write_recipe(&d),
            None,
            Some(tag.clone()),
            &Options {
                image_name: Some("web".into()),
                size_mb: Some(4096),
                source: None,
            },
        )
        .await
        .unwrap();

        // The tag names the manifest, not the blob: that is what carries the
        // annotations a build needs.
        assert_eq!(s.get_tag(&tag).await.unwrap(), stored.manifest);
        let m = s.get_manifest(&stored.manifest).await.unwrap();
        assert!(is_dockerfile(&m));
        assert_eq!(
            dockerfile_entry(&m).unwrap().digest,
            stored.dockerfile.digest
        );
        assert!(context_entry(&m).is_none());
        assert_eq!(image_name(&m), Some("web"));
        assert_eq!(size_mb(&m), Some(4096));
    }

    #[tokio::test]
    async fn re_putting_the_same_recipe_lands_on_the_same_manifest() {
        // The manifest has no timestamp, so pushing an unchanged Dockerfile is
        // idempotent rather than accumulating one manifest per push.
        let d = tmpdir();
        let s = store_in(&d);
        let df = write_recipe(&d);
        let opts = Options {
            image_name: Some("web".into()),
            ..Options::default()
        };

        let a = put(&s, &df, None, None, &opts).await.unwrap();
        let b = put(&s, &df, None, None, &opts).await.unwrap();
        assert_eq!(a.manifest, b.manifest);
        assert!(b.dockerfile.deduped);
        assert_eq!(s.list_manifests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_different_image_name_is_a_different_manifest() {
        // The annotations are part of the address. Two deployments building the
        // same recipe under different names must not collide on one manifest.
        let d = tmpdir();
        let s = store_in(&d);
        let df = write_recipe(&d);

        let a = put(
            &s,
            &df,
            None,
            None,
            &Options {
                image_name: Some("web".into()),
                ..Options::default()
            },
        )
        .await
        .unwrap();
        let b = put(
            &s,
            &df,
            None,
            None,
            &Options {
                image_name: Some("api".into()),
                ..Options::default()
            },
        )
        .await
        .unwrap();

        assert_ne!(a.manifest, b.manifest);
        // One recipe, one blob: only the manifest differs.
        assert_eq!(a.dockerfile.digest, b.dockerfile.digest);
    }

    #[tokio::test]
    async fn a_context_round_trips_through_pack_and_export() {
        let d = tmpdir();
        let s = store_in(&d);

        let ctx = d.path().join("ctx");
        std::fs::create_dir_all(ctx.join("app")).unwrap();
        std::fs::write(ctx.join("app/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(ctx.join("README"), b"hi").unwrap();

        let archive = d.path().join("context.tar.gz");
        let size = pack_context(&ctx, &archive).unwrap();
        assert!(size > 0);

        let stored = put(
            &s,
            &write_recipe(&d),
            Some(&archive),
            Some(TagName::parse("web").unwrap()),
            &Options::default(),
        )
        .await
        .unwrap();
        assert!(stored.context.is_some());

        let out = d.path().join("out");
        let exported = export(&s, &Ref::Tag(TagName::parse("web").unwrap()), &out)
            .await
            .unwrap();
        assert_eq!(exported.manifest, stored.manifest);
        assert_eq!(std::fs::read(out.join(DOCKERFILE_ENTRY)).unwrap(), RECIPE);
        assert!(exported.context.is_some());

        // The archive that comes back out is byte-identical to the one that went
        // in, which is what makes the manifest digest mean anything.
        assert_eq!(
            std::fs::read(out.join(CONTEXT_ENTRY)).unwrap(),
            std::fs::read(&archive).unwrap()
        );
    }

    #[test]
    fn packing_the_same_tree_twice_gives_the_same_bytes() {
        // Deterministic header mode is what makes this true, and it is what
        // stops a re-push of an unchanged context from re-uploading it.
        let d = tmpdir();
        let ctx = d.path().join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::write(ctx.join("a"), b"one").unwrap();
        std::fs::write(ctx.join("b"), b"two").unwrap();

        let first = d.path().join("1.tar.gz");
        let second = d.path().join("2.tar.gz");
        pack_context(&ctx, &first).unwrap();
        pack_context(&ctx, &second).unwrap();
        assert_eq!(
            std::fs::read(&first).unwrap(),
            std::fs::read(&second).unwrap()
        );
    }

    #[tokio::test]
    async fn exporting_a_rootfs_manifest_is_refused() {
        // `heyvm mvm build -f rootfs.ext4` is not a useful failure mode.
        let d = tmpdir();
        let s = store_in(&d);
        let blob = s.insert_bytes(b"an image".to_vec()).await.unwrap();
        let m = Manifest::new(crate::manifest::KIND_ROOTFS).with_entry(
            "rootfs.ext4",
            blob.digest.clone(),
            blob.size,
        );
        let digest = s.put_manifest(&m).await.unwrap();

        let e = export(&s, &Ref::Digest(digest), &d.path().join("out"))
            .await
            .unwrap_err();
        assert!(e.to_string().contains(KIND_DOCKERFILE), "{e}");
    }

    #[tokio::test]
    async fn an_enormous_dockerfile_is_refused_before_it_is_stored() {
        let d = tmpdir();
        let s = store_in(&d);
        let p = d.path().join("Dockerfile");
        std::fs::write(&p, vec![b'#'; (MAX_DOCKERFILE_BYTES + 1) as usize]).unwrap();

        let e = put(&s, &p, None, None, &Options::default())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("--context"), "{e}");
        assert!(s.list_blobs().await.unwrap().is_empty());
    }

    #[test]
    fn a_manifest_without_a_recipe_names_what_it_does_hold() {
        let m = Manifest::new(KIND_DOCKERFILE).with_entry(
            CONTEXT_ENTRY,
            Digest::parse(&hex::encode([1u8; 32])).unwrap(),
            10,
        );
        let e = dockerfile_entry(&m).unwrap_err();
        assert!(e.to_string().contains(CONTEXT_ENTRY), "{e}");
    }

    #[test]
    fn a_malformed_size_annotation_falls_back_rather_than_failing() {
        let m = Manifest::new(KIND_DOCKERFILE).annotate(ANN_SIZE_MB, "quite big");
        assert_eq!(size_mb(&m), None);
    }
}
