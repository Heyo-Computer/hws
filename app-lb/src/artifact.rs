//! Pulling a deployment's content out of an artifact store.
//!
//! The store is [`artifacts`](https://github.com/sarocu/artifacts) — content
//! addressed, and already the thing that holds heyvm's base images (`art heyvm
//! import`). A deployment's `artifact` block names a store and a reference; this
//! module turns that pair into bytes on this host, and reports the digest they
//! came from.
//!
//! What those bytes become depends on the backend, and the two are different
//! enough to be worth naming:
//!
//! * **A managed (`vm`) deployment** gets an `<name>.ext4` in heyvm's image
//!   directory that `heyvmd` can boot. [`Puller::pull`].
//! * **A site** gets a `tar`/`tar.gz` bundle unpacked into `site.root`.
//!   [`Puller::pull_tree`], with the unpacking itself in [`crate::unpack`].
//!
//! Everything below the resolve step is shared, because the hard parts are the
//! same either way: turning a tag into a digest, getting the bytes across, and
//! proving they are the bytes that were asked for.
//!
//! Two transports, chosen by how `artifact.store` is spelled, because the two
//! situations are genuinely different rather than one being a fallback:
//!
//! * **A path** — a store on this host. Handed to `art heyvm materialize`,
//!   which skips the blob's holes instead of copying its zeros. The artifacts
//!   README measures this at 581 MiB written for a 20 GiB rootfs; nothing
//!   app-lb could implement over a socket competes with that, and the binary is
//!   already there if the store is.
//! * **A URL** — an `art serve` somewhere else. app-lb streams the blob itself.
//!   This is what lets one store feed a fleet, and it is how a host with no
//!   `art` binary and no local store still boots the same image.
//!
//! ## What this module insists on
//!
//! **The digest is verified before the bytes are used.** A rootfs is the thing
//! the kernel boots and a bundle is the thing that gets written across a
//! directory on this host. A truncated body, a proxy that helpfully transcoded
//! something, a store that answered the wrong blob — all of those produce a file
//! that is not what was asked for, and the only cheap way to notice is to hash
//! it and compare.
//!
//! Where that check happens differs by path, and it is worth being precise
//! because one of them is not free:
//!
//! * **Over the wire**, [`Puller::fetch_blob`] hashes the body as it lands, so
//!   nothing is ever written under a final name unverified.
//! * **From a local store**, `art heyvm materialize` hashes as it copies — but
//!   only on the copying path. `art get` *hardlinks* when it can, which writes
//!   no bytes and therefore hashes none, so [`verify_file`] does it here before
//!   a bundle is unpacked.
//!
//! **The image is named after the digest, so a re-pull is free.** `<base>-<12
//! hex>` is a pure function of the content, so the file being present is proof
//! the right bytes are on disk and the fetch can be skipped entirely. That
//! matters more here than for a build: rebuilding a Dockerfile is minutes of
//! CPU, but re-fetching a rootfs is gigabytes over a network somebody pays for.
//!
//! **Nothing is written under its final name until it is complete.** Everything
//! lands on a temporary file in the same directory and is renamed into place
//! once it has been verified and grown. heyvmd resolves an image by looking for
//! `<name>.ext4` and does not care how long it has been there, so a partial file
//! under the final name is a VM that boots halfway.

use crate::config::{ArtifactSpec, is_remote_store};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Filename of a rootfs inside an artifact manifest. Matches `ROOTFS_FILENAME`
/// in the artifacts crate, which in turn matches mvm-ctrl's
/// `driver/sync.rs`. A manifest with several entries — a sync bundle — is
/// resolved by finding this one.
const ROOTFS_FILENAME: &str = "rootfs.ext4";

/// Entry names and kind of a Dockerfile manifest, matching `src/dockerfile.rs`
/// in the artifacts crate. Copied rather than depended on, for the same reason
/// [`Manifest`] below is: this side only ever reads these, and the dependency
/// would pull an axum tree and a syscall layer in to spell three constants.
pub const KIND_DOCKERFILE: &str = "heyvm.dockerfile.v1";
pub const DOCKERFILE_ENTRY: &str = "Dockerfile";
const CONTEXT_ENTRY: &str = "context.tar.gz";
/// The manifest's own `--size-mb` default.
const ANN_SIZE_MB: &str = "heyvm.size_mb";

/// Directory the build context is unpacked into, beneath the recipe directory.
/// `heyvm mvm build -c` is pointed here, so a Dockerfile sitting beside it is
/// deliberately *outside* the context — it is not a file the build should be
/// able to `COPY`.
const CONTEXT_DIR: &str = "context";

/// A sha256 in the only spelling the store accepts.
const DIGEST_HEX_LEN: usize = 64;

/// How long to wait for the store to answer at all. Short, because this is a
/// connect and a response head, not a body.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a single read of the blob body may stall before the pull is called
/// dead. Deliberately *not* a whole-request timeout: a rootfs is gigabytes, and
/// any total ceiling large enough to allow a slow link is too large to notice a
/// hung one.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// What a *rootfs* pull did. Every field is reported on the job record, because
/// "which bytes are live" is the question a pull exists to answer.
#[derive(Debug, Clone)]
pub struct Pulled {
    /// The rootfs blob's digest — what `artifact.ref` resolved to.
    pub digest: String,
    /// The heyvm image name written into `vm.image`.
    pub image: String,
    pub path: PathBuf,
    /// Final size of the file on disk, after any growth.
    pub size: u64,
    /// Bytes transferred or copied. Zero when the image was already present.
    pub bytes_written: u64,
    /// Whether the fetch was skipped because the content-addressed image was
    /// already on disk.
    pub reused: bool,
}

/// What a *site* pull did. The tree counterpart of [`Pulled`], and deliberately
/// not the same type: a site produces no image name and no file, so half of
/// [`Pulled`] would be `None` here and the other half would need explaining.
#[derive(Debug, Clone)]
pub struct PulledTree {
    /// The bundle blob's digest — what `artifact.ref` resolved to, and what the
    /// marker beside the root now records.
    pub digest: String,
    /// The directory now serving it.
    pub root: PathBuf,
    /// Regular files unpacked.
    pub files: usize,
    /// Uncompressed bytes written into the tree.
    pub unpacked: u64,
    /// Bytes transferred from the store. Zero from a local store means the blob
    /// was hardlinked rather than copied, which is the normal case.
    pub bytes_written: u64,
    /// Whether the whole pull was skipped because this digest is already the one
    /// deployed at `root`.
    pub reused: bool,
}

/// A site tree whose download, unpack and index validation are complete, but
/// which has not yet replaced the served tree. Correlated callers use this
/// boundary to perform their final configuration check immediately before the
/// two-rename publication and digest-marker update.
pub(crate) struct PreparedTree {
    digest: String,
    root: PathBuf,
    files: usize,
    unpacked: u64,
    bytes_written: u64,
    reused: bool,
    staged: Option<crate::unpack::Staged>,
}

/// What a *guest mount* pull did. The third reading of a bundle, and its own
/// type for the same reason [`PulledTree`] is: nothing here is a rootfs, and the
/// destination is a content-addressed tree rather than a directory somebody
/// named.
#[derive(Debug, Clone)]
pub struct PulledMount {
    /// The guest path this tree will be mounted at. Carried through so a job
    /// covering several mounts can report per-mount outcomes without the caller
    /// re-pairing them by index.
    pub path: String,
    /// The bundle blob's digest — what the mount's `ref` resolved to, and what
    /// gets written back into the spec.
    pub digest: String,
    /// The tree on this host, which is what the daemon is given.
    pub tree: PathBuf,
    /// Regular files unpacked. Zero on a reuse, where nothing was unpacked.
    pub files: usize,
    /// Uncompressed bytes written into the tree.
    pub unpacked: u64,
    /// Bytes transferred from the store. Zero from a local store means the blob
    /// was hardlinked rather than copied.
    pub bytes_written: u64,
    /// Whether the tree for this digest was already on the host and nothing
    /// moved. The common case on every replica after the first deployment to
    /// name a given corpus.
    pub reused: bool,
}

/// What a Dockerfile-manifest fetch produced: a build, laid out and ready to
/// run.
#[derive(Debug, Clone)]
pub struct FetchedDockerfile {
    /// The manifest digest the reference resolved to. This is what the built
    /// image is named after, because it is the only thing that covers the whole
    /// build input — recipe, context and annotations together.
    pub manifest: String,
    /// The recipe on disk.
    pub dockerfile: PathBuf,
    /// The `docker build` context. An empty directory when the manifest had no
    /// context entry, which is correct rather than a special case: a recipe that
    /// copies nothing in needs a context that contains nothing.
    pub context: PathBuf,
    /// Regular files unpacked from the context, or `None` when there was none.
    pub context_files: Option<usize>,
    /// The manifest's `heyvm.size_mb` annotation, if it recorded a usable one.
    pub size_mb: Option<u64>,
    /// Bytes transferred from the store.
    pub bytes_written: u64,
}

/// Materializes a store's blobs onto this host: rootfs images into one
/// directory, site bundles into the directory each site is served from.
pub struct Puller {
    /// The `art` CLI, for the local-store path.
    art_bin: String,
    /// app-lb's own scratch for an image on its way to the daemon: the blob
    /// is fetched or materialized here, then uploaded (`PUT /images/:name`)
    /// into the daemon's catalog and removed. Nothing here is where the
    /// daemon looks.
    scratch: PathBuf,
    /// The daemon, for the upload and for the "already there" check.
    vms: crate::vm::VmManager,
    /// `HOME` for the `art` child, when app-lb and heyvmd run as different
    /// users. `art` does not read `$HOME` for the store root (that comes from
    /// `--root`), but it does for `~/.artifacts` defaults and for anything the
    /// binary itself resolves, so it is passed for the same reason `heyvm` gets
    /// it.
    home: Option<String>,
    http: reqwest::Client,
    candidate: bool,
    /// Rollout-owned, bounded stage codes; never URLs, credentials or bodies.
    pub(crate) preparation_progress: Option<tokio::sync::watch::Sender<String>>,
}

impl Puller {
    pub fn new(art_bin: String, scratch: PathBuf, home: Option<String>, vms: crate::vm::VmManager) -> Self {
        Self {
            art_bin,
            scratch,
            vms,
            home,
            candidate: false,
            preparation_progress: None,
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .build()
                .unwrap_or_default(),
        }
    }

    /// Isolate rollout transport policy from legacy pulls. All candidate GET,
    /// HEAD and blob downloads use this client, never a redirect destination.
    pub fn for_candidate(&self) -> Result<Self, String> {
        Ok(Self {
            art_bin: self.art_bin.clone(), scratch: self.scratch.clone(),
            vms: self.vms.clone(), home: self.home.clone(), candidate: true,
            preparation_progress: None,
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT).read_timeout(READ_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build().map_err(|e| e.to_string())?,
        })
    }

    /// Verify the immutable manifest itself, not just the blob it names.
    /// The artifacts API emits its canonical manifest JSON verbatim.
    pub async fn pinned_rootfs(&self, spec: &ArtifactSpec, key: Option<&str>) -> Result<String, String> {
        let base = spec.store.trim_end_matches('/');
        // This entry point is safe even when invoked on a legacy puller.
        let safe;
        let puller = if self.candidate { self } else { safe = self.for_candidate()?; &safe };
        let response = puller.get(&format!("{base}/manifests/{}", spec.artifact_ref), key).await.map_err(|e| e.to_string())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND { return Ok(spec.artifact_ref.clone()); }
        if !response.status().is_success() { return Err("pinned rootfs manifest unavailable".into()); }
        let bytes = candidate_manifest_bytes(response).await?;
        if format!("{:x}", Sha256::digest(&bytes)) != spec.artifact_ref { return Err("rootfs manifest digest mismatch".into()); }
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        blob_entry(&manifest, &spec.artifact_ref, Some(ROOTFS_FILENAME)).map(|(digest, _)| digest)
    }

    /// Resolve `spec.artifact_ref`, put the rootfs behind it in the image
    /// directory, and say what happened.
    ///
    /// `api_key` is the resolved value of `spec.auth`, already read out of the
    /// secret store — this module never touches secrets itself, so the value has
    /// exactly one way in and cannot be logged by accident.
    ///
    /// `log` receives progress lines. Errors are strings: they go straight onto
    /// a job record for a person to read.
    pub async fn pull(
        &self,
        deployment_id: &str,
        spec: &ArtifactSpec,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<Pulled, String> {
        let dir = self.scratch.as_path();
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;

        self.pull_into(dir, deployment_id, None, spec, api_key, force, log).await
    }

    /// [`pull`](Self::pull), into the catalog name `image` rather than the
    /// one [`ArtifactSpec::image_for`] would choose. A thaw needs this: an
    /// offloaded image comes back under the name a deployment's `vm.image`
    /// already says, whatever shape that name has.
    pub async fn pull_as(
        &self,
        image: &str,
        spec: &ArtifactSpec,
        api_key: Option<&str>,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<Pulled, String> {
        let dir = self.scratch.as_path();
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
        self.pull_into(dir, image, Some(image), spec, api_key, false, log).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn pull_into(
        &self,
        dir: &Path,
        deployment_id: &str,
        name: Option<&str>,
        spec: &ArtifactSpec,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<Pulled, String> {
        if spec.is_remote() {
            self.pull_remote(dir, deployment_id, name, spec, api_key, force, log).await
        } else {
            if api_key.is_some() {
                // Said rather than ignored: a key configured here is a
                // credential somebody believes is protecting something.
                log("artifact.auth is set on a local store; a store root is protected by \
                     file permissions, not by an API key, and the secret is unused"
                    .to_string());
            }
            self.pull_local(dir, deployment_id, name, spec, force, log).await
        }
    }

    /// Whether `store` still serves the blob `digest`, and at `size` bytes
    /// when a size is known. The check an offload makes before it deletes the
    /// only local copy: the store is the copy that remains.
    pub async fn verify_blob(
        &self,
        store: &str,
        digest: &str,
        api_key: Option<&str>,
        size: Option<u64>,
    ) -> Result<(), String> {
        if !is_digest(digest) {
            return Err(format!("{digest:?} is not a blob digest"));
        }
        if is_remote_store(store) {
            let base = store.trim().trim_end_matches('/');
            let url = format!("{base}/blobs/{digest}");
            let resp = self.head(&url, api_key).await.map_err(|e| format!("HEAD {url} failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("HEAD {url} answered {}", resp.status()));
            }
            // The header, not `content_length()`: on a HEAD that reads the
            // (empty) body's size hint and answers 0.
            let got = resp
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            if let (Some(want), Some(got)) = (size, got)
                && want != got
            {
                return Err(format!("{url} is {got} bytes, expected {want}"));
            }
            Ok(())
        } else {
            let (got, len) = self.stat_local(store.trim(), digest).await?;
            if got != digest {
                return Err(format!("{store} resolves {digest} to {got}"));
            }
            if let Some(want) = size
                && want != len
            {
                return Err(format!("{store} holds {digest} at {len} bytes, expected {want}"));
            }
            Ok(())
        }
    }

    /// Put the file at `path` into `store` and point `tag` at it, returning
    /// the digest the store recorded — the offload of an image that came from
    /// a build and so exists nowhere else.
    ///
    /// The digest is computed here first and the store must agree with it:
    /// `PUT /blobs/{digest}` refuses bytes that hash to anything else, and a
    /// local `art put` reports the digest it stored. The tag is what keeps the
    /// blob out of the store's garbage collection.
    pub async fn push_image(
        &self,
        store: &str,
        path: &Path,
        tag: &str,
        api_key: Option<&str>,
    ) -> Result<(String, u64), String> {
        if is_remote_store(store) {
            let (digest, size) = sha256_file(path).await?;
            let base = store.trim().trim_end_matches('/');
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| format!("could not open {}: {e}", path.display()))?;
            let body = reqwest::Body::from(file);
            let url = format!("{base}/blobs/{digest}");
            let mut req = self.http.put(&url).body(body);
            if let Some(k) = api_key {
                req = req.header("x-api-key", k);
            }
            let resp = req.send().await.map_err(|e| format!("PUT {url} failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("PUT {url} answered {}", resp.status()));
            }
            let url = format!("{base}/tags/{tag}");
            let mut req = self.http.put(&url).body(digest.clone());
            if let Some(k) = api_key {
                req = req.header("x-api-key", k);
            }
            let resp = req.send().await.map_err(|e| format!("PUT {url} failed: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("PUT {url} answered {}", resp.status()));
            }
            Ok((digest, size))
        } else {
            let mut cmd = self.art(store.trim());
            cmd.arg("--json").arg("put").arg(path).arg("--squash").arg("--tag").arg(tag);
            let out = self.run(cmd).await?;
            let v: serde_json::Value = serde_json::from_str(&out)
                .map_err(|e| format!("`art put` produced output that is not JSON: {e}"))?;
            let digest = v
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or("`art put` reported no digest")?
                .to_string();
            let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            Ok((digest, size))
        }
    }

    // -- builds: a Dockerfile manifest laid out on disk ----------------------

    /// Resolve a Dockerfile manifest and write it into `dir` as a buildable
    /// tree: `<dir>/Dockerfile` and `<dir>/context/`.
    ///
    /// `dir` is **wiped first**, and that is the point rather than tidiness. A
    /// context left over from the previous build could satisfy a `COPY` the
    /// current recipe no longer ships, producing an image that builds here and
    /// nowhere else — the same failure `git clean -xffdq` prevents on the git
    /// path, arriving by a different route.
    ///
    /// Both transports end in the same place, but only one of them is free:
    ///
    /// * **A URL** — `GET /manifests/{ref}`, then the blobs, hashed as they land.
    /// * **A path** — `art dockerfile export`, which hardlinks. A hardlink writes
    ///   no bytes and therefore hashes none, so the digests are checked here
    ///   afterwards. It is worth doing: a context is untrusted input that is
    ///   about to be unpacked across a directory on this host.
    pub async fn fetch_dockerfile(
        &self,
        store: &str,
        reference: &str,
        api_key: Option<&str>,
        dir: &Path,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<FetchedDockerfile, String> {
        let base = store.trim().trim_end_matches('/');
        let remote = is_remote_store(base);

        // Removed and recreated, never merged into.
        let _ = tokio::fs::remove_dir_all(dir).await;
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;

        let recipe = dir.join(DOCKERFILE_ENTRY);
        let archive = dir.join(CONTEXT_ENTRY);
        let context = dir.join(CONTEXT_DIR);

        let (manifest, size_mb, bytes_written) = if remote {
            self.fetch_dockerfile_remote(base, reference, api_key, &recipe, &archive, log)
                .await?
        } else {
            if api_key.is_some() {
                log("build.auth is set on a local store; a store root is protected by file \
                     permissions, not by an API key, and the secret is unused"
                    .to_string());
            }
            self.export_dockerfile_local(base, reference, dir, log).await?
        };

        tokio::fs::create_dir_all(&context)
            .await
            .map_err(|e| format!("could not create {}: {e}", context.display()))?;

        let context_files = if tokio::fs::metadata(&archive).await.is_ok() {
            // Untarring is synchronous and a context can be hundreds of
            // megabytes of gzip: on the job task directly it would stall every
            // other future on this runtime thread for the duration.
            let (from, into) = (archive.clone(), context.clone());
            let unpacked = tokio::task::spawn_blocking(move || {
                crate::unpack::extract_into(&from, &into, 0)
            })
            .await
            .map_err(|e| format!("the context unpack task did not finish: {e}"))??;
            log(format!(
                "unpacked {} file{} ({}) of build context",
                unpacked.files,
                if unpacked.files == 1 { "" } else { "s" },
                human(unpacked.bytes),
            ));
            // The archive is not part of the context and must not be visible to
            // a `COPY`. It is also the whole context a second time on disk.
            let _ = tokio::fs::remove_file(&archive).await;
            Some(unpacked.files)
        } else {
            log("this recipe has no build context".to_string());
            None
        };

        Ok(FetchedDockerfile {
            manifest,
            dockerfile: recipe,
            context,
            context_files,
            size_mb,
            bytes_written,
        })
    }

    /// `GET /manifests/{ref}` and then the blobs it names.
    async fn fetch_dockerfile_remote(
        &self,
        base: &str,
        reference: &str,
        api_key: Option<&str>,
        recipe: &Path,
        archive: &Path,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<(String, Option<u64>, u64), String> {
        let url = format!("{base}/manifests/{reference}");
        let resp = self
            .get(&url, api_key)
            .await
            .map_err(|e| format!("GET {url} failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "GET {url} answered {status}{} — `build.ref` must name a Dockerfile manifest \
                 in this store. Push one with `heyctl artifact push-dockerfile --tag \
                 {reference}`",
                detail(&body)
            ));
        }
        let m: Manifest = resp
            .json()
            .await
            .map_err(|e| format!("the manifest at {url} was not readable: {e}"))?;
        check_dockerfile_kind(&m, reference)?;

        // The digest the reference resolved to. Asked for separately because
        // `GET /manifests/{tag}` answers with the manifest, not with its address,
        // and the address is what the image gets named after. A reference that is
        // already a digest is its own answer and costs no round trip.
        let manifest_digest = if is_digest(reference) {
            reference.to_string()
        } else {
            match self.tag_digest(base, reference, api_key).await? {
                Some(d) => d,
                None => {
                    return Err(format!(
                        "{base} served a manifest for {reference:?} but has no tag by that name"
                    ));
                }
            }
        };

        let df = named_entry(&m, DOCKERFILE_ENTRY, reference)?;
        log(format!(
            "{reference} resolves to {manifest_digest} at {base} (Dockerfile {}, {})",
            short(&df.digest),
            human(df.size),
        ));
        let mut written = self
            .fetch_blob(base, &df.digest, api_key, recipe, df.size, log)
            .await?;

        if let Some(ctx) = m.entries.iter().find(|e| e.name == CONTEXT_ENTRY) {
            written += self
                .fetch_blob(base, &ctx.digest, api_key, archive, ctx.size, log)
                .await?;
        }
        Ok((manifest_digest, m.size_mb(), written))
    }

    /// `art dockerfile export` — the local-store path, which hardlinks.
    async fn export_dockerfile_local(
        &self,
        root: &str,
        reference: &str,
        dir: &Path,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<(String, Option<u64>, u64), String> {
        // Asked for first: it is one cheap invocation, and it is the only place
        // the annotations and the entry digests are visible on this path.
        let mut cmd = self.art(root);
        cmd.arg("manifest").arg(reference);
        let out = self.run(cmd).await?;
        let m: Manifest = serde_json::from_str(&out)
            .map_err(|e| format!("`art manifest` produced output that is not a manifest: {e}"))?;
        check_dockerfile_kind(&m, reference)?;
        let df = named_entry(&m, DOCKERFILE_ENTRY, reference)?;

        let mut cmd = self.art(root);
        cmd.arg("dockerfile").arg("export").arg(reference).arg(dir);
        let out = self.run(cmd).await?;
        let v: serde_json::Value = serde_json::from_str(&out).map_err(|e| {
            format!("`art dockerfile export` produced output that is not JSON: {e}")
        })?;
        let manifest_digest = v
            .get("manifest")
            .and_then(|d| d.as_str())
            .ok_or("`art dockerfile export` reported no manifest digest")?
            .to_string();
        let written = ["dockerfile", "context"]
            .iter()
            .filter_map(|k| v.get(*k)?.get("bytesWritten")?.as_u64())
            .sum();

        log(format!(
            "{reference} resolves to {manifest_digest} in {root} ({})",
            if written == 0 { "hardlinked" } else { "copied" }
        ));

        // `art dockerfile export` hardlinks when it can, and a hardlink hashes
        // nothing. The context is about to be unpacked across a directory on
        // this host, so it is verified before that happens rather than after.
        verify_file(&dir.join(DOCKERFILE_ENTRY), &df.digest).await?;
        if let Some(ctx) = m.entries.iter().find(|e| e.name == CONTEXT_ENTRY) {
            verify_file(&dir.join(CONTEXT_ENTRY), &ctx.digest).await?;
        }

        Ok((manifest_digest, m.size_mb(), written))
    }

    // -- sites: a bundle unpacked into the served directory ------------------

    /// Resolve `spec.artifact_ref`, unpack the bundle behind it into
    /// `site.root`, and say what happened.
    ///
    /// The order is the point, and it is not the order the equivalent shell
    /// commands run in. The bundle is fetched, verified, unpacked *beside* the
    /// live tree and checked for the index the site will look for — and only
    /// then swapped in. Every way this can fail therefore fails with the
    /// previous site still serving, which is the one thing `git pull && npm run
    /// build && mv -T dist public` cannot promise.
    pub async fn pull_tree(
        &self,
        spec: &ArtifactSpec,
        site: &crate::config::SiteSpec,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<PulledTree, String> {
        let prepared = self.prepare_tree(spec, site, api_key, force, log).await?;
        self.publish_tree(prepared, log)
    }

    pub(crate) async fn prepare_tree(
        &self,
        spec: &ArtifactSpec,
        site: &crate::config::SiteSpec,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<PreparedTree, String> {
        let root = PathBuf::from(site.root.trim());
        let remote = spec.is_remote();
        let base = spec.store.trim().trim_end_matches('/').to_string();

        // Resolve first: it is one round trip, and it is what makes the reuse
        // check below possible without moving any bytes.
        let (digest, size) = if remote {
            self.resolve_remote(&base, &spec.artifact_ref, api_key, None)
                .await?
        } else {
            if api_key.is_some() {
                log("artifact.auth is set on a local store; a store root is protected by \
                     file permissions, not by an API key, and the secret is unused"
                    .to_string());
            }
            self.stat_local(&base, &spec.artifact_ref).await?
        };
        log(format!(
            "{} resolves to {digest} ({}) {} {base}",
            spec.artifact_ref,
            human(size),
            if remote { "at" } else { "in" },
        ));

        // The site counterpart of "the image is already on disk". The digest is
        // recorded beside the root rather than encoded in a filename, because a
        // directory cannot be content-addressed by its name the way an image
        // file is.
        if !force && crate::unpack::deployed_digest(&root).as_deref() == Some(digest.as_str()) {
            log(format!(
                "{} is already serving this digest; nothing to unpack",
                root.display()
            ));
            return Ok(PreparedTree {
                digest,
                root,
                files: 0,
                unpacked: 0,
                bytes_written: 0,
                reused: true,
                staged: None,
            });
        }

        // Beside the root, so a bundle too large for `/tmp` is not a surprise
        // and the local store's hardlink lands on the filesystem the files are
        // going to anyway.
        let bundle = Scratch::new(crate::unpack::scratch_path(&root, "bundle")?);
        let bytes_written = if remote {
            self.fetch_blob(&base, &digest, api_key, bundle.path(), size, log)
                .await?
        } else {
            let written = self.get_local(&base, &digest, bundle.path()).await?;
            // `art get` hardlinks when it can, and a hardlink hashes nothing.
            verify_file(bundle.path(), &digest).await?;
            log(format!(
                "{} from {base} ({})",
                human(size),
                if written == 0 { "hardlinked" } else { "copied" }
            ));
            written
        };

        // Unpacking is synchronous, and a bundle can be hundreds of megabytes
        // of gzip: on the job task directly it would stall every other future
        // on this runtime thread for the duration.
        let strip = spec.strip();
        let index = site.index.trim().to_string();
        let (staged, unpacked) = {
            let root = root.clone();
            let bundle_path = bundle.path().to_path_buf();
            tokio::task::spawn_blocking(move || {
                let (staged, unpacked) = crate::unpack::stage(&root, &bundle_path, strip)?;
                crate::unpack::verify_index(staged.dir(), &index, strip)?;
                Ok::<_, String>((staged, unpacked))
            })
            .await
            .map_err(|e| format!("the unpack task did not finish: {e}"))??
        };

        self.preparation_stage("site_tree_prepared");
        Ok(PreparedTree { digest, root, files: unpacked.files, unpacked: unpacked.bytes,
            bytes_written, reused: false, staged: Some(staged) })
    }

    pub(crate) fn publish_tree(
        &self,
        mut prepared: PreparedTree,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<PulledTree, String> {
        if let Some(staged) = prepared.staged.take() {
            staged.commit()?;
            log(format!(
                "unpacked {} file{} ({}) into {}",
                prepared.files,
                if prepared.files == 1 { "" } else { "s" },
                human(prepared.unpacked),
                prepared.root.display(),
            ));
        }

        // After the swap, so the marker can only ever describe a tree that is
        // actually in place.
        //
        // If it cannot be written the *old* marker must go, and that matters
        // more than it looks: a marker left claiming the digest this deploy
        // replaced would make a later pull of that digest skip its work and
        // report "already serving" over a tree holding something else. Losing
        // the marker only costs the next pull its shortcut, so the failure is
        // logged rather than raised — the deploy itself succeeded.
        if !prepared.reused && let Err(e) = crate::unpack::record_digest(&prepared.root, &prepared.digest) {
            crate::unpack::forget_digest(&prepared.root);
            log(format!("{e}; the next pull will unpack again rather than skip"));
        }

        Ok(PulledTree {
            digest: prepared.digest,
            root: prepared.root,
            files: prepared.files,
            unpacked: prepared.unpacked,
            bytes_written: prepared.bytes_written,
            reused: prepared.reused,
        })
    }

    // -- guest mounts: a bundle unpacked into a content-addressed tree ------

    /// Resolve a mount's reference and unpack the bundle behind it into a tree
    /// under the mount store, so the daemon has a directory to build a VM's
    /// mount image from.
    ///
    /// The third destination for the same kind of bundle, and the one with the
    /// least to arrange: a rootfs has to land under a name heyvmd resolves and a
    /// site has to replace a tree that is being served *right now*, but a mount
    /// tree is named after its own digest and nothing is reading the name until
    /// it exists. So there is no staging-and-swap here — there is staging and a
    /// single rename, and losing that rename to a concurrent pull of the same
    /// digest is a success rather than a conflict.
    ///
    /// What does have to be arranged is that nothing incomplete ever appears
    /// under the final name, for exactly the reason a half-written rootfs must
    /// not: a create that finds the directory takes it as proof the bytes are
    /// there, and `mke2fs -d` on a half-unpacked tree produces a VM whose data
    /// is silently short.
    ///
    /// `force` re-fetches over a tree already on disk. As with a rootfs pull
    /// there is normally no reason to — the directory name *is* the digest — so
    /// it is for the one case the name cannot describe: a tree damaged after it
    /// was written.
    pub async fn pull_mount(
        &self,
        mount: &crate::config::MountSpec,
        store: &crate::mounts::MountStore,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<PulledMount, String> {
        let remote = mount.is_remote();
        let base = mount.store.trim().trim_end_matches('/').to_string();
        let strip = mount.strip();
        let guest_path = mount.guest_path().to_string();

        // One round trip, and it is what makes the reuse check below possible
        // without moving any bytes.
        let (digest, size) = if remote {
            self.resolve_remote(&base, &mount.artifact_ref, api_key, None)
                .await?
        } else {
            if api_key.is_some() {
                log(format!(
                    "the auth on mount {guest_path} names a local store; a store root is \
                     protected by file permissions, not by an API key, and the secret is unused"
                ));
            }
            self.stat_local(&base, &mount.artifact_ref).await?
        };
        log(format!(
            "{guest_path}: {} resolves to {digest} ({}) {} {base}",
            mount.artifact_ref,
            human(size),
            if remote { "at" } else { "in" },
        ));

        let dest = store.tree_path(&digest, strip);
        if dest.is_dir() && !force {
            // Reusing a tree the sweep could be about to reclaim — a rollback to
            // an old digest nothing currently names — leaves a millisecond in
            // which the spec is written against a tree that has just been
            // removed. Deliberately not defended against here: the next create
            // refuses with a message naming the mount and the endpoint that
            // fixes it, which is a better outcome than the state a lock or a
            // reservation file would need to keep correct.
            log(format!(
                "{guest_path}: {} is already unpacked; nothing to fetch",
                dest.display()
            ));
            return Ok(PulledMount {
                path: guest_path,
                digest,
                tree: dest,
                files: 0,
                unpacked: 0,
                bytes_written: 0,
                reused: true,
            });
        }

        store.ensure_root()?;
        // Both the bundle and the tree it unpacks to live inside one staging
        // directory, so a pull that dies halfway leaves exactly one thing behind
        // and the sweep has one shape to recognise.
        let staging = ScratchDir::new(store.staging_path(&unique_token()))?;
        let bundle = staging.path().join("bundle");
        let bytes_written = if remote {
            self.fetch_blob(&base, &digest, api_key, &bundle, size, log)
                .await?
        } else {
            let written = self.get_local(&base, &digest, &bundle).await?;
            // `art get` hardlinks when it can, and a hardlink hashes nothing.
            verify_file(&bundle, &digest).await?;
            log(format!(
                "{guest_path}: {} from {base} ({})",
                human(size),
                if written == 0 { "hardlinked" } else { "copied" }
            ));
            written
        };

        // Unpacking is synchronous and a corpus can be gigabytes of gzip: on the
        // job task directly it would stall every other future on this runtime
        // thread for the duration.
        self.preparation_stage("mount_unpack");
        let tree = staging.path().join("tree");
        let unpacked = {
            let (bundle, tree) = (bundle.clone(), tree.clone());
            tokio::task::spawn_blocking(move || {
                // Created up front rather than left to the first entry: a bundle
                // holding nothing would otherwise leave no directory at all, and
                // an empty mount is a legitimate thing to ship.
                std::fs::create_dir_all(&tree)
                    .map_err(|e| format!("could not create {}: {e}", tree.display()))?;
                crate::unpack::extract_into(&bundle, &tree, strip)
            })
            .await
            .map_err(|e| format!("the unpack task did not finish: {e}"))??
        };
        // The bundle has served its purpose and is a second copy of the same
        // bytes. Removing it before the rename keeps the high-water mark at one
        // copy plus the tree rather than two.
        let _ = tokio::fs::remove_file(&bundle).await;

        // `force` means the tree on disk is not trusted, so it goes before the
        // new one lands. Nothing reads a tree except a VM create, and one racing
        // this window would have been reading the copy being replaced.
        if force && dest.is_dir() {
            log(format!(
                "{guest_path}: replacing the existing tree at {}",
                dest.display()
            ));
            std::fs::remove_dir_all(&dest).map_err(|e| {
                format!("could not remove the damaged tree at {}: {e}", dest.display())
            })?;
        }

        let tree = store.commit(&tree, &digest, strip)?;
        log(format!(
            "{guest_path}: unpacked {} file{} ({}) into {}",
            unpacked.files,
            if unpacked.files == 1 { "" } else { "s" },
            human(unpacked.bytes),
            tree.display(),
        ));

        Ok(PulledMount {
            path: guest_path,
            digest,
            tree,
            files: unpacked.files,
            unpacked: unpacked.bytes,
            bytes_written,
            reused: false,
        })
    }

    /// `art get` — the blob's bytes at a path, hardlinked if the filesystem
    /// allows it. Returns what was actually written, which is `0` for a link.
    async fn get_local(&self, root: &str, digest: &str, dest: &Path) -> Result<u64, String> {
        // `art get` refuses to clobber, and a crashed run can leave one behind.
        let _ = tokio::fs::remove_file(dest).await;
        let mut cmd = self.art(root);
        cmd.arg("get").arg(digest).arg("-o").arg(dest);
        let out = self.run(cmd).await?;
        let v: serde_json::Value = serde_json::from_str(&out)
            .map_err(|e| format!("`art get` produced output that is not JSON: {e}"))?;
        Ok(v.get("bytesWritten").and_then(|b| b.as_u64()).unwrap_or(0))
    }

    // -- remote: art serve over HTTP ---------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn pull_remote(
        &self,
        dir: &Path,
        deployment_id: &str,
        name: Option<&str>,
        spec: &ArtifactSpec,
        api_key: Option<&str>,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<Pulled, String> {
        let base = spec.store.trim().trim_end_matches('/');
        let (digest, expected_size) = self
            .resolve_remote(base, &spec.artifact_ref, api_key, Some(ROOTFS_FILENAME))
            .await?;
        log(format!(
            "{} resolves to {digest} ({}) at {base}",
            spec.artifact_ref,
            human(expected_size),
        ));

        let image = name.map(str::to_string).unwrap_or_else(|| spec.image_for(deployment_id, &digest));

        if !force
            && let Some((path, size)) = self.usable_on_daemon(&image, expected_size, spec.grow_gb).await?
        {
            log(format!(
                "{} is already in the daemon's catalog with this digest; nothing to fetch",
                path.display()
            ));
            return Ok(Pulled {
                digest,
                image,
                path,
                size,
                bytes_written: 0,
                reused: true,
            });
        }

        let tmp = TempImage::new(dir, &image);
        let written = self
            .fetch_blob(base, &digest, api_key, tmp.path(), expected_size, log)
            .await?;
        let (path, size) = self.upload(tmp, &image, spec.grow_gb, log).await?;

        Ok(Pulled {
            digest,
            image,
            path,
            size,
            bytes_written: written,
            reused: false,
        })
    }

    /// Turn a tag or a digest into the rootfs blob's digest and size.
    ///
    /// `GET /manifests/{ref}` is asked first for either spelling, because that
    /// is the route that resolves a tag *and* the route that describes what a
    /// manifest digest contains. Only if that fails and the reference is itself
    /// 64 hex characters is it treated as naming the blob directly — the store
    /// permits tagging a blob, and `HEAD /blobs/{digest}` is how to find out.
    async fn resolve_remote(
        &self,
        base: &str,
        reference: &str,
        api_key: Option<&str>,
        expected: Option<&str>,
    ) -> Result<(String, u64), String> {
        let url = format!("{base}/manifests/{reference}");
        let manifest_err = match self.get(&url, api_key).await {
            Ok(resp) if resp.status().is_success() => {
                let m: Manifest = if self.candidate {
                    serde_json::from_slice(&candidate_manifest_bytes(resp).await?)
                        .map_err(|e| format!("the manifest at {url} was not readable: {e}"))?
                } else { resp
                    .json()
                    .await
                    .map_err(|e| format!("the manifest at {url} was not readable: {e}"))? };
                return blob_entry(&m, reference, expected);
            }
            Ok(resp) => {
                let status = resp.status();
                let body = if self.candidate { String::new() } else { resp.text().await.unwrap_or_default() };
                format!("GET {url} answered {status}{}", detail(&body))
            }
            Err(e) => format!("GET {url} failed: {e}"),
        };

        // Not a manifest. It may still name a blob directly: `art put --tag web
        // rootfs.ext4` points a tag straight at the blob rather than at a
        // manifest describing it, and that image is just as bootable as one
        // `art heyvm import` put in. A digest is its own answer; a tag has to be
        // looked up in the tag list, because the store exposes no
        // `GET /tags/{name}`.
        let digest = if is_digest(reference) {
            reference.to_string()
        } else {
            match self.tag_digest(base, reference, api_key).await {
                Ok(Some(d)) => d,
                Ok(None) => {
                    return Err(format!(
                        "{manifest_err}. The store has no tag called {reference:?} — push one \
                         with `heyctl artifact push --tag {reference}`, or \
                         `art tag {reference} <digest>` on the store itself"
                    ));
                }
                Err(e) => return Err(format!("{manifest_err}, and {e}")),
            }
        };

        let url = format!("{base}/blobs/{digest}");
        let resp = self
            .head(&url, api_key)
            .await
            .map_err(|e| format!("HEAD {url} failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(format!(
                "{manifest_err}, and HEAD {url} answered {status} — the store has neither a \
                 manifest nor a blob for {reference:?}"
            ));
        }
        let size = resp
            .content_length()
            .ok_or_else(|| format!("HEAD {url} answered without a Content-Length"))?;
        Ok((digest, size))
    }

    /// What one tag points at.
    ///
    /// `GET /tags/{name}` first, falling back to filtering `GET /tags` — not for
    /// robustness's sake, but because the single-tag route is newer than the
    /// listing and a fleet is not upgraded all at once. A store that predates it
    /// answers `405`, and re-asking is one round trip against a list of tens.
    ///
    /// The fallback is scoped to that: a `404` from the single-tag route is a
    /// real answer — this store has no such tag — and re-reading the whole
    /// listing to confirm it would only make the same reply cost twice.
    async fn tag_digest(
        &self,
        base: &str,
        tag: &str,
        api_key: Option<&str>,
    ) -> Result<Option<String>, String> {
        let url = format!("{base}/tags/{tag}");
        match self.get(&url, api_key).await {
            Ok(resp) if resp.status().is_success() => {
                let entry: TagEntry = resp
                    .json()
                    .await
                    .map_err(|e| format!("the tag at {url} was not readable: {e}"))?;
                return Ok(Some(entry.digest).filter(|d| is_digest(d)));
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => return Ok(None),
            // Anything else — a 405 from an older store, a proxy in the way —
            // falls through to the listing.
            Ok(_) | Err(_) => {}
        }

        let url = format!("{base}/tags");
        let resp = self
            .get(&url, api_key)
            .await
            .map_err(|e| format!("GET {url} failed: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("GET {url} answered {status}{}", detail(&body)));
        }
        let tags: Vec<TagEntry> = resp
            .json()
            .await
            .map_err(|e| format!("the tag list at {url} was not readable: {e}"))?;
        Ok(tags
            .into_iter()
            .find(|t| t.tag == tag)
            .map(|t| t.digest)
            .filter(|d| is_digest(d)))
    }

    /// Stream `GET /blobs/{digest}` into `dest`, hashing as it lands.
    ///
    /// The hash is the point. Everything downstream — heyvmd booting it, the
    /// image name claiming to be content-addressed — assumes the bytes on disk
    /// are the bytes the digest names, and this is the only place that is ever
    /// checked on the wire path.
    async fn fetch_blob(
        &self,
        base: &str,
        digest: &str,
        api_key: Option<&str>,
        dest: &Path,
        expected_size: u64,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<u64, String> {
        self.preparation_stage("blob_request");
        let url = format!("{base}/blobs/{digest}");
        let resp = self
            .get(&url, api_key)
            .await
            .map_err(|e| {
                self.preparation_stage(if e.is_timeout() { "blob_request_timeout" } else { "blob_request_failed" });
                format!("GET {url} failed: {e}")
            })?;
        if !resp.status().is_success() {
            let status = resp.status();
            self.preparation_stage(&format!("blob_http_{}", status.as_u16()));
            let body = if self.candidate { String::new() } else { resp.text().await.unwrap_or_default() };
            return Err(format!("GET {url} answered {status}{}", detail(&body)));
        }

        self.preparation_stage("blob_download");
        log(format!("fetching {} from {url}", human(expected_size)));
        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(|e| format!("could not create {}: {e}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let mut stream = resp.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                self.preparation_stage(if e.is_timeout() { "blob_read_timeout" } else { "blob_read_failed" });
                format!(
                    "the transfer failed after {} of {}: {e}",
                    human(written),
                    human(expected_size)
                )
            })?;
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| format!("writing {}: {e}", dest.display()))?;
            written += chunk.len() as u64;
        }
        // Flush before the digest is pronounced good: a buffered tail that never
        // reached the kernel would make the check describe memory, not the file
        // that is about to be renamed into place and booted.
        self.preparation_stage("blob_flush");
        file.flush()
            .await
            .map_err(|e| format!("flushing {}: {e}", dest.display()))?;
        file.sync_all()
            .await
            .map_err(|e| format!("syncing {}: {e}", dest.display()))?;
        drop(file);

        let actual = hex(&hasher.finalize());
        if actual != digest {
            self.preparation_stage("blob_digest_mismatch");
            return Err(format!(
                "the store answered {written} bytes that hash to {actual}, but {digest} was \
                 asked for — this is a corrupted or substituted rootfs and it has not been \
                 kept"
            ));
        }
        Ok(written)
    }

    // -- local: a store root on this host ----------------------------------

    async fn pull_local(
        &self,
        dir: &Path,
        deployment_id: &str,
        name: Option<&str>,
        spec: &ArtifactSpec,
        force: bool,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<Pulled, String> {
        let root = spec.store.trim();

        // Resolve first, so an image already on disk costs one `art stat`
        // instead of a full materialization. `stat` reports the blob a
        // reference resolves to, which is exactly the name the image gets.
        match self.stat_local(root, &spec.artifact_ref).await {
            Ok((digest, size)) => {
                log(format!(
                    "{} resolves to {digest} ({}) in {root}",
                    spec.artifact_ref,
                    human(size)
                ));
                let image = name.map(str::to_string).unwrap_or_else(|| spec.image_for(deployment_id, &digest));
                if !force
                    && let Some((path, size)) = self.usable_on_daemon(&image, size, spec.grow_gb).await?
                {
                    log(format!(
                        "{} is already in the daemon's catalog with this digest; nothing to materialize",
                        path.display()
                    ));
                    return Ok(Pulled {
                        digest,
                        image,
                        path,
                        size,
                        bytes_written: 0,
                        reused: true,
                    });
                }
            }
            Err(e) => {
                // `art stat` refuses a manifest with several entries, which a
                // sync bundle has; `art heyvm materialize` resolves those by
                // picking the rootfs. So a failure here is not fatal — it just
                // costs the shortcut.
                log(format!("could not resolve {} up front ({e}); materializing to find out",
                    spec.artifact_ref));
            }
        }

        let tmp = TempImage::new(dir, &format!("pull-{}", sanitize(deployment_id)));
        let out = self.materialize(root, spec, tmp.path()).await?;
        let image = name.map(str::to_string).unwrap_or_else(|| spec.image_for(deployment_id, &out.digest));
        log(format!(
            "materialized {} ({} written, {})",
            out.digest,
            human(out.bytes_written),
            out.method,
        ));

        // Growth is `art`'s job on this path — it was passed --grow-gb — so the
        // upload is all that is left.
        let (path, size) = self.upload(tmp, &image, None, log).await?;
        Ok(Pulled {
            digest: out.digest,
            image,
            path,
            size,
            bytes_written: out.bytes_written,
            reused: false,
        })
    }

    /// `art stat` — the digest a reference resolves to, without doing any work.
    async fn stat_local(&self, root: &str, reference: &str) -> Result<(String, u64), String> {
        let mut cmd = self.art(root);
        cmd.arg("stat").arg(reference);
        let out = self.run(cmd).await?;
        let v: serde_json::Value = serde_json::from_str(&out)
            .map_err(|e| format!("`art stat` produced output that is not JSON: {e}"))?;
        let digest = v
            .get("digest")
            .and_then(|d| d.as_str())
            .ok_or("`art stat` reported no digest")?
            .to_string();
        let size = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
        Ok((digest, size))
    }

    async fn materialize(
        &self,
        root: &str,
        spec: &ArtifactSpec,
        dest: &Path,
    ) -> Result<Materialized, String> {
        let mut cmd = self.art(root);
        cmd.arg("heyvm")
            .arg("materialize")
            .arg(&spec.artifact_ref)
            .arg(dest);
        if let Some(gb) = spec.grow_gb {
            cmd.arg("--grow-gb").arg(gb.to_string());
        }
        let out = self.run(cmd).await?;
        let v: serde_json::Value = serde_json::from_str(&out)
            .map_err(|e| format!("`art heyvm materialize` produced output that is not JSON: {e}"))?;
        Ok(Materialized {
            digest: v
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or("`art heyvm materialize` reported no digest")?
                .to_string(),
            bytes_written: v.get("bytesWritten").and_then(|b| b.as_u64()).unwrap_or(0),
            method: v
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("copy")
                .to_string(),
        })
    }

    /// An `art` invocation against one store root, in JSON mode.
    ///
    /// `--root` rather than `ART_ROOT` so the store is visible in the process
    /// list next to the command that used it, and so an `ART_ROOT` inherited
    /// from app-lb's own environment cannot quietly redirect a pull.
    fn art(&self, root: &str) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.art_bin);
        cmd.arg("--root").arg(root).arg("--json");
        if let Some(home) = &self.home {
            cmd.env("HOME", home);
        }
        cmd
    }

    async fn run(&self, mut cmd: tokio::process::Command) -> Result<String, String> {
        let bin = self.art_bin.clone();
        let out = cmd
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => format!(
                    "{bin} is not on app-lb's PATH. A deployment pulling from a local store \
                     needs the `art` CLI on this host — install it, or set APP_LB_ART_BIN to \
                     its path, or point artifact.store at an `art serve` URL instead"
                ),
                _ => format!("could not run {bin}: {e}"),
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let msg = stderr.trim();
            return Err(format!(
                "{bin} exited {}{}",
                out.status.code().unwrap_or(-1),
                if msg.is_empty() {
                    String::new()
                } else {
                    format!(": {msg}")
                }
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    // -- shared ------------------------------------------------------------

    /// Grow if asked, then rename into place. Returns the final size.
    /// Whether the daemon already holds `image` at (at least) the size this
    /// pull would produce. The daemon's answer, so a catalog on another host
    /// is as good as one on this one.
    async fn usable_on_daemon(
        &self,
        image: &str,
        expected_size: u64,
        grow_gb: Option<u64>,
    ) -> Result<Option<(PathBuf, u64)>, String> {
        let Some(info) = self
            .vms
            .image(image)
            .await
            .map_err(|e| format!("could not ask the daemon about {image}: {e}"))?
        else {
            return Ok(None);
        };
        Ok(image_is_usable(info.size_bytes, expected_size, grow_gb)
            .then(|| (PathBuf::from(info.path), info.size_bytes)))
    }

    /// Put a fetched or materialized image into the daemon's catalog under
    /// `image`, growing it there when asked (`?grow_gb=` — the daemon
    /// resizes the filesystem, not just the file). The scratch copy is
    /// removed either way; the daemon's path and size come back.
    async fn upload(
        &self,
        tmp: TempImage,
        image: &str,
        grow_gb: Option<u64>,
        log: &mut (dyn FnMut(String) + Send),
    ) -> Result<(PathBuf, u64), String> {
        self.preparation_stage("daemon_image_import");
        let local = tokio::fs::metadata(tmp.path())
            .await
            .map_err(|e| format!("stat {}: {e}", tmp.path().display()))?
            .len();
        log(format!("uploading {} to the daemon as {image}", human(local)));
        let opts = heyo_sdk::ImageUploadOptions {
            sha256: None,
            grow_gb,
        };
        let info = self
            .vms
            .upload_image(image, tmp.path(), &opts)
            .await
            .map_err(|e| format!("could not upload {image} to the daemon: {e}"))?;
        if info.size_bytes > local {
            log(format!("grown on the daemon from {} to {}", human(local), human(info.size_bytes)));
        }
        drop(tmp);
        Ok((PathBuf::from(info.path), info.size_bytes))
    }

    fn preparation_stage(&self, stage: &str) {
        if let Some(progress) = &self.preparation_progress {
            progress.send_replace(stage.to_string());
        }
    }

    async fn get(&self, url: &str, api_key: Option<&str>) -> reqwest::Result<reqwest::Response> {
        self.authed(self.http.get(url), api_key).send().await
    }

    async fn head(&self, url: &str, api_key: Option<&str>) -> reqwest::Result<reqwest::Response> {
        self.authed(self.http.head(url), api_key).send().await
    }

    /// `Authorization: Bearer`, which the store accepts alongside `X-Api-Key`.
    /// Bearer is the one that survives a proxy in between without a config
    /// change, since a custom header is the thing an intermediary strips.
    fn authed(&self, req: reqwest::RequestBuilder, api_key: Option<&str>) -> reqwest::RequestBuilder {
        match api_key {
            Some(k) => req.bearer_auth(k),
            None => req,
        }
    }
}

const CANDIDATE_MANIFEST_MAX_BYTES: usize = 1024 * 1024;

async fn candidate_manifest_bytes(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|n| n > CANDIDATE_MANIFEST_MAX_BYTES as u64) {
        return Err("candidate manifest exceeds 1 MiB".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > CANDIDATE_MANIFEST_MAX_BYTES - bytes.len() {
            return Err("candidate manifest exceeds 1 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct Materialized {
    digest: String,
    bytes_written: u64,
    method: String,
}

/// Just enough of the store's manifest to find a rootfs in it.
///
/// Deliberately not the `artifacts` crate's `Manifest`: taking that dependency
/// would pull an axum tree and a `libc` syscall layer into app-lb to read four
/// fields, and this side only ever *reads* a manifest. `#[serde(default)]` on
/// everything so a manifest gaining a field is not a failed pull.
#[derive(serde::Deserialize)]
struct Manifest {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    entries: Vec<ManifestEntry>,
    /// Free-form, and read only for defaults a caller may override. A value that
    /// does not parse is treated as absent — a build that refused to start over
    /// a malformed *default* would be worse than one that lets heyvm size the
    /// image itself.
    #[serde(default)]
    annotations: std::collections::BTreeMap<String, String>,
}

impl Manifest {
    fn size_mb(&self) -> Option<u64> {
        self.annotations.get(ANN_SIZE_MB)?.trim().parse().ok()
    }
}

/// Refuse a manifest that is not a recipe, by name and before anything is
/// fetched.
///
/// Worth its own check rather than letting the missing `Dockerfile` entry speak:
/// pointing `build.ref` at a rootfs tag is the obvious mistake, and "that is an
/// image, use `artifact` to pull it" is a different instruction from "that
/// manifest is malformed".
fn check_dockerfile_kind(m: &Manifest, reference: &str) -> Result<(), String> {
    if m.kind == KIND_DOCKERFILE {
        return Ok(());
    }
    Err(format!(
        "{reference:?} is a {:?} manifest, not {KIND_DOCKERFILE:?}. `build.store` names a \
         Dockerfile to build; a manifest holding an image that is already built is pulled \
         with an `artifact` block instead",
        m.kind
    ))
}

/// One entry of a manifest, by name.
fn named_entry<'a>(m: &'a Manifest, name: &str, reference: &str) -> Result<&'a ManifestEntry, String> {
    let e = m.entries.iter().find(|e| e.name == name).ok_or_else(|| {
        format!(
            "the manifest for {reference:?} has no {name:?} entry (it holds: {})",
            match m.entries.len() {
                0 => "nothing".to_string(),
                _ => m
                    .entries
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        )
    })?;
    if !is_digest(&e.digest) {
        return Err(format!(
            "the manifest for {reference:?} names {name:?} with digest {:?}, which is not a \
             sha256",
            e.digest
        ));
    }
    Ok(e)
}

/// A digest, short enough to read in a log line.
fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// One row of `GET /tags`.
#[derive(serde::Deserialize)]
struct TagEntry {
    tag: String,
    digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestEntry {
    #[serde(default)]
    name: String,
    digest: String,
    #[serde(default)]
    size: u64,
}

/// The blob a manifest is standing in for: the entry with the expected name, or
/// the only one.
///
/// Both rules are needed. `art heyvm import` writes a single-entry manifest and
/// names it `rootfs.ext4`, but a manifest holding one unrelated blob is still
/// unambiguous, and `art put --tag` produces exactly that. Anything else is
/// reported rather than guessed — picking an entry out of a bundle by position
/// would deploy whichever file happened to sort first.
///
/// `expected` is what the caller is looking for by name, and there is one only
/// for a rootfs: a site bundle has no filename convention, so it relies on the
/// single-entry rule alone.
fn blob_entry(m: &Manifest, reference: &str, expected: Option<&str>) -> Result<(String, u64), String> {
    let entry = expected
        .and_then(|name| m.entries.iter().find(|e| e.name == name))
        .or(if m.entries.len() == 1 {
            m.entries.first()
        } else {
            None
        });
    match entry {
        Some(e) if is_digest(&e.digest) => Ok((e.digest.clone(), e.size)),
        Some(e) => Err(format!(
            "the manifest for {reference:?} names {:?} with digest {:?}, which is not a sha256",
            e.name, e.digest
        )),
        None if m.entries.is_empty() => {
            Err(format!("the manifest for {reference:?} is empty"))
        }
        None => Err(format!(
            "the manifest for {reference:?} holds {} entries{}: {}. Tag the blob you want \
             directly — a manifest with several entries does not say which one this \
             deployment is for",
            m.entries.len(),
            match expected {
                Some(name) => format!(" and none is called {name}"),
                None => String::new(),
            },
            m.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", "),
        )),
    }
}


/// A partial image, removed unless it is committed.
///
/// The name is dotted and carries the pid, so a crash leaves something
/// identifiable in the image directory rather than a plausible-looking
/// `<name>.ext4` that `heyvm mvm images` would list and someone would boot. It
/// is in the image directory rather than `/tmp` so the commit is a rename on one
/// filesystem — across filesystems it would be a second full copy of a rootfs,
/// and a non-atomic one.
/// Whether an image already in the catalog can stand in for this pull: at
/// least the blob's length (a shorter one is the remains of a failed write),
/// and at least the size a `grow_gb` asks for — `grow_gb` is about the guest,
/// not the content, so it is not in the image's name, and without this an
/// image would keep being reused at its old length while the guest silently
/// got none of the room the spec now asks for.
fn image_is_usable(size: u64, expected_size: u64, grow_gb: Option<u64>) -> bool {
    let required = expected_size.max(grow_gb.map(|gb| gb * 1024 * 1024 * 1024).unwrap_or(0));
    required == 0 || size >= required
}

struct TempImage {
    path: PathBuf,
}

impl TempImage {
    fn new(dir: &Path, stem: &str) -> Self {
        Self {
            path: dir.join(format!(".{stem}.{}.ext4.part", std::process::id())),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

}

impl Drop for TempImage {
    fn drop(&mut self) {
        // Synchronous on purpose: `Drop` cannot await, and leaving a
        // multi-gigabyte partial file behind to be tidied up "later" means
        // the next pull on a full disk fails for the wrong reason.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A file removed when it goes out of scope, however the scope ends.
///
/// Unlike [`TempImage`] there is no commit: a bundle is read and discarded, and
/// what survives a site pull is the unpacked tree rather than the archive.
struct Scratch(PathBuf);

impl Scratch {
    fn new(path: PathBuf) -> Self {
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The directory counterpart of [`Scratch`]: a working directory removed on
/// drop, so every early return between "started unpacking" and "moved it into
/// place" cleans up after itself.
///
/// Nothing marks it committed, because nothing needs to: a commit *renames the
/// tree out* of this directory, and what is left is the husk this should remove
/// either way.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(path: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&path).map_err(|e| {
            format!("could not create the staging directory {}: {e}", path.display())
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A name no concurrent pull on this host will pick, for a staging directory.
///
/// The process id alone is not enough — one app-lb runs several pulls — and a
/// counter alone is not enough across a restart, so it is both, plus the clock
/// to separate two runs of the same pid that both start at zero.
fn unique_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos:x}-{n:x}", std::process::id())
}

/// Hash a file already on disk and confirm it is the blob that was asked for.
///
/// The wire path does this as the bytes land ([`Puller::fetch_blob`]); this is
/// for the local path, where `art get` hardlinks the blob and so writes — and
/// hashes — nothing at all. Cheap next to the unpack it precedes, and it is the
/// only thing standing between a store somebody has written to and a directory
/// this host serves.
async fn verify_file(path: &Path, digest: &str) -> Result<(), String> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("could not read {} back to verify it: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut read: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        read += n as u64;
    }

    let actual = hex(&hasher.finalize());
    if actual != digest {
        return Err(format!(
            "the store produced {read} bytes that hash to {actual}, but {digest} was asked \
             for — this is a corrupted or substituted bundle and it has not been unpacked"
        ));
    }
    Ok(())
}


fn is_digest(s: &str) -> bool {
    s.len() == DIGEST_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A deployment id is only constrained by the route table, and this ends up in a
/// filename.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .take(64)
        .collect()
}

/// An error body worth appending, or nothing. The store answers errors as JSON
/// with an `error` key; anything else is passed through trimmed.
fn detail(body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        return String::new();
    }
    let msg = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| Some(v.get("error")?.as_str()?.to_string()))
        .unwrap_or_else(|| body.chars().take(200).collect());
    format!(": {msg}")
}

/// Byte counts a person can read at a glance. Shared with the job records,
/// which report the same numbers.
pub fn human(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// The SHA-256 and length of a file, read once in 1 MiB chunks.
async fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("could not open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut len = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: &[(&str, &str, u64)]) -> Manifest {
        manifest_of("heyvm.rootfs.v1", entries)
    }

    fn manifest_of(kind: &str, entries: &[(&str, &str, u64)]) -> Manifest {
        Manifest {
            kind: kind.to_string(),
            entries: entries
                .iter()
                .map(|(name, digest, size)| ManifestEntry {
                    name: name.to_string(),
                    digest: digest.to_string(),
                    size: *size,
                })
                .collect(),
            annotations: Default::default(),
        }
    }

    fn d(prefix: &str) -> String {
        let mut s = prefix.to_string();
        while s.len() < DIGEST_HEX_LEN {
            s.push('a');
        }
        s
    }

    /// What a rootfs pull looks for.
    fn rootfs_entry(m: &Manifest, reference: &str) -> Result<(String, u64), String> {
        blob_entry(m, reference, Some(ROOTFS_FILENAME))
    }

    #[test]
    fn a_dockerfile_manifest_yields_its_recipe_and_its_context() {
        let m = manifest_of(
            KIND_DOCKERFILE,
            &[
                (DOCKERFILE_ENTRY, &d("1111"), 812),
                (CONTEXT_ENTRY, &d("2222"), 40_213),
            ],
        );
        assert!(check_dockerfile_kind(&m, "web-rootfs").is_ok());
        assert_eq!(named_entry(&m, DOCKERFILE_ENTRY, "web").unwrap().digest, d("1111"));
        assert_eq!(named_entry(&m, CONTEXT_ENTRY, "web").unwrap().size, 40_213);
    }

    #[test]
    fn a_recipe_is_found_by_name_not_by_position() {
        // `context.tar.gz` sorts first. Picking entry zero would hand a gzip
        // file to `heyvm mvm build -f`.
        let m = manifest_of(
            KIND_DOCKERFILE,
            &[(CONTEXT_ENTRY, &d("2222"), 40), (DOCKERFILE_ENTRY, &d("1111"), 8)],
        );
        assert_eq!(named_entry(&m, DOCKERFILE_ENTRY, "web").unwrap().digest, d("1111"));
    }

    #[test]
    fn pointing_a_build_at_a_rootfs_manifest_says_to_pull_it_instead() {
        // The obvious mistake: `build.ref` given an image tag. "That is an image,
        // pull it" is a different instruction from "that manifest is malformed",
        // so the kind is checked before the entries are.
        let m = manifest(&[("rootfs.ext4", &d("c74abee2"), 4096)]);
        let e = check_dockerfile_kind(&m, "debian-hermes").unwrap_err();
        assert!(e.contains("heyvm.rootfs.v1"), "{e}");
        assert!(e.contains("artifact"), "{e}");
    }

    #[test]
    fn a_dockerfile_manifest_with_no_recipe_names_what_it_does_hold() {
        let m = manifest_of(KIND_DOCKERFILE, &[(CONTEXT_ENTRY, &d("2222"), 40)]);
        let e = named_entry(&m, DOCKERFILE_ENTRY, "web").unwrap_err();
        assert!(e.contains(CONTEXT_ENTRY), "{e}");

        let empty = manifest_of(KIND_DOCKERFILE, &[]);
        assert!(
            named_entry(&empty, DOCKERFILE_ENTRY, "web")
                .unwrap_err()
                .contains("nothing")
        );
    }

    #[test]
    fn a_size_annotation_is_a_default_and_never_a_failure() {
        let mut m = manifest_of(KIND_DOCKERFILE, &[(DOCKERFILE_ENTRY, &d("1111"), 8)]);
        assert_eq!(m.size_mb(), None);

        m.annotations.insert(ANN_SIZE_MB.into(), "4096".into());
        assert_eq!(m.size_mb(), Some(4096));

        // Annotations are free text on the store's side. A build that refused to
        // start over a malformed *default* would be worse than one that lets
        // heyvm size the image itself.
        m.annotations.insert(ANN_SIZE_MB.into(), "quite big".into());
        assert_eq!(m.size_mb(), None);
    }

    #[test]
    fn a_heyvm_import_manifest_resolves_to_its_rootfs() {
        let m = manifest(&[("rootfs.ext4", &d("c74abee2"), 21_474_836_480)]);
        assert_eq!(
            rootfs_entry(&m, "debian-hermes").unwrap(),
            (d("c74abee2"), 21_474_836_480)
        );
    }

    #[test]
    fn a_bundle_resolves_by_name_not_by_position() {
        // `manifest.json` sorts first; picking entry zero would boot it.
        let m = manifest(&[
            ("manifest.json", &d("1111"), 512),
            ("rootfs.ext4", &d("2222"), 4096),
        ]);
        assert_eq!(rootfs_entry(&m, "bundle").unwrap().0, d("2222"));
    }

    #[test]
    fn a_lone_entry_resolves_whatever_it_is_called() {
        // `art put --tag` names the entry after the file it came from.
        let m = manifest(&[("web.ext4", &d("3333"), 100)]);
        assert_eq!(rootfs_entry(&m, "web").unwrap().0, d("3333"));
    }

    /// A site bundle has no filename convention — `dist.tgz`, `site.tar`,
    /// whatever the CI job called it — so it resolves on the single-entry rule
    /// alone, and `rootfs.ext4` means nothing special to it.
    #[test]
    fn a_site_bundle_resolves_without_an_expected_name() {
        let m = manifest(&[("dist.tgz", &d("6666"), 4_194_304)]);
        assert_eq!(
            blob_entry(&m, "marketing-live", None).unwrap(),
            (d("6666"), 4_194_304)
        );

        // And with several entries it is ambiguous rather than guessed, even
        // though one of them is a rootfs: nothing says a site wants that one.
        let m = manifest(&[("rootfs.ext4", &d("7777"), 1), ("dist.tgz", &d("8888"), 2)]);
        let err = blob_entry(&m, "mixed", None).unwrap_err();
        assert!(err.contains("dist.tgz"), "{err}");
        assert!(!err.contains("none is called"), "no name was expected: {err}");
    }

    #[test]
    fn an_ambiguous_manifest_is_reported_with_what_it_holds() {
        let m = manifest(&[("a.img", &d("4444"), 1), ("b.img", &d("5555"), 2)]);
        let err = rootfs_entry(&m, "pair").unwrap_err();
        assert!(err.contains("a.img"), "{err}");
        assert!(err.contains("b.img"), "{err}");
        assert!(err.contains(ROOTFS_FILENAME), "it should name what it looked for: {err}");
    }

    #[test]
    fn an_empty_manifest_says_so_rather_than_panicking() {
        assert!(rootfs_entry(&manifest(&[]), "empty").is_err());
        assert!(blob_entry(&manifest(&[]), "empty", None).is_err());
    }

    #[test]
    fn a_manifest_entry_whose_digest_is_not_a_sha256_is_refused() {
        let m = manifest(&[("rootfs.ext4", "not-a-digest", 1)]);
        assert!(rootfs_entry(&m, "bad").is_err());
    }

    #[tokio::test]
    async fn a_bundle_that_is_not_the_blob_that_was_asked_for_is_refused() {
        let dir = std::env::temp_dir().join(format!("applb-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle");
        std::fs::write(&path, b"hello").unwrap();

        // sha256("hello")
        let real = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_file(&path, real).await.is_ok());

        let err = verify_file(&path, &d("dead")).await.unwrap_err();
        assert!(err.contains("has not been unpacked"), "{err}");
        assert!(err.contains(real), "it should report what it actually got: {err}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn digests_are_lowercase_hex_of_exactly_the_right_length() {
        assert!(is_digest(&d("c74abee2ce84")));
        assert!(!is_digest(&d("C74ABEE2")), "uppercase is a second spelling");
        assert!(!is_digest("c74abee2"), "too short");
        assert!(!is_digest(&(d("c74a") + "a")), "too long");
    }

    #[test]
    fn a_temp_image_is_removed_unless_it_is_committed() {
        let dir = std::env::temp_dir().join(format!("applb-art-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = {
            let tmp = TempImage::new(&dir, "web");
            std::fs::write(tmp.path(), b"partial").unwrap();
            tmp.path().to_path_buf()
        };
        assert!(!path.exists(), "a dropped temp image left {} behind", path.display());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The catalog's answer decides a reuse: at least the blob's length, and
    /// at least what a `grow_gb` asks for.
    #[test]
    fn an_image_shorter_than_its_blob_or_its_grow_gb_is_not_reused() {
        assert!(image_is_usable(9, 9, None));
        // A grown image is longer than the blob and still usable.
        assert!(image_is_usable(9, 4, None));
        // A short one is the remains of a failed write.
        assert!(!image_is_usable(9, 4096, None));
        assert!(image_is_usable(4096, 4096, None));
        assert!(
            !image_is_usable(4096, 4096, Some(1)),
            "a 4 KiB image cannot stand in for one asked to be 1 GiB"
        );
        assert!(image_is_usable(1 << 30, 4096, Some(1)));
        assert!(image_is_usable(0, 0, None), "an unknown size cannot refuse");
    }

    #[test]
    fn an_error_body_is_unwrapped_when_it_is_the_stores_json() {
        assert_eq!(detail(r#"{"error":"blob not found"}"#), ": blob not found");
        assert_eq!(detail("plain text"), ": plain text");
        assert_eq!(detail("  "), "");
    }

    #[test]
    fn byte_counts_are_readable() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(21_474_836_480), "20.0 GiB");
    }

    #[tokio::test]
    async fn rollout_rootfs_manifest_is_verified_before_its_blob_is_trusted() {
        use axum::{Router, routing::get, extract::{Path, State}, http::StatusCode, response::IntoResponse};
        const MANIFEST: &str = r#"{"schema":1,"kind":"heyvm.rootfs.v1","entries":[{"name":"rootfs.ext4","digest":"1111111111111111111111111111111111111111111111111111111111111111","size":123}],"annotations":{}}"#;
        // Independently computed with sha256sum, not from the resolver's output.
        const HASH: &str = "dd468e827f167dc1603d2f896da50dff2b6de2427d78dcc844dce55fed313104";
        let tamper = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let app = Router::new().route("/manifests/:id", get(|Path(id): Path<String>, State(tamper): State<std::sync::Arc<std::sync::atomic::AtomicBool>>| async move {
            if id != HASH { return StatusCode::NOT_FOUND.into_response(); }
            if tamper.load(std::sync::atomic::Ordering::SeqCst) { MANIFEST.replace("123", "124").into_response() }
            else { MANIFEST.into_response() }
        })).with_state(tamper.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let vms = crate::vm::VmManager::new(Some("http://127.0.0.1:1".into()), None, crate::mounts::MountStore::new(dir.path().join("mounts"), 0)).unwrap();
        let puller = Puller::new("art".into(), dir.path().join("scratch"), None, vms);
        let mut artifact: ArtifactSpec = serde_json::from_value(serde_json::json!({"store":base,"ref":HASH})).unwrap();
        assert_eq!(puller.pinned_rootfs(&artifact, None).await.unwrap(), "1".repeat(64));
        tamper.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(puller.pinned_rootfs(&artifact, None).await.unwrap_err().contains("digest mismatch"));
        artifact.artifact_ref = "2".repeat(64);
        assert_eq!(puller.pinned_rootfs(&artifact, None).await.unwrap(), "2".repeat(64), "blob refs must remain exact");
        server.abort();
    }

    #[tokio::test]
    async fn preparation_progress_distinguishes_http_failure_and_corrupt_blob_without_response_secrets() {
        use axum::{Router, routing::get, http::StatusCode};
        let app = Router::new()
            .route("/denied/blobs/:digest", get(|| async { (StatusCode::FORBIDDEN, "credential-super-secret") }))
            .route("/corrupt/blobs/:digest", get(|| async { "changed" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let vms = crate::vm::VmManager::new(Some("http://127.0.0.1:1".into()), None, crate::mounts::MountStore::new(dir.path().join("mounts"), 0)).unwrap();
        let mut candidate = Puller::new("art".into(), dir.path().join("scratch"), None, vms).for_candidate().unwrap();
        let (progress, stages) = tokio::sync::watch::channel("initializing".to_string());
        candidate.preparation_progress = Some(progress);
        for (mode, stage) in [("denied", "blob_http_403"), ("corrupt", "blob_digest_mismatch")] {
            let error = candidate.fetch_blob(&format!("{base}/{mode}"), &"a".repeat(64), None,
                &dir.path().join("blob"), 7, &mut |_| {}).await.unwrap_err();
            assert_eq!(&*stages.borrow(), stage);
            assert!(!error.contains("credential-super-secret"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn candidate_manifest_limit_covers_length_and_chunked_boundaries() {
        use axum::{Router, routing::get, extract::Path, response::IntoResponse, body::Body};
        let app = Router::new().route("/:mode/manifests/:size", get(|Path((mode, size)): Path<(String, usize)>| async move {
            let mut bytes = br#"{"schema":1,"kind":"heyvm.rootfs.v1","entries":[{"name":"rootfs.ext4","digest":"1111111111111111111111111111111111111111111111111111111111111111","size":123}],"annotations":{}}"#.to_vec();
            bytes.resize(size, b' ');
            if mode == "length" { return bytes.into_response(); }
            let chunks: Vec<_> = bytes.chunks(7919).map(|chunk| Ok::<_, std::io::Error>(chunk.to_vec())).collect();
            Body::from_stream(futures::stream::iter(chunks)).into_response()
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let vms = crate::vm::VmManager::new(Some("http://127.0.0.1:1".into()), None, crate::mounts::MountStore::new(dir.path().join("mounts"), 0)).unwrap();
        let legacy = Puller::new("art".into(), dir.path().join("scratch"), None, vms);
        let candidate = legacy.for_candidate().unwrap();
        for mode in ["length", "chunked"] {
            for size in [1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1] {
                let url = format!("{base}/{mode}/manifests/{size}");
                let response = candidate.get(&url, None).await.unwrap();
                assert_eq!(response.content_length().is_some(), mode == "length");
                let bytes = candidate_manifest_bytes(response).await;
                if size <= 1024 * 1024 { assert_eq!(bytes.unwrap().len(), size); }
                else { assert!(bytes.unwrap_err().contains("exceeds 1 MiB")); }
                let resolved = candidate.resolve_remote(&format!("{base}/{mode}"), &size.to_string(), None, Some(ROOTFS_FILENAME)).await;
                if size <= 1024 * 1024 { assert_eq!(resolved.unwrap(), ("1".repeat(64), 123)); }
                else {
                    assert!(resolved.unwrap_err().contains("exceeds 1 MiB"));
                    let artifact: ArtifactSpec = serde_json::from_value(serde_json::json!({"store":format!("{base}/{mode}"),"ref":size.to_string()})).unwrap();
                    assert!(legacy.pinned_rootfs(&artifact, None).await.unwrap_err().contains("exceeds 1 MiB"));
                    assert_eq!(legacy.resolve_remote(&format!("{base}/{mode}"), &size.to_string(), None, Some(ROOTFS_FILENAME)).await.unwrap(), ("1".repeat(64), 123), "legacy behavior is unchanged");
                }
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn candidate_requests_never_follow_bearer_redirects_but_legacy_still_does() {
        use axum::{Router, routing::get, http::{HeaderMap, StatusCode}, response::IntoResponse};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let leaks = Arc::new(AtomicUsize::new(0));
        let received = leaks.clone();
        let app = Router::new()
            .route("/manifests/:id", get(|| async { (StatusCode::TEMPORARY_REDIRECT, [("location", "/target")]).into_response() }))
            .route("/target", get(move |headers: HeaderMap| { let received = received.clone(); async move {
                assert_eq!(headers.get("authorization").unwrap(), "Bearer test-credential");
                received.fetch_add(1, Ordering::SeqCst);
                "redirected"
            }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let vms = crate::vm::VmManager::new(Some("http://127.0.0.1:1".into()), None, crate::mounts::MountStore::new(dir.path().join("mounts"), 0)).unwrap();
        let legacy = Puller::new("art".into(), dir.path().join("scratch"), None, vms);
        let candidate = legacy.for_candidate().unwrap();
        let artifact: ArtifactSpec = serde_json::from_value(serde_json::json!({"store":base,"ref":"a".repeat(64)})).unwrap();
        let url = format!("{base}/manifests/{}", artifact.artifact_ref);
        assert!(legacy.pinned_rootfs(&artifact, Some("test-credential")).await.is_err());
        assert_eq!(candidate.get(&url, Some("test-credential")).await.unwrap().status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(candidate.head(&url, Some("test-credential")).await.unwrap().status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(leaks.load(Ordering::SeqCst), 0, "candidate redirects must not reach even a same-origin credential sink");
        assert_eq!(legacy.get(&url, Some("test-credential")).await.unwrap().status(), StatusCode::OK);
        assert_eq!(leaks.load(Ordering::SeqCst), 1, "legacy client retains its existing policy");
        server.abort();
    }

    /// Both transports, against a real store, laying out a real recipe.
    ///
    /// Opt-in because it needs something this repository does not ship: a store
    /// with a Dockerfile manifest in it, and — for the local half — the `art`
    /// binary on `PATH`. The unit tests above pin the *shapes* app-lb parses;
    /// this is the one that proves those shapes are what `art` and `art serve`
    /// actually emit, which is the part no amount of hand-written JSON can
    /// establish.
    ///
    /// ```text
    /// export ART_ROOT=/tmp/store
    /// art dockerfile put ./Dockerfile --context ./app --tag proj
    /// ART_API_KEY=k art serve --listen 127.0.0.1:38099 &
    /// APP_LB_TEST_ART_ROOT=$ART_ROOT \
    /// APP_LB_TEST_ART_URL=http://127.0.0.1:38099 \
    /// APP_LB_TEST_ART_KEY=k APP_LB_TEST_ART_REF=proj \
    ///   cargo test --bin app-lb fetches_a_dockerfile -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "needs a live artifact store; see the doc comment"]
    async fn fetches_a_dockerfile_manifest_from_a_real_store() {
        let Ok(reference) = std::env::var("APP_LB_TEST_ART_REF") else {
            eprintln!("set APP_LB_TEST_ART_REF to run this");
            return;
        };
        let key = std::env::var("APP_LB_TEST_ART_KEY").ok();
        let puller = Puller::new(
            std::env::var("APP_LB_TEST_ART_BIN").unwrap_or_else(|_| "art".into()),
            std::env::temp_dir().join("applb-df-test-scratch"),
            None,
            crate::vm::VmManager::new(
                Some("http://127.0.0.1:1".into()),
                None,
                crate::mounts::MountStore::new(std::env::temp_dir().join("applb-df-test-mounts"), 0),
            )
            .unwrap(),
        );

        let scratch = std::env::temp_dir().join(format!("applb-df-test-{}", std::process::id()));
        for (label, store) in [
            ("url", std::env::var("APP_LB_TEST_ART_URL").ok()),
            ("root", std::env::var("APP_LB_TEST_ART_ROOT").ok()),
        ] {
            let Some(store) = store else { continue };
            let dir = scratch.join(label);
            let mut lines = Vec::new();
            let fetched = puller
                .fetch_dockerfile(&store, &reference, key.as_deref(), &dir, &mut |l| {
                    lines.push(l)
                })
                .await
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            eprintln!("[{label}] {}\n  {}", fetched.manifest, lines.join("\n  "));

            assert!(is_digest(&fetched.manifest), "{label}");
            let recipe = std::fs::read_to_string(&fetched.dockerfile)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert!(recipe.contains("FROM"), "{label}: {recipe:?}");
            // The context is a directory `heyvm mvm build -c` can be pointed at,
            // never the archive it arrived as.
            assert!(fetched.context.is_dir(), "{label}");
            assert!(
                !fetched.context.join(CONTEXT_ENTRY).exists()
                    && !fetched.dockerfile.with_file_name(CONTEXT_ENTRY).exists(),
                "{label}: the archive was left where a COPY could reach it",
            );
        }

        // The same reference through two transports must produce the same
        // manifest digest, or the image name would depend on how it was fetched.
        if scratch.join("url").is_dir() && scratch.join("root").is_dir() {
            assert_eq!(
                std::fs::read(scratch.join("url").join(DOCKERFILE_ENTRY)).unwrap(),
                std::fs::read(scratch.join("root").join(DOCKERFILE_ENTRY)).unwrap(),
            );
        }
        std::fs::remove_dir_all(&scratch).ok();
    }
}
