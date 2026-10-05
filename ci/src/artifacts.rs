//! Where build artifacts go: disk, S3, or the `artifacts` store.
//!
//! ## One store, and who moves the bytes into it
//!
//! A runner never owns release storage. With `ART_S3_BUCKET`, Sam's global
//! `art` store writes through to one authoritative bucket; regional daemons
//! are caches, not independent stores. CI uses its HTTP API, not CI's separate
//! raw-S3 sink. Controller and guest endpoints must address that same logical
//! store. Without a remote tier, separate art roots remain separate stores.
//!
//! Who *moves the bytes* there is a separate question, answered by
//! [`ArtifactSink::guest_push`]. The orchestrator's own path — read the file out
//! of the guest, push it onward — is the only one that works for every sink,
//! and it is slow on firecracker: the read is exec output, and exec output is
//! the emulated serial console, tens of KiB/s. app-obs's 40 MB tarball spent a
//! quarter of an hour leaving its VM that way. So a sink that is an HTTP store
//! with a content-addressed blob route hands out a [`GuestPush`], the guest
//! `curl -T`s the blob itself at network speed, and the orchestrator verifies
//! it landed and then writes the manifest, tag and labels — the parts that
//! name the artifact and that only it knows the coordinates for. The blob is
//! the same bytes under the same digest whichever side sent it.
//!
//! ## Three constraints of the `artifacts` store shape the design
//!
//! - **CI uses flat tags** (`ci-<workflow>-<run>-<name>`) for compatibility.
//!   The global store also accepts namespaced `repo:tag` references. Release
//!   retention uses separate `release-*` roots and never moves a live alias.
//! - **Annotations must stay content-only.** The manifest is addressed by its
//!   own hash and carries no timestamp field on purpose, so an unchanged
//!   re-import dedupes. Putting a build time in an annotation would change the
//!   digest and destroy that. Mutable build metadata lives in `ci_artifact`,
//!   keyed by digest.
//! - **Deployments use digests, not mutable tags.** Tags resolve through
//!   `GET /manifests/{tag}`; the global store also exposes `GET /tags/{name}`.
//!
//! ## Labels: what a person sees in the store
//!
//! The three constraints above are why the store's own view of a CI artifact
//! used to be a digest, a flattened tag and a bag of `ci.*` annotations nobody
//! reads. `PUT /labels/{digest}` is the store's answer: mutable metadata keyed
//! by digest, which — unlike an annotation — can say what something *is* without
//! changing the manifest's hash and breaking dedup.
//!
//! So the push sets one on both objects it creates. The blob's names the file;
//! the manifest's names the artifact, and carries whatever the workflow's
//! `description:` said. A store fronted by `art serve` then lists "app-lb — the
//! proxy and heyctl, release build" rather than twelve hex characters.
//!
//! ## Public links
//!
//! A workflow that says `public: true` on its upload wants the tarball
//! fetchable by link — an install script on a fresh host, a download in a
//! README — with no `ART_API_KEY` in hand. The store's `PUT /public/{digest}`
//! is exactly that and no more: it opens anonymous `GET`/`HEAD /blobs/{digest}`
//! for that one blob, while the tag, the manifest, every listing and every
//! write stay behind the key. So the push flags the blob after naming it and
//! reports the resulting `{store}/blobs/{digest}` as the artifact's public
//! link. Refused rather than skipped when the store cannot do it: a build that
//! promised a public link and produced a 401 has failed, however green the
//! rest of it was.
//!
//! The push sequence is lifted from `app-lb/serverctl/src/artifact.rs`: hash,
//! `HEAD /blobs/{digest}` (a 404 is an answer, not an error), `PUT
//! /blobs/{digest}` with an explicit `Content-Length` so the store's free-space
//! guard can refuse before the first byte, `PUT /manifests`, `PUT /tags/{name}`.

use crate::config::{ArtifactSinkKind, ArtifactsConfig, Config, S3Config};
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;

/// What a stored artifact is, once stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifact {
    pub sink: &'static str,
    /// SHA256 for disk and content-addressed uploads. Older disk records may
    /// omit it; downloads of those records can only verify their size.
    pub digest: Option<String>,
    pub size_bytes: u64,
    /// How to get it back — a path, an `s3://` URL, or a tag.
    pub uri: String,
    /// Where anyone can fetch it with no credential, when the workflow asked
    /// for that (`with.public: true`) and the sink could grant it. Only the
    /// `artifacts` sink can — a blob it has marked public answers `GET
    /// /blobs/{digest}` anonymously — so this is `None` for disk and S3
    /// whatever the workflow said.
    pub public_url: Option<String>,
}

/// Which run and job an artifact belongs to.
#[derive(Debug, Clone)]
pub struct ArtifactRef {
    pub run_id: String,
    pub job_key: String,
    pub workflow_id: String,
    pub name: String,
    /// What the workflow's `description:` said, if anything.
    ///
    /// Only the `artifacts` sink has anywhere to put it — disk and S3 store a
    /// file and a key — which is why it is `Option` rather than a defaulted
    /// string: absent means "the workflow said nothing", and a sink with no
    /// concept of a description ignores it either way.
    pub description: Option<String>,
    /// The workflow's `public: true`: once stored, the tarball should be
    /// fetchable by anyone who has its link. Download-only — the store's
    /// public flag opens `GET /blobs/{digest}` for that one digest and nothing
    /// else, so the tag, the manifest and every listing stay behind the key.
    pub public: bool,
    /// A second, **stable** tag to move onto this upload — the workflow's
    /// `alias:`.
    ///
    /// [`tag_for`] names an artifact after the run that made it, which is
    /// right for addressing one build and useless for following the newest:
    /// a deployment pinned to `ci-…-00000004-release-retail` keeps serving
    /// that build forever, and every release needs somebody to repoint it by
    /// hand. An alias is the moving half of the pair — `retail-live` — so a
    /// deployment names it once and a pull takes whatever the last green run
    /// published.
    ///
    /// Refused if it starts with `ci-`: that prefix belongs to the per-run
    /// tags, and an alias that could overwrite one would let a workflow
    /// rewrite another run's address.
    pub alias: Option<String>,
}

/// What a guest needs to push a blob into the store itself: where, and as
/// whom. See the module docs for why this exists.
///
/// The token is the sink's own write token. There is no narrower credential to
/// hand out — the store has no scoped or short-lived keys — so it goes to the
/// guest for the one exec that uses it, through the exec `env`, the same route
/// every `env:` secret of a `run:` step already takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPush {
    /// Base URL of the store as the guest reaches it.
    pub url: String,
    pub token: Option<String>,
}

/// Identity of a raw ext4 publication. Unlike [`StoredArtifact`], the digest
/// here names the rootfs manifest (the reference app-lb consumes), while
/// `blob_digest` names the bytes pushed by the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRootfs {
    pub store_url: String,
    pub manifest_digest: String,
    pub blob_digest: String,
    pub size_bytes: u64,
}

#[async_trait]
pub trait ArtifactSink: Send + Sync {
    /// Store `bytes` the orchestrator has in hand.
    async fn put(&self, r: &ArtifactRef, bytes: Vec<u8>) -> Result<StoredArtifact, ArtifactError>;

    /// Read bytes named by a database record through this configured sink.
    /// Implementations must not treat `uri` as a caller-provided URL/path.
    async fn get(&self, stored: &StoredArtifact) -> Result<Vec<u8>, ArtifactError>;

    /// Give an already-stored artifact a release-owned GC root. Sinks must
    /// opt in: retaining a path or object without a verifiable pin would let a
    /// release catalog promise durability the sink does not provide.
    async fn retain(
        &self,
        stored: &StoredArtifact,
        key: &str,
    ) -> Result<StoredArtifact, ArtifactError> {
        let _ = (stored, key);
        Err(ArtifactError::Misconfigured(format!(
            "the {} sink does not support release artifact retention",
            self.kind()
        )))
    }

    /// How a guest can push a blob into this sink directly, if it can at all.
    /// `None` — the default — means the orchestrator reads the bytes out of the
    /// guest and calls [`Self::put`].
    fn guest_push(&self) -> Option<GuestPush> {
        None
    }

    /// Finish storing a blob the guest has already pushed: verify the sink
    /// holds `digest` at `size` bytes, then record it as `r` the way
    /// [`Self::put`] would have. Only meaningful for a sink whose
    /// [`Self::guest_push`] is `Some`.
    async fn put_pushed(
        &self,
        r: &ArtifactRef,
        digest: &str,
        size: u64,
    ) -> Result<StoredArtifact, ArtifactError> {
        let _ = (r, size);
        Err(ArtifactError::Misconfigured(format!(
            "the {} sink cannot accept a blob pushed from a guest (digest {digest})",
            self.kind()
        )))
    }

    /// Finish an already-pushed raw ext4 image as a bootable rootfs manifest.
    /// This is opt-in so disk/S3 can never masquerade as a rootfs registry.
    async fn publish_pushed_rootfs(
        &self, digest: &str, size: u64, image: &str,
    ) -> Result<PublishedRootfs, ArtifactError> {
        let _ = (size, image);
        Err(ArtifactError::Misconfigured(format!(
            "the {} sink is not a rootfs registry (blob {digest})", self.kind()
        )))
    }

    fn kind(&self) -> &'static str;
}

/// Build the configured sink.
pub fn sink_for(config: &Config) -> Result<Box<dyn ArtifactSink>, ArtifactError> {
    match config.artifact_sink {
        ArtifactSinkKind::Disk => Ok(Box::new(DiskSink {
            root: config.artifact_dir.clone(),
        })),
        ArtifactSinkKind::S3 => {
            let s3 = config
                .s3
                .clone()
                .ok_or_else(|| ArtifactError::Misconfigured("CI_S3_BUCKET is not set".into()))?;
            Ok(Box::new(S3Sink::new(s3)?))
        }
        ArtifactSinkKind::Artifacts => {
            let a = config
                .artifacts
                .clone()
                .ok_or_else(|| ArtifactError::Misconfigured("CI_ARTIFACT_URL is not set".into()))?;
            Ok(Box::new(ArtifactsSink::new(a)))
        }
    }
}

// ---- disk ---------------------------------------------------------------

pub struct DiskSink {
    root: PathBuf,
}

#[async_trait]
impl ArtifactSink for DiskSink {
    fn kind(&self) -> &'static str {
        "disk"
    }

    async fn put(&self, r: &ArtifactRef, bytes: Vec<u8>) -> Result<StoredArtifact, ArtifactError> {
        let path = self
            .root
            .join(safe(&r.run_id))
            .join(safe(&r.job_key))
            .join(safe(&r.name));
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ArtifactError::Io(format!("{}: {e}", parent.display())))?;
        }
        let size = bytes.len() as u64;
        let digest = hex::encode(Sha256::digest(&bytes));
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|e| ArtifactError::Io(format!("{}: {e}", path.display())))?;
        Ok(StoredArtifact {
            sink: "disk",
            digest: Some(digest),
            size_bytes: size,
            uri: path.to_string_lossy().into_owned(),
            public_url: None,
        })
    }

    async fn get(&self, stored: &StoredArtifact) -> Result<Vec<u8>, ArtifactError> {
        if stored.sink != self.kind() {
            return Err(ArtifactError::InvalidRecord(format!("artifact was recorded for the {} sink, not disk", stored.sink)));
        }
        let root = tokio::fs::canonicalize(&self.root).await
            .map_err(|e| ArtifactError::Io(format!("resolving artifact directory: {e}")))?;
        let path = tokio::fs::canonicalize(&stored.uri).await
            .map_err(|e| ArtifactError::Io(format!("resolving recorded artifact: {e}")))?;
        if !path.starts_with(&root) {
            return Err(ArtifactError::InvalidRecord("disk artifact path is outside the configured artifact directory".into()));
        }
        let bytes = tokio::fs::read(&path).await
            .map_err(|e| ArtifactError::Io(format!("reading {}: {e}", path.display())))?;
        validate(stored, &bytes)?;
        Ok(bytes)
    }
}

// ---- s3 -----------------------------------------------------------------

pub struct S3Sink {
    config: S3Config,
    client: tokio::sync::OnceCell<aws_sdk_s3::Client>,
}

#[async_trait]
impl ArtifactSink for S3Sink {
    fn kind(&self) -> &'static str {
        "s3"
    }

    async fn put(&self, r: &ArtifactRef, bytes: Vec<u8>) -> Result<StoredArtifact, ArtifactError> {
        let key = self.key_for(r);
        let size = bytes.len() as u64;
        let digest = hex::encode(Sha256::digest(&bytes));
        self.client()
            .await?
            .put_object()
            .bucket(&self.config.bucket)
            .key(&key)
            .content_length(size as i64)
            .content_type("application/octet-stream")
            .metadata("sha256", &digest)
            .body(bytes.into())
            .send()
            .await
            .map_err(|e| {
                ArtifactError::Transport(format!("S3 PUT s3://{}/{key}: {e}", self.config.bucket))
            })?;
        Ok(StoredArtifact {
            sink: "s3",
            digest: Some(digest),
            size_bytes: size,
            uri: format!("s3://{}/{key}", self.config.bucket),
            public_url: None,
        })
    }

    async fn get(&self, stored: &StoredArtifact) -> Result<Vec<u8>, ArtifactError> {
        if stored.sink != self.kind() {
            return Err(ArtifactError::InvalidRecord(format!(
                "artifact was recorded for the {} sink, not s3",
                stored.sink
            )));
        }
        let key = self.key_from_uri(&stored.uri)?;
        let response = self
            .client()
            .await?
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(format!("S3 GET {}: {e}", stored.uri)))?;
        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| {
                ArtifactError::Transport(format!("reading S3 object {}: {e}", stored.uri))
            })?
            .into_bytes()
            .to_vec();
        validate(stored, &bytes)?;
        Ok(bytes)
    }
}

impl S3Sink {
    pub fn new(config: S3Config) -> Result<Self, ArtifactError> {
        if config.bucket.trim().is_empty() {
            return Err(ArtifactError::Misconfigured("CI_S3_BUCKET is empty".into()));
        }
        if let Some(endpoint) = &config.endpoint {
            reqwest::Url::parse(endpoint).map_err(|e| {
                ArtifactError::Misconfigured(format!("CI_S3_ENDPOINT is not a valid URL: {e}"))
            })?;
        }
        Ok(Self {
            config,
            client: tokio::sync::OnceCell::new(),
        })
    }

    #[cfg(test)]
    fn with_client(config: S3Config, client: aws_sdk_s3::Client) -> Self {
        let cell = tokio::sync::OnceCell::new();
        cell.set(client).expect("new S3 client cell");
        Self {
            config,
            client: cell,
        }
    }

    async fn client(&self) -> Result<&aws_sdk_s3::Client, ArtifactError> {
        self.client
            .get_or_try_init(|| async {
                let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
                if let Some(region) = &self.config.region {
                    loader = loader.region(aws_sdk_s3::config::Region::new(region.clone()));
                }
                let shared = loader.load().await;
                let mut builder = aws_sdk_s3::config::Builder::from(&shared);
                if let Some(endpoint) = &self.config.endpoint {
                    builder = builder.endpoint_url(endpoint).force_path_style(true);
                }
                Ok(aws_sdk_s3::Client::from_conf(builder.build()))
            })
            .await
    }

    fn key_for(&self, r: &ArtifactRef) -> String {
        let suffix = format!("{}/{}/{}", safe(&r.run_id), safe(&r.job_key), safe(&r.name));
        let prefix = self.config.prefix.trim_matches('/');
        if prefix.is_empty() {
            suffix
        } else {
            format!("{prefix}/{suffix}")
        }
    }

    fn key_from_uri<'a>(&self, uri: &'a str) -> Result<&'a str, ArtifactError> {
        let rest = uri.strip_prefix("s3://").ok_or_else(|| {
            ArtifactError::InvalidRecord("S3 artifact URI must start with s3://".into())
        })?;
        let (bucket, key) = rest.split_once('/').ok_or_else(|| {
            ArtifactError::InvalidRecord("S3 artifact URI has no object key".into())
        })?;
        if bucket != self.config.bucket {
            return Err(ArtifactError::InvalidRecord(
                "S3 artifact URI names a foreign bucket".into(),
            ));
        }
        let prefix = self.config.prefix.trim_matches('/');
        if key.is_empty() || (!prefix.is_empty() && !key.starts_with(&format!("{prefix}/"))) {
            return Err(ArtifactError::InvalidRecord(
                "S3 artifact URI is outside the configured prefix".into(),
            ));
        }
        Ok(key)
    }
}

// ---- the artifacts store ------------------------------------------------

pub struct ArtifactsSink {
    http: reqwest::Client,
    config: ArtifactsConfig,
}

impl ArtifactsSink {
    pub fn new(config: ArtifactsConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.token {
            Some(t) => rb.bearer_auth(t),
            None => rb,
        }
    }
}

#[async_trait]
impl ArtifactSink for ArtifactsSink {
    fn kind(&self) -> &'static str {
        "artifacts"
    }

    async fn put(&self, r: &ArtifactRef, bytes: Vec<u8>) -> Result<StoredArtifact, ArtifactError> {
        let base = &self.config.url;
        let size = bytes.len() as u64;
        let digest = hex::encode(Sha256::digest(&bytes));

        // A 404 here is the answer "not stored yet", not a failure — the same
        // distinction serverctl's client makes.
        if self.stat_blob(&digest).await?.is_none() {
            let put = self
                .auth(self.http.put(format!("{base}/blobs/{digest}")))
                // Explicit, so the store's free-space guard can refuse before
                // the first byte crosses rather than after the last.
                .header(reqwest::header::CONTENT_LENGTH, size)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes)
                .send()
                .await
                .map_err(|e| ArtifactError::Transport(e.to_string()))?;
            check(put, "uploading a blob").await?;
        }

        self.finish(r, digest, size).await
    }

    async fn get(&self, stored: &StoredArtifact) -> Result<Vec<u8>, ArtifactError> {
        if stored.sink != self.kind() {
            return Err(ArtifactError::InvalidRecord(format!("artifact was recorded for the {} sink, not artifacts", stored.sink)));
        }
        let digest = stored.digest.as_deref().ok_or_else(||
            ArtifactError::InvalidRecord("artifacts-store record has no digest".into()))?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ArtifactError::InvalidRecord("artifacts-store record has an invalid digest".into()));
        }
        let response = self.auth(self.http.get(format!("{}/blobs/{digest}", self.config.url)))
            .send().await.map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let bytes = check(response, "downloading a blob").await?.bytes().await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?.to_vec();
        validate(stored, &bytes)?;
        Ok(bytes)
    }

    async fn retain(
        &self,
        stored: &StoredArtifact,
        key: &str,
    ) -> Result<StoredArtifact, ArtifactError> {
        if stored.sink != self.kind() {
            return Err(ArtifactError::InvalidRecord(format!(
                "artifact was recorded for the {} sink, not artifacts",
                stored.sink
            )));
        }
        if key.is_empty() {
            return Err(ArtifactError::InvalidRecord("release retention key is empty".into()));
        }
        let digest = stored.digest.as_deref().ok_or_else(|| {
            ArtifactError::InvalidRecord("artifacts-store record has no digest".into())
        })?;
        validate_digest(digest)?;
        self.verify_retained_blob(digest, stored.size_bytes).await?;

        // Build this only from immutable recorded content. In particular, do
        // not resolve `stored.uri`: it may be an alias that has since moved.
        let manifest = retained_manifest(digest, stored.size_bytes, key);
        let response = self
            .auth(self.http.put(format!("{}/manifests", self.config.url)))
            .json(&manifest)
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let body: Value = check(response, "storing a release retention manifest")
            .await?
            .json()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let manifest_digest = body.get("digest").and_then(Value::as_str).ok_or_else(|| {
            ArtifactError::InvalidRecord("store omitted the retention manifest digest".into())
        })?;
        validate_digest(manifest_digest)?;

        let tag = retention_tag(key);
        let response = self
            .auth(self.http.put(format!("{}/tags/{tag}", self.config.url)))
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(manifest_digest.to_string())
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        check(response, "setting a release retention tag").await?;

        // Confirm the root still points at bytes with the recorded identity
        // after pinning; this also catches a store/configuration mismatch.
        self.verify_retained_blob(digest, stored.size_bytes).await?;
        Ok(StoredArtifact { uri: tag, ..stored.clone() })
    }

    fn guest_push(&self) -> Option<GuestPush> {
        Some(GuestPush {
            url: self.config.url_for_guest().to_string(),
            token: self.config.token.clone(),
        })
    }

    /// The guest said the store answered its `PUT /blobs/{digest}` with a 2xx.
    /// Ask the store, not the guest: a `HEAD` for the digest, with the size the
    /// guest measured checked against the one the store reports. Only then is
    /// the artifact named — a manifest pointing at a blob that is not there
    /// would be a tag that resolves to a 404 on somebody's install.
    async fn put_pushed(
        &self,
        r: &ArtifactRef,
        digest: &str,
        size: u64,
    ) -> Result<StoredArtifact, ArtifactError> {
        match self.stat_blob(digest).await? {
            None => Err(ArtifactError::NotPushed {
                digest: digest.to_string(),
                detail: "the store does not have it".to_string(),
            }),
            Some(Some(stored)) if stored != size => Err(ArtifactError::NotPushed {
                digest: digest.to_string(),
                detail: format!("the guest measured {size} bytes, the store holds {stored}"),
            }),
            Some(_) => self.finish(r, digest.to_string(), size).await,
        }
    }

    async fn publish_pushed_rootfs(
        &self, digest: &str, size: u64, image: &str,
    ) -> Result<PublishedRootfs, ArtifactError> {
        validate_digest(digest)?;
        if image.trim().is_empty() {
            return Err(ArtifactError::InvalidRecord("rootfs image name is empty".into()));
        }
        match self.stat_blob(digest).await? {
            None => return Err(ArtifactError::NotPushed { digest: digest.into(), detail: "the store does not have it".into() }),
            Some(Some(stored)) if stored != size => return Err(ArtifactError::NotPushed {
                digest: digest.into(), detail: format!("the guest measured {size} bytes, the store holds {stored}"),
            }),
            // A rootfs publication requires a verified HEAD size, rather than
            // accepting an old store that omitted Content-Length.
            Some(None) => return Err(ArtifactError::NotPushed { digest: digest.into(), detail: "HEAD did not report a Content-Length".into() }),
            Some(Some(_)) => {}
        }
        let manifest = rootfs_manifest(digest, size, image);
        let response = self.auth(self.http.put(format!("{}/manifests", self.config.url)))
            .json(&manifest).send().await.map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let body: serde_json::Value = check(response, "storing a rootfs manifest").await?
            .json().await.map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let manifest_digest = body.get("digest").and_then(Value::as_str)
            .ok_or_else(|| ArtifactError::InvalidRecord("store omitted the rootfs manifest digest".into()))?;
        validate_digest(manifest_digest)?;
        Ok(PublishedRootfs { store_url: self.config.url.trim_end_matches('/').into(),
            manifest_digest: manifest_digest.into(), blob_digest: digest.into(), size_bytes: size })
    }
}

impl ArtifactsSink {
    async fn verify_retained_blob(&self, digest: &str, size: u64) -> Result<(), ArtifactError> {
        match self.stat_blob(digest).await? {
            None => Err(ArtifactError::InvalidRecord(format!(
                "retained blob {digest} is missing from the configured artifact store"
            ))),
            Some(None) => Err(ArtifactError::InvalidRecord(format!(
                "HEAD for retained blob {digest} omitted Content-Length"
            ))),
            Some(Some(actual)) if actual != size => Err(ArtifactError::InvalidRecord(format!(
                "retained blob {digest} has size {actual}, expected {size}"
            ))),
            Some(Some(_)) => Ok(()),
        }
    }

    /// `HEAD /blobs/{digest}`: `None` when the store does not have it, else the
    /// size it reports (which a store predating `Content-Length` on HEAD may
    /// omit, hence the inner `Option`).
    async fn stat_blob(&self, digest: &str) -> Result<Option<Option<u64>>, ArtifactError> {
        let base = &self.config.url;
        let head = self
            .auth(self.http.head(format!("{base}/blobs/{digest}")))
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        if head.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let head = check(head, "checking for a blob").await?;
        let size = head
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        Ok(Some(size))
    }

    /// Everything after the blob is in the store: manifest, tag, labels.
    async fn finish(
        &self,
        r: &ArtifactRef,
        digest: String,
        size: u64,
    ) -> Result<StoredArtifact, ArtifactError> {
        let base = &self.config.url;
        let manifest = manifest_for(r, &digest, size);
        let put_manifest = self
            .auth(self.http.put(format!("{base}/manifests")))
            .json(&manifest)
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let manifest_digest: serde_json::Value = check(put_manifest, "storing a manifest")
            .await?
            .json()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        let manifest_digest = manifest_digest
            .get("digest")
            .and_then(|v| v.as_str())
            .unwrap_or(&digest)
            .to_string();

        let tag = tag_for(r);
        let put_tag = self
            .auth(self.http.put(format!("{base}/tags/{tag}")))
            // The body is the bare digest as text/plain, not JSON.
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(manifest_digest.clone())
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        check(put_tag, "setting a tag").await?;

        // The alias, if the workflow asked for one. It fails the upload rather
        // than being best-effort like a label: an alias is what a deployment
        // *resolves through*, so a run that stored bytes but left the alias on
        // the previous build has published nothing and must say so.
        if let Some(alias) = r.alias.as_deref() {
            let alias = validate_alias(alias)?;
            let put_alias = self
                .auth(self.http.put(format!("{base}/tags/{alias}")))
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .body(manifest_digest.clone())
                .send()
                .await
                .map_err(|e| ArtifactError::Transport(e.to_string()))?;
            check(put_alias, "moving the alias tag").await?;
        }

        // The public flag goes on the blob, by digest, after it is named and
        // before the labels: a failure here must fail the upload — a workflow
        // that asked for a public link and got a build that 401s on it has
        // been lied to — but the tag is already set, so what a re-run sees
        // is a store that dedups the bytes and only the flag to redo.
        let public_url = if r.public {
            Some(self.make_public(&digest).await?)
        } else {
            None
        };

        // Both objects get a label, and they say different things: the blob is
        // the tarball, the manifest is the artifact. Which matters on the blob
        // page, where the only other thing on offer is a size.
        //
        // Best-effort, and deliberately last. A label is what the store shows a
        // person, not what a client resolves through — so a store too old to
        // have the route, or one that refuses the write, must leave the upload
        // succeeded rather than fail a build over a caption.
        self.label(
            &digest,
            &format!("{} ({})", r.name, r.workflow_id),
            r.description.as_deref(),
        )
        .await;
        self.label(&manifest_digest, &r.name, r.description.as_deref())
            .await;

        Ok(StoredArtifact {
            sink: "artifacts",
            digest: Some(digest),
            size_bytes: size,
            uri: tag,
            public_url,
        })
    }

    /// `PUT /public/{digest}`: open anonymous `GET /blobs/{digest}` for this
    /// one blob. Returns the link to hand out — the store's answer carries a
    /// path, and the base is the URL the orchestrator reaches the store by,
    /// which is the one people reach it by too (`CI_ARTIFACT_GUEST_URL` is a
    /// guest-only alias and never the link).
    async fn make_public(&self, digest: &str) -> Result<String, ArtifactError> {
        let base = &self.config.url;
        let put = self
            .auth(self.http.put(format!("{base}/public/{digest}")))
            .send()
            .await
            .map_err(|e| ArtifactError::Transport(e.to_string()))?;
        // A store predating public downloads has no such route, and its 404
        // looks exactly like "no such blob" — which cannot be, the blob was
        // HEADed and tagged moments ago. Say what to do rather than "not
        // found".
        if put.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ArtifactError::Store {
                what: "making the blob public".to_string(),
                status: 404,
                slug: "no_public_route".to_string(),
                message: format!(
                    "{base} answered 404 to PUT /public/{digest}; it predates public \
                     downloads. Upgrade the store, or drop `public: true` from the \
                     upload step"
                ),
            });
        }
        check(put, "making the blob public").await?;
        Ok(format!("{base}/blobs/{digest}"))
    }
}

impl ArtifactsSink {
    /// Name and describe one digest, ignoring every way it can fail.
    ///
    /// Logged rather than returned: every caller is on the success path of an
    /// upload that has already stored the bytes, and there is no outcome here
    /// that should turn a green build red.
    async fn label(&self, digest: &str, name: &str, description: Option<&str>) {
        let base = &self.config.url;
        let body = serde_json::json!({ "name": name, "description": description });
        match self
            .auth(self.http.put(format!("{base}/labels/{digest}")))
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {}
            // A 404 is the ordinary answer from a store predating labels, and
            // is not worth a warning on every upload.
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                tracing::debug!(digest, "the store has no /labels route; skipping");
            }
            Ok(r) => tracing::warn!(digest, status = %r.status(), "could not label an artifact"),
            Err(e) => tracing::warn!(digest, error = %e, "could not label an artifact"),
        }
    }
}

async fn check(
    response: reqwest::Response,
    what: &str,
) -> Result<reqwest::Response, ArtifactError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    let slug = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("no detail");
    Err(ArtifactError::Store {
        what: what.to_string(),
        status: status.as_u16(),
        slug: slug.to_string(),
        message: message.to_string(),
    })
}

/// The manifest for one artifact.
///
/// Content-only: no timestamps, no run duration, nothing that varies between two
/// builds of identical bytes. The manifest is addressed by its own hash, so an
/// unchanged re-upload has to produce the same digest or dedup stops working.
/// The run id *is* included, because two runs producing the same bytes are still
/// two artifacts a user needs to tell apart — and the tag already encodes it.
fn manifest_for(r: &ArtifactRef, digest: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "kind": "generic",
        "entries": [{ "name": r.name, "digest": digest, "size": size }],
        "annotations": {
            "ci.workflow": r.workflow_id,
            "ci.run": r.run_id,
            "ci.job": r.job_key,
            "ci.name": r.name,
        }
    })
}

fn rootfs_manifest(digest: &str, size: u64, image: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": 1, "kind": "heyvm.rootfs.v1",
        "entries": [{"name":"rootfs.ext4", "digest":digest, "size":size}],
        "annotations": {"heyvm.image":image, "heyvm.nominal_size":size.to_string(), "heyvm.primitive":"ext4_raw"}
    })
}

fn retained_manifest(digest: &str, size: u64, key: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": 1,
        "kind": "generic",
        "entries": [{"name": "artifact", "digest": digest, "size": size}],
        "annotations": {"ci.release.key": key}
    })
}

/// Stable, legal GC-root name. The complete key is hashed rather than
/// sanitised or truncated; 224 hash bits fit after the release prefix.
fn retention_tag(key: &str) -> String {
    let hash = hex::encode(Sha256::digest(key.as_bytes()));
    format!("release-{}", &hash[..56])
}

fn validate_digest(digest: &str) -> Result<(), ArtifactError> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(ArtifactError::InvalidRecord("digest must be 64 lowercase hexadecimal characters".into()));
    }
    Ok(())
}

/// A tag the store will accept: `[A-Za-z0-9_.-]`, at most 64 characters, no
/// leading `-` or `.`.
///
/// Everything meaningful is also in the manifest annotations, so truncation
/// loses addressability, never information.
pub fn tag_for(r: &ArtifactRef) -> String {
    let raw = format!(
        "ci-{}-{}-{}-{}",
        safe(&r.workflow_id),
        safe(&r.run_id),
        safe(&r.job_key),
        safe(&r.name)
    );
    let mut tag: String = raw.chars().take(64).collect();
    while tag.starts_with('-') || tag.starts_with('.') {
        tag.remove(0);
    }
    if tag.is_empty() {
        tag.push_str("ci-artifact");
    }
    tag
}

/// An alias the store will accept, or why it will not.
///
/// Stricter than [`safe`] on purpose: a per-run tag is generated, so mangling
/// an odd character in it is a kindness, while an alias is typed by a person
/// into a workflow and then typed again into a deployment's `artifact.ref`. A
/// `retail live` silently stored as `retail-live` is two names for one thing
/// and a deployment that resolves neither.
pub fn validate_alias(alias: &str) -> Result<&str, ArtifactError> {
    let bad = |why: &str| {
        Err(ArtifactError::InvalidRecord(format!(
            "`alias: {alias}` is not a usable tag: {why}"
        )))
    };
    if alias.is_empty() || alias.len() > 64 {
        return bad("it must be 1 to 64 characters");
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return bad("only letters, digits, `-`, `_` and `.` are allowed");
    }
    if alias.starts_with('-') || alias.starts_with('.') {
        return bad("it may not start with `-` or `.`");
    }
    if alias.starts_with("ci-") {
        return bad("the `ci-` prefix names the per-run tags, which an alias must not overwrite");
    }
    Ok(alias)
}

/// Reduce a component to the tag/path charset.
fn safe(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    // `..` as a whole component would traverse on the disk sink.
    if out.chars().all(|c| c == '.') {
        return "-".to_string();
    }
    out
}

#[derive(Debug)]
pub enum ArtifactError {
    Misconfigured(String),
    Io(String),
    Transport(String),
    InvalidRecord(String),
    Corrupt(String),
    Store {
        what: String,
        status: u16,
        slug: String,
        message: String,
    },
    /// A guest reported pushing a blob the store then could not vouch for.
    NotPushed {
        digest: String,
        detail: String,
    },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misconfigured(e) => write!(f, "the artifact sink is misconfigured: {e}"),
            Self::Io(e) => write!(f, "writing an artifact: {e}"),
            Self::Transport(e) => write!(f, "could not reach the artifact store: {e}"),
            Self::InvalidRecord(e) => write!(f, "invalid recorded artifact: {e}"),
            Self::Corrupt(e) => write!(f, "downloaded artifact failed validation: {e}"),
            Self::Store {
                what,
                status,
                slug,
                message,
            } => {
                write!(f, "{what} failed ({status}")?;
                if !slug.is_empty() {
                    write!(f, " {slug}")?;
                }
                write!(f, "): {message}")?;
                // The store's own slugs, translated into what to do about them.
                match slug.as_str() {
                    "no_space" => write!(f, ". The store is full."),
                    "unauthorized" => write!(f, ". Check CI_ARTIFACT_TOKEN."),
                    "read_only" => write!(f, ". The store has ART_READ_ONLY set."),
                    "invalid_tag" => write!(
                        f,
                        ". A tag may only contain [A-Za-z0-9_.-] and must be at most \
                         64 characters."
                    ),
                    _ => Ok(()),
                }
            }
            Self::NotPushed { digest, detail } => write!(
                f,
                "the guest reported pushing blob {digest} to the store, but {detail}. \
                 Is CI_ARTIFACT_GUEST_URL the same store as CI_ARTIFACT_URL?"
            ),
        }
    }
}

fn validate(stored: &StoredArtifact, bytes: &[u8]) -> Result<(), ArtifactError> {
    if bytes.len() as u64 != stored.size_bytes {
        return Err(ArtifactError::Corrupt(format!("expected {} bytes, received {}", stored.size_bytes, bytes.len())));
    }
    if let Some(expected) = &stored.digest {
        let actual = hex::encode(Sha256::digest(bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(ArtifactError::Corrupt(format!("sha256 mismatch: expected {expected}, received {actual}")));
        }
    }
    Ok(())
}

impl std::error::Error for ArtifactError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::path::Path;

    fn aref() -> ArtifactRef {
        ArtifactRef {
            run_id: "019fca648a6e-00000000".into(),
            job_key: "build-x86_64".into(),
            workflow_id: "myapp".into(),
            name: "binary.tar.gz".into(),
            description: None,
            public: false,
            alias: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn global_store_release_survives_region_cache_loss_and_build_cleanup() {
        use ::artifacts::{config::Config, http::{router, ServeState}, registry::Registry,
            remote::Remote, store::Store};
        use std::time::Duration;

        async fn region(root: PathBuf, remote: Remote) -> (ArtifactsSink, tokio::task::JoinHandle<()>) {
            let store = Store::open(&Config { root: root.clone(), min_free_bytes: 0,
                gc_min_age: Duration::ZERO, heyvm_images_dir: root.join("images") }).unwrap();
            let registry = Registry::new(store, Some(remote), Default::default());
            let app = router(ServeState::new(registry, Some("fixture-key".into()), false));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
            (ArtifactsSink::new(ArtifactsConfig { url, token: Some("fixture-key".into()), guest_url: None }), server)
        }

        let dir = tempfile::tempdir().unwrap();
        let bucket = dir.path().join("bucket");
        let remote = Remote::fs(bucket.clone()).unwrap();
        let (first, first_server) = region(dir.path().join("first"), remote.clone()).await;
        let (second, second_server) = region(dir.path().join("second"), remote.clone()).await;
        let bytes = b"immutable release\0from first region\n".to_vec();
        let build = first.put(&aref(), bytes.clone()).await.unwrap();
        // Pin through a different, initially empty cache: no process-local
        // store or mock HTTP response can satisfy this assertion.
        let retained = second.retain(&build, "build/component/digest").await.unwrap();
        assert_eq!(retained.digest, Some(hex::encode(Sha256::digest(&bytes))));
        assert_eq!(second.get(&retained).await.unwrap(), bytes);
        assert_eq!(first.retain(&build, "build/component/digest").await.unwrap(), retained);

        first.auth(first.http.delete(format!("{}/tags/{}", first.config.url, build.uri)))
            .send().await.unwrap().error_for_status().unwrap();
        // A distinct unpinned blob proves that GC actually sweeps, while the
        // release root preserves the selected bytes independently of build tags.
        let orphan = b"unreferenced build scratch";
        let orphan_digest = hex::encode(Sha256::digest(orphan));
        first.auth(first.http.put(format!("{}/blobs/{orphan_digest}", first.config.url)))
            .body(orphan.to_vec()).send().await.unwrap().error_for_status().unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let swept = ::artifacts::s3ops::gc(&remote, Duration::ZERO, false).await.unwrap();
        assert_eq!(swept.blobs_removed, 1);

        first_server.abort(); second_server.abort();
        let _ = first_server.await; let _ = second_server.await;
        std::fs::remove_dir_all(dir.path().join("first")).unwrap();
        std::fs::remove_dir_all(dir.path().join("second")).unwrap();
        let (replacement, replacement_server) = region(dir.path().join("replacement"), remote).await;
        assert_eq!(replacement.get(&retained).await.unwrap(), bytes);
        let manifest: Value = replacement.auth(replacement.http.get(format!(
            "{}/manifests/{}", replacement.config.url, retained.uri)))
            .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        assert_eq!(manifest["entries"][0]["digest"], retained.digest.as_deref().unwrap());
        // Warm reads do not prove a durable write. Make the remote unusable:
        // retention must fail, even though the blob/manifest are cached.
        std::fs::rename(&bucket, dir.path().join("offline-bucket")).unwrap();
        std::fs::write(&bucket, b"remote unavailable").unwrap();
        assert!(replacement.retain(&retained, "another-release").await.is_err());
        replacement_server.abort();
        let _ = replacement_server.await;
    }

    #[test]
    fn rootfs_publication_schema_matches_app_lb() {
        let digest = "a".repeat(64);
        let m = rootfs_manifest(&digest, 4096, "app-image");
        assert_eq!(m["kind"], "heyvm.rootfs.v1");
        assert_eq!(m["entries"][0], serde_json::json!({"name":"rootfs.ext4","digest":digest,"size":4096}));
        assert_eq!(m["annotations"]["heyvm.primitive"], "ext4_raw");
        assert_eq!(m["annotations"]["heyvm.nominal_size"], "4096");
        assert_eq!(m["annotations"]["heyvm.image"], "app-image");
        assert!(validate_digest(&"A".repeat(64)).is_err());
        assert!(validate_digest("abc").is_err());
    }

    /// The store's tag charset excludes `/`, which every natural artifact
    /// coordinate contains.
    #[test]
    fn a_tag_fits_the_stores_charset_and_length() {
        let tag = tag_for(&aref());
        assert!(
            tag.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "{tag}"
        );
        assert!(tag.len() <= 64, "{} chars: {tag}", tag.len());
        assert!(!tag.starts_with('-') && !tag.starts_with('.'));
        assert!(tag.contains("myapp"), "{tag}");
    }

    #[test]
    fn a_slash_in_any_component_never_reaches_the_tag() {
        let mut r = aref();
        r.name = "dist/app.tar.gz".into();
        r.workflow_id = "org/app".into();
        let tag = tag_for(&r);
        assert!(!tag.contains('/'), "{tag}");
    }

    /// Truncation must still produce something the store accepts.
    #[test]
    fn a_very_long_name_is_truncated_to_a_legal_tag() {
        let mut r = aref();
        r.name = "x".repeat(300);
        let tag = tag_for(&r);
        assert_eq!(tag.len(), 64);
        assert!(!tag.starts_with('-'));
    }

    #[test]
    fn a_pathological_component_still_yields_a_usable_tag() {
        let r = ArtifactRef {
            run_id: "..".into(),
            job_key: "..".into(),
            workflow_id: "..".into(),
            name: "..".into(),
            description: None,
            public: false,
            alias: None,
        };
        let tag = tag_for(&r);
        assert!(!tag.is_empty());
        assert!(!tag.starts_with('.'), "{tag}");
    }

    /// The manifest is addressed by its own hash, so two uploads of identical
    /// bytes from the same run must produce byte-identical manifests — that is
    /// what makes the store dedupe.
    #[test]
    fn a_manifest_is_content_only_and_therefore_stable() {
        let a = manifest_for(&aref(), "deadbeef", 42);
        let b = manifest_for(&aref(), "deadbeef", 42);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        let text = serde_json::to_string(&a).unwrap();
        for forbidden in ["createdAt", "timestamp", "builtAt", "duration"] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} would break dedup: {text}"
            );
        }
        assert_eq!(a["entries"][0]["digest"], "deadbeef");
        assert_eq!(a["annotations"]["ci.run"], "019fca648a6e-00000000");
    }

    #[tokio::test]
    async fn the_disk_sink_writes_under_run_and_job() {
        let root = std::env::temp_dir().join(format!("ci-art-{}", crate::vm::new_id()));
        let sink = DiskSink { root: root.clone() };
        let stored = sink.put(&aref(), b"payload".to_vec()).await.unwrap();
        assert_eq!(stored.sink, "disk");
        assert_eq!(stored.size_bytes, 7);
        assert_eq!(std::fs::read(&stored.uri).unwrap(), b"payload");
        assert!(stored.uri.contains("build-x86_64"), "{}", stored.uri);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn disk_download_roundtrips_and_rejects_changed_bytes() {
        let root = std::env::temp_dir().join(format!("ci-art-{}", crate::vm::new_id()));
        let sink = DiskSink { root: root.clone() };
        let stored = sink.put(&aref(), b"payload".to_vec()).await.unwrap();
        assert_eq!(sink.get(&stored).await.unwrap(), b"payload");
        // Equal length distinguishes digest checking from a size-only check.
        tokio::fs::write(&stored.uri, b"changed").await.unwrap();
        assert!(matches!(sink.get(&stored).await.unwrap_err(), ArtifactError::Corrupt(_)));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn artifacts_download_uses_configured_store_auth_and_checks_digest() {
        use axum::{Router, body::Bytes, extract::{Path as AxumPath, State}, http::{HeaderMap, StatusCode}, response::IntoResponse, routing::get};
        #[derive(Clone)]
        struct StateData { bytes: Bytes }
        let bytes = Bytes::from_static(b"native-output");
        let app = Router::new().route("/blobs/{digest}", get(
            |State(st): State<StateData>, AxumPath(_): AxumPath<String>, headers: HeaderMap| async move {
                if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer scoped-token") {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                st.bytes.into_response()
            })).with_state(StateData { bytes: bytes.clone() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let sink = ArtifactsSink::new(ArtifactsConfig { url: format!("http://{addr}"), token: Some("scoped-token".into()), guest_url: None });
        let stored = StoredArtifact { sink: "artifacts", digest: Some(hex::encode(Sha256::digest(&bytes))), size_bytes: bytes.len() as u64, uri: "ignored-recorded-tag".into(), public_url: None };
        assert_eq!(sink.get(&stored).await.unwrap(), bytes);
        let corrupt = StoredArtifact { digest: Some("0".repeat(64)), ..stored };
        assert!(matches!(sink.get(&corrupt).await.unwrap_err(), ArtifactError::Corrupt(_)));
    }

    /// An artifact name arrives from a workflow file; one `..` would write
    /// outside the artifact directory.
    #[tokio::test]
    async fn the_disk_sink_cannot_be_escaped_by_a_hostile_name() {
        let root = std::env::temp_dir().join(format!("ci-art-{}", crate::vm::new_id()));
        let mut r = aref();
        r.name = "../../escaped".into();
        let stored = DiskSink { root: root.clone() }
            .put(&r, b"x".to_vec())
            .await
            .unwrap();
        assert!(
            Path::new(&stored.uri).starts_with(&root),
            "escaped to {}",
            stored.uri
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_s3_key_is_stable_and_slash_separated() {
        let sink = S3Sink::new(S3Config {
                bucket: "bkt".into(),
                prefix: "/ci/".into(),
                region: None,
                endpoint: None,
        })
        .unwrap();
        assert_eq!(
            sink.key_for(&aref()),
            "ci/019fca648a6e-00000000/build-x86_64/binary.tar.gz"
        );
    }

    fn mock_s3(endpoint: String) -> S3Sink {
        let config = S3Config {
            bucket: "private-reports".into(),
            prefix: "ci".into(),
            region: Some("us-test-1".into()),
            endpoint: Some(endpoint.clone()),
        };
        let sdk = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-test-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test-access",
                "test-secret",
                None,
                None,
                "test",
            ))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        S3Sink::with_client(config, aws_sdk_s3::Client::from_conf(sdk))
    }

    #[tokio::test]
    async fn s3_upload_and_download_are_signed_private_and_integrity_checked() {
        use axum::{
            Router,
            body::Bytes,
            extract::State,
            http::{HeaderMap, StatusCode},
            response::IntoResponse,
            routing::put,
        };
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Mock(Arc<Mutex<Vec<u8>>>);
        async fn object(
            State(state): State<Mock>,
            headers: HeaderMap,
            body: Bytes,
        ) -> impl IntoResponse {
            assert!(
                headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 "))
            );
            if body.is_empty() {
                (StatusCode::OK, state.0.lock().unwrap().clone())
            } else {
                *state.0.lock().unwrap() = body.to_vec();
                (StatusCode::OK, Vec::new())
            }
        }
        let app = Router::new()
            .route(
                "/private-reports/ci/019fca648a6e-00000000/build-x86_64/binary.tar.gz",
                put(object).get(object),
            )
            .with_state(Mock::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let sink = mock_s3(endpoint);
        let stored = sink.put(&aref(), b"debug-report".to_vec()).await.unwrap();
        assert_eq!(
            stored.uri,
            "s3://private-reports/ci/019fca648a6e-00000000/build-x86_64/binary.tar.gz"
        );
        assert_eq!(stored.public_url, None);
        assert_eq!(sink.get(&stored).await.unwrap(), b"debug-report");
        let bad = StoredArtifact {
            digest: Some("0".repeat(64)),
            ..stored
        };
        assert!(matches!(
            sink.get(&bad).await.unwrap_err(),
            ArtifactError::Corrupt(_)
        ));
    }

    #[tokio::test]
    async fn s3_rejects_foreign_uris_before_network_access() {
        let sink = S3Sink::new(S3Config {
            bucket: "ours".into(),
            prefix: "reports".into(),
            region: None,
            endpoint: None,
        })
        .unwrap();
        for uri in [
            "s3://theirs/reports/run/job/file",
            "s3://ours/other/run/job/file",
            "https://ours/reports/run/job/file",
        ] {
            let stored = StoredArtifact {
                sink: "s3",
                digest: None,
                size_bytes: 0,
                uri: uri.into(),
                public_url: None,
            };
            assert!(
                matches!(
                    sink.get(&stored).await.unwrap_err(),
                    ArtifactError::InvalidRecord(_)
                ),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn s3_server_errors_fail_the_upload() {
        use axum::{Router, http::StatusCode, routing::put};
        let app = Router::new().route(
            "/{*path}",
            put(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let err = mock_s3(endpoint)
            .put(&aref(), b"report".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, ArtifactError::Transport(_)), "{err}");
    }

    /// A sink that cannot take a pushed blob says so through the trait, so
    /// the dispatcher never has to know which sink it holds.
    #[tokio::test]
    async fn only_the_artifacts_sink_offers_a_guest_push() {
        let disk = DiskSink {
            root: std::env::temp_dir(),
        };
        assert!(disk.guest_push().is_none());
        let err = disk.put_pushed(&aref(), "ab", 1).await.unwrap_err();
        assert!(err.to_string().contains("disk"), "{err}");

        let sink = ArtifactsSink::new(ArtifactsConfig {
            url: "http://orchestrator-only:9000".into(),
            token: Some("t".into()),
            guest_url: None,
        });
        assert_eq!(
            sink.guest_push(),
            Some(GuestPush {
                url: "http://orchestrator-only:9000".into(),
                token: Some("t".into()),
            })
        );
        let sink = ArtifactsSink::new(ArtifactsConfig {
            url: "http://orchestrator-only:9000".into(),
            token: None,
            guest_url: Some("https://art.example".into()),
        });
        assert_eq!(
            sink.guest_push().unwrap().url,
            "https://art.example",
            "the guest gets the URL it can reach, not the orchestrator's"
        );
    }

    /// A fake `art serve` that answers the routes the sink uses, recording
    /// every manifest and tag it is asked to write.
    struct FakeStore {
        url: String,
        /// `HEAD /blobs/{digest}` answers: digest → size the store claims.
        blobs: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
        head_without_size: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
        manifests: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        tags: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        /// Digests `PUT /public/{digest}` was called for.
        publics: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl FakeStore {
        async fn start() -> Self {
            Self::start_with(true).await
        }

        /// `public_route: false` plays a store from before public downloads
        /// existed: `PUT /public/…` is an unknown route and 404s bare.
        async fn start_with(public_route: bool) -> Self {
            use axum::{Router, extract::State, routing::put};
            #[derive(Clone)]
            struct St {
                blobs: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
                head_without_size: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
                manifests: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
                tags: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
                publics: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
            }
            let st = St {
                blobs: Default::default(),
                head_without_size: Default::default(),
                manifests: Default::default(),
                tags: Default::default(),
                publics: Default::default(),
            };
            let public = Router::new().route(
                "/public/{digest}",
                put(
                    |State(st): State<St>, axum::extract::Path(d): axum::extract::Path<String>| async move {
                        st.publics.lock().unwrap().push(d.clone());
                        axum::Json(serde_json::json!({
                            "digest": d, "public": true, "url": format!("/blobs/{d}")
                        }))
                    },
                ),
            );
            let app = Router::new()
                .route(
                    "/blobs/{digest}",
                    axum::routing::head(
                        |State(st): State<St>, axum::extract::Path(d): axum::extract::Path<String>| async move {
                            if st.head_without_size.lock().unwrap().contains(&d) {
                                return (
                                    reqwest::StatusCode::OK,
                                    [(axum::http::header::CONTENT_LENGTH, "unknown")],
                                )
                                    .into_response();
                            }
                            match st.blobs.lock().unwrap().get(&d) {
                                Some(size) => (
                                    reqwest::StatusCode::OK,
                                    [(axum::http::header::CONTENT_LENGTH, size.to_string())],
                                )
                                    .into_response(),
                                None => reqwest::StatusCode::NOT_FOUND.into_response(),
                            }
                        },
                    ),
                )
                .route(
                    "/manifests",
                    put(
                        |State(st): State<St>, axum::Json(m): axum::Json<serde_json::Value>| async move {
                            st.manifests.lock().unwrap().push(m);
                            axum::Json(serde_json::json!({ "digest": DIGEST }))
                        },
                    ),
                )
                .route(
                    "/tags/{tag}",
                    put(
                        |State(st): State<St>, axum::extract::Path(t): axum::extract::Path<String>, body: String| async move {
                            st.tags.lock().unwrap().push((t, body));
                            reqwest::StatusCode::OK
                        },
                    ),
                )
                .merge(if public_route { public } else { Router::new() })
                .with_state(st.clone());
            use axum::response::IntoResponse;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                url: format!("http://{addr}"),
                blobs: st.blobs,
                head_without_size: st.head_without_size,
                manifests: st.manifests,
                tags: st.tags,
                publics: st.publics,
            }
        }

        fn sink(&self) -> ArtifactsSink {
            ArtifactsSink::new(ArtifactsConfig {
                url: self.url.clone(),
                token: None,
                guest_url: None,
            })
        }
    }

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    fn stored_artifact() -> StoredArtifact {
        StoredArtifact {
            sink: "artifacts",
            digest: Some(DIGEST.into()),
            size_bytes: 3,
            uri: "ci-original-build-tag".into(),
            public_url: None,
        }
    }

    #[tokio::test]
    async fn unsupported_sinks_refuse_retention_by_default() {
        let sink = DiskSink { root: PathBuf::from("unused") };
        let err = sink.retain(&stored_artifact(), "release/component").await.unwrap_err();
        assert!(matches!(err, ArtifactError::Misconfigured(_)), "{err}");
        assert!(err.to_string().contains("does not support"), "{err}");
    }

    #[tokio::test]
    async fn retention_refuses_a_record_from_another_sink() {
        let store = FakeStore::start().await;
        let foreign = StoredArtifact { sink: "s3", ..stored_artifact() };
        let err = store.sink().retain(&foreign, "release/component").await.unwrap_err();
        assert!(matches!(err, ArtifactError::InvalidRecord(_)), "{err}");
        assert!(store.manifests.lock().unwrap().is_empty());
        assert!(store.tags.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn retention_is_content_addressed_deterministic_and_preserves_the_build_tag() {
        let store = FakeStore::start().await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 3);
        let original = stored_artifact();
        let key = "product/release-with-a-full-identifier/component-linux-arm64";
        let first = store.sink().retain(&original, key).await.unwrap();
        let second = store.sink().retain(&original, key).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(original.uri, "ci-original-build-tag");
        assert_eq!(first.digest, original.digest);
        assert_eq!(first.size_bytes, original.size_bytes);
        assert_eq!(first.uri, retention_tag(key));
        assert_eq!(first.uri.len(), 64);
        assert!(first.uri.starts_with("release-"));
        let manifests = store.manifests.lock().unwrap();
        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0], manifests[1], "retry changed immutable content");
        assert_eq!(manifests[0]["entries"][0]["digest"], DIGEST);
        assert_eq!(manifests[0]["entries"][0]["size"], 3);
        assert_eq!(manifests[0]["annotations"]["ci.release.key"], key);
        let tags = store.tags.lock().unwrap();
        assert_eq!(tags.len(), 2);
        assert!(tags.iter().all(|(tag, target)| tag == &first.uri && target == DIGEST));
        assert!(!tags.iter().any(|(tag, _)| tag == &original.uri));
    }

    #[tokio::test]
    async fn retention_requires_a_head_size_matching_the_record() {
        let store = FakeStore::start().await;
        store.head_without_size.lock().unwrap().insert(DIGEST.into());
        let err = store.sink().retain(&stored_artifact(), "release/a").await.unwrap_err();
        assert!(err.to_string().contains("omitted Content-Length"), "{err}");
        assert!(store.manifests.lock().unwrap().is_empty());
        assert!(store.tags.lock().unwrap().is_empty());

        store.head_without_size.lock().unwrap().clear();
        store.blobs.lock().unwrap().insert(DIGEST.into(), 4);
        let err = store.sink().retain(&stored_artifact(), "release/a").await.unwrap_err();
        assert!(err.to_string().contains("size 4, expected 3"), "{err}");
        assert!(store.manifests.lock().unwrap().is_empty());
        assert!(store.tags.lock().unwrap().is_empty());
    }

    /// The guest's word is not enough: a blob it says it pushed is looked up
    /// in the store, and a missing one is an error before any manifest or
    /// tag exists that would point at it.
    #[tokio::test]
    async fn a_pushed_blob_the_store_lacks_is_an_error_and_names_nothing() {
        let store = FakeStore::start().await;
        let err = store
            .sink()
            .put_pushed(&aref(), DIGEST, 3)
            .await
            .unwrap_err();
        assert!(matches!(err, ArtifactError::NotPushed { .. }), "{err}");
        assert!(err.to_string().contains(DIGEST), "{err}");
        assert!(store.manifests.lock().unwrap().is_empty());
        assert!(store.tags.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_pushed_blob_of_the_wrong_size_is_an_error() {
        let store = FakeStore::start().await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 999);
        let err = store
            .sink()
            .put_pushed(&aref(), DIGEST, 3)
            .await
            .unwrap_err();
        assert!(matches!(err, ArtifactError::NotPushed { .. }), "{err}");
        assert!(err.to_string().contains("999"), "{err}");
        assert!(store.manifests.lock().unwrap().is_empty());
    }

    /// The alias is the moving half of the pair: the per-run tag still names
    /// this build, and a second tag points at the same manifest, so a
    /// deployment pinned to the alias follows the newest green run.
    #[tokio::test]
    async fn an_alias_is_set_beside_the_run_tag_and_resolves_to_the_same_manifest() {
        let store = FakeStore::start().await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 3);
        let r = ArtifactRef { alias: Some("retail-live".into()), ..aref() };
        let stored = store.sink().put_pushed(&r, DIGEST, 3).await.unwrap();

        // The artifact still reports its own immutable address, not the alias.
        assert_eq!(stored.uri, tag_for(&r));
        let tags = store.tags.lock().unwrap();
        assert_eq!(
            tags.as_slice(),
            &[
                (tag_for(&r), DIGEST.to_string()),
                ("retail-live".to_string(), DIGEST.to_string()),
            ],
            "both tags, and both resolving to the manifest the run stored",
        );
    }

    /// An alias is typed by a person into a workflow and then again into a
    /// deployment's `artifact.ref`, so a name the store would mangle is an
    /// error rather than a quiet rewrite — and the `ci-` namespace is not the
    /// workflow's to write into.
    #[test]
    fn an_unusable_alias_is_refused_with_the_reason() {
        assert_eq!(validate_alias("retail-live").unwrap(), "retail-live");
        assert_eq!(validate_alias("docs.live_2").unwrap(), "docs.live_2");

        for (bad, why) in [
            ("", "1 to 64"),
            ("retail live", "only letters"),
            ("-retail", "may not start"),
            (".retail", "may not start"),
            ("ci-Heyo-Mono-01a0-00000004-release-retail", "per-run tags"),
        ] {
            let err = validate_alias(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{bad:?} -> {err}");
        }
        assert!(validate_alias(&"a".repeat(65)).is_err());
    }

    /// The store has it at the size the guest measured: the artifact is named
    /// exactly as an orchestrator-side `put` would have named it.
    #[tokio::test]
    async fn a_pushed_blob_the_store_has_is_named_like_any_other() {
        let store = FakeStore::start().await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 3);
        let stored = store.sink().put_pushed(&aref(), DIGEST, 3).await.unwrap();
        assert_eq!(stored.sink, "artifacts");
        assert_eq!(stored.digest.as_deref(), Some(DIGEST));
        assert_eq!(stored.size_bytes, 3);
        assert_eq!(stored.uri, tag_for(&aref()));

        let manifests = store.manifests.lock().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0]["entries"][0]["digest"], DIGEST);
        assert_eq!(manifests[0]["entries"][0]["size"], 3);
        let tags = store.tags.lock().unwrap();
        assert_eq!(
            tags.as_slice(),
            &[(tag_for(&aref()), DIGEST.to_string())]
        );
        assert!(
            store.publics.lock().unwrap().is_empty(),
            "an artifact is private unless the workflow says otherwise"
        );
        assert_eq!(stored.public_url, None);
    }

    /// `public: true` flags the *blob* — the bytes a link fetches — and the
    /// link it returns is the store's own `/blobs/{digest}`, absolute, under
    /// the URL the orchestrator was configured with.
    #[tokio::test]
    async fn a_public_artifact_is_flagged_by_digest_and_returns_its_link() {
        let store = FakeStore::start().await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 3);
        let r = ArtifactRef {
            public: true,
            ..aref()
        };
        let stored = store.sink().put_pushed(&r, DIGEST, 3).await.unwrap();
        assert_eq!(
            store.publics.lock().unwrap().as_slice(),
            &[DIGEST.to_string()],
            "the flag goes on the blob, not the manifest"
        );
        assert_eq!(
            stored.public_url.as_deref(),
            Some(format!("{}/blobs/{DIGEST}", store.url).as_str())
        );
        // The rest of the upload is unchanged by the flag.
        assert_eq!(stored.uri, tag_for(&r));
        assert_eq!(store.tags.lock().unwrap().len(), 1);
    }

    /// The flag is the last thing that changes the manifest's meaning to a
    /// reader, so it must not be dropped quietly: a store without the route
    /// fails the upload with the fix in the message, and the tag it had
    /// already set is left in place for the re-run to dedup against.
    #[tokio::test]
    async fn a_store_without_public_downloads_fails_the_upload_loudly() {
        let store = FakeStore::start_with(false).await;
        store.blobs.lock().unwrap().insert(DIGEST.into(), 3);
        let r = ArtifactRef {
            public: true,
            ..aref()
        };
        let err = store.sink().put_pushed(&r, DIGEST, 3).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("making the blob public"), "{text}");
        assert!(text.contains("predates public downloads"), "{text}");
        assert!(text.contains("public: true"), "{text}");
        assert_eq!(store.tags.lock().unwrap().len(), 1, "named before flagged");
    }

    /// The store's slugs are machine-readable; the error turns them into what to
    /// do about them.
    #[test]
    fn store_errors_translate_the_slug_into_an_action() {
        let e = ArtifactError::Store {
            what: "uploading a blob".into(),
            status: 507,
            slug: "no_space".into(),
            message: "insufficient storage".into(),
        };
        assert!(e.to_string().contains("The store is full"), "{e}");

        let e = ArtifactError::Store {
            what: "uploading a blob".into(),
            status: 401,
            slug: "unauthorized".into(),
            message: "nope".into(),
        };
        assert!(e.to_string().contains("CI_ARTIFACT_TOKEN"), "{e}");
    }

    /// The property that makes a description safe to add at all: it is metadata
    /// *about* the artifact, so it must not reach the manifest.
    ///
    /// A manifest is addressed by its own hash. Putting a description in an
    /// annotation would give two uploads of identical bytes two different
    /// manifest digests the moment somebody edited the workflow's wording — and
    /// the store would accumulate a manifest per edit instead of deduplicating.
    /// The description goes to `PUT /labels/{digest}`, which is mutable and
    /// keyed by digest, precisely so it can change without moving anything.
    #[test]
    fn a_description_does_not_change_the_manifest() {
        let plain = aref();
        let described = ArtifactRef {
            description: Some("the proxy and heyctl, release build".into()),
            ..aref()
        };

        let a = manifest_for(&plain, "d".repeat(64).as_str(), 10);
        let b = manifest_for(&described, "d".repeat(64).as_str(), 10);
        assert_eq!(a, b, "the description leaked into the manifest");

        // ...and the tag is likewise untouched, so the artifact stays where
        // anything already pointing at it expects to find it.
        assert_eq!(tag_for(&plain), tag_for(&described));
    }
}
