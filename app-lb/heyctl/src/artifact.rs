//! The HTTP client for an artifact store (`art serve`).
//!
//! A second client rather than a mode of [`crate::blocking::Client`], because it
//! talks to a different service with a different auth scheme. app-lb's admin API
//! is HTTP Basic and JSON bodies all the way down; a store is a bearer token and
//! a route whose body is a twenty-gigabyte disk image. The one thing they share
//! is `ureq`, and sharing an `Agent` between them would mean sharing a timeout
//! that is right for exactly one of them.
//!
//! ## Push, in the order the store requires it
//!
//! 1. **Hash the file.** `PUT /blobs/{digest}` carries the name in the URL, so
//!    the digest has to exist before the request does. The store re-hashes what
//!    arrives and answers `409` if the two disagree, which is what makes a
//!    corrupted upload a failure rather than a wrong blob under a right name.
//! 2. **Ask whether it is already there** (`HEAD /blobs/{digest}`). A rootfs
//!    that has not changed since the last push is the common case, and skipping
//!    it turns a re-push into two round trips.
//! 3. **Upload**, streaming from the file. Never `read_to_end` — the whole point
//!    of these images is that they do not fit anywhere convenient.
//! 4. **Write a manifest** describing the blob as a rootfs, and **move a tag**
//!    onto the manifest.
//!
//! Steps 4 and 5 are what make a pushed image indistinguishable from one that
//! `art heyvm import` put in. app-lb's puller resolves a reference by asking for
//! its manifest and looking for the `rootfs.ext4` entry; a bare blob with a tag
//! pointing at it would upload fine and then be unpullable.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Manifest `kind` for a single ext4 rootfs, and the annotation keys that go
/// with it. Copied from the artifacts crate rather than depended on: this is a
/// wire format shared with app-lb's puller, and taking the dependency would pull
/// a syscall layer and an axum tree into a CLI to write five string constants.
const KIND_ROOTFS: &str = "heyvm.rootfs.v1";
const SCHEMA_VERSION: u32 = 1;
const ROOTFS_FILENAME: &str = "rootfs.ext4";
const ANN_PRIMITIVE: &str = "heyvm.primitive";
const ANN_IMAGE: &str = "heyvm.image";
const ANN_NOMINAL_SIZE: &str = "heyvm.nominal_size";
const PRIMITIVE_EXT4_RAW: &str = "ext4_raw";

/// The Dockerfile manifest, from the same source. A recipe rather than an
/// image: app-lb's `build.store` names one of these and builds it, where
/// `artifact.ref` names a rootfs and boots it.
const KIND_DOCKERFILE: &str = "heyvm.dockerfile.v1";
const DOCKERFILE_ENTRY: &str = "Dockerfile";
const CONTEXT_ENTRY: &str = "context.tar.gz";
const ANN_SIZE_MB: &str = "heyvm.size_mb";
const ANN_SOURCE: &str = "dockerfile.source";

/// Ceiling on the Dockerfile itself, matching the store's own. A recipe is
/// kilobytes; something claiming otherwise is most often a whole build context
/// passed where the Dockerfile was meant, and catching it here beats uploading
/// it and being refused.
const MAX_DOCKERFILE_BYTES: u64 = 1 << 20;

/// Read size for the hashing pass. Large enough that the syscall overhead
/// disappears against a multi-gigabyte file.
const HASH_CHUNK: usize = 1 << 20;

pub struct RegistryClient {
    agent: ureq::Agent,
    base: String,
    api_key: Option<String>,
}

impl RegistryClient {
    pub fn new(url: &str, api_key: Option<&str>, insecure: bool, timeout: Duration) -> Result<Self> {
        let mut tls = ureq::native_tls::TlsConnector::builder();
        if insecure {
            tls.danger_accept_invalid_certs(true);
            tls.danger_accept_invalid_hostnames(true);
        }
        let connector = tls.build().context("building the TLS connector")?;

        let agent = ureq::AgentBuilder::new()
            // Applied to establishing the connection, not to the transfer: a
            // blob upload legitimately runs for minutes and must not be cut off
            // by a timeout meant for an unresponsive server.
            .timeout_connect(timeout)
            .user_agent(concat!("heyctl/", env!("CARGO_PKG_VERSION")))
            .tls_connector(Arc::new(connector))
            .build();

        Ok(Self {
            agent,
            base: normalize_url(url),
            api_key: api_key.map(str::to_string),
        })
    }

    pub fn url(&self) -> &str {
        &self.base
    }

    pub fn has_credentials(&self) -> bool {
        self.api_key.is_some()
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let req = self.agent.request(method, &format!("{}{}", self.base, path));
        match &self.api_key {
            // Bearer rather than `X-Api-Key`: the store accepts either, and a
            // custom header is the one an intermediary strips.
            Some(k) => req.set("Authorization", &format!("Bearer {k}")),
            None => req,
        }
    }

    /// Status + body for whatever the store said, including 4xx/5xx.
    fn raw(&self, req: ureq::Request) -> Result<(u16, String)> {
        match req.call() {
            Ok(resp) => {
                let status = resp.status();
                Ok((status, resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Status(code, resp)) => {
                Ok((code, resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => Err(anyhow!(
                "cannot reach the artifact store at {} ({t}) — is `art serve` running, and is \
                 the url right?",
                self.base
            )),
        }
    }

    fn send(&self, method: &str, path: &str) -> Result<(u16, String)> {
        let (code, body) = self.raw(self.request(method, path))?;
        if code >= 400 {
            return Err(self.api_error(code, &body));
        }
        Ok((code, body))
    }

    fn json(&self, method: &str, path: &str) -> Result<Value> {
        let (_, text) = self.send(method, path)?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .with_context(|| format!("the store's answer to {method} {path} was not JSON"))
    }

    /// The store answers errors as `{"error": "...", ...}`; prefer that over the
    /// raw body, and say what to do about the two statuses that have an answer.
    fn api_error(&self, code: u16, body: &str) -> anyhow::Error {
        let detail = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_string))
            .unwrap_or_else(|| body.trim().chars().take(300).collect());

        match code {
            401 if self.api_key.is_some() => anyhow!(
                "the store rejected this API key (HTTP 401) — check it against the store's \
                 ART_API_KEY, or re-run `heyctl artifact login`"
            ),
            401 => anyhow!(
                "this store requires an API key (HTTP 401) — run `heyctl artifact login`, \
                 or pass --api-key"
            ),
            403 => anyhow!(
                "the store refused the write (HTTP 403){} — a store started with \
                 ART_READ_ONLY rejects every mutating route",
                if detail.is_empty() { String::new() } else { format!(": {detail}") }
            ),
            _ if detail.is_empty() => anyhow!("the store returned HTTP {code}"),
            _ => anyhow!("{detail} (HTTP {code})"),
        }
    }

    // -- reads -------------------------------------------------------------

    /// Proves this is an artifact store at all. Open even when a key is set, so
    /// it answers before the credentials are known to be good.
    pub fn healthz(&self) -> Result<()> {
        let (code, _) = self.send("GET", "/healthz")?;
        if code == 200 {
            Ok(())
        } else {
            bail!("GET /healthz answered HTTP {code}; that does not look like an artifact store")
        }
    }

    pub fn tags(&self) -> Result<Value> {
        self.json("GET", "/tags")
    }

    pub fn usage(&self) -> Result<Value> {
        self.json("GET", "/usage")
    }

    pub fn manifest(&self, reference: &str) -> Result<Value> {
        self.json("GET", &format!("/manifests/{}", escape(reference)))
    }

    /// Whether the store already holds this blob, and how big it says it is.
    /// A `404` is an answer, not a failure — it is the whole question.
    pub fn blob_exists(&self, digest: &str) -> Result<Option<u64>> {
        let req = self.request("HEAD", &format!("/blobs/{}", escape(digest)));
        match req.call() {
            Ok(resp) => Ok(Some(
                resp.header("Content-Length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            )),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, resp)) => {
                Err(self.api_error(code, &resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => Err(anyhow!(
                "cannot reach the artifact store at {} ({t})",
                self.base
            )),
        }
    }

    // -- writes ------------------------------------------------------------

    /// Stream a file into `PUT /blobs/{digest}`.
    ///
    /// `Content-Length` is set explicitly so the store sees a sized body rather
    /// than a chunked one — it means the free-space guard can refuse an upload
    /// that will not fit *before* the first byte instead of after the last.
    pub fn put_blob(&self, digest: &str, path: &Path, size: u64) -> Result<bool> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let req = self
            .request("PUT", &format!("/blobs/{}", escape(digest)))
            .set("Content-Type", "application/octet-stream")
            .set("Content-Length", &size.to_string());

        match req.send(file) {
            // 201 stored, 200 the store already had it.
            Ok(resp) => Ok(resp.status() == 201),
            Err(ureq::Error::Status(code, resp)) => {
                Err(self.api_error(code, &resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => Err(anyhow!(
                "the upload to {} failed ({t}) — nothing was tagged, so the store is unchanged",
                self.base
            )),
        }
    }

    /// Store a manifest and return its digest.
    pub fn put_manifest(&self, manifest: &Value) -> Result<String> {
        let req = self
            .request("PUT", "/manifests")
            .set("Content-Type", "application/json");
        let (code, body) = match req.send_json(manifest) {
            Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(code, resp)) => {
                return Err(self.api_error(code, &resp.into_string().unwrap_or_default()));
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(anyhow!("cannot reach the artifact store at {} ({t})", self.base));
            }
        };
        if code >= 400 {
            return Err(self.api_error(code, &body));
        }
        let v: Value = serde_json::from_str(&body)
            .context("the store's answer to PUT /manifests was not JSON")?;
        v.get("digest")
            .and_then(|d| d.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("the store stored the manifest but reported no digest"))
    }

    /// Point a tag at a digest. The body is the digest and nothing else, which
    /// is the store's own format for the file behind it.
    pub fn put_tag(&self, name: &str, digest: &str) -> Result<()> {
        let req = self
            .request("PUT", &format!("/tags/{}", escape(name)))
            .set("Content-Type", "text/plain");
        match req.send_string(digest) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, resp)) => {
                Err(self.api_error(code, &resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => {
                Err(anyhow!("cannot reach the artifact store at {} ({t})", self.base))
            }
        }
    }

    pub fn delete_tag(&self, name: &str) -> Result<()> {
        self.send("DELETE", &format!("/tags/{}", escape(name))).map(|_| ())
    }

    /// Set a repository's metadata: whether it is public — on the hub and
    /// pullable without a key — and its description.
    pub fn put_repo(&self, repo: &str, public: bool, description: Option<&str>) -> Result<Value> {
        let req = self
            .request("PUT", &format!("/repos/{}", escape(repo)))
            .set("Content-Type", "application/json");
        match req.send_json(json!({ "public": public, "description": description })) {
            Ok(resp) => serde_json::from_str(&resp.into_string().unwrap_or_default())
                .context("the store's answer to PUT /repos was not JSON"),
            Err(ureq::Error::Status(code, resp)) => {
                Err(self.api_error(code, &resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => {
                Err(anyhow!("cannot reach the artifact store at {} ({t})", self.base))
            }
        }
    }

    /// What a reference names: a manifest when there is one by that name,
    /// otherwise the blob a tag points at directly. `None` if neither exists.
    pub fn resolve(&self, reference: &str) -> Result<Option<Resolved>> {
        let (code, body) = self.raw(self.request("GET", &format!("/manifests/{}", escape(reference))))?;
        match code {
            200 => {
                let m: Value = serde_json::from_str(&body)
                    .context("the store's manifest was not JSON")?;
                return Ok(Some(Resolved::Manifest(m)));
            }
            404 => {}
            _ => return Err(self.api_error(code, &body)),
        }
        // A tag may name a bare blob (`art put --tag`).
        let (code, body) = self.raw(self.request("GET", &format!("/tags/{}", escape(reference))))?;
        match code {
            200 => {
                let v: Value = serde_json::from_str(&body).context("the store's tag was not JSON")?;
                let d = v
                    .get("digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("the store's tag carried no digest"))?;
                Ok(Some(Resolved::Blob(d.to_string())))
            }
            404 if is_digest(reference) => Ok(Some(Resolved::Blob(reference.to_string()))),
            404 => Ok(None),
            _ => Err(self.api_error(code, &body)),
        }
    }

    /// Stream `GET /blobs/{digest}` to `dest`, hashing as it lands, and refuse
    /// — deleting the file — if the bytes are not what their name promises.
    /// Written to a temp name beside `dest` and renamed into place, so a failed
    /// pull never leaves a half-file that looks complete.
    pub fn get_blob(&self, digest: &str, dest: &Path, mut progress: impl FnMut(u64, u64)) -> Result<u64> {
        let resp = match self.request("GET", &format!("/blobs/{}", escape(digest))).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, resp)) => {
                return Err(self.api_error(code, &resp.into_string().unwrap_or_default()));
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(anyhow!("cannot reach the artifact store at {} ({t})", self.base));
            }
        };
        let total = resp.header("Content-Length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let tmp = dest.with_file_name(format!(
            ".{}.heyctl-pull",
            dest.file_name().and_then(|n| n.to_str()).unwrap_or("blob")
        ));
        let result = (|| -> Result<u64> {
            let mut out = std::fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            let mut reader = resp.into_reader();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; HASH_CHUNK];
            let mut n_total = 0u64;
            loop {
                let n = reader.read(&mut buf).context("reading the download")?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                std::io::Write::write_all(&mut out, &buf[..n])
                    .with_context(|| format!("writing {}", tmp.display()))?;
                n_total += n as u64;
                progress(n_total, total);
            }
            out.sync_all().ok();
            let actual = hex(&hasher.finalize());
            if actual != digest {
                bail!("the store sent bytes that hash to {actual}, not {digest}; nothing was written");
            }
            std::fs::rename(&tmp, dest)
                .with_context(|| format!("moving the download into {}", dest.display()))?;
            Ok(n_total)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

/// What a pull reference resolved to.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    Manifest(Value),
    Blob(String),
}

pub fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A manifest entry name that is safe to use as a file name: no separator, not
/// a dot entry, not hidden.
pub fn is_safe_entry_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// The manifest `art heyvm import` writes, byte for byte.
///
/// Matching it is not cosmetic. app-lb's puller finds a rootfs by looking for
/// the entry called `rootfs.ext4`, and heyvm reads `heyvm.nominal_size` to
/// decide whether it can skip the `e2fsck -fp` + `resize2fs` pair on boot. A
/// manifest that merely *contains* the blob would pull and then resize every
/// time.
pub fn rootfs_manifest(digest: &str, size: u64, image: &str) -> Value {
    json!({
        "schema": SCHEMA_VERSION,
        "kind": KIND_ROOTFS,
        "entries": [{ "name": ROOTFS_FILENAME, "digest": digest, "size": size }],
        "annotations": {
            ANN_IMAGE: image,
            ANN_NOMINAL_SIZE: size.to_string(),
            ANN_PRIMITIVE: PRIMITIVE_EXT4_RAW,
        }
    })
}

/// The manifest `art dockerfile put` writes, byte for byte.
///
/// Matching it matters for the same reason [`rootfs_manifest`] does, one layer
/// up: app-lb finds the recipe by looking for the entry called `Dockerfile` and
/// the context by looking for `context.tar.gz`, and reads `heyvm.size_mb` as a
/// build default. A manifest that merely *contained* the two blobs would push
/// fine and then be unbuildable.
///
/// Annotations are omitted when unset rather than emitted empty: the manifest is
/// content-addressed, so an empty string is a different address from an absent
/// key, and re-pushing an unchanged recipe must land on the manifest already
/// there.
pub fn dockerfile_manifest(
    dockerfile: (&str, u64),
    context: Option<(&str, u64)>,
    image_name: Option<&str>,
    size_mb: Option<u64>,
    source: Option<&str>,
) -> Value {
    let mut entries = vec![json!({
        "name": DOCKERFILE_ENTRY,
        "digest": dockerfile.0,
        "size": dockerfile.1,
    })];
    if let Some((digest, size)) = context {
        entries.push(json!({ "name": CONTEXT_ENTRY, "digest": digest, "size": size }));
    }

    let mut annotations = serde_json::Map::new();
    if let Some(n) = image_name {
        annotations.insert(ANN_IMAGE.into(), Value::String(n.to_string()));
    }
    if let Some(mb) = size_mb {
        // A string, like every annotation: the store's annotations are a map of
        // strings and a number here would not round-trip.
        annotations.insert(ANN_SIZE_MB.into(), Value::String(mb.to_string()));
    }
    if let Some(s) = source {
        annotations.insert(ANN_SOURCE.into(), Value::String(s.to_string()));
    }

    json!({
        "schema": SCHEMA_VERSION,
        "kind": KIND_DOCKERFILE,
        "entries": entries,
        "annotations": annotations,
    })
}

/// Pack `dir` into a gzipped tar at `dest`, and report its size.
///
/// Deterministic headers, so the same tree packs to the same bytes and a
/// re-push of an unchanged context is a `HEAD` and nothing else. Every file is
/// included — no `.dockerignore` handling and no built-in exclusions — because a
/// packer that silently dropped files would produce a build that fails on
/// somebody else's host with an error pointing at the Dockerfile. Point
/// `--context` at a clean directory, or pack it yourself and pass the archive.
///
/// Symlinks are followed and stored as their content, which is what keeps the
/// archive unpackable under app-lb's "no links" rule at the other end.
pub fn pack_context(dir: &Path, dest: &Path) -> Result<u64> {
    if !dir.is_dir() {
        bail!("build context {} is not a directory", dir.display());
    }
    let out = std::fs::File::create(dest)
        .with_context(|| format!("creating {}", dest.display()))?;
    let gz = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    builder.mode(tar::HeaderMode::Deterministic);
    builder
        .append_dir_all(".", dir)
        .with_context(|| format!("packing {}", dir.display()))?;
    let gz = builder.into_inner().context("finishing the context archive")?;
    let mut out = gz.finish().context("compressing the context archive")?;
    // The digest is taken from this file immediately afterwards, so a buffered
    // tail that never reached the kernel would be a manifest naming bytes that
    // are not the ones on disk.
    out.flush().context("flushing the context archive")?;
    out.sync_all().context("syncing the context archive")?;
    Ok(std::fs::metadata(dest)
        .with_context(|| format!("reading {}", dest.display()))?
        .len())
}

/// Refuse a Dockerfile that is obviously not one, before anything is uploaded.
pub fn check_dockerfile_size(path: &Path, size: u64) -> Result<()> {
    if size > MAX_DOCKERFILE_BYTES {
        bail!(
            "{} is {}; a Dockerfile is expected to be under {}. Did you mean --context?",
            path.display(),
            crate::output::bytes(size),
            crate::output::bytes(MAX_DOCKERFILE_BYTES),
        );
    }
    Ok(())
}

/// sha256 a file, reporting progress. Returns the digest and the size.
///
/// Streamed rather than read whole for the obvious reason, and the size comes
/// from the read loop rather than from `metadata` so it describes the same bytes
/// that were hashed — a file being appended to underneath would otherwise get a
/// `Content-Length` that does not match its digest.
pub fn hash_file(path: &Path, mut progress: impl FnMut(u64, u64)) -> Result<(String, u64)> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut read_total: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        read_total += n as u64;
        progress(read_total, total);
    }
    Ok((hex(&hasher.finalize()), read_total))
}

/// Resolve `--image NAME` to the file heyvm would have built.
///
/// The same resolution mvm-ctrl does: `$MVM_DATA_DIR/images/firecracker`, else
/// `~/.heyo/images/firecracker`. `NAME` is accepted with or without the `.ext4`
/// suffix because `heyvm mvm images` prints it without and the file has it.
pub fn heyvm_image_path(name: &str) -> Result<std::path::PathBuf> {
    let dir = match std::env::var("MVM_DATA_DIR") {
        Ok(d) if !d.trim().is_empty() => std::path::PathBuf::from(d),
        _ => dirs::home_dir()
            .context("cannot find a home directory to look for heyvm's images in")?
            .join(".heyo"),
    }
    .join("images")
    .join("firecracker");

    let stem = name.strip_suffix(".ext4").unwrap_or(name);
    let path = dir.join(format!("{stem}.ext4"));
    if !path.exists() {
        bail!(
            "no heyvm image called {stem:?} — looked for {}. `heyvm mvm images` lists what \
             is built, or give a path to an .ext4 file instead",
            path.display()
        );
    }
    Ok(path)
}

/// A tag, by the store's rules. Checked here so a bad name fails before a
/// multi-gigabyte upload rather than after it.
///
/// Either flat (`debian-hermes`) or namespaced (`heyo/postgres:16`, where a
/// bare `heyo/postgres` means `:latest`). A namespaced repository is 1–4
/// lowercase `/`-separated segments, each starting with a letter or digit.
pub fn is_valid_tag(name: &str) -> bool {
    if !(name.contains('/') || name.contains(':')) {
        return is_flat_tag(name);
    }
    let (repo, tag) = name.split_once(':').unwrap_or((name, "latest"));
    is_valid_repo(repo) && is_flat_tag(tag)
}

fn is_flat_tag(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let first = name.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// A repository name, by the store's rules (`heyo/postgres`).
pub fn is_valid_repo(repo: &str) -> bool {
    if repo.is_empty() || repo.len() > 180 {
        return false;
    }
    let segments: Vec<&str> = repo.split('/').collect();
    segments.len() <= 4
        && segments.iter().all(|seg| {
            let b = seg.as_bytes();
            !b.is_empty()
                && b.len() <= 64
                && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                && b.iter().all(|&c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
                })
        })
}

/// The repository a namespaced tag belongs to; `None` for a flat tag.
pub fn repo_of(tag: &str) -> Option<&str> {
    if !(tag.contains('/') || tag.contains(':')) {
        return None;
    }
    Some(tag.split_once(':').map(|(r, _)| r).unwrap_or(tag))
}

/// Split a pull reference into the store it names and the reference within it.
///
/// `hub.heyo.work/heyo/postgres:16` names a store by host, the way an image
/// reference names a registry: the first segment is a host when there is more
/// than one segment and it contains a `.` or a `:` or is `localhost`. Anything
/// else (`heyo/postgres:16`, `debian`) is a reference into the configured store.
pub fn split_store_ref(reference: &str) -> (Option<String>, String) {
    if let Some((first, rest)) = reference.split_once('/')
        && (first.contains('.') || first.contains(':') || first == "localhost")
        && !rest.is_empty()
    {
        let scheme = if first.starts_with("localhost") || first.starts_with("127.") {
            "http"
        } else {
            "https"
        };
        return (Some(format!("{scheme}://{first}")), rest.to_string());
    }
    (None, reference.to_string())
}

/// The tag a file gets when none is given: its name without `.ext4`, which is
/// exactly what `art heyvm import` uses and therefore what `--image` round-trips
/// through.
pub fn default_tag_for(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    is_valid_tag(stem).then(|| stem.to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Accept `host:port` as shorthand for `http://host:port`, and drop a trailing
/// slash so paths concatenate cleanly.
fn normalize_url(s: &str) -> String {
    let s = s.trim();
    let with_scheme = if s.contains("://") {
        s.to_string()
    } else {
        format!("http://{s}")
    };
    with_scheme.trim_end_matches('/').to_string()
}

/// Percent-encode a path segment. A digest and a tag are both tame by the
/// store's own rules, but those rules are enforced on the store, and this is the
/// side that builds the URL.
fn escape(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_url_gets_a_scheme_and_loses_its_trailing_slash() {
        assert_eq!(normalize_url("localhost:8080"), "http://localhost:8080");
        assert_eq!(normalize_url("http://art:8080/"), "http://art:8080");
        assert_eq!(normalize_url(" https://art.example.com "), "https://art.example.com");
    }

    #[test]
    fn a_manifest_matches_what_art_heyvm_import_writes() {
        let m = rootfs_manifest("c74abee2", 4096, "debian-hermes");
        assert_eq!(m["kind"], KIND_ROOTFS);
        assert_eq!(m["schema"], 1);
        assert_eq!(m["entries"][0]["name"], ROOTFS_FILENAME);
        assert_eq!(m["entries"][0]["digest"], "c74abee2");
        assert_eq!(m["entries"][0]["size"], 4096);
        assert_eq!(m["annotations"][ANN_IMAGE], "debian-hermes");
        assert_eq!(m["annotations"][ANN_PRIMITIVE], PRIMITIVE_EXT4_RAW);
        // A string, not a number: it is an annotation, and annotations are a
        // map of strings on the store's side.
        assert_eq!(m["annotations"][ANN_NOMINAL_SIZE], "4096");
    }

    #[test]
    fn a_dockerfile_manifest_matches_what_art_dockerfile_put_writes() {
        let m = dockerfile_manifest(
            ("a1b2", 812),
            Some(("c3d4", 40213)),
            Some("web"),
            Some(4096),
            None,
        );
        assert_eq!(m["kind"], KIND_DOCKERFILE);
        assert_eq!(m["schema"], 1);
        // Order is fixed and significant: the store addresses entries as a
        // sequence, so emitting them the other way round would give the same
        // recipe a second manifest.
        assert_eq!(m["entries"][0]["name"], DOCKERFILE_ENTRY);
        assert_eq!(m["entries"][0]["digest"], "a1b2");
        assert_eq!(m["entries"][1]["name"], CONTEXT_ENTRY);
        assert_eq!(m["entries"][1]["size"], 40213);
        assert_eq!(m["annotations"][ANN_IMAGE], "web");
        // A string, not a number: annotations are a map of strings on the
        // store's side and a number would not round-trip.
        assert_eq!(m["annotations"][ANN_SIZE_MB], "4096");
    }

    #[test]
    fn an_unset_annotation_is_absent_rather_than_empty() {
        // The manifest is content-addressed, so `""` is a different address from
        // an absent key — and re-pushing an unchanged recipe has to land on the
        // manifest already there.
        let m = dockerfile_manifest(("a1b2", 812), None, None, None, None);
        assert_eq!(m["annotations"].as_object().unwrap().len(), 0);
        assert_eq!(m["entries"].as_array().unwrap().len(), 1);
        assert!(m["annotations"].get(ANN_IMAGE).is_none());
    }

    #[test]
    fn packing_the_same_tree_twice_gives_the_same_bytes() {
        // Deterministic headers are what make a re-push of an unchanged context
        // a HEAD and nothing else.
        let dir = std::env::temp_dir().join(format!("heyctl-pack-{}", std::process::id()));
        let ctx = dir.join("ctx");
        std::fs::create_dir_all(ctx.join("app")).unwrap();
        std::fs::write(ctx.join("app/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(ctx.join("README"), b"hi").unwrap();

        let first = dir.join("1.tar.gz");
        let second = dir.join("2.tar.gz");
        assert!(pack_context(&ctx, &first).unwrap() > 0);
        pack_context(&ctx, &second).unwrap();
        assert_eq!(
            std::fs::read(&first).unwrap(),
            std::fs::read(&second).unwrap()
        );

        // And it is a real gzipped tar with the files in it.
        let gz = flate2::read::GzDecoder::new(std::fs::File::open(&first).unwrap());
        let names: Vec<String> = tar::Archive::new(gz)
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert!(names.iter().any(|n| n.ends_with("app/main.rs")), "{names:?}");
        assert!(names.iter().any(|n| n.ends_with("README")), "{names:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_context_passed_as_the_dockerfile_is_caught_before_the_upload() {
        let p = Path::new("Dockerfile");
        assert!(check_dockerfile_size(p, 4096).is_ok());
        let e = check_dockerfile_size(p, MAX_DOCKERFILE_BYTES + 1).unwrap_err();
        assert!(e.to_string().contains("--context"), "{e}");
    }

    #[test]
    fn tags_follow_the_stores_rules() {
        assert!(is_valid_tag("debian-hermes"));
        assert!(is_valid_tag("ubuntu-24.04"));
        assert!(is_valid_tag("web_v2"));
        assert!(!is_valid_tag(""));
        assert!(!is_valid_tag("-leading-dash"));
        assert!(!is_valid_tag(".hidden"));
        assert!(!is_valid_tag("a//b"));
        assert!(!is_valid_tag("A/b"));
        assert!(!is_valid_tag("a/../b"));
        assert!(!is_valid_tag("a/b:c/d"));
        assert!(!is_valid_tag("has space"));
        // Namespaced, as the hub publishes them.
        assert!(is_valid_tag("heyo/postgres:16"));
        assert!(is_valid_tag("heyo/postgres"));
        assert!(is_valid_tag("a/b"));
        assert_eq!(repo_of("heyo/postgres:16"), Some("heyo/postgres"));
        assert_eq!(repo_of("heyo/postgres"), Some("heyo/postgres"));
        assert_eq!(repo_of("debian"), None);
    }

    #[test]
    fn a_pull_reference_names_its_store_like_an_image_names_its_registry() {
        assert_eq!(
            split_store_ref("hub.heyo.work/heyo/postgres:16"),
            (Some("https://hub.heyo.work".into()), "heyo/postgres:16".into())
        );
        assert_eq!(
            split_store_ref("localhost:8080/heyo/pg:1"),
            (Some("http://localhost:8080".into()), "heyo/pg:1".into())
        );
        // No host: a reference into the configured store.
        assert_eq!(split_store_ref("heyo/postgres:16"), (None, "heyo/postgres:16".into()));
        assert_eq!(split_store_ref("postgres:16"), (None, "postgres:16".into()));
        assert_eq!(split_store_ref("debian"), (None, "debian".into()));
    }

    #[test]
    fn only_plain_entry_names_are_written() {
        assert!(is_safe_entry_name("rootfs.ext4"));
        assert!(is_safe_entry_name("context.tar.gz"));
        for bad in ["", "../x", "a/b", ".bashrc", ".."] {
            assert!(!is_safe_entry_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_files_own_name_is_its_default_tag() {
        assert_eq!(
            default_tag_for(Path::new("/home/x/.heyo/images/firecracker/artifacts.ext4")),
            Some("artifacts".to_string())
        );
        // A name the store would refuse gets no default rather than a mangled
        // one — the push then asks for --tag instead of inventing something.
        assert_eq!(default_tag_for(Path::new("/tmp/.hidden.ext4")), None);
    }

    #[test]
    fn hashing_a_file_reports_the_digest_and_the_bytes_it_covered() {
        let dir = std::env::temp_dir().join(format!("heyctl-art-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob");
        std::fs::write(&path, b"hello").unwrap();

        let mut last = (0, 0);
        let (digest, size) = hash_file(&path, |done, total| last = (done, total)).unwrap();
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(size, 5);
        assert_eq!(last, (5, 5));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_segments_are_escaped() {
        assert_eq!(escape("debian-hermes"), "debian-hermes");
        assert_eq!(escape("a/b"), "a%2Fb");
    }
}
