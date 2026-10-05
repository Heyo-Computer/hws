//! Git over smart HTTP, with the object store as the authority.
//!
//! Every repo has a bare **cache** on local disk, `CACHE_DIR/<bucket>/<ns>/<repo>.git`.
//! The cache is only a working copy. Before any operation it is *hydrated*
//! from the repo's `state.json`: missing packs are downloaded and the refs are
//! rewritten to match. Two regional instances can therefore serve the same repo,
//! and a cache can be deleted at any time.
//!
//! Pushes run `git receive-pack --stateless-rpc` against the cache with a
//! `pre-receive` hook. The hook is this same binary (`remote hook pre-receive`,
//! see [`run_pre_receive`]) and it runs while the pushed objects are still in
//! git's quarantine directory. It:
//!
//! 1. uploads the quarantined packs;
//! 2. replaces `state.json` with `If-Match` on the ETag the cache was hydrated
//!    from.
//!
//! If another push (from any region) got there first, the conditional write
//! fails, the hook exits non-zero, and git itself rejects the push and drops
//! the quarantine. The client sees `pre-receive hook declined` and the reason,
//! and nothing local or remote has moved. The refs only change in the cache
//! after the authority has accepted them.
//!
//! The server-side commit path ([`crate::commit`]) pushes into the cache with a
//! local `git push`. That goes through the same receive-pack and the same hook,
//! so there is one write path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::registry::{self, RepoState};
use crate::store::{Cond, Put, Store};

pub const ZERO_ID: &str = "0000000000000000000000000000000000000000";

/// One repo, located.
#[derive(Debug, Clone)]
pub struct RepoRef {
    pub bucket: String,
    pub ns: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    fn subcommand(self) -> &'static str {
        &self.name()[4..]
    }
}

pub struct GitService {
    pub git_bin: String,
    pub cache_dir: PathBuf,
    pub max_push_bytes: u64,
    pub allow_force_push: bool,
    /// What the `pre-receive` hook execs: this binary.
    pub hook_bin: PathBuf,
    pub store: Store,
    pub hook_env: Vec<(String, String)>,
    locks: Mutex<HashMap<String, Arc<RwLock<()>>>>,
}

/// An error that reaches a git client as text, and an HTTP status.
#[derive(Debug)]
pub struct GitError {
    pub status: StatusCode,
    pub message: String,
}

impl GitError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for GitError {
    fn into_response(self) -> Response {
        (self.status, format!("{}\n", self.message)).into_response()
    }
}

impl From<registry::RegistryError> for GitError {
    fn from(e: registry::RegistryError) -> Self {
        GitError::internal(e.to_string())
    }
}

/// A hydrated cache held exclusively, for a push or a commit.
pub struct Exclusive {
    /// Held for its drop: the repo is exclusive while this lives.
    #[allow(dead_code)]
    pub guard: OwnedRwLockWriteGuard<()>,
    pub path: PathBuf,
    pub state: RepoState,
    pub etag: Option<String>,
}

/// A hydrated cache held shared, for the web UI's reads.
pub struct ReadView {
    /// Held for its drop: no push rewrites the refs while this lives.
    #[allow(dead_code)]
    guard: OwnedRwLockReadGuard<()>,
    pub path: PathBuf,
    pub state: RepoState,
}

impl GitService {
    pub fn new(
        git_bin: String,
        cache_dir: PathBuf,
        max_push_bytes: u64,
        allow_force_push: bool,
        hook_bin: PathBuf,
        store: Store,
        hook_env: Vec<(String, String)>,
    ) -> Self {
        Self {
            git_bin,
            cache_dir,
            max_push_bytes,
            allow_force_push,
            hook_bin,
            store,
            hook_env,
            locks: Mutex::new(HashMap::new()),
        }
    }

    fn lock_for(&self, r: &RepoRef) -> Arc<RwLock<()>> {
        let key = format!("{}/{}/{}", r.bucket, r.ns, r.name);
        self.locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_default()
            .clone()
    }

    pub fn cache_path(&self, r: &RepoRef) -> PathBuf {
        self.cache_dir
            .join(&r.bucket)
            .join(&r.ns)
            .join(format!("{}.git", r.name))
    }

    /// A `git` that ignores the host's and the user's configuration (hooks,
    /// signing, credential helpers) and never prompts.
    pub fn git(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.git_bin);
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .kill_on_drop(true);
        cmd
    }

    /// Run git to completion; stdout on success, stderr in the error.
    pub async fn run(&self, cmd: tokio::process::Command) -> Result<String, GitError> {
        self.run_bytes(cmd)
            .await
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// [`run`](Self::run), for output that may not be text (a blob).
    pub async fn run_bytes(&self, mut cmd: tokio::process::Command) -> Result<Vec<u8>, GitError> {
        let out = cmd
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| GitError::internal(format!("cannot run {}: {e}", self.git_bin)))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(GitError::internal(format!(
                "git failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    /// Create the cache if it is not there: a bare repo whose pushes stay as
    /// packs (so the hook has whole packs to upload) and never gc on their
    /// own (so local packs keep the names the state lists).
    async fn ensure_cache(&self, path: &Path) -> Result<(), GitError> {
        if path.join("HEAD").exists() {
            return Ok(());
        }
        let tmp = path.with_extension(format!("init{}", rand::random::<u32>()));
        if let Some(parent) = tmp.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| GitError::internal(e.to_string()))?;
        }
        let mut init = self.git();
        init.arg("init").arg("--bare").arg("-q").arg(&tmp);
        self.run(init).await?;
        let settings = [
            ("receive.unpackLimit", "1"),
            ("transfer.unpackLimit", "1"),
            ("gc.auto", "0"),
            ("receive.autogc", "false"),
            (
                "receive.denyNonFastForwards",
                if self.allow_force_push {
                    "false"
                } else {
                    "true"
                },
            ),
            ("receive.denyCurrentBranch", "ignore"),
            ("uploadpack.allowFilter", "true"),
            ("core.hooksPath", "hooks"),
        ];
        for (k, v) in settings {
            let mut c = self.git();
            c.arg("--git-dir").arg(&tmp).args(["config", k, v]);
            self.run(c).await?;
        }
        let hook = tmp.join("hooks/pre-receive");
        tokio::fs::create_dir_all(tmp.join("hooks"))
            .await
            .map_err(|e| GitError::internal(e.to_string()))?;
        tokio::fs::write(
            &hook,
            "#!/bin/sh\nexec \"$REMOTE_HOOK_BIN\" hook pre-receive\n",
        )
        .await
        .map_err(|e| GitError::internal(e.to_string()))?;
        set_executable(&hook).map_err(|e| GitError::internal(e.to_string()))?;
        // Rename into place so a concurrent first touch never sees half a repo.
        match tokio::fs::rename(&tmp, path).await {
            Ok(()) => Ok(()),
            Err(_) if path.join("HEAD").exists() => {
                let _ = tokio::fs::remove_dir_all(&tmp).await;
                Ok(())
            }
            Err(e) => Err(GitError::internal(e.to_string())),
        }
    }

    /// Bring the cache in line with the authority. Caller holds the write lock.
    async fn hydrate(
        &self,
        r: &RepoRef,
        path: &Path,
    ) -> Result<(RepoState, Option<String>), GitError> {
        self.ensure_cache(path).await?;
        let (state, etag) = registry::state(&self.store, &r.bucket, &r.ns, &r.name).await?;
        let pack_dir = path.join("objects/pack");
        tokio::fs::create_dir_all(&pack_dir)
            .await
            .map_err(|e| GitError::internal(e.to_string()))?;
        for pack in &state.packs {
            if !valid_pack_name(pack) {
                return Err(GitError::internal(format!(
                    "state lists a bad pack name {pack:?}"
                )));
            }
            if pack_dir.join(format!("{pack}.idx")).exists() {
                continue;
            }
            // The .pack before the .idx: git finds packs by their index, so
            // an index only ever appears beside a complete pack.
            for ext in ["pack", "idx"] {
                let file = format!("{pack}.{ext}");
                let obj = self
                    .store
                    .get(&r.bucket, &registry::pack_key(&r.ns, &r.name, &file))
                    .await
                    .map_err(|e| GitError::internal(e.to_string()))?
                    .ok_or_else(|| {
                        GitError::internal(format!(
                            "pack {file} is listed but missing from the store"
                        ))
                    })?;
                let tmp = pack_dir.join(format!("{file}.tmp"));
                tokio::fs::write(&tmp, &obj.bytes)
                    .await
                    .map_err(|e| GitError::internal(e.to_string()))?;
                tokio::fs::rename(&tmp, pack_dir.join(&file))
                    .await
                    .map_err(|e| GitError::internal(e.to_string()))?;
            }
        }
        write_refs(path, &state)
            .await
            .map_err(|e| GitError::internal(e.to_string()))?;
        Ok((state, etag))
    }

    pub async fn exclusive(&self, r: &RepoRef) -> Result<Exclusive, GitError> {
        let guard = self.lock_for(r).write_owned().await;
        let path = self.cache_path(r);
        let (state, etag) = self.hydrate(r, &path).await?;
        Ok(Exclusive {
            guard,
            path,
            state,
            etag,
        })
    }

    /// A hydrated cache held shared, for browsing: pushes wait until the
    /// view is dropped, other readers do not.
    pub async fn read(&self, r: &RepoRef) -> Result<ReadView, GitError> {
        let guard = self.lock_for(r).write_owned().await;
        let path = self.cache_path(r);
        let (state, _) = self.hydrate(r, &path).await?;
        Ok(ReadView {
            guard: guard.downgrade(),
            path,
            state,
        })
    }

    /// Environment for a receive-pack whose hook must commit to `r`'s state
    /// as of `etag`.
    pub fn hook_env(&self, r: &RepoRef, etag: Option<&str>) -> Vec<(String, String)> {
        let mut env = self.hook_env.clone();
        env.extend([
            (
                "REMOTE_HOOK_BIN".to_string(),
                self.hook_bin.display().to_string(),
            ),
            ("REMOTE_HOOK_BUCKET".into(), r.bucket.clone()),
            ("REMOTE_HOOK_NS".into(), r.ns.clone()),
            ("REMOTE_HOOK_REPO".into(), r.name.clone()),
            (
                "REMOTE_HOOK_ETAG".into(),
                etag.unwrap_or_default().to_string(),
            ),
        ]);
        env
    }

    /// `GET …/info/refs?service=…`
    pub async fn advertise(
        &self,
        r: &RepoRef,
        svc: Service,
        protocol: Option<&str>,
    ) -> Result<Response, GitError> {
        let guard = self.lock_for(r).write_owned().await;
        let path = self.cache_path(r);
        self.hydrate(r, &path).await?;
        let _read = guard.downgrade();
        let v2 = svc == Service::UploadPack && protocol.is_some_and(|p| p.contains("version=2"));
        let mut cmd = self.git();
        cmd.arg(svc.subcommand())
            .args(["--stateless-rpc", "--advertise-refs"])
            .arg(&path);
        if v2 {
            cmd.env("GIT_PROTOCOL", protocol.unwrap_or_default());
        }
        let out = self.run(cmd).await?;
        let mut body = Vec::new();
        // http-backend's framing: protocol v2 answers with its capability
        // advertisement alone, v0/v1 behind a `# service=` packet.
        if !v2 {
            body.extend(pkt_line(&format!("# service={}\n", svc.name())));
            body.extend(b"0000");
        }
        body.extend(out.as_bytes());
        Ok(git_response(
            format!("application/x-{}-advertisement", svc.name()),
            Body::from(body),
        ))
    }

    /// `POST …/git-upload-pack` and `POST …/git-receive-pack`.
    pub async fn rpc(
        &self,
        r: &RepoRef,
        svc: Service,
        protocol: Option<&str>,
        gzip: bool,
        body: Body,
    ) -> Result<Response, GitError> {
        let limit = match svc {
            Service::ReceivePack => self.max_push_bytes,
            // Negotiation only: wants and haves.
            Service::UploadPack => 64 * 1024 * 1024,
        };
        let input = spool(body, limit, gzip).await?;

        let guard = self.lock_for(r).write_owned().await;
        let path = self.cache_path(r);
        let (_, etag) = self.hydrate(r, &path).await?;

        let mut cmd = self.git();
        cmd.arg(svc.subcommand()).arg("--stateless-rpc").arg(&path);
        if let Some(p) = protocol.filter(|_| svc == Service::UploadPack) {
            cmd.env("GIT_PROTOCOL", p);
        }
        // Held for the whole child: a push is exclusive with everything on
        // this repo, a fetch only with pushes and hydration.
        let held: Box<dyn Send + Sync> = match svc {
            Service::ReceivePack => {
                cmd.envs(self.hook_env(r, etag.as_deref()));
                Box::new(guard)
            }
            Service::UploadPack => Box::new(guard.downgrade()),
        };
        let stdin = input
            .reopen()
            .map_err(|e| GitError::internal(e.to_string()))?;
        let mut child = cmd
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitError::internal(format!("cannot run git: {e}")))?;

        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
        let label = format!("{}/{}/{}", r.ns, r.name, svc.subcommand());
        tokio::spawn(async move {
            let _held = held;
            let _input = input;
            let err_task = tokio::spawn(async move {
                let mut s = String::new();
                let _ = stderr.read_to_string(&mut s).await;
                s
            });
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx
                            .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
            let status = child.wait().await;
            let err = err_task.await.unwrap_or_default();
            match status {
                Ok(s) if s.success() => tracing::debug!(op = %label, "git rpc done"),
                other => {
                    tracing::warn!(op = %label, status = ?other, stderr = %err.trim(), "git rpc failed")
                }
            }
        });
        let stream =
            futures_util::stream::unfold(
                rx,
                |mut rx| async move { rx.recv().await.map(|x| (x, rx)) },
            );
        Ok(git_response(
            format!("application/x-{}-result", svc.name()),
            Body::from_stream(stream.boxed()),
        ))
    }
}

fn git_response(content_type: String, body: Body) -> Response {
    let mut resp = Response::new(body);
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type).expect("ascii"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, max-age=0, must-revalidate"),
    );
    resp
}

pub fn pkt_line(s: &str) -> Vec<u8> {
    format!("{:04x}{s}", s.len() + 4).into_bytes()
}

fn valid_pack_name(p: &str) -> bool {
    p.strip_prefix("pack-").is_some_and(|h| {
        (h.len() == 40 || h.len() == 64) && h.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

#[cfg(unix)]
fn set_executable(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Replace the cache's refs and HEAD with the state's.
async fn write_refs(path: &Path, state: &RepoState) -> std::io::Result<()> {
    let refs_dir = path.join("refs");
    if refs_dir.exists() {
        tokio::fs::remove_dir_all(&refs_dir).await?;
    }
    for d in ["refs/heads", "refs/tags"] {
        tokio::fs::create_dir_all(path.join(d)).await?;
    }
    let mut packed = String::from("# pack-refs with: sorted \n");
    for (name, id) in &state.refs {
        if valid_ref(name) && id.len() >= 40 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            packed.push_str(&format!("{id} {name}\n"));
        }
    }
    let tmp = path.join("packed-refs.tmp");
    tokio::fs::write(&tmp, packed).await?;
    tokio::fs::rename(&tmp, path.join("packed-refs")).await?;
    let head = if valid_ref(&state.head) {
        state.head.as_str()
    } else {
        "refs/heads/main"
    };
    tokio::fs::write(path.join("HEAD"), format!("ref: {head}\n")).await
}

fn valid_ref(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && !name.ends_with('/')
        && name
            .bytes()
            .all(|b| b > b' ' && b != 0x7f && !b"~^:?*[\\".contains(&b))
}

/// Copy a request body to a temp file, enforcing `limit` and undoing gzip.
async fn spool(body: Body, limit: u64, gzip: bool) -> Result<tempfile::NamedTempFile, GitError> {
    let raw = tempfile::NamedTempFile::new().map_err(|e| GitError::internal(e.to_string()))?;
    let mut file = tokio::fs::File::from_std(
        raw.reopen()
            .map_err(|e| GitError::internal(e.to_string()))?,
    );
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| GitError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
        total += chunk.len() as u64;
        if total > limit {
            return Err(GitError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "request is larger than this server's {} MiB limit (REMOTE_MAX_PUSH_MB)",
                    limit >> 20
                ),
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| GitError::internal(e.to_string()))?;
    }
    file.flush()
        .await
        .map_err(|e| GitError::internal(e.to_string()))?;
    drop(file);
    if !gzip {
        return Ok(raw);
    }
    tokio::task::spawn_blocking(move || {
        let out = tempfile::NamedTempFile::new()?;
        let mut dec = flate2::read::GzDecoder::new(std::io::BufReader::new(raw.reopen()?));
        let mut w = out.reopen()?;
        // The decompressed size is bounded too: a gzip bomb is a push.
        let n = std::io::copy(&mut (&mut dec).take(limit + 1), &mut w)?;
        if n > limit {
            return Err(std::io::Error::other(
                "decompressed request exceeds the push limit",
            ));
        }
        Ok(out)
    })
    .await
    .map_err(|e| GitError::internal(e.to_string()))?
    .map_err(|e| GitError::new(StatusCode::BAD_REQUEST, format!("bad gzip body: {e}")))
}

use std::io::Read as _;

// ---------------------------------------------------------------------------
// The pre-receive hook (runs as a separate process)
// ---------------------------------------------------------------------------

/// One `<old> <new> <ref>` line from git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub old: String,
    pub new: String,
    pub name: String,
}

pub fn parse_updates(input: &str) -> Result<Vec<Update>, String> {
    input
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next(), it.next()) {
                (Some(o), Some(n), Some(r)) => Ok(Update {
                    old: o.into(),
                    new: n.into(),
                    name: r.into(),
                }),
                _ => Err(format!("malformed update line {l:?}")),
            }
        })
        .collect()
}

/// The state after `updates`, or why they cannot apply to `base`.
pub fn apply_updates(
    base: &RepoState,
    updates: &[Update],
    new_packs: &[String],
) -> Result<RepoState, String> {
    let mut next = base.clone();
    for u in updates {
        if !valid_ref(&u.name) {
            return Err(format!("refusing ref name {:?}", u.name));
        }
        let current = base
            .refs
            .get(&u.name)
            .map(String::as_str)
            .unwrap_or(ZERO_ID);
        if current != u.old {
            return Err(format!(
                "{} moved on the server since this push started (expected {}, found {}); fetch and push again",
                u.name,
                short(&u.old),
                short(current)
            ));
        }
        if u.new == ZERO_ID {
            next.refs.remove(&u.name);
        } else {
            next.refs.insert(u.name.clone(), u.new.clone());
        }
    }
    for p in new_packs {
        if !next.packs.contains(p) {
            next.packs.push(p.clone());
        }
    }
    // A first push of some branch other than the default would otherwise
    // leave HEAD dangling, and every clone would check out nothing.
    if !next.refs.contains_key(&next.head)
        && let Some(first) = updates
            .iter()
            .find(|u| u.new != ZERO_ID && u.name.starts_with("refs/heads/"))
    {
        next.head = first.name.clone();
    }
    next.version = base.version + 1;
    next.updated_at = crate::sigv4::now_unix();
    Ok(next)
}

fn short(id: &str) -> &str {
    &id[..id.len().min(10)]
}

/// `remote hook pre-receive`: commit a push to the authority, or refuse it.
/// Exit status is the verdict; stderr reaches the pushing client as `remote:`.
pub async fn run_pre_receive(store: Store) -> Result<(), String> {
    let env = |k: &str| {
        std::env::var(k)
            .map_err(|_| format!("{k} is not set; this hook only runs under the remote service"))
    };
    let (bucket, ns, repo) = (
        env("REMOTE_HOOK_BUCKET")?,
        env("REMOTE_HOOK_NS")?,
        env("REMOTE_HOOK_REPO")?,
    );
    let etag = std::env::var("REMOTE_HOOK_ETAG")
        .ok()
        .filter(|e| !e.is_empty());
    let mut input = String::new();
    tokio::io::stdin()
        .read_to_string(&mut input)
        .await
        .map_err(|e| e.to_string())?;
    let updates = parse_updates(&input)?;

    let (base, current_etag) = registry::state(&store, &bucket, &ns, &repo)
        .await
        .map_err(|e| e.to_string())?;
    if current_etag != etag {
        return Err("another push to this repo landed first; fetch and push again".into());
    }

    // Objects arrive in git's quarantine directory and only move into the
    // repo if this hook succeeds.
    let quarantine = std::env::var("GIT_QUARANTINE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("objects"));
    let mut new_packs = Vec::new();
    let pack_dir = quarantine.join("pack");
    if let Ok(entries) = std::fs::read_dir(&pack_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(base) = name.strip_suffix(".pack")
                && valid_pack_name(base)
            {
                new_packs.push(base.to_string());
            }
        }
    }
    if has_loose_objects(&quarantine) {
        return Err(
            "push arrived as loose objects, which this server cannot store \
                    (receive.unpackLimit must be 1 in the cache repo)"
                .into(),
        );
    }

    let next = apply_updates(&base, &updates, &new_packs)?;
    for pack in &new_packs {
        for ext in ["pack", "idx"] {
            let file = format!("{pack}.{ext}");
            let bytes = std::fs::read(pack_dir.join(&file)).map_err(|e| format!("{file}: {e}"))?;
            store
                .put(
                    &bucket,
                    &registry::pack_key(&ns, &repo, &file),
                    bytes,
                    Cond::None,
                )
                .await
                .map_err(|e| format!("uploading {file}: {e}"))?;
        }
    }
    let body = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
    let cond = etag.map_or(Cond::Absent, Cond::Matches);
    match store
        .put(&bucket, &registry::state_key(&ns, &repo), body, cond)
        .await
        .map_err(|e| format!("recording the push: {e}"))?
    {
        Put::Written(_) => {
            eprintln!(
                "heyo: {} ref(s) updated, stored in {}",
                updates.len(),
                bucket
            );
            Ok(())
        }
        Put::PreconditionFailed => {
            Err("another push to this repo landed first; fetch and push again".into())
        }
    }
}

fn has_loose_objects(objects: &Path) -> bool {
    std::fs::read_dir(objects)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.len() == 2
                && n.bytes().all(|b| b.is_ascii_hexdigit())
                && std::fs::read_dir(e.path()).is_ok_and(|mut d| d.next().is_some())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: char) -> String {
        c.to_string().repeat(40)
    }

    #[test]
    fn updates_apply_only_on_the_state_they_were_made_against() {
        let base = RepoState::empty("main");
        let ups = parse_updates(&format!("{ZERO_ID} {} refs/heads/main\n", id('a'))).unwrap();
        let s1 = apply_updates(&base, &ups, &["pack-".to_string() + &id('1')]).unwrap();
        assert_eq!(s1.refs["refs/heads/main"], id('a'));
        assert_eq!(s1.version, 1);
        assert_eq!(s1.packs.len(), 1);

        // Replaying the same update against the new state is a stale push.
        let err = apply_updates(&s1, &ups, &[]).unwrap_err();
        assert!(err.contains("moved on the server"), "{err}");

        // Fast-forward then delete.
        let ff = parse_updates(&format!("{} {} refs/heads/main", id('a'), id('b'))).unwrap();
        let s2 = apply_updates(&s1, &ff, &[]).unwrap();
        let del = parse_updates(&format!("{} {ZERO_ID} refs/heads/main", id('b'))).unwrap();
        assert!(apply_updates(&s2, &del, &[]).unwrap().refs.is_empty());

        assert!(
            apply_updates(
                &base,
                &parse_updates(&format!("{ZERO_ID} {} refs/heads/../x", id('a'))).unwrap(),
                &[]
            )
            .is_err()
        );
        assert!(parse_updates("garbage").is_err());
    }

    #[test]
    fn a_first_push_to_another_branch_becomes_head() {
        let base = RepoState::empty("main");
        let ups = parse_updates(&format!("{ZERO_ID} {} refs/heads/master", id('a'))).unwrap();
        assert_eq!(
            apply_updates(&base, &ups, &[]).unwrap().head,
            "refs/heads/master"
        );
    }

    #[test]
    fn framing_and_names() {
        assert_eq!(
            pkt_line("# service=git-upload-pack\n"),
            b"001e# service=git-upload-pack\n"
        );
        assert!(valid_pack_name(&format!("pack-{}", id('a'))));
        assert!(!valid_pack_name("pack-../../x"));
        assert!(
            valid_ref("refs/heads/feat/x") && !valid_ref("HEAD") && !valid_ref("refs/heads/a b")
        );
        assert_eq!(
            Service::parse("git-receive-pack").unwrap().subcommand(),
            "receive-pack"
        );
    }
}
