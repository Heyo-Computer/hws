//! HTTP surface: the JSON API under `/api`, and git smart HTTP under
//! `/<ns>/<repo>.git/…`.
//!
//! Every refusal says what to do next. The feedback that started this service
//! was an agent getting a bare 404 with nothing to act on.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{self, Authenticator, MintError, Principal, Tier};
use crate::commit::{self, CommitRequest};
use crate::config::Config;
use crate::git::{GitError, GitService, RepoRef, Service};
use crate::registry::{self, DEFAULT_BRANCH, NamespaceBinding, Registry, RegistryError, RepoMeta};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub registry: Arc<Registry>,
    pub auth: Arc<Authenticator>,
    pub git: Arc<GitService>,
    /// The shared UI's theme cookie (`ui/ui.rs`).
    pub ui: Arc<crate::heyo_ui::CookieConfig>,
}

pub fn router(state: AppState) -> Router {
    // Base64 inflates by a third; leave room for the JSON around it.
    let commit_limit = commit::MAX_COMMIT_BYTES * 3 / 2;
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/whoami", get(whoami))
        .route("/api/repos/{ns}", get(list_repos).post(create_repo))
        .route("/api/repos/{ns}/{repo}", get(get_repo).delete(delete_repo))
        .route(
            "/api/repos/{ns}/{repo}/commits",
            post(create_commit).layer(DefaultBodyLimit::max(commit_limit)),
        )
        .route("/api/tokens", get(list_tokens).post(mint_token))
        .route("/api/tokens/{id}", delete(revoke_token))
        .route("/{ns}/{repo}/info/refs", get(info_refs))
        .route("/{ns}/{repo}/{service}", post(git_rpc));
    let router = if state.cfg.web {
        router.merge(crate::web::routes())
    } else {
        router
    };
    router.with_state(state)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub struct ApiError {
    status: StatusCode,
    error: String,
    hint: Option<String>,
}

impl ApiError {
    fn new(status: StatusCode, error: impl Into<String>) -> Self {
        Self {
            status,
            error: error.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The error and its hint as one sentence, for a page.
    pub fn message(&self) -> String {
        match &self.hint {
            Some(h) => format!("{} ({h})", self.error),
            None => self.error.clone(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.error });
        if let Some(h) = self.hint {
            body["hint"] = h.into();
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<RegistryError> for ApiError {
    fn from(e: RegistryError) -> Self {
        match e {
            RegistryError::Conflict(m) => ApiError::new(StatusCode::CONFLICT, m),
            RegistryError::Invalid(m) => ApiError::new(StatusCode::BAD_REQUEST, m),
            RegistryError::Store(e) => {
                tracing::error!(error = %e, "object store failure");
                ApiError::new(StatusCode::BAD_GATEWAY, e.to_string())
            }
        }
    }
}

impl From<GitError> for ApiError {
    fn from(e: GitError) -> Self {
        ApiError::new(e.status, e.message)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

const CREDENTIAL_HINT: &str = "send `Authorization: Bearer <token>`: an hrm_ repo token, an applb_ \
     app-lb token, or a Heyo API key. git sends it as the password of Basic auth.";

async fn caller(s: &AppState, headers: &HeaderMap) -> ApiResult<Arc<Principal>> {
    let Some(bearer) = auth::bearer(headers) else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "no credential").hint(CREDENTIAL_HINT));
    };
    s.auth.authenticate(&bearer).await.ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, "credential refused").hint(format!(
            "it is unknown, expired or revoked, or its issuer is unreachable. Providers here: {}",
            s.auth.providers().join(", ")
        ))
    })
}

fn require(p: &Principal, ns: &str, repo: Option<&str>, want: Tier) -> ApiResult<()> {
    if p.allows(ns, repo, want) {
        return Ok(());
    }
    let what = repo.map_or(format!("namespace {ns}"), |r| format!("{ns}/{r}"));
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        format!(
            "{} needs {} on {what}; this credential has {}",
            p.subject,
            want.as_str(),
            p.tier_in(ns).map_or("no access", Tier::as_str)
        ),
    )
    .hint(match want {
        Tier::Admin => "creating repos and minting tokens needs a namespace admin credential",
        Tier::Write => "mint a write token with POST /api/tokens (access: write)",
        Tier::Read => "use a credential scoped to this namespace",
    }))
}

pub fn check_names(ns: &str, repo: Option<&str>) -> ApiResult<()> {
    if !registry::valid_namespace(ns) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid namespace {ns:?}"),
        ));
    }
    if let Some(r) = repo
        && !registry::valid_repo_name(r)
    {
        return Err(
            ApiError::new(StatusCode::BAD_REQUEST, format!("invalid repo name {r:?}"))
                .hint("1-100 of A-Z a-z 0-9 . _ -, not starting with . or -"),
        );
    }
    Ok(())
}

async fn bound(s: &AppState, ns: &str) -> ApiResult<NamespaceBinding> {
    s.registry.binding(ns).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            format!("namespace {ns} has no repos"),
        )
        .hint(format!("create one with POST /api/repos/{ns}"))
    })
}

pub async fn existing(
    s: &AppState,
    ns: &str,
    repo: &str,
) -> ApiResult<(NamespaceBinding, RepoMeta)> {
    let b = bound(s, ns).await?;
    let meta = s.registry.repo(&b, ns, repo).await?.ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            format!("repo {ns}/{repo} does not exist"),
        )
        .hint(format!(
            "create it with POST /api/repos/{ns} {{\"name\": \"{repo}\"}}"
        ))
    })?;
    Ok((b, meta))
}

pub fn clone_url(s: &AppState, ns: &str, repo: &str) -> String {
    format!("{}/{ns}/{repo}.git", s.cfg.public_url)
}

fn repo_json(s: &AppState, m: &RepoMeta) -> serde_json::Value {
    json!({
        "name": m.name,
        "namespace": m.namespace,
        "default_branch": m.default_branch,
        "description": m.description,
        "created_at": m.created_at,
        "created_by": m.created_by,
        "clone_url": clone_url(s, &m.namespace, &m.name),
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let store = match &s.registry.store {
        crate::store::Store::S3(_) => "s3",
        crate::store::Store::Fs(_) => "fs",
    };
    Json(json!({ "ok": true, "store": store, "providers": s.auth.providers() }))
}

async fn whoami(State(s): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Principal>> {
    Ok(Json((*caller(&s, &headers).await?).clone()))
}

async fn list_repos(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    check_names(&ns, None)?;
    let p = caller(&s, &headers).await?;
    require(&p, &ns, None, Tier::Read)?;
    let repos = match s.registry.binding(&ns).await? {
        Some(b) => s.registry.list_repos(&b, &ns).await?,
        None => vec![],
    };
    Ok(Json(
        json!({ "namespace": ns, "repos": repos.iter().map(|m| repo_json(&s, m)).collect::<Vec<_>>() }),
    ))
}

#[derive(Deserialize)]
pub struct CreateRepo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
}

async fn create_repo(
    State(s): State<AppState>,
    Path(ns): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateRepo>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let p = caller(&s, &headers).await?;
    let meta = new_repo(&s, &p, &ns, body).await?;
    let mut out = repo_json(&s, &meta);
    out["push"] = json!(format!(
        "git push {} HEAD:{}  (Basic auth, any username, password = a write token)",
        clone_url(&s, &ns, &meta.name),
        meta.default_branch
    ));
    Ok((StatusCode::CREATED, Json(out)))
}

/// Create a repo in `ns` as `p`, binding the namespace to a bucket first if
/// this is its first repo. Shared by the API and the web UI.
pub async fn new_repo(
    s: &AppState,
    p: &Principal,
    ns: &str,
    body: CreateRepo,
) -> ApiResult<RepoMeta> {
    check_names(ns, Some(&body.name))?;
    require(p, ns, None, Tier::Admin)?;
    let branch = body
        .default_branch
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BRANCH.into());
    if !commit::valid_branch(&branch) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid default_branch {branch:?}"),
        ));
    }
    let binding = match s.registry.binding(ns).await? {
        Some(b) => b,
        None => {
            let account = p.account_for(ns).or_else(|| s.cfg.default_account.clone()).ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    format!("cannot tell which Heyo account owns namespace {ns}, so there is no bucket to put it in"),
                )
                .hint(
                    "create the first repo in a namespace with a Heyo API key or login (they carry the \
                     account), or set REMOTE_DEFAULT_ACCOUNT on a self-hosted fleet",
                )
            })?;
            s.registry.bind(ns, &account).await?
        }
    };
    let meta = s
        .registry
        .create_repo(
            &binding,
            RepoMeta {
                name: body.name.clone(),
                namespace: ns.to_string(),
                default_branch: branch,
                created_at: crate::sigv4::now_unix(),
                created_by: Some(p.subject.clone()),
                description: body.description.filter(|d| !d.trim().is_empty()),
            },
        )
        .await?;
    tracing::info!(namespace = %ns, repo = %meta.name, by = %p.subject, "created repo");
    Ok(meta)
}

async fn get_repo(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let repo = registry::repo_from_url(&repo).to_string();
    check_names(&ns, Some(&repo))?;
    let p = caller(&s, &headers).await?;
    require(&p, &ns, Some(&repo), Tier::Read)?;
    let (b, meta) = existing(&s, &ns, &repo).await?;
    let (state, _) = s.registry.state(&b.bucket, &ns, &repo).await?;
    let mut out = repo_json(&s, &meta);
    out["head"] = state.head.clone().into();
    out["refs"] = json!(state.refs);
    out["empty"] = state.refs.is_empty().into();
    out["version"] = state.version.into();
    out["updated_at"] = state.updated_at.into();
    Ok(Json(out))
}

async fn delete_repo(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let p = caller(&s, &headers).await?;
    let objects = remove_repo(&s, &p, &ns, &repo).await?;
    Ok(Json(
        json!({ "deleted": format!("{ns}/{repo}"), "objects": objects }),
    ))
}

/// Delete `ns/repo` as `p`. Shared by the API and the web UI.
pub async fn remove_repo(s: &AppState, p: &Principal, ns: &str, repo: &str) -> ApiResult<usize> {
    check_names(ns, Some(repo))?;
    require(p, ns, None, Tier::Admin)?;
    let (b, _) = existing(s, ns, repo).await?;
    let r = RepoRef {
        bucket: b.bucket.clone(),
        ns: ns.to_string(),
        name: repo.to_string(),
    };
    // Exclusive, so no push lands half into a deleted repo on this instance.
    let ex = s.git.exclusive(&r).await?;
    let objects = s.registry.delete_repo(&b, ns, repo).await?;
    let _ = tokio::fs::remove_dir_all(&ex.path).await;
    drop(ex);
    tracing::info!(namespace = %ns, repo = %repo, by = %p.subject, "deleted repo");
    Ok(objects)
}

async fn create_commit(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<commit::CommitResult>> {
    check_names(&ns, Some(&repo))?;
    let p = caller(&s, &headers).await?;
    require(&p, &ns, Some(&repo), Tier::Write)?;
    let (b, meta) = existing(&s, &ns, &repo).await?;

    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let (req, entries, deletes) = if ctype.starts_with("application/json") {
        let req: CommitRequest = serde_json::from_slice(&body)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("bad commit body: {e}")))?;
        let (entries, deletes) = commit::decode(&req.files)?;
        (req, entries, deletes)
    } else if ctype.contains("gzip") || ctype.contains("tar") {
        let req = CommitRequest {
            branch: q.get("branch").cloned(),
            message: q.get("message").cloned().unwrap_or_else(|| "Upload".into()),
            files: vec![],
            base: q.get("base").cloned(),
            // A tarball is the whole tree unless asked otherwise.
            replace: q.get("replace").is_none_or(|v| v != "false"),
            author_name: None,
            author_email: None,
        };
        (req, commit::decode_tarball(&body)?, vec![])
    } else {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("cannot commit a {ctype} body"),
        )
        .hint("send JSON {message, files: [{path, content}]} or a application/gzip tarball"));
    };
    if entries.is_empty() && deletes.is_empty() && !req.replace {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "no files to commit"));
    }
    let branch = req.branch.clone().unwrap_or(meta.default_branch);
    let r = RepoRef {
        bucket: b.bucket,
        ns,
        name: repo,
    };
    let author_name = req.author_name.clone().unwrap_or_else(|| p.subject.clone());
    let author_email = req
        .author_email
        .clone()
        .unwrap_or_else(|| "agent@heyo.computer".into());
    let result = commit::commit(
        &s.git,
        &r,
        &branch,
        &req.message,
        entries,
        deletes,
        req.base.as_deref(),
        req.replace,
        (&author_name, &author_email),
    )
    .await?;
    tracing::info!(namespace = %r.ns, repo = %r.name, branch = %branch, commit = %result.commit, by = %p.subject, "server-side commit");
    Ok(Json(result))
}

#[derive(Deserialize)]
struct MintBody {
    namespace: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    repos: Vec<String>,
    access: Tier,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn mint_token(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MintBody>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let p = caller(&s, &headers).await?;
    for r in &body.repos {
        check_names(&body.namespace, Some(r))?;
    }
    let (token, rec) = s
        .auth
        .mint(
            &p,
            &body.namespace,
            &body.name,
            body.repos,
            body.access,
            body.ttl_secs,
            s.cfg.max_token_ttl_secs,
        )
        .await
        .map_err(|e| match e {
            MintError::Forbidden(m) => ApiError::new(StatusCode::FORBIDDEN, m),
            MintError::Invalid(m) => ApiError::new(StatusCode::BAD_REQUEST, m),
            MintError::Store(e) => ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()),
        })?;
    let mut out = rec.public();
    out["token"] = token.into();
    out["note"] = "shown once; store it as a secret. For app-lb builds: build.auth with \
                   username x-access-token."
        .into();
    Ok((StatusCode::CREATED, Json(out)))
}

async fn list_tokens(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let p = caller(&s, &headers).await?;
    let ns = q.get("namespace").cloned().unwrap_or_default();
    check_names(&ns, None)?;
    require(&p, &ns, None, Tier::Admin)?;
    let toks = s
        .auth
        .tokens(&ns)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(
        json!({ "namespace": ns, "tokens": toks.iter().map(|t| t.public()).collect::<Vec<_>>() }),
    ))
}

async fn revoke_token(
    State(s): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let p = caller(&s, &headers).await?;
    let rec = s
        .auth
        .token(&id)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no token {id}")))?;
    require(&p, &rec.namespace, None, Tier::Admin)?;
    s.auth
        .revoke(&id)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({ "revoked": id })))
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

/// git only sends credentials after a 401 that asks for Basic.
fn git_unauthorized(msg: &str) -> Response {
    let mut r = (
        StatusCode::UNAUTHORIZED,
        format!("{msg}\n{CREDENTIAL_HINT}\n"),
    )
        .into_response();
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"heyo remote\""),
    );
    r
}

async fn git_repo(
    s: &AppState,
    ns: &str,
    repo_seg: &str,
    headers: &HeaderMap,
    want: Tier,
) -> Result<RepoRef, Response> {
    let repo = registry::repo_from_url(repo_seg);
    check_names(ns, Some(repo)).map_err(|e| e.into_response())?;
    let Some(bearer) = auth::bearer(headers) else {
        return Err(git_unauthorized("authentication required"));
    };
    let Some(p) = s.auth.authenticate(&bearer).await else {
        return Err(git_unauthorized(
            "credential refused (unknown, expired or revoked)",
        ));
    };
    if !p.allows(ns, Some(repo), want) {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "{} may not {} {ns}/{repo}; this credential has {} there\n",
                p.subject,
                if want == Tier::Write {
                    "push to"
                } else {
                    "read"
                },
                p.tier_in(ns).map_or("no access", Tier::as_str)
            ),
        )
            .into_response());
    }
    let (b, _) = existing(s, ns, repo).await.map_err(|e| e.into_response())?;
    Ok(RepoRef {
        bucket: b.bucket,
        ns: ns.to_string(),
        name: repo.to_string(),
    })
}

fn protocol(headers: &HeaderMap) -> Option<String> {
    headers
        .get("git-protocol")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

async fn info_refs(
    State(s): State<AppState>,
    Path((ns, repo)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(svc) = q.get("service").and_then(|v| Service::parse(v)) else {
        return (
            StatusCode::FORBIDDEN,
            "only smart HTTP is served: git-upload-pack or git-receive-pack\n",
        )
            .into_response();
    };
    let want = if svc == Service::ReceivePack {
        Tier::Write
    } else {
        Tier::Read
    };
    let r = match git_repo(&s, &ns, &repo, &headers, want).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    s.git
        .advertise(&r, svc, protocol(&headers).as_deref())
        .await
        .into_response()
}

async fn git_rpc(
    State(s): State<AppState>,
    Path((ns, repo, service)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(svc) = Service::parse(&service) else {
        return (StatusCode::NOT_FOUND, "not a git service\n").into_response();
    };
    let want = if svc == Service::ReceivePack {
        Tier::Write
    } else {
        Tier::Read
    };
    let r = match git_repo(&s, &ns, &repo, &headers, want).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("gzip"));
    s.git
        .rpc(&r, svc, protocol(&headers).as_deref(), gzip, body)
        .await
        .into_response()
}
