//! A namespace's dashboard and API, under `/ns/{ns}/`.
//!
//! **Reached through app-lb's `ci` plugin, and nothing else.** app-lb proxies
//! `/namespaces/<ns>/plugins/ci/ui/<tail>` here as `/ns/<ns>/<tail>`, and
//! `/api/<x>` as `/ns/<ns>/api/<x>`, after its own session gate has decided
//! the viewer may see that namespace. It builds every request's headers from
//! scratch and adds:
//!
//! ```text
//! authorization: Bearer <CI_PLUGIN_API_TOKEN>
//! x-heyo-base: /namespaces/<ns>/plugins/ci
//! x-heyo-actor: <principal>      x-heyo-actor-email: <email>
//! x-heyo-actor-admin: true|false
//! ```
//!
//! The actor headers are trustworthy **only behind the bearer check**, which
//! is why these routes are not mounted at all without `CI_PLUGIN_API_TOKEN`,
//! and why the check runs before anything else — including deciding whether
//! the namespace in the path is real.
//!
//! Every request then has to name a namespace that app-lb currently lists as
//! having installed `ci` ([`crate::tenants`]); anything else is `404`, as is
//! any run, job, repository or token belonging to a different namespace. Every
//! lookup goes through the store's `*_in` queries for that reason, so a
//! cross-namespace id is indistinguishable from one that never existed.
//!
//! Writes — registering, minting, revoking, pausing, removing, cancelling,
//! re-running — need `x-heyo-actor-admin: true` and answer `303` to a page
//! under the base, which is the only kind of `Location` app-lb passes back.
//! Minting is the exception that renders: a token can be shown once, and a
//! redirect would have to carry it in the URL.

use super::pages::{self, RepoFlash, RepoView, Scope};
use super::{AppState, Identity, api, chrome_in, render_job, render_run, repos, stream, tail_job};
use crate::store::Run;
use axum::Form;
use axum::Json;
use axum::Router;
use axum::extract::{Extension, Path, Query, RawPathParams, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// How many runs a namespace's runs page shows, as the fleet's does.
const RECENT_RUNS: i64 = 50;

/// The bearer and the install list every request is checked against.
#[derive(Clone)]
pub struct Gate {
    /// SHA-256 of `CI_PLUGIN_API_TOKEN`. Compared in constant time against the
    /// digest of what was presented, so neither the value nor its length
    /// leaks through timing.
    token_digest: [u8; 32],
    tenants: Arc<crate::tenants::Tenants>,
}

impl Gate {
    pub fn new(token: &str, tenants: Arc<crate::tenants::Tenants>) -> Self {
        Self {
            token_digest: Sha256::digest(token.as_bytes()).into(),
            tenants,
        }
    }

    fn admits(&self, headers: &HeaderMap) -> bool {
        let Some(presented) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return false;
        };
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        digest.ct_eq(&self.token_digest).into()
    }
}

/// Who app-lb says is asking. Only ever built behind [`Gate::admits`].
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub principal: Option<String>,
    pub email: Option<String>,
    pub admin: bool,
}

impl Actor {
    fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        Self {
            principal: get("x-heyo-actor"),
            email: get("x-heyo-actor-email"),
            admin: get("x-heyo-actor-admin").as_deref() == Some("true"),
        }
    }

    /// The name the top bar shows.
    fn display(&self) -> Option<&str> {
        self.email.as_deref().or(self.principal.as_deref())
    }

    /// `(created_by, created_email)` for a registration or a token.
    fn stamp(&self) -> Option<(&str, &str)> {
        let principal = self.principal.as_deref()?;
        Some((principal, self.email.as_deref().unwrap_or("")))
    }

    /// The dispatcher's notion of a person, for a re-run's `actor_email`.
    fn identity(&self) -> Option<Identity> {
        Some(Identity {
            subject: self.principal.clone()?,
            email: self.email.clone().unwrap_or_default(),
            name: None,
        })
    }
}

/// What the gate established about a request, for its handler.
#[derive(Debug, Clone)]
pub struct NsContext {
    pub namespace: String,
    pub scope: Scope,
    pub actor: Actor,
}

/// The URLs a namespace's pages link with: app-lb's base when the request
/// came through app-lb and carries the base for *this* namespace, otherwise
/// this binary's own `/ns/{ns}/` paths.
///
/// Exact match only. The base ends up in every `href` and `Location` on the
/// page, so a value that is merely plausible — another namespace's, an
/// absolute URL, anything with a query — falls back to the native paths
/// rather than being echoed.
pub fn scope_for(namespace: &str, base: Option<&str>) -> Scope {
    let expected = format!("/namespaces/{namespace}/plugins/ci");
    Scope::namespace(namespace, base.filter(|b| *b == expected))
}

/// The routes, behind the gate. `None` without `CI_PLUGIN_API_TOKEN`.
pub fn router(state: &AppState) -> Option<Router<AppState>> {
    let token = state.config.plugin_api_token.as_deref()?;
    let gate = Gate::new(token, state.dispatcher.tenants.clone());
    Some(gated(routes(), gate))
}

fn routes() -> Router<AppState> {
    Router::new()
        .route("/ns/{ns}", get(runs_page))
        .route("/ns/{ns}/", get(runs_page))
        .route("/ns/{ns}/__ui/{*path}", get(ui_asset))
        .route("/ns/{ns}/runs/{run_id}", get(run_page))
        .route("/ns/{ns}/runs/{run_id}/cancel", post(cancel_run))
        .route("/ns/{ns}/runs/{run_id}/rerun", post(rerun_run))
        .route(
            "/ns/{ns}/runs/{run_id}/rerun-failed",
            post(rerun_failed_jobs),
        )
        .route("/ns/{ns}/runs/{run_id}/jobs/{job_key}", get(job_page))
        .route("/ns/{ns}/workflows", get(workflows_page))
        .route("/ns/{ns}/repos", get(repos_page).post(register_repo))
        .route("/ns/{ns}/repos/{repo_id}/tokens", post(create_repo_token))
        .route(
            "/ns/{ns}/repos/{repo_id}/tokens/{token_id}/revoke",
            post(revoke_repo_token),
        )
        .route("/ns/{ns}/repos/{repo_id}/enabled", post(set_repo_enabled))
        .route("/ns/{ns}/repos/{repo_id}/delete", post(delete_repo))
        .route("/ns/{ns}/api/runs", get(api_runs))
        .route("/ns/{ns}/api/runs/{run_id}", get(api_run))
        .route("/ns/{ns}/api/runs/{run_id}/logs", get(api_logs))
        .route("/ns/{ns}/api/repos", get(api_repos))
        .route("/ns/{ns}/api/stream/{run_id}/{job_key}", get(api_stream))
}

/// Put the gate in front of `routes`. `route_layer`, so a path no route
/// matches is a plain 404 that never reaches it.
fn gated<S: Clone + Send + Sync + 'static>(routes: Router<S>, gate: Gate) -> Router<S> {
    routes.route_layer(axum::middleware::from_fn_with_state(gate, guard))
}

async fn guard(
    State(gate): State<Gate>,
    params: RawPathParams,
    mut request: Request,
    next: Next,
) -> Response {
    // First, before the path is even looked at: without the bearer, the actor
    // headers are anybody's, and so is the answer to "is team-a installed".
    if !gate.admits(request.headers()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({ "error": "this route takes the ci plugin's bearer token" })),
        )
            .into_response();
    }
    let namespace = params
        .iter()
        .find(|(name, _)| *name == "ns")
        .map(|(_, value)| value.to_string())
        .unwrap_or_default();
    if !gate.tenants.is_installed(&namespace) {
        return not_installed();
    }
    let headers = request.headers();
    let context = NsContext {
        scope: scope_for(
            &namespace,
            headers.get("x-heyo-base").and_then(|v| v.to_str().ok()),
        ),
        actor: Actor::from_headers(headers),
        namespace,
    };
    request.extensions_mut().insert(context);
    next.run(request).await
}

fn not_installed() -> Response {
    error(StatusCode::NOT_FOUND, "no such namespace has installed ci")
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn chrome<'a>(state: &'a AppState, headers: &HeaderMap, ctx: &'a NsContext) -> pages::Chrome<'a> {
    chrome_in(state, headers, ctx.actor.display(), ctx.scope.clone())
}

/// A page with only a message on it, in the namespace's shell.
fn message(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &NsContext,
    status: StatusCode,
    text: &str,
) -> Response {
    if status.is_server_error() {
        tracing::warn!(namespace = %ctx.namespace, "namespace page failed: {text}");
    }
    (
        status,
        pages::layout(
            &chrome(state, headers, ctx),
            "",
            maud::html! {
                div .banner { (text) }
                p { a href=(ctx.scope.ui("/")) { "Back to runs" } }
            },
        ),
    )
        .into_response()
}

fn refuse_non_admin(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &NsContext,
) -> Result<(), Response> {
    if ctx.actor.admin {
        return Ok(());
    }
    Err(message(
        state,
        headers,
        ctx,
        StatusCode::FORBIDDEN,
        "Changing this namespace's CI is for its admins: registering a repository mints \
         a credential that can run code on the fleet's runners.",
    ))
}

/// Load a run of this namespace, or answer for why not.
async fn run_in(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &NsContext,
    run_id: &str,
) -> Result<Run, Response> {
    match state.store.get_run_in(&ctx.namespace, run_id).await {
        Ok(Some(run)) => Ok(run),
        Ok(None) => Err(message(
            state,
            headers,
            ctx,
            StatusCode::NOT_FOUND,
            &format!("No run {run_id}."),
        )),
        Err(e) => Err(message(
            state,
            headers,
            ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        )),
    }
}

// ---- pages ---------------------------------------------------------------

async fn runs_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let repo = q.get("repo").map(String::as_str).filter(|r| !r.is_empty());
    let repos = match state.store.repos_in(&ctx.namespace).await {
        Ok(repos) => repos,
        Err(e) => {
            return message(
                &state,
                &headers,
                &ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            );
        }
    };
    match state
        .store
        .recent_runs_in(&ctx.namespace, RECENT_RUNS, repo)
        .await
    {
        Ok(runs) => {
            pages::runs_page(&chrome(&state, &headers, &ctx), &runs, &repos, repo).into_response()
        }
        Err(e) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        ),
    }
}

async fn run_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let run = match run_in(&state, &headers, &ctx, &run_id).await {
        Ok(run) => run,
        Err(response) => return response,
    };
    let before = q.get("events_before").and_then(|v| v.parse::<i64>().ok());
    match render_run(&state, &chrome(&state, &headers, &ctx), &run, before).await {
        Ok(page) => page.into_response(),
        Err(e) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e,
        ),
    }
}

async fn job_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id, job_key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let run = match run_in(&state, &headers, &ctx, &run_id).await {
        Ok(run) => run,
        Err(response) => return response,
    };
    match render_job(&state, &chrome(&state, &headers, &ctx), &run, &job_key).await {
        Ok(Some(page)) => page.into_response(),
        Ok(None) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::NOT_FOUND,
            &format!("Run {run_id} has no job {job_key}."),
        ),
        Err(e) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e,
        ),
    }
}

async fn workflows_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    headers: HeaderMap,
) -> Response {
    match state.store.recent_runs_in(&ctx.namespace, 500, None).await {
        Ok(runs) => pages::workflows_page(
            &chrome(&state, &headers, &ctx),
            &super::latest_per_workflow(runs),
            &state.config.default_workflow_path,
        )
        .into_response(),
        Err(e) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        ),
    }
}

/// The stylesheet, script and fonts, under the namespace's prefix so a page
/// proxied through app-lb fetches them through the same proxy.
async fn ui_asset(Path((_, path)): Path<(String, String)>) -> Response {
    super::ui_asset(Path(path)).await
}

// ---- repositories --------------------------------------------------------

/// The fixed outcomes a write redirects with. A code rather than the message
/// itself, so nothing a request supplies is ever reflected onto the page.
fn done_message(code: &str) -> Option<&'static str> {
    Some(match code {
        "registered" => "Registered. Mint a token for it below.",
        "revoked" => "That token no longer works. Any build already running is unaffected.",
        "already-revoked" => "That token was already revoked.",
        "paused" => {
            "That repository is paused; every submit with its tokens is refused until it is resumed."
        }
        "resumed" => "That repository can submit again.",
        "removed" => "The registration and its tokens are gone. Its runs are kept.",
        _ => return None,
    })
}

/// `303` to the repositories page, carrying an outcome code.
fn back_to_repos(ctx: &NsContext, done: &str) -> Response {
    Redirect::to(&format!("{}?done={done}", ctx.scope.ui("/repos"))).into_response()
}

async fn render_repos(
    state: &AppState,
    headers: &HeaderMap,
    ctx: &NsContext,
    flash: RepoFlash,
) -> Response {
    let repos = match state.store.repos_in(&ctx.namespace).await {
        Ok(r) => r,
        Err(e) => {
            return message(
                state,
                headers,
                ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            );
        }
    };
    let mut views = Vec::with_capacity(repos.len());
    for repo in repos {
        let tokens = state.store.repo_tokens(&repo.id).await.unwrap_or_default();
        let last_run = state.store.last_run_of_repo(&repo.id).await.ok().flatten();
        views.push(RepoView {
            repo,
            tokens,
            last_run,
        });
    }
    let tenants = state.dispatcher.tenants.snapshot();
    let pool = state.runners.snapshot();
    let network =
        crate::tenancy::resolve_network(&pool, &ctx.namespace, tenants.network_for(&ctx.namespace), state.config.tenant_only)
            .ok()
            .map(|set| set.network_name.clone());
    pages::namespace_repos_page(
        &chrome(state, headers, ctx),
        &views,
        &state.config.public_url,
        network.as_deref(),
        ctx.actor.admin,
        &flash,
    )
    .into_response()
}

async fn repos_page(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let flash = q
        .get("done")
        .and_then(|c| done_message(c))
        .map(RepoFlash::done)
        .unwrap_or_default();
    render_repos(&state, &headers, &ctx, flash).await
}

#[derive(serde::Deserialize)]
struct RegisterForm {
    url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    workflow_path: String,
}

/// Register a repository in this namespace. There is no network field: where
/// a namespace builds is app-lb's plugin config, not a form.
async fn register_repo(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    let url = form.url.trim();
    if url.is_empty() {
        return render_repos(
            &state,
            &headers,
            &ctx,
            RepoFlash::failed("A clone URL is required; it is what a submit is matched against."),
        )
        .await;
    }
    let name = match form.name.trim() {
        "" => repos::name_from_url(url),
        given => given.to_string(),
    };
    let workflow_path = Some(form.workflow_path.trim()).filter(|p| !p.is_empty());
    match state
        .store
        .register_repo_in(
            &ctx.namespace,
            url,
            &name,
            workflow_path,
            None,
            ctx.actor.stamp(),
        )
        .await
    {
        Ok(repo) => {
            tracing::info!(
                namespace = %ctx.namespace,
                "registered repository {} ({}) by {}",
                repo.name,
                repo.normalized,
                ctx.actor.display().unwrap_or("anonymous")
            );
            back_to_repos(&ctx, "registered")
        }
        Err(e) => render_repos(&state, &headers, &ctx, RepoFlash::failed(e.to_string())).await,
    }
}

#[derive(serde::Deserialize)]
struct TokenForm {
    #[serde(default)]
    name: String,
}

async fn create_repo_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, repo_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    let repo = match state.store.get_repo_in(&ctx.namespace, &repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return message(
                &state,
                &headers,
                &ctx,
                StatusCode::NOT_FOUND,
                "No such repository.",
            );
        }
        Err(e) => {
            return message(
                &state,
                &headers,
                &ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            );
        }
    };
    let name = match form.name.trim() {
        "" => ctx.actor.display().unwrap_or("unnamed").to_string(),
        given => given.to_string(),
    };
    match state
        .store
        .create_repo_token(&repo.id, &name, ctx.actor.stamp())
        .await
    {
        Ok((token, plaintext)) => {
            tracing::info!(
                namespace = %ctx.namespace,
                "minted submit token {} for {} by {}",
                token.id,
                repo.name,
                ctx.actor.display().unwrap_or("anonymous")
            );
            render_repos(
                &state,
                &headers,
                &ctx,
                RepoFlash::minted(repo.name, plaintext),
            )
            .await
        }
        Err(e) => render_repos(&state, &headers, &ctx, RepoFlash::failed(e.to_string())).await,
    }
}

async fn revoke_repo_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, repo_id, token_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    match state.store.get_repo_in(&ctx.namespace, &repo_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return message(
                &state,
                &headers,
                &ctx,
                StatusCode::NOT_FOUND,
                "No such repository.",
            );
        }
        Err(e) => {
            return message(
                &state,
                &headers,
                &ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                &e.to_string(),
            );
        }
    }
    match state
        .store
        .revoke_repo_token_in(&ctx.namespace, &repo_id, &token_id)
        .await
    {
        Ok(true) => {
            tracing::info!(namespace = %ctx.namespace, "revoked submit token {token_id}");
            back_to_repos(&ctx, "revoked")
        }
        Ok(false) => back_to_repos(&ctx, "already-revoked"),
        Err(e) => render_repos(&state, &headers, &ctx, RepoFlash::failed(e.to_string())).await,
    }
}

#[derive(serde::Deserialize)]
struct EnabledForm {
    enabled: bool,
}

async fn set_repo_enabled(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, repo_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<EnabledForm>,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    match state
        .store
        .set_repo_enabled_in(&ctx.namespace, &repo_id, form.enabled)
        .await
    {
        Ok(true) => back_to_repos(&ctx, if form.enabled { "resumed" } else { "paused" }),
        Ok(false) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::NOT_FOUND,
            "No such repository.",
        ),
        Err(e) => render_repos(&state, &headers, &ctx, RepoFlash::failed(e.to_string())).await,
    }
}

async fn delete_repo(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, repo_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    match state.store.delete_repo_in(&ctx.namespace, &repo_id).await {
        Ok(true) => {
            tracing::info!(namespace = %ctx.namespace, "removed repository registration {repo_id}");
            back_to_repos(&ctx, "removed")
        }
        Ok(false) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::NOT_FOUND,
            "No such repository.",
        ),
        Err(e) => render_repos(&state, &headers, &ctx, RepoFlash::failed(e.to_string())).await,
    }
}

// ---- run actions ---------------------------------------------------------

async fn cancel_run(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    if let Err(response) = run_in(&state, &headers, &ctx, &run_id).await {
        return response;
    }
    if let Err(e) = state.store.cancel_run(&run_id).await {
        return message(
            &state,
            &headers,
            &ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            &e.to_string(),
        );
    }
    tracing::info!(namespace = %ctx.namespace, "cancelled run {run_id}");
    Redirect::to(&ctx.scope.ui(&format!("/runs/{run_id}"))).into_response()
}

async fn rerun_run(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    rerun(state, ctx, run_id, headers, false).await
}

async fn rerun_failed_jobs(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    rerun(state, ctx, run_id, headers, true).await
}

async fn rerun(
    state: AppState,
    ctx: NsContext,
    run_id: String,
    headers: HeaderMap,
    failed_only: bool,
) -> Response {
    if let Err(response) = refuse_non_admin(&state, &headers, &ctx) {
        return response;
    }
    if let Err(response) = run_in(&state, &headers, &ctx, &run_id).await {
        return response;
    }
    let who = ctx.actor.identity();
    match state
        .dispatcher
        .rerun(&run_id, failed_only, who.as_ref())
        .await
    {
        Ok(submitted) => {
            let to = submitted.run_ids.first().unwrap_or(&run_id);
            Redirect::to(&ctx.scope.ui(&format!("/runs/{to}"))).into_response()
        }
        Err(e) => message(
            &state,
            &headers,
            &ctx,
            StatusCode::BAD_REQUEST,
            &e.to_string(),
        ),
    }
}

// ---- JSON ----------------------------------------------------------------

/// [`api::run_json`], with the link pointing at this namespace's page rather
/// than the fleet dashboard.
fn run_json(state: &AppState, ctx: &NsContext, run: &Run) -> serde_json::Value {
    let mut value = api::run_json(state, run);
    value["url"] = serde_json::json!(ctx.scope.ui(&format!("/runs/{}", run.id)));
    value
}

async fn api_runs(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let repo = q.get("repo").map(String::as_str).filter(|r| !r.is_empty());
    match state
        .store
        .recent_runs_in(&ctx.namespace, RECENT_RUNS, repo)
        .await
    {
        Ok(runs) => Json(serde_json::json!({
            "runs": runs.iter().map(|r| run_json(&state, &ctx, r)).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!(namespace = %ctx.namespace, "could not list runs: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "could not list runs")
        }
    }
}

async fn api_run(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
) -> Response {
    let run = match state.store.get_run_in(&ctx.namespace, &run_id).await {
        Ok(Some(run)) => run,
        Ok(None) => return error(StatusCode::NOT_FOUND, &format!("no run {run_id}")),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "could not load that run"),
    };
    let jobs = state.store.jobs_of(&run.id).await.unwrap_or_default();
    let mut views = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let steps = state.store.steps_of(&job.id).await.unwrap_or_default();
        views.push(api::job_json(job, &steps));
    }
    Json(serde_json::json!({ "run": run_json(&state, &ctx, &run), "jobs": views })).into_response()
}

async fn api_logs(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id)): Path<(String, String)>,
    Query(q): Query<api::LogQuery>,
) -> Response {
    match state.store.get_run_in(&ctx.namespace, &run_id).await {
        Ok(Some(run)) => api::logs_of(&state, &run, &q).await,
        Ok(None) => error(StatusCode::NOT_FOUND, &format!("no run {run_id}")),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "could not load that run"),
    }
}

async fn api_repos(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
) -> Response {
    match state.store.repos_in(&ctx.namespace).await {
        Ok(repos) => Json(serde_json::json!({
            "repos": repos.iter().map(|r| serde_json::json!({
                "id": r.id,
                "name": r.name,
                "url": r.url,
                "workflow_path": r.workflow_path,
                "enabled": r.enabled,
                "created_at": r.created_at.to_rfc3339(),
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not list repositories",
        ),
    }
}

/// The live log tail. Checked twice: the run must be this namespace's, and the
/// token must be the one this namespace's job page minted for this job.
async fn api_stream(
    State(state): State<AppState>,
    Extension(ctx): Extension<NsContext>,
    Path((_, run_id, job_key)): Path<(String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    match state.store.get_run_in(&ctx.namespace, &run_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return error(StatusCode::NOT_FOUND, &format!("no run {run_id}")),
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "could not load that run"),
    }
    let token = q.get("token").map(String::as_str).unwrap_or_default();
    if !stream::verify(&state.config, token, &run_id, &job_key) {
        return error(
            StatusCode::UNAUTHORIZED,
            "this log stream token is missing, expired, or for another job",
        );
    }
    tail_job(state, run_id, job_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenants::{TenantSet, Tenants};
    use axum::body::Body;
    use tower::ServiceExt;

    const TOKEN: &str = "plugin-token-0123456789";

    fn gate(installed: &[&str]) -> Gate {
        let set = TenantSet {
            enabled: true,
            installed_in: installed.iter().map(|s| s.to_string()).collect(),
            tenant_network: Some("tenants".into()),
            ..TenantSet::default()
        };
        Gate::new(TOKEN, Arc::new(Tenants::fixed(set, true)))
    }

    /// The real gate in front of a handler that reports what it was given, so
    /// the gate is tested without a database behind it.
    fn app(installed: &[&str]) -> Router {
        async fn echo(Extension(ctx): Extension<NsContext>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "namespace": ctx.namespace,
                "runs": ctx.scope.ui("/"),
                "api": ctx.scope.api("/runs"),
                "admin": ctx.actor.admin,
                "who": ctx.actor.display(),
            }))
        }
        gated(
            Router::new()
                .route("/ns/{ns}/", get(echo))
                .route("/ns/{ns}/runs/{run_id}", get(echo)),
            gate(installed),
        )
    }

    async fn call(
        app: Router,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    const BEARER: (&str, &str) = ("authorization", "Bearer plugin-token-0123456789");

    #[tokio::test]
    async fn no_or_wrong_bearer_is_401_before_the_namespace_is_considered() {
        for headers in [
            vec![],
            vec![("authorization", "Bearer nope")],
            vec![("authorization", TOKEN)],
        ] {
            // Installed or not, the answer is the same: whether a namespace
            // exists is not something an unauthenticated caller learns.
            for uri in ["/ns/team-a/", "/ns/team-z/"] {
                let (status, _) = call(app(&["team-a"]), uri, &headers).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} {headers:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_namespace_that_is_not_installed_or_not_a_name_is_404() {
        for uri in ["/ns/team-b/", "/ns/team-b/runs/r1", "/ns/../", "/ns/a%2Fb/"] {
            let (status, _) = call(app(&["team-a"]), uri, &[BEARER]).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
        let (status, body) = call(app(&["team-a"]), "/ns/team-a/runs/r1", &[BEARER]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["namespace"], "team-a");
    }

    #[tokio::test]
    async fn the_base_is_used_only_when_it_is_this_namespaces() {
        let proxied = [BEARER, ("x-heyo-base", "/namespaces/team-a/plugins/ci")];
        let (_, body) = call(app(&["team-a"]), "/ns/team-a/", &proxied).await;
        assert_eq!(body["runs"], "/namespaces/team-a/plugins/ci/ui");
        assert_eq!(body["api"], "/namespaces/team-a/plugins/ci/api/runs");

        for bogus in [
            "/namespaces/team-b/plugins/ci",
            "https://evil.example/namespaces/team-a/plugins/ci",
            "/namespaces/team-a/plugins/ci/",
            "/namespaces/team-a/plugins/obs",
        ] {
            let (_, body) = call(
                app(&["team-a"]),
                "/ns/team-a/",
                &[BEARER, ("x-heyo-base", bogus)],
            )
            .await;
            assert_eq!(body["runs"], "/ns/team-a/", "{bogus}");
            assert_eq!(body["api"], "/ns/team-a/api/runs", "{bogus}");
        }
    }

    #[tokio::test]
    async fn the_actor_comes_from_app_lbs_headers_and_admin_must_say_true() {
        let (_, body) = call(
            app(&["team-a"]),
            "/ns/team-a/",
            &[
                BEARER,
                ("x-heyo-actor", "user:42"),
                ("x-heyo-actor-email", "a@example.com"),
                ("x-heyo-actor-admin", "true"),
            ],
        )
        .await;
        assert_eq!(body["admin"], true);
        assert_eq!(body["who"], "a@example.com");
        for admin in ["false", "TRUE", "1", "yes"] {
            let (_, body) = call(
                app(&["team-a"]),
                "/ns/team-a/",
                &[BEARER, ("x-heyo-actor-admin", admin)],
            )
            .await;
            assert_eq!(body["admin"], false, "{admin}");
        }
    }

    #[test]
    fn scope_urls_in_both_modes() {
        let proxied = scope_for("team-a", Some("/namespaces/team-a/plugins/ci"));
        assert_eq!(proxied.ui("/"), "/namespaces/team-a/plugins/ci/ui");
        assert_eq!(
            proxied.ui("/runs/r1"),
            "/namespaces/team-a/plugins/ci/ui/runs/r1"
        );
        assert_eq!(
            proxied.api("/stream/r1/b"),
            "/namespaces/team-a/plugins/ci/api/stream/r1/b"
        );
        let direct = scope_for("team-a", None);
        assert_eq!(direct.ui("/"), "/ns/team-a/");
        assert_eq!(direct.ui("/repos"), "/ns/team-a/repos");
        assert_eq!(direct.api("/runs"), "/ns/team-a/api/runs");
        assert_eq!(Scope::Fleet.ui("/runs/r1"), "/runs/r1");
        assert_eq!(Scope::Fleet.api("/stream/r1/b"), "/api/stream/r1/b");
    }

    #[test]
    fn redirect_targets_stay_under_the_base_and_codes_are_not_reflected() {
        let ctx = NsContext {
            namespace: "team-a".into(),
            scope: scope_for("team-a", Some("/namespaces/team-a/plugins/ci")),
            actor: Actor::default(),
        };
        let res = back_to_repos(&ctx, "registered");
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("/namespaces/team-a/plugins/ci/"),
            "{location}"
        );
        assert_eq!(done_message("<script>"), None);
        assert!(done_message("registered").is_some());
    }

    #[test]
    fn the_bearer_check_needs_the_exact_token() {
        let g = gate(&[]);
        let mut h = HeaderMap::new();
        assert!(!g.admits(&h));
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {TOKEN}").parse().unwrap(),
        );
        assert!(g.admits(&h));
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {TOKEN}x").parse().unwrap(),
        );
        assert!(!g.admits(&h));
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {TOKEN}").parse().unwrap(),
        );
        assert!(!g.admits(&h));
    }
}
