//! The HTTP surface: a server-rendered dashboard plus the machine endpoints.
//!
//! **Auth is app-lb's job, not ours.** Deployed behind an app-lb `AuthGate`, a
//! browser request arrives carrying `x-auth-request-email` / `-user` / `-name`,
//! which app-lb strips unconditionally before setting, so they cannot be
//! spoofed. This module reads them and never re-implements a login.
//!
//! One consequence shapes every route below: **an app-lb gate admits browsers
//! and nothing else.** The split is `Accept: text/html`, so curl, `git submit`,
//! and a page's own `EventSource` all get `401 {"error":"authentication
//! required"}`. Machine routes therefore live under `/api` and are listed in the
//! deployment's `public_paths`, each carrying its own credential — the submit
//! endpoint a repository token or an HMAC, the read API in [`api`] the same
//! repository token scoped to the run it is asking about, the log stream a
//! short-TTL run-scoped token minted by the page that opens it.
//!
//! The repository-management routes are the mirror image: they are *not* in
//! `public_paths`, precisely because minting a submit token is minting the right
//! to run code on a runner. They are for browsers, they run behind the gate, and
//! they check an admin role on top of it.

pub mod api;
pub mod identity;
mod instance_http;
mod ns;
pub mod pages;
pub mod stream;

use crate::config::Config;
use crate::dispatch::Dispatcher;
use crate::repos;
use crate::runners::Runners;
use crate::store::{Repo, Store};
use crate::trigger;
use axum::Form;
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use identity::Identity;
use pages::{RepoFlash, RepoView};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const RUN_EVENT_PAGE_SIZE: i64 = 50;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub runners: Arc<Runners>,
    pub store: Store,
    pub dispatcher: Arc<Dispatcher>,
}

pub fn router(
    config: Arc<Config>,
    runners: Arc<Runners>,
    store: Store,
    dispatcher: Arc<Dispatcher>,
) -> Router {
    // The submit body carries a whole source tree, so it needs its own limit —
    // axum defaults to 2 MiB, which no real repository fits in. The real ceiling
    // is `CI_MAX_SOURCE_BYTES`, checked after decoding; this one just keeps a
    // hostile body from being buffered first. Base64 inflates by 4/3, plus room
    // for the JSON envelope.
    let submit_limit = config.max_source_bytes.saturating_mul(4) / 3 + (1 << 20);

    let state = AppState {
        config: config.clone(),
        runners,
        store: store.clone(),
        dispatcher: dispatcher.clone(),
    };

    Router::new()
        // Unauthenticated by design and listed in `public_paths`: app-lb probes
        // it after an `update` job to decide whether the service actually came
        // back, so a gate in front of it would make every deploy look failed.
        .route("/healthz", get(healthz))
        .route("/__ui/{*path}", get(ui_asset))
        .route("/", get(runs_page))
        // Behind the identity gate, never a repository-token/public machine API.
        .route("/releases", get(release_catalog).post(register_release))
        .route("/release-builds", get(release_builds).post(build_release))
        .route("/release-environments", get(release_environments))
        .route("/release-promotions", post(promote_release))
        .route("/release-automation", post(release_automation))
        .route("/maintenance", get(maintenance_status))
        .route("/maintenance/{id}/{action}", post(maintenance_action))
        .route("/maintenance/runners/{runner}", get(runner_maintenance_status))
        .route("/maintenance/runners/{runner}/{id}/{action}", post(runner_maintenance_action))
        .route("/runs/{run_id}", get(run_page))
        // Admin-only like the other state-changing routes: cancelling stops
        // somebody's build.
        .route("/runs/{run_id}/cancel", post(cancel_run))
        .route("/runs/{run_id}/rerun", post(rerun_run))
        .route("/runs/{run_id}/rerun-failed", post(rerun_failed_jobs))
        .route("/runs/{run_id}/jobs/{job_key}", get(job_page))
        // `/runners` was this page's name when there was one network to show.
        // Kept because it is in people's history and in the README of a running
        // deployment; both render the same page.
        .route("/networks", get(networks_page))
        .route("/runners", get(networks_page))
        // Behind the gate and admin-only, like /repos: joining a host to a
        // network grants host-shell access to it through the network, so it is
        // not a read.
        .route("/networks/{network_id}/join", post(join_network))
        .route("/vms", get(vms_page))
        // Admin-only: destroying a VM is destroying somebody's warm cache, and
        // on a claimed one it would fail a live build — which is why the pool
        // refuses those rather than trusting the page not to offer them.
        .route("/vms/{sandbox_id}/destroy", post(destroy_vm))
        // Admin-only for the same reason: a resize restarts the VM. Idle ones
        // only, refused by the pool rather than trusted to the page.
        .route("/vms/{sandbox_id}/resize", post(resize_vm))
        .route("/vms/cleanup-failed", post(cleanup_failed_vms))
        .route("/workflows", get(workflows_page))
        // Behind the gate on purpose, and admin-only on top of it: a submit
        // token is the right to run code on a runner, so minting one is not a
        // read.
        .route("/repos", get(repos_page).post(register_repo))
        .route("/repos/{repo_id}/tokens", post(create_repo_token))
        .route(
            "/repos/{repo_id}/tokens/{token_id}/revoke",
            post(revoke_repo_token),
        )
        .route("/repos/{repo_id}/enabled", post(set_repo_enabled))
        .route("/repos/{repo_id}/network", post(set_repo_network))
        .route("/repos/{repo_id}/delete", post(delete_repo))
        // In `public_paths`, because an `EventSource` sends
        // `Accept: text/event-stream` and app-lb's gate admits only
        // `text/html`. It carries its own run-scoped token instead.
        .route("/api/stream/{run_id}/{job_key}", get(log_stream))
        .route("/api/native/register", post(native_register))
        .route("/api/native/poll", post(native_poll))
        .route("/api/native/heartbeat", post(native_heartbeat))
        .route("/api/native/complete", post(native_complete))
        .route("/api/native/jobs/{lease}/source", get(native_source))
        .route("/api/native/jobs/{lease}/release-source/{index}", get(native_release_source))
        .route("/api/native/jobs/{lease}/artifacts/{index}", post(native_artifact).layer(DefaultBodyLimit::max(512 * 1024 * 1024)))
        .route("/api/lifecycle", get(application_lifecycle))
        .route("/api/lifecycle/retirements/{id}", get(retirement_status).post(retire_application))
        .route("/api/lifecycle/updates/{id}", get(application_update_status).post(activate_application_update))
        .route("/api/lifecycle/updates/{id}/prepare", post(prepare_regional_update))
        .route("/api/lifecycle/updates/{id}/cancel", post(cancel_regional_child))
        .route(
            "/api/submit",
            post(submit).layer(DefaultBodyLimit::max(submit_limit)),
        )
        // The read half of the machine API: run status and logs, on the same
        // repository token a submit uses. In `public_paths` beside the two
        // above, for the reason this module's header gives — a machine route
        // behind the gate answers 401 whatever it carries. See [`api`].
        .merge(api::router())
        // A namespace's pages and API, for app-lb's `ci` plugin proxy. Not
        // mounted without CI_PLUGIN_API_TOKEN, and never in `public_paths`:
        // see [`ns`].
        .merge(ns::router(&state).unwrap_or_default())
        .layer(axum::middleware::from_fn_with_state(state.clone(), instance_http::route))
        .with_state(state)
}

async fn release_automation(State(state): State<AppState>, headers: HeaderMap,
    Json(request): Json<crate::release_environment::AutomationRequest>) -> axum::response::Response {
    if let Err(response) = may_manage(&state, &headers).await { return response; }
    match crate::release_environment::automation(&state.dispatcher, request).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":error.to_string()}))).into_response(),
    }
}

async fn release_environments(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = may_manage(&state, &headers).await { return response; }
    match crate::release_environment::list(&state.dispatcher).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            tracing::error!(%error, "cannot list release environments");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn promote_release(State(state): State<AppState>, headers: HeaderMap,
    Json(request): Json<crate::release_environment::Request>) -> axum::response::Response {
    let who = match may_manage(&state, &headers).await { Ok(who) => who, Err(response) => return response };
    let actor = who.as_ref().map(|who| who.subject.as_str()).unwrap_or("local-admin");
    match crate::release_environment::admit(&state.dispatcher, request, actor, false).await {
        Ok(value) => (StatusCode::ACCEPTED, Json(value)).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":error.to_string()}))).into_response(),
    }
}

async fn release_builds(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = may_manage(&state, &headers).await { return response; }
    match crate::release_build::list(&state.store).await {
        Ok(builds) => Json(serde_json::json!({"builds":builds})).into_response(),
        Err(error) => {
            tracing::error!(%error, "cannot list release builds");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn build_release(State(state): State<AppState>, headers: HeaderMap,
    Json(request): Json<crate::release_build::Request>) -> axum::response::Response {
    let who = match may_manage(&state, &headers).await {
        Ok(who) => who, Err(response) => return response,
    };
    let actor = who.as_ref().map(|who| who.subject.as_str()).unwrap_or("local-admin");
    match crate::release_build::admit(&state.dispatcher, request, actor).await {
        Ok(build) => (StatusCode::ACCEPTED, Json(build)).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":error.to_string()}))).into_response(),
    }
}

async fn release_catalog(
    State(state): State<AppState>, headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if let Err(response) = may_manage(&state, &headers).await { return response; }
    match crate::release_catalog::list(&state.store, query.get("before").map(String::as_str)).await {
        Ok(releases) => Json(serde_json::json!({"releases":releases})).into_response(),
        Err(error) => {
            tracing::error!(%error, "cannot list release catalog");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn register_release(
    State(state): State<AppState>, headers: HeaderMap,
    Json(request): Json<crate::release_catalog::Request>,
) -> axum::response::Response {
    let who = match may_manage(&state, &headers).await {
        Ok(who) => who,
        Err(response) => return response,
    };
    let actor = who.as_ref().map(|who| who.subject.as_str()).unwrap_or("local-admin");
    match crate::release_catalog::register(&state.store, request, actor).await {
        Ok(release) => Json(release).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":error.to_string()}))).into_response(),
    }
}

async fn maintenance_admin(state: &AppState, headers: &HeaderMap) -> Result<Identity, axum::response::Response> {
    may_manage(state, headers).await?.ok_or_else(||
        error(StatusCode::UNAUTHORIZED, "maintenance requires an authenticated CI admin"))
}

async fn runner_maintenance_status(State(state): State<AppState>, Path(runner): Path<String>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = maintenance_admin(&state, &headers).await { return response; }
    match crate::host_maintenance::runner_drain_status(&state.store, &runner).await {
        Ok(status) => Json(status).into_response(),
        Err(detail) => {
            tracing::error!(%runner, %detail, "could not read runner drain");
            error(StatusCode::SERVICE_UNAVAILABLE, "runner drain status unavailable")
        }
    }
}

async fn runner_maintenance_action(State(state): State<AppState>, Path((runner, id, action)): Path<(String, uuid::Uuid, String)>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = maintenance_admin(&state, &headers).await { return response; }
    let pause = match action.as_str() {
        "pause" => true,
        "resume" => false,
        _ => return error(StatusCode::BAD_REQUEST, "expected pause or resume"),
    };
    if pause && state.runners.snapshot().locate(&runner).is_none() {
        return error(StatusCode::NOT_FOUND, "unknown runner ID");
    }
    match tokio::time::timeout(Duration::from_secs(5), crate::host_maintenance::runner_drain(&state.store, &runner, id, pause)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(detail)) => {
            tracing::warn!(%runner, %id, %detail, "runner drain transition refused");
            error(StatusCode::CONFLICT, "runner drain transition refused")
        }
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "read runner drain status before retrying the same operation ID"),
    }
}

async fn maintenance_status(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = maintenance_admin(&state, &headers).await { return response; }
    match state.dispatcher.executor.status().await {
        Ok(status) => Json(status).into_response(),
        Err(detail) => {
            tracing::error!(%detail, "could not read operator maintenance");
            error(StatusCode::SERVICE_UNAVAILABLE, "maintenance status unavailable")
        }
    }
}

async fn maintenance_action(State(state): State<AppState>, Path((id, action)): Path<(uuid::Uuid, String)>, headers: HeaderMap) -> axum::response::Response {
    let _who = match maintenance_admin(&state, &headers).await {
        Ok(who) => who,
        Err(response) => return response,
    };
    let operation = async {
        match action.as_str() {
            "pause" => state.dispatcher.executor.pause(id).await,
            "quiesce" => state.dispatcher.executor.quiesce(id).await,
            "resume" => state.dispatcher.executor.resume(id).await,
            "retire" => {
                if state.config.managed_deployment.is_some() || state.config.controller_deployment.is_none()
                    || state.config.controller_app_lb_url.is_none() {
                    Err("operator configuration retirement requires an app-lb CI deployment".into())
                } else if let Some(boot) = headers.get("x-ci-target-boot").and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<uuid::Uuid>().ok()) {
                    state.dispatcher.executor.retire_for_configuration(id, boot).await
                } else {
                    Err("configuration retirement requires x-ci-target-boot".into())
                }
            }
            _ => Err("unknown maintenance action".into()),
        }
    };
    match tokio::time::timeout(Duration::from_secs(5), operation).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(detail)) => {
            tracing::warn!(%id, %action, %detail, "operator maintenance transition refused");
            error(StatusCode::CONFLICT, "maintenance transition refused; inspect maintenance status and logs")
        }
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "maintenance transition timed out; read status before retrying the same operation ID"),
    }
}

fn application_lifecycle_auth(state: &AppState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    use subtle::ConstantTimeEq;
    let Some(expected) = state.config.application_lifecycle_token.as_deref().filter(|s| !s.is_empty()) else {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "application lifecycle is not configured"));
    };
    let Some(got) = bearer(headers) else { return Err(error(StatusCode::UNAUTHORIZED, "application lifecycle bearer required")); };
    if !bool::from(got.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(error(StatusCode::UNAUTHORIZED, "invalid application lifecycle bearer"));
    }
    Ok(())
}

async fn application_lifecycle(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = application_lifecycle_auth(&state, &headers) { return response; }
    if let Some(deployment) = &state.config.managed_deployment {
        return Json(serde_json::json!({"applicationId":state.config.application_id,
            "deploymentId":deployment,"bootId":state.dispatcher.executor.boot_id(),
            "revision":state.config.expected_sha,"capabilities":["managed-retirement-v1"]})).into_response();
    }
    if state.config.application_id.is_none() || state.config.application_orchestrator_url.is_none()
        || state.config.controller_deployment.is_none() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "application lifecycle is not configured");
    }
    let admission = match state.dispatcher.executor.status().await {
        Ok(status) => status,
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE,"CI admissions unavailable"),
    };
    Json(serde_json::json!({"applicationId":state.config.application_id,
        "deploymentId":state.config.controller_deployment,"authority":state.config.controller_app_lb_url,
        "bootId":state.dispatcher.executor.boot_id(),"revision":state.config.expected_sha,
        "binarySha256":crate::controller_rollout::binary_sha256(),"admissionsOpen":admission["admissionClosed"] == false,
        "capabilities":["release-update","regional-release-update-v1"]})).into_response()
}

async fn prepare_regional_update(State(state):State<AppState>,Path(id):Path<String>,headers:HeaderMap,
    Json(request):Json<crate::regional_update::Preparation>) -> axum::response::Response {
    if let Err(response)=application_lifecycle_auth(&state,&headers) { return response; }
    match crate::regional_update::prepare(&state.dispatcher,&id,&request).await {
        Ok(value)=>(StatusCode::ACCEPTED,Json(value)).into_response(),
        Err(error)=>{ tracing::warn!(%error,%id,"regional preparation refused"); error_response_regional() }
    }
}

fn error_response_regional() -> axum::response::Response {
    error(StatusCode::CONFLICT,"regional lifecycle request unresolved; see CI logs")
}

#[derive(serde::Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct RegionalCancellation { parent_operation_id:String }

async fn cancel_regional_child(State(state):State<AppState>,Path(id):Path<String>,headers:HeaderMap,
    Json(request):Json<RegionalCancellation>) -> axum::response::Response {
    if let Err(response)=application_lifecycle_auth(&state,&headers) { return response; }
    match crate::regional_update::cancel_child(&state.dispatcher,&id,&request.parent_operation_id).await {
        Ok(value)=>Json(value).into_response(),
        Err(error)=>{ tracing::warn!(%error,%id,"regional cancellation unresolved"); error_response_regional() }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetirementEnvelope { request_hash: String, request: crate::application_lifecycle::Retirement }

async fn retire_application(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap,
    Json(envelope): Json<RetirementEnvelope>) -> axum::response::Response {
    if let Err(response) = application_lifecycle_auth(&state, &headers) { return response; }
    if id != envelope.request.command_id { return error(StatusCode::CONFLICT,"retirement identity mismatch"); }
    match crate::application_lifecycle::accept(&state.dispatcher,envelope.request,&envelope.request_hash).await {
        Ok(status) => (StatusCode::ACCEPTED,Json(status)).into_response(),
        Err(_) => error(StatusCode::CONFLICT,"retirement was not accepted"),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetirementQuery { request_hash: String }

async fn retirement_status(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap,
    Query(query): Query<RetirementQuery>) -> axum::response::Response {
    if let Err(response) = application_lifecycle_auth(&state, &headers) { return response; }
    match crate::application_lifecycle::status(state.store.pool(),&id,&query.request_hash).await {
        Ok(status) => Json(status).into_response(),
        Err(_) => error(StatusCode::NOT_FOUND,"retirement receipt unavailable"),
    }
}

async fn application_update_status(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap) -> axum::response::Response {
    if let Err(response) = application_lifecycle_auth(&state, &headers) { return response; }
    match crate::controller_rollout::application_status(&state.dispatcher, &id).await {
        Ok(status) => Json(status).into_response(),
        Err(_) => error(StatusCode::NOT_FOUND, "application update unavailable"),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationActivation { intent_hash: String }

async fn activate_application_update(State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap,
    Json(activation): Json<ApplicationActivation>) -> axum::response::Response {
    if let Err(response) = application_lifecycle_auth(&state, &headers) { return response; }
    match crate::controller_rollout::activate_application_update(&state.dispatcher, &id, &activation.intent_hash).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => error(StatusCode::CONFLICT, "application update cannot be activated"),
    }
}

fn native_auth(state: &AppState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    use subtle::ConstantTimeEq;
    let Some(expected)=state.config.native_runner_secret.as_deref() else { return Err(error(StatusCode::SERVICE_UNAVAILABLE,"native runners are not configured")); };
    let Some(got)=bearer(headers) else { return Err(error(StatusCode::UNAUTHORIZED,"native runner bearer required")); };
    if expected.as_bytes().ct_eq(got.as_bytes()).into() { Ok(()) } else { Err(error(StatusCode::UNAUTHORIZED,"invalid native runner bearer")) }
}
async fn native_register(State(s):State<AppState>,h:HeaderMap,Json(r):Json<crate::native::Registration>)->impl IntoResponse { if let Err(e)=native_auth(&s,&h){return e}; match crate::native::register(&s.store,r).await {Ok(())=>Json(serde_json::json!({"ok":true})).into_response(),Err(e)=>error(StatusCode::BAD_REQUEST,&e)} }
fn native_poll_error(e: crate::native::PollError) -> axum::response::Response {
    match e {
        crate::native::PollError::Rejected(message) => error(StatusCode::CONFLICT, &message),
        crate::native::PollError::Internal(detail) => {
            tracing::error!(error = %detail, "native runner poll failed");
            error(StatusCode::SERVICE_UNAVAILABLE, "native runner polling is temporarily unavailable")
        }
    }
}
async fn native_poll(State(s):State<AppState>,h:HeaderMap,Json(p):Json<crate::native::Poll>)->impl IntoResponse { if let Err(e)=native_auth(&s,&h){return e};let _admission=match s.dispatcher.executor.admission_permit().await{Ok(g)=>g,Err(e)=>return error(StatusCode::SERVICE_UNAVAILABLE,&e)};if let Ok(runs)=crate::native::pending_advancements(&s.store).await{for run in runs{if s.dispatcher.advance_run(&run).await.is_ok(){let _=crate::native::advancement_done(&s.store,&run).await;}}} match crate::native::poll(&s.store,p,&s.config.public_url,&s.dispatcher.secrets).await {Ok(job)=>Json(serde_json::json!({"job":job})).into_response(),Err(e)=>native_poll_error(e)} }
async fn native_heartbeat(State(s):State<AppState>,h:HeaderMap,Json(u):Json<crate::native::LeaseUpdate>)->impl IntoResponse { if let Err(e)=native_auth(&s,&h){return e};let _effect=match s.dispatcher.executor.effect_permit().await{Ok(g)=>g,Err(e)=>return error(StatusCode::SERVICE_UNAVAILABLE,&e)};match crate::native::heartbeat(&s.store,&u).await {Ok(true)=>StatusCode::NO_CONTENT.into_response(),Ok(false)=>error(StatusCode::CONFLICT,"lease expired or fenced"),Err(e)=>error(StatusCode::INTERNAL_SERVER_ERROR,&e)} }
async fn native_complete(State(s):State<AppState>,h:HeaderMap,Json(c):Json<crate::native::Completion>)->impl IntoResponse { if let Err(e)=native_auth(&s,&h){return e};let _effect=match s.dispatcher.executor.effect_permit().await{Ok(g)=>g,Err(e)=>return error(StatusCode::SERVICE_UNAVAILABLE,&e)};match crate::native::complete(&s.store,&s.dispatcher.secrets,c).await {Ok(Some(run))=>{match s.dispatcher.advance_run(&run).await{Ok(_)=>{let _=crate::native::advancement_done(&s.store,&run).await;},Err(e)=>tracing::error!("native completion scheduling failed: {e}")} StatusCode::NO_CONTENT.into_response()},Ok(None)=>error(StatusCode::CONFLICT,"lease expired or fenced"),Err(e)=>error(StatusCode::CONFLICT,&e)} }
async fn native_source(State(s):State<AppState>,h:HeaderMap,Path(lease):Path<uuid::Uuid>)->impl IntoResponse {
    if let Err(e)=native_auth(&s,&h){return e}
    let run_id=match crate::native::source_run(&s.store,lease).await {Ok(Some(r))=>r,Ok(None)=>return error(StatusCode::CONFLICT,"lease expired or fenced"),Err(e)=>return error(StatusCode::INTERNAL_SERVER_ERROR,&e)};
    let run=match s.store.get_run(&run_id).await {Ok(Some(r))=>r,Ok(None)=>return error(StatusCode::CONFLICT,"run disappeared"),Err(e)=>return error(StatusCode::INTERNAL_SERVER_ERROR,&e.to_string())};
    let descriptor=match s.store.source_descriptor(&run_id).await{Ok(v)=>v,Err(e)=>return error(StatusCode::INTERNAL_SERVER_ERROR,&e.to_string())};
    Json(serde_json::json!({"repository":run.repo_url,"descriptor":descriptor,"workflowPath":run.workflow_path})).into_response()
}
async fn native_release_source(State(s):State<AppState>,h:HeaderMap,Path((lease,index)):Path<(uuid::Uuid,usize)>)->impl IntoResponse {
    if let Err(e)=native_auth(&s,&h){return e}
    let (run_id,sha)=match crate::native::release_source_context(&s.store,lease,index).await{Ok(Some(v))=>v,Ok(None)=>return error(StatusCode::CONFLICT,"lease expired or fenced"),Err(e)=>return error(StatusCode::BAD_REQUEST,&e)};
    let run=match s.store.get_run(&run_id).await {Ok(Some(r))=>r,Ok(None)=>return error(StatusCode::CONFLICT,"run disappeared"),Err(e)=>return error(StatusCode::INTERNAL_SERVER_ERROR,&e.to_string())};
    Json(serde_json::json!({"repository":run.repo_url,"sha":sha})).into_response()
}
#[derive(serde::Deserialize)] struct NativeArtifactQuery{name:String,#[serde(default)]description:Option<String>,#[serde(default)]public:bool,#[serde(default)]alias:Option<String>}
async fn native_artifact(State(s):State<AppState>,h:HeaderMap,Path((lease,index)):Path<(uuid::Uuid,usize)>,Query(q):Query<NativeArtifactQuery>,body:Bytes)->impl IntoResponse {
    if let Err(e)=native_auth(&s,&h){return e};
    let _effect = match s.dispatcher.executor.effect_permit().await {
        Ok(permit) => permit,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    if q.name.trim().is_empty()||q.name.contains('/')||q.name.contains('\\')||q.name==".."{return error(StatusCode::BAD_REQUEST,"invalid artifact name")};let (run,_job,key,workflow)=match crate::native::artifact_context(&s.store,lease,index).await{Ok(Some(v))=>v,Ok(None)=>return error(StatusCode::CONFLICT,"lease expired or fenced"),Err(e)=>return error(StatusCode::BAD_REQUEST,&e)};let r=crate::artifacts::ArtifactRef{run_id:run,job_key:key,workflow_id:workflow,name:q.name.clone(),description:q.description,public:q.public,alias:q.alias.filter(|a|!a.trim().is_empty())};let stored=match s.dispatcher.artifacts.put(&r,body.to_vec()).await{Ok(v)=>v,Err(e)=>return error(StatusCode::BAD_GATEWAY,&e.to_string())};match crate::native::record_artifact(&s.store,lease,index,&q.name,&stored).await{Ok(true)=>StatusCode::NO_CONTENT.into_response(),Ok(false)=>error(StatusCode::CONFLICT,"lease expired or fenced during upload"),Err(e)=>error(StatusCode::INTERNAL_SERVER_ERROR,&e)}
}

/// How a submit proved it may start a build.
enum Credential {
    /// A per-repository token, and the registration it is scoped to.
    Repo(Box<Repo>),
    /// The installation-wide `CI_WEBHOOK_SECRET`, HMAC'd over the raw body.
    /// Says nothing about which repository is submitting, which is the reason
    /// the other one exists.
    Shared,
}

/// The `Bearer` a submit token arrives as.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    // Case-insensitive on the scheme, per RFC 7235; curl and every client
    // library spell it `Bearer`, but a shell script pasting `bearer` should not
    // fail with "not signed correctly".
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Decide whether a submit may proceed, before its body is parsed.
///
/// The ordering is the security property: a `Json` extractor would deserialize
/// an unauthenticated body first, and the credential check would then be
/// guarding a decision already made.
async fn authenticate_submit(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Credential, axum::response::Response> {
    if let Some(token) = bearer(headers) {
        return match state.store.authenticate_repo_token(token).await {
            Ok(Some(repo)) => Ok(Credential::Repo(Box::new(repo))),
            // One message for malformed, unknown, wrong, revoked and disabled
            // alike: saying which one it was tells an attacker how far they got.
            Ok(None) => {
                tracing::debug!("rejected a submit token that resolves to no repository");
                Err(error(
                    StatusCode::UNAUTHORIZED,
                    &format!(
                        "that submit token is not valid for any registered repository. \
                         Register the repository at {}/repos, then \
                         `git config ci.token <token>`.",
                        state.config.public_url
                    ),
                ))
            }
            Err(e) => {
                // A database failure is ours, not the caller's, and it must not
                // read as a rejected credential — that sends someone to rotate
                // a token that was fine.
                tracing::error!("could not check a submit token: {e}");
                Err(error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not check that submit token; the database is unreachable",
                ))
            }
        };
    }

    if state.config.require_repo_token {
        tracing::debug!("rejected a shared-secret submit; CI_REQUIRE_REPO_TOKEN is set");
        return Err(error(
            StatusCode::UNAUTHORIZED,
            &format!(
                "this server accepts only per-repository submit tokens \
                 (CI_REQUIRE_REPO_TOKEN is set). Register the repository at \
                 {}/repos, then `git config ci.token <token>`.",
                state.config.public_url
            ),
        ));
    }

    let signature = headers
        .get(trigger::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok());
    match trigger::verify_signature(&state.config.webhook_secret, body, signature) {
        Ok(()) => Ok(Credential::Shared),
        Err(e) => {
            // Logged at debug, not warn: an unauthenticated public endpoint gets
            // scanned, and a warn per probe is how a log becomes unreadable.
            tracing::debug!("rejected an unsigned submit: {e}");
            Err(error(e.status(), &e.to_string()))
        }
    }
}

/// `POST /api/submit` — what `git submit` calls.
async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let credential = match authenticate_submit(&state, &headers, &body).await {
        Ok(c) => c,
        Err(response) => return response,
    };

    let req: trigger::SubmitRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("malformed submit: {e}")),
    };

    // The shared secret cannot say which repository it is for, but the payload
    // can, and a registration matching it still decides the workflow glob and
    // gives the run a home on the repositories page. This is not a privilege
    // grant: whoever holds the installation-wide secret may already submit as
    // anything, which is the weakness the token path exists to fix.
    let matched;
    let repo = match &credential {
        Credential::Repo(r) => Some(r.as_ref()),
        Credential::Shared if !req.repository.url.trim().is_empty() => {
            matched = state
                .store
                .repo_by_url(&req.repository.url)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("could not look up {:?}: {e}", req.repository.url);
                    None
                })
                .filter(|r| r.enabled);
            matched.as_ref()
        }
        Credential::Shared => None,
    };

    // A token is scoped to one repository, and this is where that is worth
    // anything: without it, a token issued for a repository somebody may push to
    // would build any repository at all, which is a build of *their* workflow
    // file with *this* repository's secrets.
    if let Some(repo) = repo
        && !req.repository.url.trim().is_empty()
        && !repos::same_repo(&repo.url, &req.repository.url)
    {
        tracing::warn!(
            "refused a submit for {:?} with a token for {:?}",
            req.repository.url,
            repo.url
        );
        return error(
            StatusCode::FORBIDDEN,
            &format!(
                "this submit token is registered to {}, but the submit is for {}. \
                 Use the token minted for that repository.",
                repo.url, req.repository.url
            ),
        );
    }

    // A namespace's token stops working the moment app-lb stops listing the
    // namespace as installed — checked here, before the source is unpacked,
    // and again by the dispatcher for re-runs.
    if let Some(repo) = repo
        && repo.is_tenant()
        && !state.dispatcher.tenants.is_installed(&repo.namespace)
    {
        return error(
            StatusCode::FORBIDDEN,
            &crate::dispatch::DispatchError::NotInstalled(repo.namespace.clone()).to_string(),
        );
    }
    // A tenant-only instance has no fleet repositories: a shared-secret submit
    // or a fleet registration's token is refused here, before the source is
    // unpacked, and again by the dispatcher.
    if state.config.tenant_only && !repo.is_some_and(|r| r.is_tenant()) {
        return error(
            StatusCode::FORBIDDEN,
            &crate::dispatch::DispatchError::TenantOnly.to_string(),
        );
    }

    // Present only when a browser reached this through app-lb's gate; `git
    // submit` arrives with a token and no identity, so the payload's `pusher` is
    // the fallback.
    let who = Identity::from_headers(&headers);

    match state.dispatcher.submit(&req, who.as_ref(), repo).await {
        Ok(submitted) => {
            tracing::info!(
                "accepted a submit for {} ({}) via {}: {} run(s)",
                repo.map(|r| r.name.as_str())
                    .unwrap_or(&req.repository.name),
                req.branch(),
                match repo {
                    Some(r) => format!("a token for {}", r.name),
                    None => "the shared secret".to_string(),
                },
                submitted.run_ids.len()
            );
            (
                StatusCode::ACCEPTED,
                axum::Json(serde_json::json!({
                    "runs": submitted.run_ids,
                    "submission": submitted.submission,
                    "url": format!("{}/", state.config.public_url),
                    // Warnings, not errors: the runs exist. A job pinned to a
                    // host that is briefly offline waits rather than failing,
                    // and the client says so at the terminal that submitted it.
                    "warnings": submitted.warnings,
                })),
            )
                .into_response()
        }
        Err(crate::dispatch::DispatchError::ControllerUnavailable(message)) =>
            error(StatusCode::SERVICE_UNAVAILABLE, &message),
        Err(e @ crate::dispatch::DispatchError::NotInstalled(_)) =>
            error(StatusCode::FORBIDDEN, &e.to_string()),
        Err(e @ crate::dispatch::DispatchError::TenantOnly) =>
            error(StatusCode::FORBIDDEN, &e.to_string()),
        Err(e) => {
            tracing::warn!("submit failed: {e}");
            error(StatusCode::BAD_REQUEST, &e.to_string())
        }
    }
}

fn error(status: StatusCode, message: &str) -> axum::response::Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Some(sha) = &state.config.expected_sha
        && let Ok(value) = sha.parse() {
        headers.insert("x-ci-revision", value);
    }
    if let Some(hash) = crate::controller_rollout::binary_sha256()
        && let Ok(value) = hash.parse() {
        headers.insert("x-ci-binary-sha256", value);
    }
    (headers, "ok\n")
}

/// Where the executor records a VM's own console. Mirrors checkout at `-1`; see
/// `Dispatcher::capture_vm_log`.
const VM_LOG_STEP_IDX: i32 = -2;

/// How many runs the landing page shows. A dashboard is for "what happened
/// recently"; anything older is a query, not a scroll.
const RECENT_RUNS: i64 = 50;

fn who_of(headers: &HeaderMap) -> Option<Identity> {
    Identity::from_headers(headers)
}

/// The page shell for one request: which app, who is signed in, and the theme
/// their cookie asked for.
///
/// Built per request and per page rather than kept on `AppState`, because the
/// theme is a property of the *caller*, not of the process — two people on one
/// instance can be looking at different palettes.
fn chrome<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    who: Option<&'a Identity>,
) -> pages::Chrome<'a> {
    chrome_in(state, headers, who.map(|i| i.display()), pages::Scope::Fleet)
}

/// [`chrome`] for any scope, with the signed-in name already resolved — a
/// namespace page's comes from app-lb's actor headers, not from an
/// [`Identity`].
fn chrome_in<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    who: Option<&'a str>,
    scope: pages::Scope,
) -> pages::Chrome<'a> {
    let cookies = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok());
    let theme = crate::heyo_ui::theme_from_cookie_header(cookies, &state.config.ui_cookie_name);
    pages::Chrome {
        app_name: &state.config.name,
        who,
        html_attrs: crate::heyo_ui::html_attrs(
            theme,
            state.config.ui_cookie_domain.as_deref(),
            &state.config.ui_cookie_name,
        ),
        scope,
    }
}

/// `GET /__ui/{*path}` — the shared stylesheet, the theme script and the fonts,
/// served by this binary.
///
/// Same origin on purpose: these dashboards are read over SSH tunnels and from
/// networks with no route to the public internet, so the look cannot depend on
/// a CDN being reachable. The bytes are compiled in, so there is no directory
/// to deploy alongside the binary and nothing to traverse out of.
async fn ui_asset(Path(path): Path<String>) -> axum::response::Response {
    match crate::heyo_ui::asset(&path) {
        Some(a) => (
            [
                (axum::http::header::CONTENT_TYPE, a.content_type),
                (
                    axum::http::header::CACHE_CONTROL,
                    crate::heyo_ui::cache_control(&a),
                ),
            ],
            a.bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found\n").into_response(),
    }
}

async fn runs_page(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = who_of(&headers);
    // `?repo=<id>` narrows to one registered repository. An id that matches
    // nothing filters everything out rather than erroring — the page says "no
    // runs" and offers the way back, which is the right answer for a stale
    // bookmark of a deleted registration.
    let repo = q.get("repo").map(String::as_str).filter(|r| !r.is_empty());
    let repos = match state.store.repos().await {
        Ok(repos) => repos,
        Err(e) => return page_error(&state, &headers, who.as_ref(), &e.to_string()),
    };
    // `?namespace=<ns>` narrows to one tenant, and `-` to the fleet's own.
    // The picker and the column appear only once a namespace has run.
    let namespace = match q.get("namespace").map(String::as_str) {
        None | Some("") => None,
        Some("-") => Some(""),
        Some(ns) => Some(ns),
    };
    let namespaces = state.store.run_namespaces().await.unwrap_or_default();
    let runs = match namespace {
        Some(ns) => state.store.recent_runs_in(ns, RECENT_RUNS, repo).await,
        None => state.store.recent_runs(RECENT_RUNS, repo).await,
    };
    match runs {
        Ok(runs) => pages::runs_page_with_namespaces(
            &chrome(&state, &headers, who.as_ref()),
            &runs,
            &repos,
            repo,
            &namespaces,
            namespace,
        )
        .into_response(),
        Err(e) => page_error(&state, &headers, who.as_ref(), &e.to_string()),
    }
}

async fn run_page(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = who_of(&headers);
    let event_before = q.get("events_before").and_then(|value| value.parse::<i64>().ok());
    match state.store.get_run(&run_id).await {
        Ok(Some(run)) => {
            match render_run(&state, &chrome(&state, &headers, who.as_ref()), &run, event_before).await {
                Ok(page) => page.into_response(),
                Err(e) => page_error(&state, &headers, who.as_ref(), &e),
            }
        }
        Ok(None) => not_found(&state, &headers, who.as_ref(), &format!("No run {run_id}.")),
        Err(e) => page_error(&state, &headers, who.as_ref(), &e.to_string()),
    }
}

/// Everything a run page shows, for a run the caller has already decided the
/// viewer may see — the fleet page by its gate, a namespace's by its scope.
async fn render_run(
    state: &AppState,
    chrome: &pages::Chrome<'_>,
    run: &crate::store::Run,
    event_before: Option<i64>,
) -> Result<maud::Markup, String> {
    let run_id = run.id.as_str();
    let jobs = state.store.jobs_of(run_id).await.map_err(|e| e.to_string())?;
    let artifacts = state.store.artifacts_of(run_id).await.unwrap_or_default();

    // The VM log is the step recorded at index -2 by the executor. Read
    // from the same place as any other step log, so a swept run shows
    // the row with the bytes gone rather than vanishing from the page.
    let mut vm_logs = Vec::new();
    for job in &jobs {
        let steps = state.store.steps_of(&job.id).await.map_err(|e| e.to_string())?;
        if let Some(step) = steps.iter().find(|s| s.idx == VM_LOG_STEP_IDX) {
            let log = state.store.read_log(step).await.map_err(|e| e.to_string())?;
            vm_logs.push((job.display.clone(), log));
        }
    }

    let reruns = state.store.reruns_of(run_id).await.unwrap_or_default();
    let release = crate::release::get(&state.store, run_id)
        .await
        .map_err(|e| format!("could not load release: {e}"))?;
    let deployments = state
        .store
        .service_deployments_of(run_id)
        .await
        .map_err(|e| format!("could not load deployments: {e}"))?;
    let mut events = state
        .store
        .run_events(run_id, event_before, RUN_EVENT_PAGE_SIZE + 1)
        .await
        .map_err(|e| format!("could not load event timeline: {e}"))?;
    let events_have_more = events.len() as i64 > RUN_EVENT_PAGE_SIZE;
    if events_have_more {
        events.pop();
    }
    Ok(pages::run_page_with_deployments(
        chrome,
        run,
        &reruns,
        &jobs,
        &artifacts,
        &vm_logs,
        release.as_ref(),
        &deployments,
        &events,
        event_before,
        events_have_more,
        state.config.log_retention.map(|d| d.as_secs() / 86_400),
    ))
}

/// `POST /runs/{id}/cancel` — stop a run.
///
/// Marks the run and every unfinished job cancelled, which is all it takes to
/// stop work in each of the three states it might be in: a queued job is dropped
/// when JetStream delivers it, a job about to start is refused by `start_job`,
/// and a running one notices at its next step boundary. Nothing has to reach a
/// runner.
async fn cancel_run(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    match state.store.cancel_run(&run_id).await {
        Ok(Some(jobs)) => {
            tracing::info!(
                "cancelled run {run_id} ({jobs} job(s)) by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
        }
        Ok(None) => {
            tracing::debug!("run {run_id} was already finished; nothing to cancel");
        }
        Err(e) => return page_error(&state, &headers, who.as_ref(), &e.to_string()),
    }
    // Back to the run, which now shows what happened — rather than a flash on a
    // page the browser would re-post on refresh.
    axum::response::Redirect::to(&format!("/runs/{run_id}")).into_response()
}

/// `POST /runs/{id}/rerun` — run a finished run's source again, every job.
///
/// The dashboard's manual trigger. There is no "run this workflow" button
/// with a branch picker because this service never clones: the only source it
/// can run is one a submit already sent, and the run page is where that source
/// is. The new run gets `rerun_of` pointing here, and the browser lands on it.
async fn rerun_run(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    rerun(state, run_id, headers, false).await
}

/// `POST /runs/{id}/rerun-failed` — the same, carrying every job that succeeded
/// over as finished and scheduling only the rest.
async fn rerun_failed_jobs(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    rerun(state, run_id, headers, true).await
}

async fn rerun(
    state: AppState,
    run_id: String,
    headers: HeaderMap,
    failed_only: bool,
) -> axum::response::Response {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    match state
        .dispatcher
        .rerun(&run_id, failed_only, who.as_ref())
        .await
    {
        Ok(submitted) => {
            for w in &submitted.warnings {
                tracing::info!("re-run of {run_id}: {w}");
            }
            // One workflow file was named, so one run came back; the redirect
            // is to it. A `--only` that matched a file under two workflow
            // objects' globs could start two, in which case the first is
            // shown and the runs page lists the rest.
            match submitted.run_ids.first() {
                Some(new_id) => {
                    axum::response::Redirect::to(&format!("/runs/{new_id}")).into_response()
                }
                None => axum::response::Redirect::to(&format!("/runs/{run_id}")).into_response(),
            }
        }
        Err(e) => page_error(&state, &headers, who.as_ref(), &e.to_string()),
    }
}

async fn job_page(
    State(state): State<AppState>,
    Path((run_id, job_key)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = who_of(&headers);

    let Ok(Some(run)) = state.store.get_run(&run_id).await else {
        return not_found(&state, &headers, who.as_ref(), &format!("No run {run_id}."));
    };
    match render_job(&state, &chrome(&state, &headers, who.as_ref()), &run, &job_key).await {
        Ok(Some(page)) => page.into_response(),
        Ok(None) => not_found(
            &state,
            &headers,
            who.as_ref(),
            &format!("Run {run_id} has no job {job_key}."),
        ),
        Err(e) => page_error(&state, &headers, who.as_ref(), &e),
    }
}

/// One job's page, for a run the caller has already decided the viewer may
/// see. `None` when the run has no such job.
async fn render_job(
    state: &AppState,
    chrome: &pages::Chrome<'_>,
    run: &crate::store::Run,
    job_key: &str,
) -> Result<Option<maud::Markup>, String> {
    let jobs = state.store.jobs_of(&run.id).await.unwrap_or_default();
    let Some(job) = jobs.into_iter().find(|j| j.job_key == job_key) else {
        return Ok(None);
    };

    let mut steps = Vec::new();
    let stored_steps = state.store.steps_of(&job.id).await.map_err(|e| e.to_string())?;
    for step in stored_steps {
        let log = state.store.read_log(&step).await.map_err(|e| e.to_string())?.unwrap_or_default();
        steps.push((step, log));
    }

    // Only mint a token while there is still something to stream. A finished
    // job gets a static page, and no credential is handed out that nothing
    // needs.
    let token = (!matches!(
        job.status.as_str(),
        "success" | "failure" | "skipped" | "cancelled"
    ))
    .then(|| stream::mint(&state.config, &run.id, job_key));

    Ok(Some(pages::job_page(chrome, run, &job, &steps, token.as_deref())))
}

async fn workflows_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let who = who_of(&headers);
    // The fleet's workflows only. A namespace names its own, and a tenant
    // repository called `deploy` is not the fleet's deploy workflow.
    match state.store.recent_runs_in("", 500, None).await {
        Ok(runs) => pages::workflows_page(
            &chrome(&state, &headers, who.as_ref()),
            &latest_per_workflow(runs),
            &state.config.default_workflow_path,
        )
        .into_response(),
        Err(e) => page_error(&state, &headers, who.as_ref(), &e.to_string()),
    }
}

/// Each workflow id once, with its most recent run.
fn latest_per_workflow(runs: Vec<crate::store::Run>) -> Vec<(String, Option<crate::store::Run>)> {
    // Newest first already, so the first sighting of an id is its most
    // recent run.
    let mut seen: Vec<(String, Option<crate::store::Run>)> = Vec::new();
    for r in runs {
        if !seen.iter().any(|(id, _)| *id == r.workflow_id) {
            seen.push((r.workflow_id.clone(), Some(r)));
        }
    }
    seen
}

// ---- registered repositories --------------------------------------------

/// Who may register a repository and mint a token for it.
///
/// Two admissible cases, and the second one is a deliberate trade:
///
/// - **A gated deployment.** app-lb forwards an identity, and the person behind
///   it must hold the `admin` role in `ci_user`, seeded from `CI_ADMIN_EMAILS`.
/// - **A deployment that forwards no identity at all and names no admins.**
///   That is the local loop: no gate, no accounts, and anyone who can reach the
///   dashboard can already read every build log. Refusing here would leave the
///   page unusable in the one configuration it is developed in.
///
/// The moment `CI_ADMIN_EMAILS` names anybody, an anonymous request is refused —
/// an installation that has declared who its admins are has said that "nobody in
/// particular" is not one of them.
async fn may_manage(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<Identity>, axum::response::Response> {
    check_origin(state, headers)?;

    let who = Identity::from_headers(headers);
    let Some(who) = who else {
        if state.config.admin_emails.is_empty() {
            return Ok(None);
        }
        return Err(refused(
            state,
            headers,
            None,
            StatusCode::UNAUTHORIZED,
            "This request carries no identity, and this installation names its admins in \
             CI_ADMIN_EMAILS. Reach this page through the app-lb gate that forwards \
             x-auth-request-user.",
        ));
    };

    match state
        .store
        .upsert_user(
            &who.subject,
            &who.email,
            who.name.as_deref(),
            &state.config.admin_emails,
        )
        .await
    {
        Ok(role) if role == "admin" => Ok(Some(who)),
        Ok(_) => Err(refused(
            state,
            headers,
            Some(&who),
            StatusCode::FORBIDDEN,
            "Registering a repository mints a credential that can run code on a runner, \
             so it is admin-only. Ask someone on CI_ADMIN_EMAILS to add you.",
        )),
        Err(e) => {
            tracing::error!("could not resolve a role: {e}");
            Err(page_error(state, headers, Some(&who), &e.to_string()))
        }
    }
}

/// Refuse a request that a different site made on a logged-in browser's behalf.
///
/// These routes are POST forms authenticated by an app-lb session cookie, which
/// a cross-site form submission carries just as happily as the real page does.
/// Without this, a page anywhere could delete a registration — or register one —
/// on behalf of whoever is signed in. It could not *read* the minted token back,
/// so this is vandalism rather than credential theft, but it is still somebody
/// else deciding what this installation builds.
///
/// **Absent `Origin` passes**, which is the deliberate limit. A browser sends it
/// on every cross-origin form POST, so the attack this defends against always
/// carries one; `curl` and a scripted client send none, and a cross-site request
/// cannot forge one. It is checked on GET too — a navigation carries no `Origin`
/// and a same-origin fetch carries a matching one, so nothing legitimate is
/// caught.
fn check_origin(state: &AppState, headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|o| !o.is_empty() && *o != "null")
    else {
        return Ok(());
    };

    if origin.trim_end_matches('/') == state.config.public_url {
        return Ok(());
    }

    tracing::warn!(
        "refused a repositories request from origin {origin:?}; this app is {:?}",
        state.config.public_url
    );
    Err(refused(
        state,
        headers,
        None,
        StatusCode::FORBIDDEN,
        "This request came from another site. If it came from this dashboard, \
         CI_PUBLIC_URL does not match the address the browser is using — set it to \
         the URL people actually visit.",
    ))
}

fn refused(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    status: StatusCode,
    message: &str,
) -> axum::response::Response {
    (
        status,
        pages::layout(
            &chrome(state, headers, who),
            "repos",
            maud::html! {
                div .banner { (message) }
                p { a href="/" { "Back to runs" } }
            },
        ),
    )
        .into_response()
}

/// Render `/repos`, optionally with the outcome of the POST that produced it.
async fn render_repos(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    flash: RepoFlash,
) -> axum::response::Response {
    let repos = match state.store.repos().await {
        Ok(r) => r,
        Err(e) => return page_error(state, headers, who, &e.to_string()),
    };

    let mut views = Vec::with_capacity(repos.len());
    for repo in repos {
        // A failure to read one repository's tokens must not blank the page;
        // an empty token list is visibly wrong in a way a 500 is not fixable
        // from.
        let tokens = state.store.repo_tokens(&repo.id).await.unwrap_or_default();
        let last_run = state.store.last_run_of_repo(&repo.id).await.ok().flatten();
        views.push(RepoView {
            repo,
            tokens,
            last_run,
        });
    }

    pages::repos_page(
        &chrome(state, headers, who),
        &views,
        &state.config.public_url,
        state.config.require_repo_token,
        &state.runners.snapshot(),
        &flash,
    )
    .into_response()
}

async fn repos_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    render_repos(&state, &headers, who.as_ref(), RepoFlash::default()).await
}

#[derive(serde::Deserialize)]
struct RegisterForm {
    url: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    workflow_path: String,
    #[serde(default)]
    network: String,
}

async fn register_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let url = form.url.trim();
    if url.is_empty() {
        return render_repos(
            &state,
            &headers,
            who.as_ref(),
            RepoFlash::failed("A clone URL is required; it is what a submit is matched against."),
        )
        .await;
    }

    let name = match form.name.trim() {
        "" => repos::name_from_url(url),
        given => given.to_string(),
    };
    let workflow_path = Some(form.workflow_path.trim()).filter(|p| !p.is_empty());
    let actor = who.as_ref().map(|w| (w.subject.as_str(), w.email.as_str()));

    // The picker only offers served networks, so anything else arrived from
    // somewhere other than this page. Resolved to the canonical name rather than
    // stored verbatim, so an id typed into the form still reads as a name later.
    let pool = state.runners.snapshot();
    let network = match form.network.trim() {
        "" => None,
        name => match pool.find(name).filter(|s| s.served) {
            Some(set) => Some(set.network_name.clone()),
            None => {
                return render_repos(
                    &state,
                    &headers,
                    who.as_ref(),
                    RepoFlash::failed(format!(
                        "This orchestrator does not serve a network named {name:?}. \
                         See Networks for what it does serve."
                    )),
                )
                .await;
            }
        },
    };

    match state
        .store
        .register_repo(url, &name, workflow_path, network.as_deref(), actor)
        .await
    {
        Ok(repo) => {
            tracing::info!(
                "registered repository {} ({}) on network {:?} by {}",
                repo.name,
                repo.normalized,
                repo.network.as_deref().unwrap_or("(default)"),
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            render_repos(
                &state,
                &headers,
                who.as_ref(),
                RepoFlash::done(format!(
                    "{} is registered. Mint a token for it below.",
                    repo.name
                )),
            )
            .await
        }
        Err(e) => {
            render_repos(
                &state,
                &headers,
                who.as_ref(),
                RepoFlash::failed(e.to_string()),
            )
            .await
        }
    }
}

#[derive(serde::Deserialize)]
struct TokenForm {
    #[serde(default)]
    name: String,
}

/// Mint a token, and render the page that shows it.
///
/// A redirect would be the conventional answer to a POST, but the token can only
/// be shown once and a redirect would have to carry it in the URL — where it
/// lands in browser history, in a `Referer`, and in every access log between
/// here and the browser. So the POST renders its own result.
async fn create_repo_token(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let repo = match state.store.get_repo(&repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return render_repos(
                &state,
                &headers,
                who.as_ref(),
                RepoFlash::failed("That repository is not registered any more."),
            )
            .await;
        }
        Err(e) => return page_error(&state, &headers, who.as_ref(), &e.to_string()),
    };

    let name = match form.name.trim() {
        "" => who
            .as_ref()
            .map(|w| w.email.clone())
            .unwrap_or_else(|| "unnamed".to_string()),
        given => given.to_string(),
    };
    let actor = who.as_ref().map(|w| (w.subject.as_str(), w.email.as_str()));

    match state.store.create_repo_token(&repo.id, &name, actor).await {
        Ok((token, plaintext)) => {
            tracing::info!(
                "minted submit token {} for {} by {}",
                token.id,
                repo.name,
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            render_repos(
                &state,
                &headers,
                who.as_ref(),
                RepoFlash::minted(repo.name.clone(), plaintext),
            )
            .await
        }
        Err(e) => {
            render_repos(
                &state,
                &headers,
                who.as_ref(),
                RepoFlash::failed(e.to_string()),
            )
            .await
        }
    }
}

async fn revoke_repo_token(
    State(state): State<AppState>,
    Path((_repo_id, token_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let flash = match state.store.revoke_repo_token(&token_id).await {
        Ok(true) => {
            tracing::info!(
                "revoked submit token {token_id} by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            RepoFlash::done("That token no longer works. Any build already running is unaffected.")
        }
        Ok(false) => RepoFlash::done("That token was already revoked."),
        Err(e) => RepoFlash::failed(e.to_string()),
    };
    render_repos(&state, &headers, who.as_ref(), flash).await
}

#[derive(serde::Deserialize)]
struct NetworkForm {
    /// Empty means "the installation default", which is a real choice and so is
    /// an option in the select rather than an absent field.
    #[serde(default)]
    network: String,
}

/// Point a repository at a heyvm network.
///
/// The chosen network is checked against the pool *now*, so a typo or an
/// unserved network is refused while somebody is looking at the page — rather
/// than at the next submit, by whoever is waiting on a build.
async fn set_repo_network(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<NetworkForm>,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let wanted = form.network.trim();
    let pool = state.runners.snapshot();
    let chosen = match wanted {
        "" => None,
        name => match pool.find(name) {
            Some(set) if set.served => Some(set.network_name.clone()),
            Some(set) => {
                return render_repos(
                    &state,
                    &headers,
                    who.as_ref(),
                    RepoFlash::failed(format!(
                        "Network {} exists but this orchestrator does not take work for it. \
                         Add it to CI_NETWORK, or set CI_NETWORK=*.",
                        set.network_name
                    )),
                )
                .await;
            }
            None => {
                return render_repos(
                    &state,
                    &headers,
                    who.as_ref(),
                    RepoFlash::failed(format!("No heyvm network is named {name:?}.")),
                )
                .await;
            }
        },
    };

    let flash = match state
        .store
        .set_repo_network(&repo_id, chosen.as_deref())
        .await
    {
        Ok(true) => {
            tracing::info!(
                "assigned repository {repo_id} to network {:?} by {}",
                chosen.as_deref().unwrap_or("(default)"),
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            RepoFlash::done(match &chosen {
                Some(n) => format!(
                    "New builds of this repository run in {n}. A job with its own \
                     `uses:` still goes where the workflow says, and anything already \
                     queued keeps the network it was scheduled for."
                ),
                None => "This repository is back on the installation default network.".to_string(),
            })
        }
        Ok(false) => RepoFlash::failed("That repository is not registered."),
        Err(e) => RepoFlash::failed(e.to_string()),
    };
    render_repos(&state, &headers, who.as_ref(), flash).await
}

#[derive(serde::Deserialize)]
struct EnabledForm {
    enabled: bool,
}

/// Pause or resume a repository.
///
/// The desired state is submitted rather than flipped, so two admins clicking
/// at once converge instead of toggling each other's decision away.
async fn set_repo_enabled(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<EnabledForm>,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let flash = match state.store.set_repo_enabled(&repo_id, form.enabled).await {
        Ok(true) if form.enabled => RepoFlash::done("That repository can submit again."),
        Ok(true) => RepoFlash::done(
            "That repository is paused. Its tokens still exist, and every submit with one \
             is refused until it is resumed. The shared CI_WEBHOOK_SECRET is not affected \
             — it belongs to no repository, so nothing about one can stop it.",
        ),
        Ok(false) => RepoFlash::failed("That repository is not registered."),
        Err(e) => RepoFlash::failed(e.to_string()),
    };
    tracing::info!(
        "set repository {repo_id} enabled={} by {}",
        form.enabled,
        who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
    );
    render_repos(&state, &headers, who.as_ref(), flash).await
}

async fn delete_repo(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let flash = match state.store.delete_repo(&repo_id).await {
        Ok(true) => {
            tracing::info!(
                "removed repository registration {repo_id} by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            RepoFlash::done(
                "The registration and its tokens are gone. Its runs are kept, and a \
                 submit with one of those tokens is now refused.",
            )
        }
        Ok(false) => RepoFlash::failed("That repository is not registered."),
        Err(e) => RepoFlash::failed(e.to_string()),
    };
    render_repos(&state, &headers, who.as_ref(), flash).await
}

/// Tail a job's step logs.
///
/// Emits **rendered text appended to a specific step**, not a JSON model the
/// browser assembles into markup — the page stays server-rendered, and the
/// fifteen lines of script only append what arrived. On completion it sends
/// `done`, and the browser reloads so the final state is the server's rendering
/// rather than one stitched together client-side.
async fn log_stream(
    State(state): State<AppState>,
    Path((run_id, job_key)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = q.get("token").cloned().unwrap_or_default();
    if !stream::verify(&state.config, &token, &run_id, &job_key) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "this log stream token is missing, expired, or for another job"
            })),
        )
            .into_response();
    }
    tail_job(state, run_id, job_key)
}

/// The SSE tail itself, once a caller has decided the job may be read: the
/// fleet route by its run-scoped token, a namespace's by its namespace.
fn tail_job(state: AppState, run_id: String, job_key: String) -> axum::response::Response {
    let stream = async_stream::stream! {
        // Byte offsets already sent, per step index. A step's log only ever
        // grows, so an offset is all the state a tail needs.
        let mut sent: HashMap<i32, usize> = HashMap::new();

        loop {
            let Ok(jobs) = state.store.jobs_of(&run_id).await else { break };
            let Some(job) = jobs.into_iter().find(|j| j.job_key == job_key) else { break };

            let steps = match state.store.steps_of(&job.id).await {
                Ok(steps) => steps,
                Err(e) => {
                    tracing::error!("could not load steps for log stream: {e}");
                    yield Ok::<Event, std::convert::Infallible>(Event::default().event("error").data("step logs are temporarily unavailable"));
                    return;
                }
            };
            for step in steps {
                let text = match state.store.read_log(&step).await {
                    Ok(log) => log.unwrap_or_default(),
                    Err(e) => {
                        tracing::error!("could not stream shared step logs: {e}");
                        yield Ok::<Event, std::convert::Infallible>(Event::default().event("error").data("step logs are temporarily unavailable"));
                        return;
                    }
                };
                let already = *sent.get(&step.idx).unwrap_or(&0);
                if text.len() > already {
                    // Split on a character boundary: a log is arbitrary bytes
                    // and slicing mid-codepoint would panic.
                    let mut cut = already.min(text.len());
                    while cut < text.len() && !text.is_char_boundary(cut) {
                        cut += 1;
                    }
                    let fresh = &text[cut..];
                    if !fresh.is_empty() {
                        let payload = serde_json::json!({ "idx": step.idx, "text": fresh });
                        yield Ok::<Event, std::convert::Infallible>(
                            Event::default().event("log").data(payload.to_string()),
                        );
                    }
                    sent.insert(step.idx, text.len());
                }
            }

            if matches!(
                job.status.as_str(),
                "success" | "failure" | "skipped" | "cancelled"
            ) {
                yield Ok(Event::default().event("done").data("{}"));
                break;
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    };

    Sse::new(stream)
        // A proxy that sees nothing for a minute will close the connection;
        // a comment every fifteen seconds keeps it open through a slow step.
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn page_error(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    message: &str,
) -> axum::response::Response {
    tracing::warn!("page render failed: {message}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        pages::layout(
            &chrome(state, headers, who),
            "",
            maud::html! { div .banner { (message) } },
        ),
    )
        .into_response()
}

fn not_found(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    message: &str,
) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        pages::layout(
            &chrome(state, headers, who),
            "",
            maud::html! {
                div .banner { (message) }
                p { a href="/" { "Back to runs" } }
            },
        ),
    )
        .into_response()
}

/// Read every served route's backlog, concurrently.
///
/// One round trip per network and per runner, so they go together and under one
/// deadline — a dashboard must not hang because NATS is slow, and a page with no
/// gauges beats a page that never renders.
async fn queue_depths(state: &AppState) -> pages::QueueDepths {
    let pool = state.runners.snapshot();
    let mut routes = Vec::new();
    for set in pool.served() {
        if !set.network_id.is_empty() {
            routes.push((
                set.network_id.clone(),
                crate::bus::Route::Network(set.network_id.clone()),
            ));
        }
        // Every runner, not just the dispatchable ones. A queue on an offline
        // host is exactly what somebody needs to see — that is where a pinned
        // job goes to wait.
        for r in &set.runners {
            routes.push((r.id.clone(), crate::bus::Route::Runner(r.id.clone())));
        }
    }

    let reads = routes
        .iter()
        .map(|(key, route)| async move { (key.clone(), state.dispatcher.bus.depth(route).await) });

    let mut depths = pages::QueueDepths::default();
    let results = match tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::join_all(reads),
    )
    .await
    {
        Ok(results) => results,
        Err(_) => {
            depths.error = Some("The queue did not answer within 5s.".to_string());
            return depths;
        }
    };
    for (key, result) in results {
        match result {
            Ok(depth) => {
                depths.by_route.insert(key, depth);
            }
            // A stream-level failure is NATS being unreachable, not an idle
            // queue, and saying so once at the top beats a page of blanks.
            Err(e) => depths
                .error
                .get_or_insert_with(|| e.to_string())
                .clone_from(&e.to_string()),
        }
    }
    depths
}

async fn networks_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let who = Identity::from_headers(&headers);
    let depths = queue_depths(&state).await;
    pages::networks_page(
        &chrome(&state, &headers, who.as_ref()),
        &state.runners.snapshot(),
        &depths,
        &state.runners.tunnel_failures(),
        &pages::Notice::default(),
    )
}

async fn vms_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let who = Identity::from_headers(&headers);
    render_vms(&state, &headers, who.as_ref(), pages::Notice::default()).await
}

async fn render_vms(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    notice: pages::Notice,
) -> axum::response::Response {
    let vms = match state.dispatcher.vm_inventory().await {
        Ok(vms) => vms,
        Err(e) => return page_error(state, headers, who, &e.to_string()),
    };
    // Read separately and never fatal: the images table is context for the
    // pool, and a page that refuses to render the VMs because the image
    // catalog was unreadable would hide the more important half.
    let images = state.dispatcher.image_inventory().await.unwrap_or_default();
    pages::vms_page(&chrome(state, headers, who), &vms, &images, &notice).into_response()
}

async fn destroy_vm(
    State(state): State<AppState>,
    Path(sandbox_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    let _effect = match state.dispatcher.executor.effect_permit().await {
        Ok(permit) => permit,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let notice = match state.dispatcher.destroy_pooled_vm(&sandbox_id).await {
        Ok(message) => {
            tracing::info!(
                "destroyed pooled VM {sandbox_id} by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            pages::Notice::done(message)
        }
        Err(e) => pages::Notice::failed(e.to_string()),
    };
    render_vms(&state, &headers, who.as_ref(), notice).await
}

#[derive(serde::Deserialize)]
struct ResizeForm {
    size_class: String,
}

async fn resize_vm(
    State(state): State<AppState>,
    Path(sandbox_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ResizeForm>,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    let _effect = match state.dispatcher.executor.effect_permit().await {
        Ok(permit) => permit,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    // Parsed through the SDK's own enum so the page and the daemon cannot
    // disagree about what a class is called.
    let class: Result<heyo_sdk::SandboxSize, _> =
        serde_json::from_value(serde_json::Value::String(form.size_class.clone()));
    let notice = match class {
        Err(_) => pages::Notice::failed(format!("{:?} is not a size class", form.size_class)),
        Ok(class) => match state.dispatcher.resize_pooled_vm(&sandbox_id, class).await {
            Ok(message) => {
                tracing::info!(
                    "resized pooled VM {sandbox_id} to {} by {}",
                    class.as_str(),
                    who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
                );
                pages::Notice::done(message)
            }
            Err(e) => pages::Notice::failed(e.to_string()),
        },
    };
    render_vms(&state, &headers, who.as_ref(), notice).await
}

async fn cleanup_failed_vms(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };
    let _effect = match state.dispatcher.executor.effect_permit().await {
        Ok(permit) => permit,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    let notice = match state.dispatcher.destroy_failed_vms().await {
        Ok(message) => {
            tracing::info!(
                "swept VMs from failed runs by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            pages::Notice::done(message)
        }
        Err(e) => pages::Notice::failed(e.to_string()),
    };
    render_vms(&state, &headers, who.as_ref(), notice).await
}

async fn render_networks(
    state: &AppState,
    headers: &HeaderMap,
    who: Option<&Identity>,
    notice: pages::Notice,
) -> axum::response::Response {
    let depths = queue_depths(state).await;
    pages::networks_page(
        &chrome(state, headers, who),
        &state.runners.snapshot(),
        &depths,
        &state.runners.tunnel_failures(),
        &notice,
    )
    .into_response()
}

/// `POST /networks/{id}/join` — put this orchestrator's own host in a network.
///
/// The button exists because `uses: default` is useless until this machine is a
/// member of some network the instance serves, and the alternative was an error
/// message telling somebody to go and run `heyvm network add-host` on a box they
/// may not have a shell on.
async fn join_network(
    State(state): State<AppState>,
    Path(network_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let who = match may_manage(&state, &headers).await {
        Ok(w) => w,
        Err(response) => return response,
    };

    let pool = state.runners.snapshot();
    let node_id = pool.default_node_id.clone();
    if node_id.is_empty() {
        return render_networks(
            &state,
            &headers,
            who.as_ref(),
            pages::Notice::failed(
                "This machine's daemon could not be identified, so there is no host to                  add. Set CI_DEFAULT_NODE to its daemon id or name.",
            ),
        )
        .await;
    }
    let Some(network) = pool.find(&network_id) else {
        return render_networks(
            &state,
            &headers,
            who.as_ref(),
            pages::Notice::failed("That network no longer exists on this account."),
        )
        .await;
    };
    let network_name = network.network_name.clone();

    let notice = match state.runners.join_network(&network_id, &node_id).await {
        Ok(()) => {
            tracing::info!(
                "joined host {node_id} to network {network_name} by {}",
                who.as_ref().map(|w| w.display()).unwrap_or("anonymous")
            );
            // Re-read before rendering, or the page shows the state from before
            // the click and reads as though nothing happened. A failure here is
            // not the join failing — the join already succeeded — so it must not
            // be reported as one.
            if let Err(e) = state.runners.refresh().await {
                tracing::warn!("joined, but could not re-read the pool: {e}");
            }
            let served = state
                .runners
                .snapshot()
                .find(&network_id)
                .is_some_and(|n| n.served);
            let mut message = format!(
                "This host is now a member of {network_name}. It may take a moment to appear online."
            );
            if !served {
                // Joining does not make an instance take work for a network,
                // and finding that out from a queued job that never runs is
                // worse than being told now.
                message.push_str(
                    " This orchestrator does not serve that network, though, so jobs                      still cannot be sent to it — add it to CI_NETWORK, or set                      CI_NETWORK=*.",
                );
            }
            pages::Notice::done(message)
        }
        Err(e) => {
            tracing::warn!("could not join {network_name}: {e}");
            pages::Notice::failed(e.to_string())
        }
    };
    render_networks(&state, &headers, who.as_ref(), notice).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn native_poll_rejections_are_terminal_but_pool_failures_are_retryable_and_redacted() {
        for message in ["unsupported protocol 0; expected 1", "runner is not registered"] {
            let response = native_poll_error(crate::native::PollError::Rejected(message.into()));
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert!(String::from_utf8_lossy(&body).contains(message));
        }

        let detail = "pool timed out while waiting for an open connection";
        let response = native_poll_error(crate::native::PollError::Internal(detail.into()));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("temporarily unavailable"));
        assert!(!body.contains(detail));
    }

    /// Binds no port — `oneshot` drives the router directly.
    pub(crate) fn test_config() -> Arc<Config> {
        // Set the required vars for a config that validates, then drop them so
        // tests stay independent of each other's environment.
        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "test-key");
            std::env::set_var("CI_NETWORK", "test-net");
            std::env::set_var("CI_DATABASE_URL", "postgres://localhost/ci_test");
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
        }
        let c = Config::from_env().expect("test config resolves");
        Arc::new(c)
    }

    /// A pool that has never refreshed. No network call is made — `Runners`
    /// only dials when `refresh` or `client_for` is called.
    fn test_runners(config: Arc<Config>) -> Arc<Runners> {
        Arc::new(Runners::new(config))
    }

    /// A router wired to a real database.
    ///
    /// The pages read run history, so there is no honest way to exercise them
    /// without a store; a mock would test the mock.
    async fn test_router() -> Router {
        let config = test_config();
        test_router_with_config(config).await
    }

    async fn test_router_with_config(config: Arc<Config>) -> Router {
        let tenants = Arc::new(crate::tenants::Tenants::new(&config));
        test_router_with(config, tenants).await.0
    }

    /// [`test_router_with_config`] with a chosen install list, and the store
    /// behind it so a test can seed rows.
    async fn test_router_with(config: Arc<Config>, tenants: Arc<crate::tenants::Tenants>) -> (Router, Store) {
        let url = std::env::var("CI_TEST_DATABASE_URL").expect("CI_TEST_DATABASE_URL");
        let dir = std::env::temp_dir().join(format!("ci-web-logs-{}", crate::vm::new_id()));
        let store = Store::connect(&url, dir, std::time::Duration::from_secs(30))
            .await
            .expect("store");
        store.migrate().await.expect("migrations");
        let runners = test_runners(config.clone());
        let identity = crate::executor::identity(&config);
        let executor = crate::executor::ExecutorInstance::register(store.pool().clone(), &identity).await.expect("executor");
        let dispatcher = Arc::new(Dispatcher {
            executor: Arc::new(executor),
            config: config.clone(),
            store: store.clone(),
            pool: crate::pool::Pool::new(store.pool().clone()),
            images: crate::image::Catalog::new(store.pool().clone()),
            bus: Arc::new(
                // A fixed prefix, not a fresh one per test: these tests never
                // publish, so sharing one stream pair is harmless, and minting
                // a new pair per run leaves a NATS littered with them.
                crate::bus::Bus::connect(&config.nats, "citestweb")
                    .await
                    .expect("nats"),
            ),
            runners: runners.clone(),
            vms: Arc::new(crate::vm::Vms::new()),
            secrets: crate::secrets::Secrets::new(&config),
            artifacts: Arc::from(crate::artifacts::sink_for(&config).expect("disk sink")),
            objects: Arc::new(crate::objects::Workflows::new(&config)),
            tenants,
        });
        (router(config, runners, store.clone(), dispatcher), store)
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_NATS_URL; run alone"]
    async fn managed_frontends_preserve_auth_and_reject_wrong_boot_without_retry() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("routing_{}",uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options",&format!("-c search_path={schema}"));
        unsafe { std::env::set_var("CI_TEST_DATABASE_URL",url.as_str()); }
        let mut config = Arc::try_unwrap(test_config()).unwrap();
        config.managed_deployment=Some("managed-owner".into());
        config.native_runner_secret=Some("original-native-token".into());
        let owner = test_router_with_config(Arc::new(config)).await;
        let pool = sqlx::PgPool::connect(url.as_str()).await.unwrap();
        let mut config=Arc::try_unwrap(test_config()).unwrap();
        config.managed_deployment=Some("managed-standby".into());
        config.native_runner_secret=Some("original-native-token".into());
        let standby=test_router_with_config(Arc::new(config)).await;
        let boots:Vec<uuid::Uuid>=sqlx::query_scalar("SELECT boot_id FROM ci_executor_boot ORDER BY registered_at")
            .fetch_all(&pool).await.unwrap();
        assert_eq!(boots.len(),2);
        for (app,name,credential,status) in [(&owner,"direct","original-native-token",StatusCode::OK),
            (&standby,"local","original-native-token",StatusCode::OK),
            (&standby,"unauthorized","wrong-token",StatusCode::UNAUTHORIZED)] {
            let body=serde_json::json!({"runnerId":name,"name":name,"labels":["macos","x86_64"],"platform":"macos","arch":"x86_64","protocolVersion":1});
            let response=app.clone().oneshot(Request::builder().method("POST").uri("/api/native/register")
                .header("content-type","application/json").header("authorization",format!("Bearer {credential}"))
                .body(Body::from(body.to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(),status);
        }
        let names:Vec<String>=sqlx::query_scalar("SELECT id FROM ci_native_runner ORDER BY id").fetch_all(&pool).await.unwrap();
        assert_eq!(names,vec!["direct","local"]);
        // Each managed frontend is an active executor and handles admissions
        // locally; neither forwards credentials or work to a singleton.
        for (app,runner) in [(&owner,"direct"),(&standby,"local")] {
            let response=app.clone().oneshot(Request::builder().method("POST").uri("/api/native/poll")
                .header("content-type","application/json").header("authorization","Bearer original-native-token")
                .body(Body::from(serde_json::json!({"runnerId":runner,"protocolVersion":1}).to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::OK);
            let body=to_bytes(response.into_body(),1024).await.unwrap();
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(),serde_json::json!({"job":null}));
        }
        for (app,target) in [(&owner,boots[1]),(&standby,boots[0])] {
            let response=app.clone().oneshot(Request::builder().method("POST").uri("/api/native/register")
                .header("x-ci-target-boot",target.to_string())
                .body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::CONFLICT);
        }
        unsafe {std::env::set_var("CI_TEST_DATABASE_URL",base);}
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn another_controller_serves_shared_logs_and_reports_unavailable_history() {
        let app = test_router().await;
        let root = tempfile::tempdir().unwrap();
        let store = Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(), root.path().into(), Duration::from_secs(30)).await.unwrap();
        let run = crate::vm::new_id();
        let url = format!("https://example.test/{run}.git");
        let repo = store.register_repo(&url, "shared logs", None, None, None).await.unwrap();
        let (_, token) = store.create_repo_token(&repo.id, "logs", None).await.unwrap();
        let plan = crate::plan::Plan::build(&crate::workflow::Workflow::parse("logs.yml", "jobs:\n  build:\n    steps: [{run: 'true'}]\n").unwrap()).unwrap();
        store.create_run(&run, &crate::store::RunRequest { repo_id: Some(repo.id), repo_url: url, ..Default::default() }, &plan).await.unwrap();
        let job = store.jobs_of(&run).await.unwrap().remove(0);
        let sid = crate::store::step_id(&job.id, 0);
        store.create_step(&sid, &job.id, 0, "Shared output", None).await.unwrap();
        let path = root.path().join("not-created.log");
        store.append_log(&sid, &path, "regional log 雪 <tag>\n").await.unwrap();
        drop(root);
        let response = app.clone().oneshot(Request::builder().uri(format!("/api/runs/{run}/logs"))
            .header("Authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["jobs"][0]["steps"][0]["log"], "regional log 雪 <tag>\n");
        let response = app.clone().oneshot(Request::builder().uri(format!("/runs/{run}/jobs/{}", job.job_key)).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("regional log 雪 &lt;tag&gt;"), "shared logs must remain escaped in the HTML");
        // An unimported record must not masquerade as an empty log.
        sqlx::query("UPDATE ci_step SET log_path='missing-retained-file' WHERE id=$1").bind(&sid).execute(store.pool()).await.unwrap();
        let response = app.oneshot(Request::builder().uri(format!("/api/runs/{run}/logs"))
            .header("Authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        sqlx::query("UPDATE ci_step SET log_path='postgres:ci_step_log' WHERE id=$1").bind(&sid).execute(store.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn bootstrap_recovery_is_scoped_read_only_and_preserves_failure() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use serde_json::{Value, json};
        use sqlx::Row;
        use std::sync::Mutex;
        let root=tempfile::tempdir().unwrap();
        let remote=Arc::new(Mutex::new(json!({"spec":null,"receipt":null,"posts":0,"bad_live":true})));
        let fake=Router::new()
            .route("/v1/secrets",get(|| async {Json(json!({"secrets":[{"path":"ci/recovery/default/ADMIN","tags":[]}]}))}))
            .route("/v1/secrets/read",post(|| async {Json(json!({"valueBase64":STANDARD.encode("scoped-token")}))}))
            .route("/deployments",post(|State(r):State<Arc<Mutex<Value>>>,Json(spec):Json<Value>| async move {
                let cmd=spec["update"]["commands"][0].as_str().unwrap();
                let encoded=cmd.rsplit_once(" '").unwrap().1.trim_end_matches('\'');
                let envelope:Value=serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
                assert_eq!(envelope["verify_only"],true);
                let mut r=r.lock().unwrap(); r["spec"]=spec.clone(); r["posts"]=json!(r["posts"].as_u64().unwrap()+1); Json(spec)
            }))
            .route("/deployments/{id}",get(|State(r):State<Arc<Mutex<Value>>>| async move {Json(r.lock().unwrap()["spec"].clone())}))
            .route("/deployments/{id}/update",post(|Path(id):Path<String>| async move {
                assert!(id.starts_with("heyvm-verify-")); Json(json!({"id":"verify-job"}))
            }))
            .route("/deployments/{id}/jobs",get(|State(r):State<Arc<Mutex<Value>>>,Path(id):Path<String>| async move {
                let r=r.lock().unwrap(); let mut receipt=r["receipt"].clone();
                if id!="original"&&r["bad_live"]==true {receipt["heyvm_sha256"]=json!("wrong");}
                Json(json!([{"id":if id=="original" {"original-job"} else {"verify-job"},"deployment":id,"kind":"update","status":"succeeded",
                    "log":[format!("HEYO_HEYVM_BOOTSTRAP_RESULT={}",STANDARD.encode(serde_json::to_vec(&receipt).unwrap()))]}]))
            })).with_state(remote.clone());
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base=format!("http://{}",listener.local_addr().unwrap());
        let server=tokio::spawn(async move {axum::serve(listener,fake).await.unwrap()});
        let runner=crate::vm::new_id(); let operation=crate::vm::new_id(); let run=crate::vm::new_id();
        let target=json!({"repository":"https://github.com/Heyo-Computer/heyo.git","app_lb_admin_url":base,"app_lb_deployment":"host","app_lb_namespace":"default",
            "runner_hd_id":runner,"backend_server_id":"backend","executable":"/usr/bin/heyvm","unit":"heyvm.service","state_dir":"/var/lib/heyvm-update",
            "config_json_path":"/etc/heyvm.json","systemd_drop_in_path":"/etc/systemd/system/heyvm.service.d/update.conf","local_health_url":"http://127.0.0.1:3000/health","target_alias":"eu1","region":"eu1"});
        let mut config=Arc::try_unwrap(test_config()).unwrap();
        config.host_heyvm_bootstrap_targets=Some(json!({"eu1":target}).to_string());
        config.heyosecret_url=Some(base); config.heyosecret_token=Some("test".into());
        let app=test_router_with_config(Arc::new(config)).await;
        let store=Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(),root.path().into(),std::time::Duration::from_secs(30)).await.unwrap();
        let repo=store.register_repo("https://github.com/Heyo-Computer/heyo.git","recovery",None,None,None).await.unwrap();
        let other=store.register_repo(&format!("https://example.test/{run}.git"),"other",None,None,None).await.unwrap();
        let (_,token)=store.create_repo_token(&repo.id,"recovery",None).await.unwrap();
        let (_,wrong)=store.create_repo_token(&other.id,"other",None).await.unwrap();
        let plan=crate::plan::Plan::build(&crate::workflow::Workflow::parse("recovery.yml","jobs:\n  bootstrap:\n    steps: [{run: 'true'}]\n").unwrap()).unwrap();
        store.create_run(&run,&crate::store::RunRequest {workflow_id:"recovery".into(),repo_id:Some(repo.id),repo_url:"https://github.com/Heyo-Computer/heyo.git".into(),sha:"a".repeat(40),..Default::default()},&plan).await.unwrap();
        let job=store.jobs_of(&run).await.unwrap().remove(0); let step=crate::store::step_id(&job.id,0);
        store.create_step(&step,&job.id,0,"bootstrap",None).await.unwrap();
        store.set_job_status(&job.id,crate::store::JobStatus::Failure,Some("original timeout")).await.unwrap();
        store.set_run_status(&run,crate::store::RunStatus::Failure,Some("original timeout")).await.unwrap();
        let receipt=json!({"protocol":"host-heyvm-bootstrap-v1","operation_id":operation,"request_sha256":"d".repeat(64),"target_alias":"eu1","status":"succeeded",
            "heyvm_sha256":"c".repeat(64),"config_sha256":"e".repeat(64),"systemd_drop_in_sha256":"f".repeat(64),"backend_server_id":"backend","region":"eu1"});
        remote.lock().unwrap()["receipt"]=receipt;
        let req=json!({"alias":"eu1","target":target,"token_secret":"ADMIN","request_sha256":"d".repeat(64),"config_sha256":"e".repeat(64),"systemd_drop_in_sha256":"f".repeat(64),
            "artifact":{"operation_id":operation,"artifact_url":"https://artifact.test/blob","artifact_sha256":"a".repeat(64),"artifact_size":42,"inner_path":"heyvm.tar.gz","inner_archive_sha256":"b".repeat(64),"heyvm_sha256":"c".repeat(64)}});
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) VALUES($1,$2,$3,$4,'backend','hash','failed','failed','sha','main')")
            .bind(&operation).bind(&step).bind(&run).bind(&job.id).execute(store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_host_heyvm_bootstrap(id,runner_hd_id,request,launcher_recipe,deadline,phase,delivery_armed,launcher_deployment_id,launcher_job_id) VALUES($1,$2,$3,'{}',now()-interval '1 hour','failed',true,'original','original-job')")
            .bind(&operation).bind(&runner).bind(req).execute(store.pool()).await.unwrap();
        let path=format!("/api/runs/{run}/bootstrap/{operation}/recover");
        for (credential,status) in [(None,StatusCode::UNAUTHORIZED),(Some(wrong.as_str()),StatusCode::NOT_FOUND),(Some(token.as_str()),StatusCode::CONFLICT)] {
            let mut request=Request::builder().method("POST").uri(&path);
            if let Some(token)=credential {request=request.header("Authorization",format!("Bearer {token}"));}
            let response=app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),status);
            assert!(crate::host_maintenance::cordoned(&store,&runner).await.unwrap());
        }
        assert_eq!(remote.lock().unwrap()["posts"],1);
        remote.lock().unwrap()["bad_live"]=json!(false);
        // A concurrent owner or superseding release must not be bypassed by recovery.
        let mut owner=store.pool().begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,222))").bind(&runner).execute(&mut *owner).await.unwrap();
        let response=app.clone().oneshot(Request::builder().method("POST").uri(&path).header("Authorization",format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(),StatusCode::CONFLICT);
        owner.rollback().await.unwrap();
        for phase in ["superseded","polling"] {
            sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase=$2 WHERE id=$1").bind(&operation).bind(phase).execute(store.pool()).await.unwrap();
            let response=app.clone().oneshot(Request::builder().method("POST").uri(&path).header("Authorization",format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::CONFLICT);
        }
        sqlx::query("UPDATE ci_host_heyvm_bootstrap SET phase='failed' WHERE id=$1").bind(&operation).execute(store.pool()).await.unwrap();
        assert_eq!(remote.lock().unwrap()["posts"],1);
        for expected in ["recovered","already_passed"] {
            let response=app.clone().oneshot(Request::builder().method("POST").uri(&path).header("Authorization",format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(),StatusCode::OK);
            let result:Value=serde_json::from_slice(&to_bytes(response.into_body(),1024*1024).await.unwrap()).unwrap(); assert_eq!(result["status"],expected);
        }
        assert_eq!(remote.lock().unwrap()["posts"],2);
        assert!(!crate::host_maintenance::cordoned(&store,&runner).await.unwrap());
        assert_eq!(store.get_run(&run).await.unwrap().unwrap().status,"failure");
        assert_eq!(store.get_job(&job.id).await.unwrap().unwrap().error.as_deref(),Some("original timeout"));
        let row=sqlx::query("SELECT status,phase FROM ci_service_deployment WHERE id=$1").bind(&operation).fetch_one(store.pool()).await.unwrap();
        assert_eq!(row.get::<String,_>("status"),"failed"); assert_eq!(row.get::<String,_>("phase"),"failed");
        assert!(store.run_events(&run,None,100).await.unwrap().iter().any(|e|e.event_type=="ci.host.bootstrap.recovered.v1"));
        server.abort();
    }

    /// The token half of the submit credential, without a database: what does
    /// and does not count as a `Bearer` presentation.
    #[test]
    fn a_bearer_is_recognised_however_it_is_spelled_and_not_otherwise() {
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            if !v.is_empty() {
                h.insert(AUTHORIZATION, v.parse().unwrap());
            }
            h
        };
        assert_eq!(bearer(&headers("Bearer cis_k.s")), Some("cis_k.s"));
        assert_eq!(bearer(&headers("bearer cis_k.s")), Some("cis_k.s"));
        assert_eq!(bearer(&headers("Bearer   cis_k.s  ")), Some("cis_k.s"));

        // A credential for something else must fall through to the HMAC path
        // rather than being taken as a failed submit token.
        assert_eq!(bearer(&headers("Basic dXNlcjpwdw==")), None);
        assert_eq!(bearer(&headers("Bearer")), None);
        assert_eq!(bearer(&headers("Bearer ")), None);
        assert_eq!(bearer(&headers("")), None);
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn healthz_answers_without_a_credential() {
        let app = test_router().await;
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn machine_cache_cleanup_requires_own_repository_bearer() {
        use hmac::Mac;
        let root = tempfile::tempdir().unwrap();
        let app = test_router().await;
        let store = Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(),
            root.path().into(), std::time::Duration::from_secs(30)).await.unwrap();
        let run = crate::vm::new_id();
        let url = format!("https://example.test/{run}.git");
        let repo = store.register_repo(&url, "cleanup", None, None, None).await.unwrap();
        let other = store.register_repo(&format!("{url}-other"), "other", None, None, None).await.unwrap();
        let (_, token) = store.create_repo_token(&repo.id, "cleanup", None).await.unwrap();
        let (_, wrong_token) = store.create_repo_token(&other.id, "other", None).await.unwrap();
        let plan = crate::plan::Plan::build(&crate::workflow::Workflow::parse("cleanup.yml",
            "jobs:\n  build:\n    steps: [{run: 'true'}]\n").unwrap()).unwrap();
        store.create_run(&run, &crate::store::RunRequest {repo_id: Some(repo.id),
            repo_url: url, ..Default::default()}, &plan).await.unwrap();
        let path = format!("/api/runs/{run}/cache/sb-missing/destroy");
        for (credential, expected) in [(None, StatusCode::UNAUTHORIZED),
            (Some("invalid"), StatusCode::UNAUTHORIZED), (Some(wrong_token.as_str()), StatusCode::NOT_FOUND),
            (Some(token.as_str()), StatusCode::CONFLICT)] {
            let mut request = Request::builder().method("POST").uri(&path);
            if let Some(token) = credential { request = request.header("Authorization", format!("Bearer {token}")); }
            let response = app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), expected);
        }
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"0123456789abcdef").unwrap();
        mac.update(path.as_bytes());
        let response = app.oneshot(Request::builder().method("POST").uri(&path)
            .header(trigger::SIGNATURE_HEADER, format!("sha256={}", hex::encode(mac.finalize().into_bytes())))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "read HMACs cannot delete caches");
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn machine_rerun_is_repo_scoped_and_carries_successes() {
        use base64::Engine;
        let root = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("CI_WORKSPACE_DIR", root.path());
            std::env::set_var("CI_NATIVE_RUNNER_SECRET", "test-native-secret");
        }
        let app = test_router().await;
        let store = Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(),
            root.path().join("logs"), std::time::Duration::from_secs(30)).await.unwrap();
        let url = format!("https://example.com/{}.git", crate::vm::new_id());
        let repo = store.register_repo(&url, "retry", Some("ci/test.yml"), None, None).await.unwrap();
        let other = store.register_repo(&format!("{url}-other"), "other", None, None, None).await.unwrap();
        let (token_row, token) = store.create_repo_token(&repo.id, "test", None).await.unwrap();
        let (_, wrong_token) = store.create_repo_token(&other.id, "test", None).await.unwrap();

        let workflow = b"name: retry\non: [submit]\njobs:\n  passed:\n    runs-on: [macos-intel]\n    steps: [{run: 'echo passed'}]\n  failed:\n    runs-on: [windows-x64]\n    steps: [{run: 'echo retry'}]\n";
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut archive = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(workflow.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "ci/test.yml", &workflow[..]).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        let payload = serde_json::json!({
            "repository": {"url": url}, "ref": "refs/heads/test", "after": "a".repeat(40),
            "source": {"format": "tar.gz", "contentBase64": base64::engine::general_purpose::STANDARD.encode(bytes)}
        });
        let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/submit")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(payload.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&body));
        let submitted: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let run = submitted["runs"][0].as_str().unwrap();
        let path = format!("/api/runs/{run}/rerun-failed");
        async fn post(app: Router, path: &str, token: Option<&str>) -> axum::response::Response {
            let mut req = Request::builder().method("POST").uri(path);
            if let Some(token) = token { req = req.header("Authorization", format!("Bearer {token}")); }
            app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
        }
        // Auth refusals must precede the dispatcher, including when the run exists.
        for (credential, expected) in [(None, StatusCode::UNAUTHORIZED),
            (Some("invalid"), StatusCode::UNAUTHORIZED), (Some(wrong_token.as_str()), StatusCode::NOT_FOUND)] {
            assert_eq!(post(app.clone(), &path, credential).await.status(), expected);
        }
        assert_eq!(post(app.clone(), &path, Some(&token)).await.status(), StatusCode::CONFLICT,
            "an active run must not be duplicated");
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"0123456789abcdef").unwrap();
        mac.update(path.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        let response = app.clone().oneshot(Request::builder().method("POST").uri(&path)
            .header(trigger::SIGNATURE_HEADER, signature).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "read signatures must not grant write access");
        assert!(store.reruns_of(run).await.unwrap().is_empty());
        store.set_job_status(&crate::store::job_id(run, "failed"), crate::store::JobStatus::Failure, Some("offline")).await.unwrap();
        store.set_run_status(run, crate::store::RunStatus::Failure, None).await.unwrap();
        assert_eq!(post(app.clone(), &path, Some(&token)).await.status(), StatusCode::CONFLICT,
            "a failed rollup with an active sibling must not be retried");
        assert!(store.reruns_of(run).await.unwrap().is_empty());
        store.set_job_status(&crate::store::job_id(run, "passed"), crate::store::JobStatus::Success, None).await.unwrap();
        let response = post(app.clone(), &path, Some(&token)).await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(status, StatusCode::ACCEPTED, "{}", String::from_utf8_lossy(&body));
        let retried: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let next = retried["runs"][0].as_str().unwrap();
        assert_ne!(next, run);
        let new_run = store.get_run(next).await.unwrap().unwrap();
        assert_eq!(new_run.rerun_of.as_deref(), Some(run));
        assert_eq!(new_run.sha, "a".repeat(40));
        let response = app.clone().oneshot(Request::builder().uri(format!("/api/runs/{run}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let original: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(original["reruns"].as_array().unwrap().len(), 1);
        assert_eq!(original["reruns"][0]["id"], next, "a lost POST response can be reconciled by reading the parent");
        let jobs = store.jobs_of(next).await.unwrap();
        let passed = jobs.iter().find(|job| job.job_key == "passed").unwrap();
        assert_eq!(passed.status, "success");
        assert!(passed.carried_from.is_some());
        assert_eq!(jobs.iter().find(|job| job.job_key == "failed").unwrap().status, "queued");
        store.set_repo_enabled(&repo.id, false).await.unwrap();
        assert_eq!(post(app.clone(), &path, Some(&token)).await.status(), StatusCode::UNAUTHORIZED);
        store.set_repo_enabled(&repo.id, true).await.unwrap();
        store.revoke_repo_token(&token_row.id).await.unwrap();
        assert_eq!(post(app, &path, Some(&token)).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(store.reruns_of(run).await.unwrap().len(), 1);
        store.delete_repo(&repo.id).await.unwrap();
        store.delete_repo(&other.id).await.unwrap();
        unsafe {
            std::env::remove_var("CI_WORKSPACE_DIR");
            std::env::remove_var("CI_NATIVE_RUNNER_SECRET");
        }
    }

    /// The networks page must render before the first refresh lands, because
    /// that is exactly when someone is looking at it — a cold start with a
    /// cloud that has not answered yet.
    ///
    /// Both spellings, because `/runners` is what this page was called and is
    /// in people's history.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn the_networks_page_renders_with_an_empty_pool() {
        for uri in ["/networks", "/runners"] {
            let app = test_router().await;
            let res = app
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            let body = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains("heyvm network create"), "{uri}: {html}");
        }
    }

    /// A cross-site form POST carries the session cookie; without this check it
    /// would also carry the decision.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_repository_post_from_another_origin_is_refused() {
        let app = test_router().await;
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/repos")
                    .header("origin", "https://evil.example.com")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("url=git@github.com:evil/app.git"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// And the page's own form still works. `CI_PUBLIC_URL` defaults to
    /// `http://<listen addr>` in the test config, which is what the browser
    /// would send.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL"]
    async fn a_repository_post_from_this_app_is_allowed() {
        let config = test_config();
        let app = test_router().await;
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/repos")
                    .header("origin", &config.public_url)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("url=&name=&workflow_path="))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Rejected for the empty URL, not for the origin — which is the point.
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("A clone URL is required"), "{html}");
    }

    /// The namespace routes end to end against a real store: the bearer, the
    /// install list, scoping of every id by namespace, admin-only writes, and
    /// where a write sends the browser afterwards.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn namespace_routes_are_gated_installed_and_scoped() {
        const PLUGIN: &str = "plugin-token-for-tests-0123";
        const BASE: &str = "/namespaces/team-a/plugins/ci";
        let mut config = Arc::try_unwrap(test_config()).unwrap();
        config.plugin_api_token = Some(PLUGIN.into());
        let config = Arc::new(config);
        let tenants = Arc::new(crate::tenants::Tenants::fixed(
            crate::tenants::TenantSet {
                enabled: true,
                installed_in: vec!["team-a".into(), "team-b".into()],
                tenant_network: Some("tenants".into()),
                ..Default::default()
            },
            true,
        ));
        let (app, store) = test_router_with(config.clone(), tenants).await;

        let url = format!("https://example.test/{}.git", crate::vm::new_id());
        let a = store.register_repo_in("team-a", &url, "a", None, None, None).await.unwrap();
        let b = store.register_repo_in("team-b", &url, "b", None, None, None).await.unwrap();
        let (b_token, _) = store.create_repo_token(&b.id, "b", None).await.unwrap();
        let plan = crate::plan::Plan::build(
            &crate::workflow::Workflow::parse("wf.yml", "jobs:\n  build:\n    steps: [{run: x}]\n").unwrap(),
        )
        .unwrap();
        let (a_run, b_run) = (crate::vm::new_id(), crate::vm::new_id());
        for (run, repo, ns) in [(&a_run, &a, "team-a"), (&b_run, &b, "team-b")] {
            store
                .create_run(
                    run,
                    &crate::store::RunRequest {
                        repo_id: Some(repo.id.clone()),
                        repo_url: url.clone(),
                        namespace: ns.into(),
                        ..Default::default()
                    },
                    &plan,
                )
                .await
                .unwrap();
        }

        async fn send(app: &Router, method: &str, uri: &str, extra: &[(&str, &str)], body: &str) -> axum::response::Response {
            let mut req = Request::builder().method(method).uri(uri);
            for (k, v) in extra {
                req = req.header(*k, *v);
            }
            if method == "POST" {
                req = req.header("content-type", "application/x-www-form-urlencoded");
            }
            app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap()
        }
        let bearer = format!("Bearer {PLUGIN}");
        let viewer: Vec<(&str, &str)> = vec![("authorization", &bearer), ("x-heyo-base", BASE), ("x-heyo-actor", "user:1")];
        let mut admin = viewer.clone();
        admin.push(("x-heyo-actor-admin", "true"));

        // No bearer: 401 everywhere, installed or not.
        for uri in ["/ns/team-a/", &format!("/ns/team-a/runs/{a_run}"), "/ns/team-c/"] {
            assert_eq!(send(&app, "GET", uri, &[], "").await.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
        // Not installed: 404.
        assert_eq!(send(&app, "GET", "/ns/team-c/", &viewer, "").await.status(), StatusCode::NOT_FOUND);

        // Its own run renders, with links under the base.
        let res = send(&app, "GET", &format!("/ns/team-a/runs/{a_run}"), &viewer, "").await;
        assert_eq!(res.status(), StatusCode::OK);
        let html = String::from_utf8(to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec()).unwrap();
        assert!(html.contains(&format!("{BASE}/ui/runs/{a_run}/jobs/build")), "{html}");

        // Another namespace's ids are 404 on every route.
        for uri in [
            format!("/ns/team-a/runs/{b_run}"),
            format!("/ns/team-a/runs/{b_run}/jobs/build"),
            format!("/ns/team-a/api/runs/{b_run}"),
            format!("/ns/team-a/api/runs/{b_run}/logs"),
            format!("/ns/team-a/api/stream/{b_run}/build?token={}", stream::mint(&config, &b_run, "build")),
        ] {
            assert_eq!(send(&app, "GET", &uri, &viewer, "").await.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        for uri in [
            format!("/ns/team-a/repos/{}/tokens/{}/revoke", b.id, b_token.id),
            format!("/ns/team-a/repos/{}/tokens", b.id),
            format!("/ns/team-a/repos/{}/delete", b.id),
            format!("/ns/team-a/runs/{b_run}/cancel"),
        ] {
            assert_eq!(send(&app, "POST", &uri, &admin, "").await.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        // team-b's token under team-a's repository id is not revoked either.
        let res = send(&app, "POST", &format!("/ns/team-a/repos/{}/tokens/{}/revoke", a.id, b_token.id), &admin, "").await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert!(store.repo_tokens(&b.id).await.unwrap()[0].is_active());

        // The API lists only this namespace.
        let res = send(&app, "GET", "/ns/team-a/api/runs", &viewer, "").await;
        let body: serde_json::Value = serde_json::from_slice(&to_bytes(res.into_body(), 1 << 22).await.unwrap()).unwrap();
        let ids: Vec<&str> = body["runs"].as_array().unwrap().iter().filter_map(|r| r["id"].as_str()).collect();
        assert!(ids.contains(&a_run.as_str()) && !ids.contains(&b_run.as_str()), "{body}");

        // Writes need the admin header, and land under the base.
        let form = format!("url={}&name=x", urlencode_form(&format!("{url}-2")));
        assert_eq!(send(&app, "POST", "/ns/team-a/repos", &viewer, &form).await.status(), StatusCode::FORBIDDEN);
        let res = send(&app, "POST", "/ns/team-a/repos", &admin, &form).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers()["location"].to_str().unwrap().to_string();
        assert!(location.starts_with(&format!("{BASE}/ui/repos")), "{location}");
        let registered = store.repos_in("team-a").await.unwrap();
        assert!(registered.iter().any(|r| r.name == "x"));
        assert!(store.repos().await.unwrap().iter().all(|r| r.name != "x"), "not a fleet registration");

        // A bogus base falls back to the native paths.
        let mut bogus = admin.clone();
        bogus[1] = ("x-heyo-base", "/namespaces/team-b/plugins/ci");
        let res = send(&app, "GET", "/ns/team-a/", &bogus, "").await;
        let html = String::from_utf8(to_bytes(res.into_body(), 1 << 22).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("href=\"/ns/team-a/repos\"") && !html.contains("/namespaces/team-b"), "{html}");

        // A namespace token submitting while its namespace is not installed is
        // refused before anything is unpacked.
        let c = store.register_repo_in("team-c", &url, "c", None, None, None).await.unwrap();
        let (_, c_token) = store.create_repo_token(&c.id, "c", None).await.unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/submit")
                    .header("authorization", format!("Bearer {c_token}"))
                    .body(Body::from(r#"{"source":{"format":"git-patch","contentBase64":""}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let text = String::from_utf8(to_bytes(res.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(text.contains("has not installed ci"), "{text}");

        // On a tenant-only instance a fleet registration's token is refused,
        // and an installed namespace's is not refused for that reason.
        let fleet = store.register_repo(&format!("{url}-fleet"), "fleet", None, None, None).await.unwrap();
        let (_, fleet_token) = store.create_repo_token(&fleet.id, "f", None).await.unwrap();
        let (_, a_token) = store.create_repo_token(&a.id, "a", None).await.unwrap();
        let mut only = Arc::try_unwrap(test_config()).unwrap();
        only.plugin_api_token = Some(PLUGIN.into());
        only.tenant_only = true;
        let only_tenants = Arc::new(crate::tenants::Tenants::fixed(
            crate::tenants::TenantSet {
                enabled: true,
                installed_in: vec!["team-a".into()],
                tenant_network: Some("tenants".into()),
                ..Default::default()
            },
            true,
        ));
        let (only_app, _) = test_router_with(Arc::new(only), only_tenants).await;
        for (token, refused) in [(&fleet_token, true), (&a_token, false)] {
            let res = only_app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/submit")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::from(r#"{"source":{"format":"git-patch","contentBase64":""}}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = res.status();
            let text = String::from_utf8(to_bytes(res.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
            assert_eq!(text.contains("builds only for namespaces"), refused, "{status} {text}");
            if refused {
                assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
            }
        }
        store.delete_repo(&fleet.id).await.unwrap();

        for r in store.repos_in("team-a").await.unwrap() {
            store.delete_repo(&r.id).await.unwrap();
        }
        store.delete_repo(&b.id).await.unwrap();
        store.delete_repo(&c.id).await.unwrap();
    }

    fn urlencode_form(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    /// Without CI_PLUGIN_API_TOKEN the namespace routes do not exist at all.
    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL and CI_NATS_URL"]
    async fn namespace_routes_are_absent_without_the_plugin_token() {
        let app = test_router().await;
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/ns/team-a/")
                    .header("authorization", "Bearer anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
