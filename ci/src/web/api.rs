//! The machine-readable read API: "did my run work, and if not, why".
//!
//! ## Why this exists
//!
//! Submitting was answerable and reading was not. `POST /api/submit` hands back
//! run ids, and until this module there was nothing a program could do with
//! one: `/runs/{id}` renders HTML behind app-lb's browser gate, and
//! `/api/stream/{run}/{job}` needs a token minted by the page it is opened
//! from. A client that submitted a build was therefore blind to its outcome,
//! and silence is the worst possible answer — it reads as failure, and a slow
//! run is indistinguishable from a dead one. That is not a hypothetical: a run
//! that took nineteen minutes and published normally was reported to a user as
//! a failure, because nothing here could say otherwise.
//!
//! So these routes exist to answer the CI-owned questions, and are shaped
//! around them rather than around the tables:
//!
//! - `GET /api/runs/{run_id}` — is it finished, and did it work?
//! - `GET /api/runs/{run_id}/logs` — it did not work; what was printed?
//! - `GET /api/runs/{run_id}/deployments` — what happened to service deploys?
//!
//! ## The credential
//!
//! A repository submit token, the same one `POST /api/submit` takes and the
//! same one `git submit` already has in `git config ci.token`. Nothing new to
//! mint, and nothing new to explain: whoever may start a run may read it.
//!
//! **Scoped to the run's repository**, checked on every request. A token is
//! issued per repository precisely so it cannot act on another's builds, and a
//! read is an act — logs carry command output, environment echoes and failure
//! messages from somebody else's code. `authenticate_repo_token` says which
//! repository the token is for; the run says which repository it belongs to;
//! they must agree.
//!
//! The installation-wide `CI_WEBHOOK_SECRET` also works, signed over the
//! request path the way a submit is signed over its body. It is deliberately
//! never accepted as a plain bearer: the submit path never puts that value in a
//! header, and a read route that did would be the easiest place in the system
//! to leak it. Whoever holds it may already submit as anything, so no scope is
//! checked for it — which is the same weakness the per-repository token exists
//! to fix, stated here rather than discovered later.
//!
//! ## These routes must be in `public_paths`
//!
//! app-lb's gate splits on `Accept: text/html` and admits browsers only, so a
//! machine route outside `public_paths` answers `401` to every client whatever
//! credential it carries — which is the trap [`crate::web`] documents at the
//! top of the module. `/api/runs/` is listed in `ci/deploy/ci.json` beside
//! `/api/submit` and `/api/stream/` for that reason, and carries its own
//! credential because being outside the gate has never meant being open.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::Deserialize;

use crate::store::{JobRow, JobStatus, Repo, Run, RunStatus, ServiceDeploymentRow, StepRow};
use crate::trigger;

use super::AppState;

/// How much of each step's log is returned when the caller does not say.
///
/// A cap rather than the whole thing, because the common caller is a language
/// model reading a tool result into a bounded context, and a 40 MB `cargo
/// build` log helps nobody. The *tail* rather than the head: a failure is at
/// the end.
const DEFAULT_TAIL_BYTES: usize = 16_384;

/// The most any single step will return, however large a `tail` is asked for.
/// Bounds one request's memory; a caller wanting more should read the stream.
const MAX_TAIL_BYTES: usize = 1_048_576;

/// The step index the executor records a VM's own console at. Mirrors
/// `VM_LOG_STEP_IDX` in [`super`]; checkout is `-1`. Both are real steps with
/// real logs, and both are returned — a job that fails before its first
/// declared step has its explanation in one of them and nowhere else.
const VM_LOG_STEP_IDX: i32 = -2;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/runs/{run_id}", get(run_status))
        .route("/api/runs/{run_id}/rerun-failed", post(rerun_failed))
        .route("/api/runs/{run_id}/cache/{sandbox_id}/destroy", post(destroy_run_cache))
        .route("/api/runs/{run_id}/bootstrap/{operation_id}/recover", post(recover_bootstrap))
        .route("/api/runs/{run_id}/maintenance/{operation_id}/recover", post(recover_maintenance))
        .route("/api/runs/{run_id}/logs", get(run_logs))
        .route("/api/runs/{run_id}/events", get(run_events))
        .route("/api/runs/{run_id}/deployments", get(run_deployments))
        .route("/api/runs/{run_id}/release", get(run_release))
}

/// A submit credential can retire its own run's idle build cache, not a host's
/// entire pool. Read signatures never authorize this mutation. Last-use and
/// idle status are rechecked atomically when the durable eviction is admitted.
async fn destroy_run_cache(
    State(state): State<AppState>,
    Path((run_id, sandbox_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    if bearer(&headers).is_none() {
        return error(StatusCode::UNAUTHORIZED, "a repository submit bearer token is required");
    }
    let reader = match authenticate(&state, &headers, "").await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await { return response; }
    let _effect = match state.dispatcher.executor.effect_permit().await {
        Ok(permit) => permit,
        Err(e) => return error(StatusCode::SERVICE_UNAVAILABLE, &e),
    };
    match state.dispatcher.destroy_run_cache(&sandbox_id, Some(&run_id)).await {
        Ok(message) => {
            tracing::info!(run = %run_id, sandbox = %sandbox_id, "repository caller reclaimed its idle cache");
            axum::Json(serde_json::json!({"sandbox_id":sandbox_id,"status":"destroyed","message":message})).into_response()
        }
        Err(crate::dispatch::DispatchError::VmNotSweepable(_)) =>
            error(StatusCode::CONFLICT, "no idle cache last used by this run on a served runner"),
        Err(e) => {
            tracing::error!(run = %run_id, sandbox = %sandbox_id, "cache cleanup not confirmed: {e}");
            error(StatusCode::SERVICE_UNAVAILABLE, "cache cleanup not confirmed; durable eviction remains available for reconciliation")
        }
    }
}

/// A submit credential can retry its own repository without a browser session.
/// Require a bearer: read-path HMAC signatures must never authorize a write.
async fn rerun_failed(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    if bearer(&headers).is_none() {
        return error(StatusCode::UNAUTHORIZED, "a repository submit bearer token is required");
    }
    let reader = match authenticate(&state, &headers, "").await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await {
        return response;
    }
    // Reuse the existing rerun path: original source, successful-job carryover,
    // repository policy and unresolved-deployment checks all remain in force.
    match state.dispatcher.rerun(&run_id, true, None).await {
        Ok(submitted) => (StatusCode::ACCEPTED, axum::Json(serde_json::json!({
            "runs": submitted.run_ids,
            "url": format!("{}/", state.config.public_url),
            "warnings": submitted.warnings,
        }))).into_response(),
        Err(crate::dispatch::DispatchError::Workflow(message)) =>
            error(StatusCode::CONFLICT, &message),
        Err(crate::dispatch::DispatchError::ControllerUnavailable(message)) =>
            error(StatusCode::SERVICE_UNAVAILABLE, &message),
        Err(e) => {
            tracing::error!(run = %run_id, "could not rerun failed jobs: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "could not rerun failed jobs")
        }
    }
}

async fn recover_bootstrap(
    State(state): State<AppState>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    if bearer(&headers).is_none() {
        return error(StatusCode::UNAUTHORIZED, "a repository submit bearer token is required");
    }
    let reader = match authenticate(&state, &headers, "").await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await {
        return response;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(120),
        crate::host_heyvm_bootstrap_coordinator::recover(&state.dispatcher, &run_id, &operation_id)).await {
        Ok(Ok(result)) => axum::Json(result).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(run=%run_id, operation=%operation_id, error=%e, "bootstrap recovery refused; fence retained");
            error(StatusCode::CONFLICT, "bootstrap recovery verification failed; fence retained; inspect controller logs")
        }
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "bootstrap recovery timed out; inspect recovery events before retrying"),
    }
}

async fn recover_maintenance(
    State(state): State<AppState>,
    Path((run_id, operation_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    if bearer(&headers).is_none() {
        return error(StatusCode::UNAUTHORIZED, "a repository submit bearer token is required");
    }
    let reader = match authenticate(&state, &headers, "").await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await { return response; }
    match tokio::time::timeout(std::time::Duration::from_secs(90),
        crate::host_maintenance::recover(&state.dispatcher, &run_id, &operation_id)).await {
        Ok(Ok(result)) => axum::Json(result).into_response(),
        Ok(Err(e)) => {
            tracing::warn!(run=%run_id, operation=%operation_id, error=%e, "maintenance recovery refused; fence retained");
            error(StatusCode::CONFLICT, "maintenance recovery refused; inspect the persisted operation and controller logs")
        }
        Err(_) => error(StatusCode::GATEWAY_TIMEOUT, "maintenance recovery timed out; inspect recovery events before retrying"),
    }
}

const DEFAULT_EVENT_LIMIT: i64 = 50;
const MAX_EVENT_LIMIT: i64 = 100;

#[derive(Debug, Deserialize)]
struct EventQuery {
    before: Option<i64>,
    limit: Option<i64>,
}

async fn run_events(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Query(q): Query<EventQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let path = format!("/api/runs/{run_id}/events");
    let reader = match authenticate(&state, &headers, &path).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    if let Err(r) = readable_run(&state, &reader, &run_id).await {
        return r;
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_EVENT_LIMIT)
        .clamp(1, MAX_EVENT_LIMIT);
    match state.store.run_events(&run_id, q.before, limit + 1).await {
        Ok(mut events) => {
            let has_more = events.len() as i64 > limit;
            if has_more {
                events.pop();
            }
            let next_before = has_more
                .then(|| events.last().map(|e| e.revision))
                .flatten();
            axum::Json(serde_json::json!({
                "events": events.iter().map(event_json).collect::<Vec<_>>(),
                "next_before": next_before,
                "limit": limit
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!("could not load events for run {run_id}: {e}");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load run events",
            )
        }
    }
}

fn event_json(event: &crate::store::RunEvent) -> serde_json::Value {
    // Replay must return the same envelope as NATS, including repository,
    // commit and artifact identity, rather than a lossy display projection.
    let mut payload = event.payload.clone();
    payload["publication"] = serde_json::json!({
        "state": if event.published_at.is_some() { "published" } else { "pending" },
        "published_at": event.published_at.map(|t| t.to_rfc3339()), "attempts": event.attempts,
        "last_error": event.last_error
    });
    payload
}

async fn run_deployments(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let path = format!("/api/runs/{run_id}/deployments");
    let reader = match authenticate(&state, &headers, &path).await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await {
        return response;
    }
    match state.store.service_deployments_of(&run_id).await {
        Ok(deployments) => axum::Json(serde_json::json!({
            "run_id": run_id,
            "deployments": deployments.iter().map(deployment_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("could not load deployments for run {run_id}: {e}");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load run deployments",
            )
        }
    }
}

fn deployment_json(deployment: &ServiceDeploymentRow) -> serde_json::Value {
    serde_json::json!({
        "id": deployment.id,
        "step_id": deployment.step_id,
        "run_id": deployment.run_id,
        "job_id": deployment.job_id,
        "service_id": deployment.service_id,
        "status": deployment.status,
        "phase": deployment.phase,
        "message": deployment.message,
        "error": deployment.error,
        "sha": deployment.sha,
        "git_ref": deployment.git_ref,
        "created_at": deployment.created_at.to_rfc3339(),
        "updated_at": deployment.updated_at.to_rfc3339(),
    })
}

async fn run_release(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let path = format!("/api/runs/{run_id}/release");
    let reader = match authenticate(&state, &headers, &path).await {
        Ok(reader) => reader,
        Err(response) => return response,
    };
    if let Err(response) = readable_run(&state, &reader, &run_id).await {
        return response;
    }
    match crate::release::get(&state.store, &run_id).await {
        Ok(release) => axum::Json(serde_json::json!({
            "run_id": run_id,
            "release": release,
        }))
        .into_response(),
        Err(e) => {
            tracing::error!("could not load release for run {run_id}: {e}");
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load run release",
            )
        }
    }
}

// -- authentication ----------------------------------------------------------

/// What proved the caller may read this run.
enum Reader {
    /// A per-repository token. Carries the registration it is scoped to, which
    /// is then checked against the run.
    Repo(Box<Repo>),
    /// The installation-wide secret, HMAC'd over the request path. Unscoped, by
    /// the same reasoning `Credential::Shared` is unscoped for a submit.
    Shared,
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// Decide whether a read may proceed, before anything is loaded.
///
/// One refusal message for malformed, unknown, revoked and disabled alike, for
/// the reason [`crate::store::Store::authenticate_repo_token`] gives: saying
/// which one it was tells an unauthenticated caller how far they got.
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<Reader, axum::response::Response> {
    if let Some(token) = bearer(headers) {
        return match state.store.authenticate_repo_token(token).await {
            Ok(Some(repo)) => Ok(Reader::Repo(Box::new(repo))),
            Ok(None) => {
                tracing::debug!("rejected a read token that resolves to no repository");
                Err(error(
                    StatusCode::UNAUTHORIZED,
                    &format!(
                        "that token is not valid for any registered repository. It is the \
                         same submit token this server takes on /api/submit — register the \
                         repository at {}/repos, then `git config ci.token <token>`.",
                        state.config.public_url
                    ),
                ))
            }
            // Ours, not theirs. A database failure that reads as a rejected
            // credential sends somebody to rotate a token that was fine.
            Err(e) => {
                tracing::error!("could not check a read token: {e}");
                Err(error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not check that token; the database is unreachable",
                ))
            }
        };
    }

    // The path is what is signed. A GET has no body to sign, and signing the
    // path still binds the signature to the run being asked about, so one
    // capture cannot be replayed against another run.
    let signature = headers
        .get(trigger::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok());
    match trigger::verify_signature(&state.config.webhook_secret, path.as_bytes(), signature) {
        Ok(()) => Ok(Reader::Shared),
        Err(e) => {
            // Debug, not warn: this endpoint is on the open internet and gets
            // scanned, and a warn per probe is how a log becomes unreadable.
            tracing::debug!("rejected an unsigned read: {e}");
            Err(error(
                e.status(),
                &format!(
                    "{e}. Present a repository submit token as `Authorization: Bearer …`, \
                     or sign the request path with CI_WEBHOOK_SECRET as `{}: sha256=…`.",
                    trigger::SIGNATURE_HEADER
                ),
            ))
        }
    }
}

/// Load the run, and refuse one the reader's token does not cover.
///
/// A run belonging to another repository answers `404`, not `403`: the caller
/// holds a credential for a different repository, so whether this id exists is
/// not something they are entitled to learn. Same answer for an id that was
/// never real, which is the point.
async fn readable_run(
    state: &AppState,
    reader: &Reader,
    run_id: &str,
) -> Result<Run, axum::response::Response> {
    let run = match state.store.get_run(run_id).await {
        Ok(Some(run)) => run,
        Ok(None) => return Err(error(StatusCode::NOT_FOUND, &format!("no run {run_id}"))),
        Err(e) => {
            tracing::error!("could not load run {run_id}: {e}");
            return Err(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load that run; the database is unreachable",
            ));
        }
    };

    let allowed = match reader {
        Reader::Shared => true,
        // `repo_id` first, and the URL only as a fallback: the id is what the
        // submit authenticated as, while the URL is payload the submitter chose.
        // A pre-registration run has no `repo_id` at all, and comparing URLs is
        // the only thing left that means anything for those.
        Reader::Repo(repo) => match &run.repo_id {
            Some(id) => id == &repo.id,
            None => crate::repos::same_repo(&repo.url, &run.repo_url),
        },
    };

    if !allowed {
        tracing::debug!("refused run {run_id} to a token for another repository");
        return Err(error(StatusCode::NOT_FOUND, &format!("no run {run_id}")));
    }
    Ok(run)
}

// -- GET /api/runs/{run_id} --------------------------------------------------

/// The whole answer to "did it work", in one request.
///
/// Jobs and their steps are included rather than left to a second call: a
/// failed run is nearly always followed by "which job", and a client that has
/// to ask again has to know to ask. Step *logs* are not — those are the other
/// route, because they are unbounded and this one should stay small enough to
/// poll.
async fn run_status(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let path = format!("/api/runs/{run_id}");
    let reader = match authenticate(&state, &headers, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let run = match readable_run(&state, &reader, &run_id).await {
        Ok(r) => r,
        Err(response) => return response,
    };

    let jobs = state.store.jobs_of(&run_id).await.unwrap_or_default();
    let mut job_views = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let steps = state.store.steps_of(&job.id).await.unwrap_or_default();
        job_views.push(job_json(job, &steps));
    }
    let artifacts = state.store.artifacts_of(&run_id).await.unwrap_or_default();
    let reports: Vec<serde_json::Value> = match sqlx::query_scalar("SELECT jsonb_build_object('job_id',job_id,'attempt',attempt,'sandbox_id',sandbox_id,'s3_uri',s3_uri,'uploaded_at',uploaded_at,'error',last_error) FROM ci_debug_report WHERE run_id=$1 ORDER BY job_key,attempt")
        .bind(&run_id).fetch_all(state.store.pool()).await {
        Ok(reports) => reports,
        Err(e) => {
            tracing::error!("could not load debug reports for {run_id}: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "could not load debug reports");
        }
    };
    let reruns = match state.store.reruns_of(&run_id).await {
        Ok(reruns) => reruns,
        Err(e) => {
            tracing::error!("could not load reruns for {run_id}: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "could not load reruns");
        }
    };

    let validation_ids = match crate::submission::validations(&state.store, &run_id).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!("could not load submission validations for {run_id}: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "could not load submission validations");
        }
    };
    let mut validations = Vec::new();
    for id in validation_ids {
        match readable_run(&state, &reader, &id).await {
            Ok(validation) => validations.push(run_json(&state, &validation)),
            Err(response) => return response,
        }
    }
    axum::Json(serde_json::json!({
        "run": run_json(&state, &run),
        "validations": validations,
        "reruns": reruns.iter().map(|run| run_json(&state, run)).collect::<Vec<_>>(),
        "jobs": job_views,
        "debug_reports": reports,
        "artifacts": artifacts
            .iter()
            .map(|a| serde_json::json!({
                "name": a.name,
                "sink": a.sink,
                "digest": a.digest,
                "size_bytes": a.size_bytes,
                "uri": a.uri,
                "public_url": a.public_url,
            }))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

pub(super) fn run_json(state: &AppState, run: &Run) -> serde_json::Value {
    let status = RunStatus::parse(&run.status);
    serde_json::json!({
        "id": run.id,
        "status": run.status,
        // The field a poller actually branches on. Deriving "is it over" from a
        // status string is where a caller gets it wrong — `queued` and
        // `running` are both "not yet", and a status this build has never heard
        // of must not read as finished.
        "finished": status.is_some_and(|s| s.is_terminal()),
        "error": run.error,
        "workflow": {
            "id": run.workflow_id,
            "path": run.workflow_path,
            "name": run.workflow_name,
        },
        "repo": {
            "id": run.repo_id,
            "name": run.repo_name,
            "url": run.repo_url,
        },
        "ref": run.git_ref,
        "sha": run.sha,
        "actor_email": run.actor_email,
        "rerun_of": run.rerun_of,
        "created_at": run.created_at.to_rfc3339(),
        "started_at": run.started_at.map(|t| t.to_rfc3339()),
        "finished_at": run.finished_at.map(|t| t.to_rfc3339()),
        // So a person reading a tool's output can open the thing being
        // described, rather than reassembling the URL from a hostname they
        // would have to already know.
        "url": format!("{}/runs/{}", state.config.public_url.trim_end_matches('/'), run.id),
    })
}

pub(super) fn job_json(job: &JobRow, steps: &[StepRow]) -> serde_json::Value {
    let status = JobStatus::parse(&job.status);
    serde_json::json!({
        "key": job.job_key,
        "display": job.display,
        "status": job.status,
        "finished": status.is_some_and(|s| s.is_terminal()),
        "attempt": job.attempt,
        "network": job.network,
        "sandbox_id": job.sandbox_id,
        "error": job.error,
        "carried_from": job.carried_from,
        "queued_at": job.queued_at.map(|t| t.to_rfc3339()),
        "started_at": job.started_at.map(|t| t.to_rfc3339()),
        "finished_at": job.finished_at.map(|t| t.to_rfc3339()),
        // The number that separates "the build is slow" from "nothing ever
        // claimed this job", which are the two diagnoses a stuck run has and
        // which look identical from the outside.
        "queue_wait_secs": job.queue_wait().map(|d| d.as_secs()),
        "steps": steps.iter().map(step_json).collect::<Vec<_>>(),
    })
}

fn step_json(step: &StepRow) -> serde_json::Value {
    serde_json::json!({
        "idx": step.idx,
        "name": step_name(step),
        "uses": step.uses,
        "status": step.status,
        "exit_code": step.exit_code,
        "error": step.error,
        // Whether there is anything to fetch from the logs route, without
        // fetching it.
        "log_bytes": step.log_bytes,
        "started_at": step.started_at.map(|t| t.to_rfc3339()),
        "finished_at": step.finished_at.map(|t| t.to_rfc3339()),
    })
}

/// The two negative indices are real steps with empty-ish names, and a caller
/// reading a list of steps deserves to be told which is which rather than
/// having to know the convention.
fn step_name(step: &StepRow) -> String {
    match step.idx {
        VM_LOG_STEP_IDX if step.name.trim().is_empty() => "VM console".to_string(),
        -1 if step.name.trim().is_empty() => "checkout".to_string(),
        _ => step.name.clone(),
    }
}

// -- GET /api/runs/{run_id}/logs ---------------------------------------------

#[derive(Debug, Deserialize)]
pub(super) struct LogQuery {
    /// One job's logs rather than every job's. The `job_key`, as the status
    /// response spells it.
    job: Option<String>,
    /// Bytes of each step's log to return, from the end. Capped at
    /// [`MAX_TAIL_BYTES`].
    tail: Option<usize>,
    /// Only steps that did not succeed. The default is every step, because
    /// "why did this fail" is sometimes answered by what the step before it
    /// printed.
    failed_only: Option<bool>,
}

/// What was printed.
///
/// Separate from the status route because it is unbounded where that one is
/// small: status is for polling, this is for the one time a run failed. Logs
/// are read from the same shared storage as the dashboard, so a run whose logs
/// have been swept returns the rows with `log: null` and zero byte counts,
/// rather than looking as though the steps never ran.
async fn run_logs(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Query(q): Query<LogQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let path = format!("/api/runs/{run_id}/logs");
    let reader = match authenticate(&state, &headers, &path).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    let run = match readable_run(&state, &reader, &run_id).await {
        Ok(r) => r,
        Err(response) => return response,
    };
    logs_of(&state, &run, &q).await
}

/// The logs answer for a run the caller may read, shared with the namespace
/// API, which decides readability by namespace rather than by token.
pub(super) async fn logs_of(state: &AppState, run: &Run, q: &LogQuery) -> axum::response::Response {
    let run_id = run.id.as_str();
    let tail = q.tail.unwrap_or(DEFAULT_TAIL_BYTES).min(MAX_TAIL_BYTES);
    let failed_only = q.failed_only.unwrap_or(false);

    let mut jobs = match state.store.jobs_of(&run_id).await {
        Ok(jobs) => jobs,
        Err(e) => {
            tracing::error!("could not load jobs for shared logs: {e}");
            return error(StatusCode::SERVICE_UNAVAILABLE, "step logs are temporarily unavailable");
        }
    };
    if let Some(want) = q.job.as_deref() {
        jobs.retain(|j| j.job_key == want);
        if jobs.is_empty() {
            return error(
                StatusCode::NOT_FOUND,
                &format!("run {run_id} has no job {want}"),
            );
        }
    }

    let mut out = Vec::with_capacity(jobs.len());
    for job in &jobs {
        let steps = match state.store.steps_of(&job.id).await {
            Ok(steps) => steps,
            Err(e) => {
                tracing::error!("could not load steps for shared logs: {e}");
                return error(StatusCode::SERVICE_UNAVAILABLE, "step logs are temporarily unavailable");
            }
        };
        let mut step_logs = Vec::new();
        for step in &steps {
            if failed_only && matches!(step.status.as_str(), "success" | "skipped" | "pending") {
                continue;
            }
            let full = match state.store.read_log(step).await {
                Ok(log) => log,
                Err(e) => {
                    tracing::error!("could not read shared step logs: {e}");
                    return error(StatusCode::SERVICE_UNAVAILABLE, "step logs are temporarily unavailable");
                }
            };
            let (text, truncated) = match &full {
                Some(t) => tail_of(t, tail),
                None => (None, false),
            };
            step_logs.push(serde_json::json!({
                "idx": step.idx,
                "name": step_name(step),
                "status": step.status,
                "exit_code": step.exit_code,
                "error": step.error,
                "log_bytes": step.log_bytes,
                // Stated, because silently truncated output reads as complete
                // output — and a caller that sees the tail of a build log with
                // no marker will conclude the build started there.
                "truncated": truncated,
                "log": text,
            }));
        }
        out.push(serde_json::json!({
            "key": job.job_key,
            "display": job.display,
            "status": job.status,
            "error": job.error,
            "steps": step_logs,
        }));
    }

    axum::Json(serde_json::json!({
        "run_id": run.id,
        "status": run.status,
        "finished": RunStatus::parse(&run.status).is_some_and(|s| s.is_terminal()),
        "tail_bytes": tail,
        "jobs": out,
    }))
    .into_response()
}

/// The last `max` bytes of `text`, on a character boundary.
///
/// Cutting a UTF-8 string by byte offset can land inside a multi-byte
/// character, so the cut is moved forward to the next boundary rather than
/// producing a string that will not serialize.
fn tail_of(text: &str, max: usize) -> (Option<String>, bool) {
    if text.len() <= max {
        return (Some(text.to_string()), false);
    }
    let mut cut = text.len() - max;
    while cut < text.len() && !text.is_char_boundary(cut) {
        cut += 1;
    }
    (Some(text[cut..].to_string()), true)
}

fn error(status: StatusCode, message: &str) -> axum::response::Response {
    (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_api_projects_identity_revision_and_truthful_state() {
        let now = chrono::Utc::now();
        let deployment = ServiceDeploymentRow {
            id: "operation-1".into(),
            step_id: "run.deploy.0".into(),
            run_id: "run".into(),
            job_id: "run.deploy".into(),
            service_id: "api".into(),
            status: "submission_unknown".into(),
            phase: Some("submitting".into()),
            message: Some("the response was lost; do not resubmit".into()),
            error: None,
            sha: "0123456789abcdef".into(),
            git_ref: "refs/heads/release".into(),
            created_at: now,
            updated_at: now,
        };
        let json = deployment_json(&deployment);
        assert_eq!(json["id"], "operation-1");
        assert_eq!(json["service_id"], "api");
        assert_eq!(json["status"], "submission_unknown");
        assert_eq!(json["phase"], "submitting");
        assert_eq!(json["sha"], "0123456789abcdef");
        assert_eq!(json["git_ref"], "refs/heads/release");
        assert_eq!(json["message"], "the response was lost; do not resubmit");
        assert!(json["created_at"].as_str().is_some() && json["updated_at"].as_str().is_some());
    }

    #[test]
    fn history_preserves_the_bus_envelope_and_adds_publication_state() {
        let envelope = serde_json::json!({
            "version": 1, "type": "ci.artifact.published.v1", "repo_id": "repo-a",
            "run_id": "run-a", "sha": "112233", "git_ref": "refs/heads/release",
            "artifact": { "digest": "ab".repeat(32), "size_bytes": 37 }
        });
        let mut event = crate::store::RunEvent {
            id: uuid::Uuid::new_v4(),
            revision: 42,
            event_type: "ci.artifact.published.v1".into(),
            payload: envelope.clone(),
            job_id: Some("run-a.build".into()),
            job_key: Some("build".into()),
            step_id: Some("run-a.build.0".into()),
            status: "published".into(),
            error: None,
            transitioned_at: chrono::Utc::now(),
            published_at: None,
            attempts: 2,
            last_error: Some("NATS unavailable".into()),
        };
        let mut json = event_json(&event);
        assert_eq!(json["publication"]["state"], "pending");
        assert_eq!(json["publication"]["attempts"], 2);
        json.as_object_mut().unwrap().remove("publication");
        assert_eq!(json, envelope);
        event.published_at = Some(chrono::Utc::now());
        event.last_error = None;
        assert_eq!(event_json(&event)["publication"]["state"], "published");
        assert_eq!(
            event.payload, envelope,
            "rendering must not mutate the saved fact"
        );
    }

    #[test]
    fn a_short_log_is_returned_whole_and_not_marked_truncated() {
        let (text, truncated) = tail_of("hello", 16);
        assert_eq!(text.as_deref(), Some("hello"));
        assert!(!truncated);
    }

    /// The tail, not the head: a failure is at the end of a build log.
    #[test]
    fn a_long_log_keeps_its_end() {
        let (text, truncated) = tail_of("aaaaBOOM", 4);
        assert_eq!(text.as_deref(), Some("BOOM"));
        assert!(truncated);
    }

    /// Cutting by byte offset can land inside a multi-byte character; the cut
    /// moves forward rather than producing a string that will not serialize.
    #[test]
    fn a_cut_inside_a_character_moves_to_the_next_boundary() {
        // 'é' is two bytes, so a cut at 1 from the end is mid-character.
        let (text, truncated) = tail_of("xé", 2);
        assert!(truncated);
        let text = text.expect("some text");
        assert!(text.is_char_boundary(0) && text.is_char_boundary(text.len()));
        assert_eq!(text, "é");
    }

    /// The negative indices are real steps whose names are empty; a caller
    /// reading the list should not have to know the convention.
    #[test]
    fn the_executors_own_steps_are_named() {
        let step = |idx: i32, name: &str| StepRow {
            id: "s".into(),
            job_id: "j".into(),
            idx,
            name: name.into(),
            uses: None,
            status: "success".into(),
            exit_code: Some(0),
            operation_id: None,
            log_path: None,
            log_bytes: 0,
            error: None,
            started_at: None,
            finished_at: None,
        };
        assert_eq!(step_name(&step(-2, "")), "VM console");
        assert_eq!(step_name(&step(-1, "")), "checkout");
        assert_eq!(step_name(&step(0, "build")), "build");
        // A name that was actually recorded always wins over the convention.
        assert_eq!(step_name(&step(-1, "clone")), "clone");
    }
}
