//! Turning queued jobs into steps that ran.
//!
//! Two halves that never call each other directly:
//!
//! - **The scheduler** ([`Dispatcher::advance_run`]) decides which jobs are
//!   ready and publishes them. It runs after a run is created and again after
//!   every job finishes.
//! - **The executor** ([`Dispatcher::run_job`]) pulls one job, gets a VM, runs
//!   its steps, and records what happened.
//!
//! They communicate through Postgres and JetStream rather than in memory, which
//! is what lets the executor for a runner live in a different process from the
//! scheduler — and what makes a crash between the two recoverable.
//!
//! ## Everything here is written to be run twice
//!
//! A JetStream redelivery is normal: a runner reboots, a dispatcher is killed
//! mid-build, an ack is lost. So every step of the path is idempotent.
//!
//! - Job and step row ids are *derived* from the run and job key, so a second
//!   delivery addresses the same rows rather than making new ones.
//! - [`crate::store::Store::start_job`] refuses a job that already reached a
//!   terminal state, which drops a redelivery of work that finished just before
//!   its ack was lost.
//! - A step's `operationId` is its row id, and the daemon's exec-operation route
//!   is idempotent on that id — so re-running a step that is still in flight
//!   reattaches to it instead of starting the build a second time.

use crate::bus::{Bus, JobMessage, Route};
use crate::config::Config;
use crate::expr::Context;
use crate::plan::JobPlan;
use crate::pool::Pool;
use crate::runners::Runners;
use crate::store::{JobClaim, JobStatus, RunStatus, StepStatus, Store, step_id};
use crate::vm::{ExecOutput, SizeCheck, Vm, VmError, Vms, sandbox_name};
use crate::workflow::{Fallback, Step};
use async_nats::jetstream::AckKind;
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::Row;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long to wait for a VM to boot before giving up on a job.
const BOOT_TIMEOUT: Duration = Duration::from_secs(300);

/// How often a running step checks whether its job was cancelled. The cost is
/// one indexed row read per tick per running job; the benefit is a cancel
/// button that frees the queue in seconds instead of at the step's own end.
const CANCEL_POLL: Duration = Duration::from_secs(15);

/// Default per-step timeout when the workflow does not set `timeout-minutes`.
/// Bounded well under the job timeout so one runaway step cannot consume the
/// whole job budget and leave later steps no time at all.
const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Guest timeout for `tar -czf` of a `ci/upload-artifact` path. Packing is
/// guest CPU against a local disk — a few seconds per hundred megabytes — and
/// is separate from reading the result out, which is the slow part and gets
/// the rest of the step's budget.
const ARTIFACT_PACK_TIMEOUT: Duration = Duration::from_secs(600);

/// Guest timeout for the guest's own push of a packed artifact to the store
/// (`curl -T`, see [`guest_push_command`]). This is a network upload from the
/// guest: seconds for anything a workflow here produces, a minute or two for a
/// slow link. A push still running at this point is a guest that cannot really
/// reach the store, and the rest of the step's budget belongs to the fallback
/// — reading the tarball out over the exec channel — not to waiting on it.
const ARTIFACT_GUEST_PUSH_TIMEOUT: Duration = Duration::from_secs(300);

/// Where the submitted tree lands, and where steps run, when the `vm:` block
/// does not say. Matches the daemon's own default mount.
const DEFAULT_WORKDIR: &str = "/workspace";

/// Nonce source for VM names. Hex, because the daemon derives a tap subnet from
/// the sandbox id by parsing it as hex.
static NONCE: AtomicU64 = AtomicU64::new(1);

/// What a submit produced: the runs it started, and anything the submitter
/// should know that did not stop it starting them.
pub struct Submitted {
    pub run_ids: Vec<String>,
    pub warnings: Vec<String>,
    /// The release run is the completion boundary for coordinated submissions.
    pub submission: Option<String>,
}

/// Where one job runs, resolved from its `uses:` against the live pool.
///
/// `node: None` is the only case that goes on a network's shared queue; every
/// other form pins, and a pinned job waits for its host rather than migrating.
#[derive(Debug)]
struct Placement<'a> {
    network: &'a crate::runners::RunnerSet,
    node: Option<&'a crate::runners::Runner>,
    /// An existing sandbox on `node`. When set, the `vm:` block is unused and
    /// steps exec into this VM rather than one built for the job.
    vm: Option<&'a str>,
}

/// The queue's own account of a job the reaper is about to fail.
///
/// The reaper's question — "why did nobody run this" — cannot be answered
/// from the runner pool alone. A pool full of online hosts and a job that
/// nobody touched is a contradiction until you ask the queue, and the queue
/// distinguishes three cases the pool cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueVerdict {
    /// Nothing is bound to the subject: the message is waiting for a reader
    /// that does not exist.
    NoConsumer,
    /// Bound, and the message is still sitting there undelivered — while
    /// nothing on the route is in flight. The consumer exists but is not
    /// pulling.
    Waiting(u64),
    /// Bound, working, and behind: something on the route is in flight and
    /// this job's message is queued behind it. That is capacity, not a fault —
    /// each route is consumed one job at a time — and a job here has not
    /// started, so none of its timeouts have either.
    Busy { in_flight: u64, waiting: u64 },
    /// Bound, and something is holding the message right now without having
    /// acked it. Not this process — this process would have logged it.
    InFlightElsewhere(u64),
    /// Bound, and the queue is empty while the row still says `queued`.
    /// The message was delivered *and acked*, and not by us: under
    /// `WorkQueue` retention an ack is what deletes it. Another consumer on
    /// the same durable took the job.
    TakenElsewhere,
    /// NATS could not be asked; say nothing rather than guess.
    Unknown,
}

impl QueueVerdict {
    /// Read the queue's two counters into a verdict.
    ///
    /// The order matters. A route with work in flight *and* a backlog is a
    /// runner that is simply busy, and must be recognised before either
    /// counter is read on its own — read as `Waiting` it would be failed as
    /// "nothing consumed the queue", which is how N jobs on one host came to
    /// produce one success and N-1 timeouts.
    fn from_depth(depth: Option<crate::bus::QueueDepth>) -> Self {
        match depth {
            None => Self::NoConsumer,
            Some(d) if d.in_flight > 0 && d.waiting > 0 => Self::Busy {
                in_flight: d.in_flight,
                waiting: d.waiting,
            },
            Some(d) if d.waiting > 0 => Self::Waiting(d.waiting),
            Some(d) if d.in_flight > 0 => Self::InFlightElsewhere(d.in_flight),
            Some(_) => Self::TakenElsewhere,
        }
    }

    /// Whether the job is waiting its turn behind a live consumer.
    fn is_capacity_wait(self) -> bool {
        matches!(self, Self::Busy { .. })
    }
}

pub struct Dispatcher {
    pub executor: Arc<crate::executor::ExecutorInstance>,
    pub config: Arc<Config>,
    pub store: Store,
    pub pool: Pool,
    /// What this orchestrator has built in each runner's image catalog. The
    /// daemon exposes no way to list images, so this is the only record of it.
    pub images: crate::image::Catalog,
    pub bus: Arc<Bus>,
    pub runners: Arc<Runners>,
    pub vms: Arc<Vms>,
    pub secrets: crate::secrets::Secrets,
    pub artifacts: Arc<dyn crate::artifacts::ArtifactSink>,
    pub objects: Arc<crate::objects::Workflows>,
    /// Which namespaces installed the `ci` plugin, and where they build.
    pub tenants: Arc<crate::tenants::Tenants>,
}

impl Dispatcher {
    /// Where a run's checkout lives. Populated by the trigger before the run is
    /// scheduled; read here for `cache_key_files` hashing.
    pub fn workspace(&self, run_id: &str) -> PathBuf {
        self.config.workspace_dir.join(run_id)
    }

    // ---- submission -----------------------------------------------------

    /// Turn a verified submit into a run, and schedule it.
    ///
    /// The workflow files come from the *submitted tree*, not from a checkout
    /// this process makes: what runs is what the submitter had. A tree with
    /// several matching workflow files produces one run per file, because two
    /// workflows in one repository are two independent answers to "did this
    /// commit pass".
    ///
    /// `repo` is the registration the submit token authenticated as, when it
    /// used one. It is *authority*, not a hint: the caller has already refused
    /// a payload naming a different repository, so the URL a run is recorded
    /// against comes from the registration rather than from a field the client
    /// filled in.
    pub async fn submit(
        &self,
        req: &crate::trigger::SubmitRequest,
        actor: Option<&crate::web::identity::Identity>,
        repo: Option<&crate::store::Repo>,
    ) -> Result<Submitted, DispatchError> {
        let _admission = self.executor.admission_permit().await
            .map_err(DispatchError::ControllerUnavailable)?;
        self.submit_admitted(req, actor, repo).await
    }

    async fn submit_admitted(
        &self,
        req: &crate::trigger::SubmitRequest,
        actor: Option<&crate::web::identity::Identity>,
        repo: Option<&crate::store::Repo>,
    ) -> Result<Submitted, DispatchError> {
        let run_seed = crate::vm::new_id();
        let workspace = crate::trigger::Workspace::for_run(&self.config, &run_seed);
        tokio::fs::create_dir_all(&self.config.workspace_dir)
            .await
            .map_err(|e| DispatchError::Checkout(e.to_string()))?;

        let size =
            crate::trigger::materialize(&req.source, &workspace, self.config.max_source_bytes)?;
        let source_bytes = tokio::fs::read(&workspace.descriptor).await
            .map_err(|e| DispatchError::Checkout(e.to_string()))?;

        // Read once, from the seed workspace, before any run is created: every
        // workflow file in this submit is looking at the same commit, and a
        // second `git diff` per file would be the same answer at the same cost.
        // Copied onto each run so the scheduler and the dashboard read it from
        // the row rather than from a tree that gets swept.
        let changes = crate::trigger::changed_paths(&workspace, &req.before);
        tracing::info!("submit: {changes}");

        // Which repository this is, in one place. A registration's URL is the
        // canonical spelling and wins over the payload's, which matters for the
        // client that has no `origin` remote at all: it sends an empty URL, and
        // without the token nothing downstream could say what was built.
        let repo_url = match repo {
            Some(r) => r.url.clone(),
            None => req.repository.url.clone(),
        };

        // A namespace's registration plans under the tenant policy: one
        // network, decided by app-lb's plugin config and checked against the
        // pool here, and none of the operator's per-repository statements —
        // release policies and workflow objects are matched by URL, and a
        // tenant registering a fleet repository's URL must not inherit them.
        let namespace = repo.map(|r| r.namespace.clone()).unwrap_or_default();
        if namespace.is_empty() && self.config.tenant_only {
            return Err(DispatchError::TenantOnly);
        }
        let tenant_network = if namespace.is_empty() {
            None
        } else {
            if !self.tenants.is_installed(&namespace) {
                return Err(DispatchError::NotInstalled(namespace));
            }
            let pool = self.runners.snapshot();
            let tenants = self.tenants.snapshot();
            let set = crate::tenancy::resolve_network(&pool, &namespace, tenants.network_for(&namespace), self.config.tenant_only)
                .map_err(|e| DispatchError::Tenancy(e.to_string()))?;
            if req.workflow_id.is_some() {
                return Err(DispatchError::Tenancy(
                    "workflow objects are fleet configuration and cannot be named by a namespace submit".into(),
                ));
            }
            Some(set.clone())
        };

        // Policy comes from the CI service's operator configuration, never the
        // submitted tree. Resolve every target before admitting any run.
        let release_policy = match &tenant_network {
            Some(_) => None,
            None => crate::release_policy::select(self.config.release_policies.as_deref(), &repo_url)
                .map_err(|e| DispatchError::Workflow(e.to_string()))?,
        };
        // A partial submit (`--only`, a named workflow object, a rerun) never
        // authorizes merge or deployment, so its release workflow is not planned
        // at all. Planning it only to discard it meant its placement still had
        // to resolve: a release job pinned to a network this instance does not
        // serve refused `git submit --only <build>` outright.
        let partial = req.only.iter().any(|s| !s.trim().is_empty())
            || req.workflow_id.is_some()
            || req.rerun.is_some();
        let operator_plan = match release_policy.as_ref().filter(|_| !partial) {
            Some(policy) => Some(crate::release_policy::prepare(self, &repo_url, policy).await
                .map_err(|e| DispatchError::Workflow(e.to_string()))?),
            None => None,
        };

        // A registered workflow object decides the path glob and the id; without
        // one, the installation-wide default applies. Matching is on the
        // *repository*, because `git submit` knows what it is a clone of but not
        // what somebody named the object.
        let objects = self.objects.snapshot();
        let matched: Vec<crate::objects::Workflow> = match &req.workflow_id {
            _ if tenant_network.is_some() => Vec::new(),
            Some(id) => objects.find(id).cloned().into_iter().collect(),
            None => objects.for_repo(&repo_url).cloned().collect(),
        };
        if let Some(id) = &req.workflow_id
            && matched.is_empty()
            && objects.loaded
        {
            return Err(DispatchError::Workflow(format!(
                "no workflow object {id:?} is registered. \
                 `serverctl get workflows` lists what is."
            )));
        }

        // Several objects may name one repository — `build` and `nightly` with
        // different globs is a legitimate setup — and each is an independent
        // answer to "did this commit pass", so each gets its own runs. Picking
        // one silently would make the other stop building for no stated reason.
        //
        // With no objects at all, one synthetic entry carries the defaults, so
        // an installation that never registers anything still works.
        struct Source {
            id: Option<String>,
            pattern: String,
            /// The network jobs from this source run in when they do not say.
            network: Option<String>,
        }
        let sources: Vec<Source> = if matched.is_empty() {
            vec![Source {
                id: None,
                // A registration's assigned network, else the installation
                // default. This is the whole point of assigning one: a workflow
                // that says nothing about where it runs still lands somewhere
                // deliberate rather than wherever this instance happens to
                // consider first.
                // A namespace's network is the policy's, whatever the
                // registration row says — it has no network field to set.
                network: match &tenant_network {
                    Some(set) => Some(set.network_name.clone()),
                    None => repo
                        .and_then(|r| r.network.clone())
                        .filter(|n| !n.trim().is_empty()),
                },
                // A registration may carry its own glob, for the repository
                // whose workflows are not where this installation's default
                // says. A workflow object still wins over it: the object is the
                // more specific statement, and it is the one that also names a
                // network and a secrets prefix.
                pattern: repo
                    .and_then(|r| r.workflow_path.clone())
                    .filter(|p| !p.trim().is_empty())
                    .unwrap_or_else(|| self.config.default_workflow_path.clone()),
            }]
        } else {
            matched
                .iter()
                .map(|w| Source {
                    id: Some(w.id.clone()),
                    pattern: w.path.clone(),
                    // A workflow object names a network of its own; it is the
                    // more specific statement, so it wins over the repository's
                    // assignment, and the assignment fills in when it is blank.
                    network: Some(w.network.clone())
                        .filter(|n| !n.trim().is_empty())
                        .or_else(|| repo.and_then(|r| r.network.clone()))
                        .filter(|n| !n.trim().is_empty()),
                })
                .collect()
        };

        let mut run_ids = Vec::new();
        let mut planned = Vec::new();
        let mut release_run_id = None;
        let mut release_skipped = false;
        let mut patterns_tried = Vec::new();
        // `--only` bookkeeping: which selectors found a workflow file at all.
        // Checked across every source, after the loop — a selector that matched
        // nothing anywhere is a mistake worth failing the submit over, and a
        // per-source check would wrongly fail a selector that matches the
        // *other* object's glob.
        let only: Vec<String> = req
            .only
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut only_matched: Vec<bool> = vec![false; only.len()];
        // Workflow files that matched the glob and then declined to build, with
        // the filter that declined. Kept apart from `warnings` because they are
        // the difference between "nothing matched your glob" — a mistake worth
        // an error — and "your filters said no", which is the feature working.
        let mut skipped: Vec<String> = Vec::new();
        // Carried back to the client. A submit that queued but will not run
        // until something changes should say so at the terminal that made it,
        // not only on a page nobody has open.
        let mut warnings: Vec<String> = Vec::new();
        if !partial && release_policy.as_ref().is_some_and(|p|
            p.submission_mode == crate::release_policy::SubmissionMode::MergeOnly) {
            warnings.push("operator policy: validate and merge only; this submission will not deploy".into());
        }

        for (source_index, source) in sources.iter().enumerate() {
            let mut files = crate::trigger::find_workflows(&workspace.root, &source.pattern)?;
            if let Some(policy) = &release_policy {
                files = crate::release_policy::workflows(files, policy, source_index == 0)
                    .map_err(|e| DispatchError::Workflow(e.to_string()))?;
            }
            patterns_tried.push(source.pattern.clone());
            if files.is_empty() {
                continue;
            }
            tracing::info!(
                "submit: {size} bytes, {} workflow file(s) matching {} for {}",
                files.len(),
                source.pattern,
                source.id.as_deref().unwrap_or("(no object)")
            );

            for (path, text) in &files {
                let wf = crate::workflow::Workflow::parse(path, text)
                    .map_err(|e| DispatchError::Workflow(e.to_string()))?;
                // Before anything else reads the file: a namespace workflow
                // that asks for a fleet capability is refused outright, not
                // skipped, so the submitter learns why it did not run.
                if let Some(set) = &tenant_network {
                    crate::tenancy::check_workflow(&wf, set)
                        .map_err(|e| DispatchError::Tenancy(e.to_string()))?;
                }
                let is_release = wf.on.iter().any(|t| t == "release");
                if is_release && wf.on.len() != 1 {
                    return Err(DispatchError::Workflow(format!(
                        "{path}: release must be a coordinator-only trigger"
                    )));
                }
                if is_release && partial {
                    release_skipped = true;
                    continue;
                }
                // `--only`: the submit names the workflow files it wants, and
                // every other file is left alone — not "declined", not warned
                // about, simply not asked.
                let named = if only.is_empty() || is_release {
                    false
                } else {
                    let mut hit = false;
                    for (i, sel) in only.iter().enumerate() {
                        if crate::trigger::selector_matches(sel, path, wf.name.as_deref()) {
                            only_matched[i] = true;
                            hit = true;
                        }
                    }
                    if !hit {
                        continue;
                    }
                    true
                };
                if !is_release && !wf.on.iter().any(|t| t == "submit") {
                    if named {
                        // Explicitly asked for, and unable to comply: that is
                        // an answer for the terminal, not a line in a log.
                        return Err(DispatchError::Workflow(format!(
                            "{path} was named by --only but does not trigger on `submit`; \
                             add `submit` to its `on:` list to run it this way"
                        )));
                    }
                    tracing::info!("{path} does not trigger on `submit`; skipping");
                    continue;
                }
                // The monorepo gate. Evaluated per workflow file, because that
                // is the unit a run is created for: in a repository with an
                // `api.yml` and a `web.yml`, a commit touching only `api/` must
                // produce one run and not two.
                //
                // A workflow named by `--only` runs even when the gate says no:
                // naming it *is* the decision the gate exists to infer, the way
                // a manual dispatch outranks a path filter. Said out loud in the
                // response, so a run on an unexpected branch is never a mystery.
                if let Err(why) = wf.on_submit.admits(req.branch(), &changes) {
                    if is_release {
                        return Err(DispatchError::Workflow(format!(
                            "{path}: release workflow cannot filter submission membership"
                        )));
                    }
                    if named {
                        let by = if req.rerun.is_some() {
                            "the re-run"
                        } else {
                            "--only"
                        };
                        warnings.push(format!("{path}: trigger filters bypassed by {by} ({why})"));
                    } else {
                        tracing::info!("{path} declined this submit: {why}");
                        skipped.push(format!("{path}: {why}"));
                        continue;
                    }
                }
                let mut plan = match operator_plan.as_ref().filter(|_| is_release) {
                    Some(plan) => plan.clone(),
                    None => crate::plan::Plan::build(&wf)
                        .map_err(|e| DispatchError::Workflow(e.to_string()))?,
                };
                if is_release {
                    crate::submission::validate_release_plan(&plan)
                        .map_err(DispatchError::Workflow)?;
                }

                // Resolved once, here, and written into every job that did not
                // name a network with `uses:`. The plan is persisted on the job
                // row and is what a redelivery executes, so a job runs in the
                // network it was scheduled for even if the repository is
                // reassigned mid-build — the same reason the expanded plan is
                // stored rather than recomputed.
                self.assign_network(&mut plan, source.network.as_deref(), &mut warnings)?;
                if let Some(set) = &tenant_network {
                    crate::tenancy::seal_plan(&mut plan, set)
                        .map_err(|e| DispatchError::Tenancy(e.to_string()))?;
                }

                // Every run's descriptor is committed below with its metadata.
                // No accepted run depends on this controller's staging directory.
                let run_id = if run_ids.is_empty() {
                    run_seed.clone()
                } else {
                    crate::vm::new_id()
                };

                let request = crate::store::RunRequest {
                            workflow_id: source
                                .id
                                .clone()
                                .or_else(|| req.workflow_id.clone())
                                .unwrap_or_else(|| match repo {
                                    Some(r) => r.name.clone(),
                                    None => req.repository.name.clone(),
                                }),
                            repo_id: repo.map(|r| r.id.clone()),
                            repo_url: repo_url.clone(),
                            git_ref: req.r#ref.clone(),
                            sha: req.after.clone(),
                            before_sha: req.before.clone(),
                            default_branch: req.repository.default_branch.clone(),
                            release_base_sha: req.repository.release_base_sha.clone(),
                            // A workflow forced by `--only` gets *unknown*
                            // changes, not the real diff. The real diff is what
                            // just declined it at the workflow gate, and the
                            // job-level `if: changed(...)` conditions read the
                            // same diff — bypassing one while the other still
                            // says "nothing relevant changed" produces a run
                            // whose every job skips, which reads as CI passing
                            // a build it never did. Unknown is the codebase's
                            // fail-open answer: every changed() filter admits,
                            // and the reason string says why on the run page.
                            changes: match &req.rerun {
                                // The same commit with the same diff: the run
                                // being re-played already answered this, and
                                // reusing its answer is what makes every
                                // `changed()` filter decide exactly as it did
                                // the first time.
                                Some(rerun) => rerun.changes.clone(),
                                None if named => crate::paths::Changes::unknown(
                                    "run forced by `git submit --only`; every changed() \
                                     filter admits",
                                ),
                                None => changes.clone(),
                            },
                            actor_subject: actor.map(|a| a.subject.clone()),
                            actor_email: actor
                                .map(|a| a.email.clone())
                                .or_else(|| req.pusher.as_ref().and_then(|p| p.email.clone())),
                            source: if req.rerun.is_some() {
                                "rerun"
                            } else {
                                "submit"
                            }
                            .to_string(),
                            rerun_of: req.rerun.as_ref().map(|r| r.of.clone()),
                            namespace: namespace.clone(),
                        };
                if is_release && release_run_id.replace(run_id.clone()).is_some() {
                    return Err(DispatchError::Workflow(
                        "a submission must have exactly one on: release workflow".into()
                    ));
                }
                planned.push((run_id.clone(), request, plan));
                run_ids.push(run_id);
            }
        }

        // A submit that started nothing is two different situations, and
        // collapsing them was survivable only while no workflow could decline.
        //
        // Nothing *matched* is a mistake — a glob pointing at a directory that
        // is not there, or a workflow that triggers on something this build does
        // not honour — and the submitter wants a non-zero exit for it.
        //
        // Everything *declining* is the feature doing its job. In a monorepo it
        // is the common case: most commits touch one package, so most workflows
        // correctly build nothing. Failing the submit for that would make `git
        // submit` red on a healthy repository, and would break any hook that
        // treats a failed submit as something to retry.
        // Selectors are checked before the started-nothing check: "--only
        // apps-obs matched no workflow file" is the answer when it is true, and
        // "nothing matched your glob" would send the reader to the wrong knob.
        let unmatched: Vec<&str> = only
            .iter()
            .zip(&only_matched)
            .filter(|(_, hit)| !**hit)
            .map(|(s, _)| s.as_str())
            .collect();
        if !unmatched.is_empty() {
            return Err(DispatchError::Workflow(format!(
                "--only {:?} matched no workflow file under {} — a selector is a file's \
                 path, its basename with or without .yml, or the workflow's `name:`",
                unmatched.join(", "),
                patterns_tried.join(", "),
            )));
        }
        // A repository with a release workflow keeps publication there, whether
        // or not this submit planned it.
        if release_run_id.is_some() || release_skipped {
            for (id, _, plan) in &planned {
                if Some(id) != release_run_id.as_ref() {
                    crate::submission::validate_validation_plan(plan)
                        .map_err(DispatchError::Workflow)?;
                }
            }
            // Partial runs and diagnostic reruns can never authorize publication.
            if release_skipped || planned.len() == 1 {
                let id = release_run_id.take();
                planned.retain(|(run, _, _)| Some(run) != id.as_ref());
                run_ids.retain(|run| Some(run) != id.as_ref());
                warnings.push("validation only: partial, rerun, or empty submissions do not authorize merge/deployment".into());
            }
        }
        if run_ids.is_empty() && skipped.is_empty() {
            return Err(crate::trigger::TriggerError::NoWorkflows(format!(
                "{} (nothing matched, or nothing triggering on `submit`)",
                patterns_tried.join(", ")
            ))
            .into());
        }
        // Reported whether or not anything else ran: with several workflows, the
        // interesting question is usually why the *other* one did not.
        warnings.extend(skipped.into_iter().map(|s| format!("no run started — {s}")));
        let mut tx = self.store.pool().begin().await
            .map_err(|e| DispatchError::Workflow(format!("begin submission: {e}")))?;
        for (id, request, plan) in &planned {
            Store::create_run_in(&mut tx, id, request, plan).await?;
            Store::record_source_in(&mut tx, id, &source_bytes).await?;
            if partial {
                sqlx::query("UPDATE ci_run SET validation_only=true WHERE id=$1")
                    .bind(id).execute(&mut *tx).await
                    .map_err(|e| DispatchError::Workflow(format!("record partial submission: {e}")))?;
            }
        }
        if let Some(release) = &release_run_id {
            let validations = run_ids.iter().filter(|id| *id != release).cloned().collect::<Vec<_>>();
            crate::submission::record(&mut tx, release, &validations).await
                .map_err(DispatchError::Workflow)?;
        }
        tx.commit().await.map_err(|e| DispatchError::Workflow(format!("commit submission: {e}")))?;
        // Nothing becomes schedulable before the complete membership commits.
        for id in &run_ids {
            if let Some(rerun) = req.rerun.as_ref().filter(|r| r.failed_only) {
                self.carry_over_successes(id, &rerun.of).await?;
            }
            self.advance_run(id).await?;
        }
        Ok(Submitted { run_ids, warnings, submission: release_run_id })
    }

    /// Start a new run from a finished one's source — the dashboard's "Run
    /// again" and "Re-run failed jobs".
    ///
    /// A re-run is a *new* run, not a reset of the old one. Run and job ids
    /// name their logs, step operation ids derive from them and the daemon
    /// reattaches to an operation it has already seen, and the failed attempt
    /// is the thing somebody will want to read next to the one that passed.
    /// What the two share is the source: every submit commits its validated
    /// descriptor with the run in Postgres, so another regional controller can
    /// replay it exactly. Checkout credentials are resolved afresh per job.
    ///
    /// It goes through [`Self::submit`] with the original run's workflow file
    /// as its one `--only` selector, so it is planned, routed and secreted
    /// exactly as a submit is; the only things a re-run adds are lineage
    /// (`rerun_of`) and, with `failed_only`, the carried-over results.
    ///
    /// `failed_only` copies every job that *succeeded* in the original into the
    /// new run as a finished row with its outputs, so `needs:` resolves and a
    /// deploy job can run again without rebuilding what already built.
    /// Everything else — failed, cancelled, skipped — is scheduled afresh, and
    /// a job that was skipped by its `if:` will be asked again.
    pub async fn rerun(
        &self,
        run_id: &str,
        failed_only: bool,
        actor: Option<&crate::web::identity::Identity>,
    ) -> Result<Submitted, DispatchError> {
        let _admission = self.executor.admission_permit().await
            .map_err(DispatchError::ControllerUnavailable)?;
        let run = self
            .store
            .get_run(run_id)
            .await?
            .ok_or_else(|| DispatchError::Workflow(format!("no run {run_id}")))?;
        if !matches!(run.status.as_str(), "success" | "failure" | "cancelled") {
            return Err(DispatchError::Workflow(format!(
                "run {run_id} is still {}; cancel it, or wait for it to finish, before \
                 re-running it",
                run.status
            )));
        }
        // A failed job can make the run's rollup fail while siblings still run.
        // Retrying that rollup must not duplicate the siblings' work.
        if self.store.jobs_of(run_id).await?.iter()
            .any(|job| !matches!(job.status.as_str(), "success" | "failure" | "skipped" | "cancelled")) {
            return Err(DispatchError::Workflow(
                "jobs in this run are still active; wait for them to finish before re-running it".into()
            ));
        }
        if self.store.has_unresolved_execution(run_id).await? {
            return Err(DispatchError::Workflow(
                "this run still owns unresolved execution; reconcile its workers before re-running it".into()
            ));
        }
        if self.store.service_deployments_of(run_id).await?.iter()
            .any(|d| !matches!(d.status.as_str(), "passed" | "failed")) {
            return Err(DispatchError::Workflow(
                "a service rollout is still running or has an unknown submission outcome; reconcile it before creating another run".into()
            ));
        }

        // The registration the original ran under, when it had one — it is
        // what decides the workflow glob, the network and the secrets prefix,
        // and a paused one must stay paused for re-runs too.
        let repo = match &run.repo_id {
            Some(id) => self.store.get_repo(id).await?,
            None => self.store.repo_by_url(&run.repo_url).await?,
        };
        // The new run belongs where the old one did, and a namespace run is
        // re-planned only from its own namespace's registration. Without it
        // there is nothing to carry the namespace — the URL fallback above is
        // fleet-only — and re-running it as a fleet build would hand a
        // tenant's source the fleet's network and secrets.
        if repo.as_ref().map(|r| r.namespace.as_str()).unwrap_or("") != run.namespace {
            return Err(DispatchError::Tenancy(format!(
                "run {run_id}'s registration is gone; register the repository again and submit"
            )));
        }
        if let Some(r) = &repo
            && !r.enabled
        {
            return Err(DispatchError::Workflow(format!(
                "{} is paused on /repos; enable it before re-running its builds",
                r.name
            )));
        }

        // A published release is not an ordinary partial submit. Re-planning
        // it would remove the release workflow, and running the merge again
        // could publish a second candidate. Admit a failed-only attempt from
        // the persisted plans and immutable publication/submission evidence.
        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ci_submission WHERE release_run_id=$1)",
        )
        .bind(run_id)
        .fetch_one(self.store.pool())
        .await
        .map_err(|e| DispatchError::Workflow(format!("inspect release submission: {e}")))?
        {
            if !failed_only {
                return Err(DispatchError::Workflow(
                    "full release reruns are unsupported because they could publish the merge again; use Re-run failed jobs on the latest failed release attempt".into(),
                ));
            }
            let submitted = self.retry_published_release(run_id, actor).await?;
            for id in &submitted.run_ids {
                self.advance_run(id).await?;
            }
            return Ok(submitted);
        }

        let bytes = self.store.source_bytes(run_id).await?;

        let req = crate::trigger::SubmitRequest {
            repository: crate::trigger::RepositoryRef {
                id: String::new(),
                name: repo
                    .as_ref()
                    .map(|r| r.name.clone())
                    .or_else(|| run.repo_name.clone())
                    .unwrap_or_default(),
                url: run.repo_url.clone(),
                default_branch: run.default_branch.clone(),
                release_base_sha: run.release_base_sha.clone(),
            },
            r#ref: run.git_ref.clone(),
            before: run.before_sha.clone(),
            after: run.sha.clone(),
            dry_run: false,
            pusher: None,
            // Resolved by repository, as the original was; the run's own
            // `workflow_id` may be the repository-name fallback rather than a
            // registered object, and naming that would be refused.
            workflow_id: None,
            only: vec![run.workflow_path.clone()],
            source: crate::trigger::SourceArchive {
                format: crate::trigger::SourceFormat::GitPatch.as_str().to_string(),
                content_base64: String::new(),
                bytes: Some(bytes),
            },
            rerun: Some(crate::trigger::Rerun {
                of: run_id.to_string(),
                failed_only,
                changes: run.changes.clone(),
            }),
        };
        let submitted = self.submit_admitted(&req, actor, repo.as_ref()).await?;
        tracing::info!(
            "re-run of {run_id} ({}) by {}: {}",
            if failed_only {
                "failed jobs"
            } else {
                "every job"
            },
            actor.map(|a| a.display()).unwrap_or("anonymous"),
            submitted.run_ids.join(", ")
        );
        Ok(submitted)
    }

    async fn retry_published_release(
        &self,
        run_id: &str,
        actor: Option<&crate::web::identity::Identity>,
    ) -> Result<Submitted, DispatchError> {
        let retry = crate::vm::new_id();
        let mut tx = self.store.pool().begin().await
            .map_err(|e| DispatchError::Workflow(format!("begin release retry: {e}")))?;
        let source = sqlx::query(
            "SELECT r.status,rel.status AS release_status
               FROM ci_run r JOIN ci_submission sub ON sub.release_run_id=r.id
               LEFT JOIN ci_release rel ON rel.run_id=r.id
              WHERE r.id=$1 FOR UPDATE OF r,sub",
        ).bind(run_id).fetch_optional(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("lock release retry source: {e}")))?
            .ok_or_else(|| DispatchError::Workflow(
                "release retry requires one unambiguous admitted submission".into()))?;
        if source.get::<Option<String>, _>("release_status").as_deref() != Some("published") {
            return Err(DispatchError::Workflow(
                "release retry requires a confirmed published release; reconcile publication before retrying failed jobs".into(),
            ));
        }
        if !matches!(source.get::<String, _>("status").as_str(), "failure" | "cancelled") {
            return Err(DispatchError::Workflow(
                "only a failed or cancelled published release can retry failed jobs".into(),
            ));
        }
        let merge_complete: bool = sqlx::query_scalar(
            "SELECT count(*)=1 AND bool_and(j.status='success') FROM ci_job j,
             LATERAL jsonb_array_elements(j.plan->'steps') s
             WHERE j.run_id=$1 AND s->>'uses'='ci/merge-release'",
        ).bind(run_id).fetch_one(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("inspect publication job: {e}")))?;
        if !merge_complete {
            return Err(DispatchError::Workflow(
                "reconcile the published merge job before retrying; release retry never repeats publication".into(),
            ));
        }
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ci_job WHERE run_id=$1 AND status NOT IN ('success','failure','skipped','cancelled'))
                 OR EXISTS(SELECT 1 FROM ci_service_deployment WHERE run_id=$1 AND status NOT IN ('passed','failed'))
                 OR EXISTS(SELECT 1 FROM ci_service_deployment d JOIN ci_service_rollout s ON s.id=d.id
                            WHERE d.run_id=$1 AND d.status='failed' AND d.phase IS DISTINCT FROM 'settled_failure')",
        ).bind(run_id).fetch_one(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("inspect release retry settlement: {e}")))?;
        if active {
            return Err(DispatchError::Workflow(
                "release work is still active or an earlier rollout failure is not terminally settled; reconcile it before retrying".into(),
            ));
        }
        let partial_effect: Option<String> = sqlx::query_scalar(
            "SELECT j.job_key FROM ci_job j JOIN ci_step s ON s.job_id=j.id
              WHERE j.run_id=$1 AND j.status<>'success' AND s.status='success'
                AND s.uses IN ('ci/deploy-service','ci/deploy-app-lb','ci/deploy-controller',
                               'ci/host-heyvm-maintenance','ci/bootstrap-host-heyvm',
                               'ci/rollout-host-heyvmd','ci/rollout-service','ci/rollout-host-app-lb')
                AND NOT (s.uses IN ('ci/rollout-service','ci/rollout-host-app-lb')
                    AND COALESCE(j.plan->'native_labels','[]'::jsonb)='[]'::jsonb
                    AND (EXISTS(SELECT 1 FROM ci_service_deployment d WHERE d.step_id=s.id AND d.status='passed')
                         OR EXISTS(SELECT 1 FROM ci_release_carried_deployment c
                                   JOIN ci_service_deployment d ON d.id=c.deployment_id
                                   WHERE c.job_id=j.id AND c.step_index=s.idx AND d.status='passed')))
              ORDER BY j.created_at LIMIT 1",
        ).bind(run_id).fetch_optional(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("inspect completed release effects: {e}")))?;
        if let Some(job) = partial_effect {
            return Err(DispatchError::Workflow(format!(
                "release job {job:?} already completed a deployment step before failing; reconcile that deployment instead of repeating the job"
            )));
        }

        // The unique retry_of index is the concurrent duplicate guard. Since
        // every accepted child is itself a submission, an old ancestor also
        // remains permanently ineligible for replay.
        let has_child: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ci_submission WHERE retry_of=$1)",
        ).bind(run_id).fetch_one(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("inspect release retry lineage: {e}")))?;
        if has_child {
            return Err(DispatchError::Workflow(
                "this release attempt already has a retry; retry failed jobs on the latest descendant instead".into(),
            ));
        }

        sqlx::query(
            "INSERT INTO ci_run(id,workflow_id,workflow_path,workflow_name,repo_url,git_ref,sha,before_sha,
                                actor_subject,actor_email,source,status,repo_id,changes,rerun_of,default_branch,release_base_sha)
             SELECT $2,workflow_id,workflow_path,workflow_name,repo_url,git_ref,sha,before_sha,$3,$4,
                    'rerun','queued',repo_id,changes,$1,default_branch,release_base_sha FROM ci_run WHERE id=$1",
        ).bind(run_id).bind(&retry).bind(actor.map(|a| &a.subject)).bind(actor.map(|a| &a.email))
            .execute(&mut *tx).await.map_err(|e| DispatchError::Workflow(format!("create release retry: {e}")))?;
        let copied_source = sqlx::query("INSERT INTO ci_run_source(run_id,descriptor) SELECT $2,descriptor FROM ci_run_source WHERE run_id=$1")
            .bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("copy release source: {e}")))?;
        if copied_source.rows_affected() != 1 {
            return Err(DispatchError::Workflow(
                "release retry requires the original persisted source descriptor".into(),
            ));
        }
        let jobs = sqlx::query("SELECT job_key,status,outputs FROM ci_job WHERE run_id=$1 ORDER BY created_at,id")
            .bind(run_id).fetch_all(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("read release jobs: {e}")))?;
        sqlx::query(
            "INSERT INTO ci_job(id,run_id,job_key,base_id,display,network,status,matrix,outputs,plan,carried_from,started_at,finished_at)
             SELECT $2||'.'||job_key,$2,job_key,base_id,display,network,
                    CASE WHEN status='success' THEN 'success' ELSE 'pending' END,matrix,
                    CASE WHEN status='success' THEN outputs ELSE '{}'::jsonb END,plan,
                    CASE WHEN status='success' THEN $1 ELSE NULL END,
                    CASE WHEN status='success' THEN now() ELSE NULL END,
                    CASE WHEN status='success' THEN now() ELSE NULL END
               FROM ci_job WHERE run_id=$1",
        ).bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("copy release job plans: {e}")))?;
        sqlx::query(
            "INSERT INTO ci_release_carried_deployment(job_id,step_index,deployment_id)
             SELECT $2||'.'||j.job_key,s.idx,d.id FROM ci_job j
               JOIN ci_step s ON s.job_id=j.id JOIN ci_service_deployment d ON d.step_id=s.id
              WHERE j.run_id=$1 AND s.status='success' AND d.status='passed'
                AND s.uses IN ('ci/rollout-service','ci/rollout-host-app-lb')
             UNION
             SELECT $2||'.'||j.job_key,c.step_index,c.deployment_id FROM ci_job j
               JOIN ci_release_carried_deployment c ON c.job_id=j.id WHERE j.run_id=$1",
        ).bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("preserve completed deployment receipts: {e}")))?;
        sqlx::query("INSERT INTO ci_submission(release_run_id,validation_count,retry_of) SELECT $2,validation_count,$1 FROM ci_submission WHERE release_run_id=$1")
            .bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("record release retry: {e}")))?;
        let copied_validations = sqlx::query("INSERT INTO ci_submission_validation(release_run_id,validation_run_id,ordinal) SELECT $2,validation_run_id,ordinal FROM ci_submission_validation WHERE release_run_id=$1")
            .bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("copy frozen validations: {e}")))?;
        let expected: i64 = sqlx::query_scalar("SELECT validation_count::bigint FROM ci_submission WHERE release_run_id=$1")
            .bind(&retry).fetch_one(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("verify frozen validations: {e}")))?;
        if copied_validations.rows_affected() as i64 != expected {
            return Err(DispatchError::Workflow(
                "release retry found incomplete frozen validation membership".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status,error)
             SELECT $2,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,'published',NULL FROM ci_release WHERE run_id=$1",
        ).bind(run_id).bind(&retry).execute(&mut *tx).await
            .map_err(|e| DispatchError::Workflow(format!("copy published release: {e}")))?;
        Store::add_event(&mut tx, &retry, None, None, None, "ci.run.status.v1", "queued", None).await?;
        for job in jobs {
            let key: String = job.get("job_key");
            let status = if job.get::<String, _>("status") == "success" { "success" } else { "pending" };
            Store::add_event(&mut tx, &retry, Some(&crate::store::job_id(&retry, &key)), Some(&key), None,
                "ci.job.status.v1", status, None).await?;
        }
        tx.commit().await.map_err(|e| DispatchError::Workflow(format!("commit release retry: {e}")))?;
        Ok(Submitted { run_ids: vec![retry.clone()], warnings: vec![
            format!("release retry reuses published candidate and frozen validation artifacts from {run_id}")
        ], submission: Some(retry) })
    }

    /// Fill a failed-only re-run's jobs with the results their counterparts
    /// earned in `from`, for every job that succeeded there. The rest stay
    /// `pending` for the scheduler.
    async fn carry_over_successes(&self, run_id: &str, from: &str) -> Result<(), DispatchError> {
        let previous = self.store.jobs_of(from).await?;
        let mut carried = 0;
        for job in previous.iter().filter(|j| j.status == "success") {
            let id = crate::store::job_id(run_id, &job.job_key);
            if self.store.carry_over_job(&id, job).await? {
                carried += 1;
            }
        }
        tracing::info!(run = %run_id, "re-run of {from}: {carried} succeeded job(s) carried over");
        Ok(())
    }

    // ---- scheduling -----------------------------------------------------

    /// Publish every job that has become ready, skip those whose `if:` is false,
    /// and roll the run up.
    ///
    /// Safe to call repeatedly and concurrently: publishing is deduplicated by
    /// the job's own id (`Nats-Msg-Id`), and moving a job from `pending` to
    /// `queued` is conditional on it still being `pending`.
    pub async fn advance_run(&self, run_id: &str) -> Result<RunStatus, DispatchError> {
        match crate::submission::gate(&self.store, run_id).await.map_err(DispatchError::Workflow)? {
            crate::submission::Gate::Waiting => return Ok(RunStatus::Queued),
            crate::submission::Gate::Rejected(reason) => {
                for job in self.store.jobs_of(run_id).await? {
                    if job.status == "pending" {
                        self.store.set_job_status(&job.id, JobStatus::Failure, Some(&reason)).await?;
                    }
                }
                return self.store.roll_up_run(run_id).await.map_err(Into::into);
            }
            crate::submission::Gate::Unmanaged | crate::submission::Gate::Ready => {}
        }
        // One read for the whole wave, not one per job: the commit a run is for
        // does not change between two jobs of the same run.
        let ci = Self::ci_scope(self.store.get_run(run_id).await?.as_ref());
        // A skip/failure has no worker completion to schedule the next wave.
        // Re-read dependency results until all such transitions have propagated.
        while self.advance_run_wave(run_id, &ci).await? {}
        Ok(self.store.roll_up_run(run_id).await?)
    }

    async fn advance_run_wave(&self, run_id: &str, ci: &Value) -> Result<bool, DispatchError> {
        let jobs = self.store.jobs_of(run_id).await?;
        let needs = self.store.needs_context(run_id).await?;
        let mut changed = false;

        // A base id is only satisfied once *every* cell of it is terminal —
        // `needs: [build]` cannot mean "the first cell of build".
        let mut terminal: HashMap<&str, bool> = HashMap::new();
        for j in &jobs {
            let is_terminal = matches!(
                j.status.as_str(),
                "success" | "failure" | "skipped" | "cancelled"
            );
            terminal
                .entry(j.base_id.as_str())
                .and_modify(|t| *t &= is_terminal)
                .or_insert(is_terminal);
        }

        for job in &jobs {
            if job.status != "pending" {
                continue;
            }
            let plan: JobPlan = match serde_json::from_value(job.plan.clone()) {
                Ok(p) => p,
                Err(e) => {
                    self.store
                        .set_job_status(
                            &job.id,
                            JobStatus::Failure,
                            Some(&format!("stored plan could not be read: {e}")),
                        )
                        .await?;
                    changed = true;
                    continue;
                }
            };

            if !plan
                .needs
                .iter()
                .all(|n| *terminal.get(n.as_str()).unwrap_or(&false))
            {
                continue;
            }

            // Decide `if:` now that dependencies have results. A dependency that
            // failed makes the default guard false, which is what stops a deploy
            // job from shipping a broken build.
            match self.should_run(&plan, &needs, ci) {
                Ok(true) => {}
                Ok(false) => {
                    self.store
                        .set_job_status(&job.id, JobStatus::Skipped, None)
                        .await?;
                    changed = true;
                    continue;
                }
                Err(e) => {
                    // A guard that cannot be understood must not run the job.
                    self.store
                        .set_job_status(
                            &job.id,
                            JobStatus::Failure,
                            Some(&format!("could not evaluate `if:` — {e}")),
                        )
                        .await?;
                    changed = true;
                    continue;
                }
            }

            if !plan.native_labels.is_empty() {
                crate::native::enqueue(&self.store, &job.id, run_id, &plan.native_labels)
                    .await.map_err(DispatchError::Native)?;
                tracing::info!(run=run_id, job=%plan.key, labels=?plan.native_labels, "queued for native runner");
                continue;
            }

            let route = match self.route_for(&plan).await {
                Ok(r) => r,
                Err(e) => {
                    self.store
                        .set_job_status(&job.id, JobStatus::Failure, Some(&e.to_string()))
                        .await?;
                    changed = true;
                    continue;
                }
            };

            if self.store.queue_job(&job.id).await? {
                let published = self
                    .bus
                    .publish_job(
                        &route,
                        &JobMessage {
                            run_id: run_id.to_string(),
                            job_id: job.id.clone(),
                            job_key: plan.key.clone(),
                        },
                    )
                    .await;

                match published {
                    Ok(()) => {
                        tracing::info!(run = run_id, job = %plan.key, route = ?route, "queued")
                    }
                    // The status was committed before this call, so a failure
                    // here leaves a row saying `queued` with nothing on the
                    // queue — two stores disagreeing, with nothing to notice.
                    // Rolling back makes the scheduler's own retry the repair;
                    // `Nats-Msg-Id` means a later duplicate publish collapses,
                    // so retrying is safe even if the message did land.
                    Err(e) => {
                        tracing::warn!(
                            run = run_id, job = %plan.key, route = ?route,
                            "could not publish, returning the job to pending: {e}"
                        );
                        if let Err(e) = self.store.unqueue_job(&job.id).await {
                            // Now it really is stranded, and saying so is all
                            // that is left.
                            tracing::error!(
                                run = run_id, job = %plan.key,
                                "could not roll back a failed publish: {e}"
                            );
                        }
                        // Deliberately not propagated: one unreachable subject
                        // must not stop the rest of the run being scheduled.
                        continue;
                    }
                }
            }
        }

        Ok(changed)
    }

    /// The `ci` expression scope: which commit this run is for, and what it
    /// changed.
    ///
    /// Built from the run row rather than persisted onto each `JobPlan`, unlike
    /// the network assignment next to it. The reason is that the two are not the
    /// same kind of fact: a repository's network can be reassigned while a build
    /// is in flight, so the plan freezes it; the commit a run is for is fixed
    /// by its durable source descriptor and cannot move under a redelivery. Freezing
    /// it anyway would copy a monorepo-sized path list onto every job row.
    ///
    /// A run this process cannot read at all yields an empty scope rather than
    /// an error: `ci.sha` resolving to null is a condition an author can see is
    /// wrong, whereas failing the job says nothing about what to fix.
    pub(crate) fn ci_scope(run: Option<&crate::store::Run>) -> Value {
        let Some(run) = run else {
            return Value::Object(Default::default());
        };
        serde_json::json!({
            "sha": run.sha,
            "before": run.before_sha,
            "release_base_sha": run.release_base_sha,
            "ref": run.git_ref,
            "branch": run.git_ref.strip_prefix("refs/heads/").unwrap_or(&run.git_ref),
            "repository": run.repo_url,
            "run_id": run.id,
            "workflow": run.workflow_id,
            "changed_files": run.changes.paths(),
            // Read by `changed()`, and worth exposing on its own: a workflow
            // that wants to be careful can write
            // `if: !ci.changes_known || changed('api/**')` and get the same
            // build-when-unsure default the path filters apply.
            "changes_known": run.changes.is_known(),
            // Empty when the diff was read. Present because "my path filter
            // matched everything" is otherwise unexplainable from inside a
            // build: `echo ${{ ci.changes_reason }}` in a step is the answer.
            "changes_reason": run.changes.reason().unwrap_or_default(),
        })
    }

    /// Evaluate a job's `if:`.
    ///
    /// The default when there is no `if:` is GitHub's: run only if every dependency
    /// succeeded. Writing an explicit `if:` opts out of that — which is
    /// how `if: always()` gets a cleanup job to run after a failure.
    fn should_run(&self, plan: &JobPlan, needs: &Value, ci: &Value) -> Result<bool, DispatchError> {
        let any_failed = plan.needs.iter().any(|n| {
            matches!(
                needs
                    .get(n)
                    .and_then(|v| v.get("result"))
                    .and_then(Value::as_str),
                Some("failure") | Some("cancelled")
            )
        });

        let Some(condition) = &plan.condition else {
            return Ok(plan.needs.iter().all(|n| needs[n]["result"] == "success"));
        };

        let mut ctx = plan.base_context();
        ctx.set("needs", needs.clone());
        ctx.set("ci", ci.clone());
        ctx.set_status(if any_failed { "failure" } else { "success" });
        ctx.eval_condition(condition)
            .map_err(|e| DispatchError::Condition(e.to_string()))
    }

    /// Stamp the run's network onto every job that does not name one, and refuse
    /// the submit if the result is a network this instance cannot dispatch to.
    ///
    /// Refusing *here* is the point. Without it the run is created, the jobs go
    /// to a queue nobody consumes, and the answer to "why is my build stuck" is
    /// a row in a table nobody thinks to look at. A submit that cannot run is an
    /// error at the client, naming the network and what is actually served.
    pub(crate) fn assign_network(
        &self,
        plan: &mut crate::plan::Plan,
        default_network: Option<&str>,
        warnings: &mut Vec<String>,
    ) -> Result<(), DispatchError> {
        let pool = self.runners.snapshot();
        for job in &mut plan.jobs {
            if !job.native_labels.is_empty() {
                if self.config.native_runner_secret.is_none() {
                    return Err(DispatchError::Native("configure native runners before submitting runs-on jobs".into()));
                }
                continue;
            }
            // `uses: default` names no network on purpose — it is wherever this
            // orchestrator's host happens to be — so the repository's assignment
            // must not be written over it.
            if job.target.network.is_none()
                && !job.target.local
                && let Some(net) = default_network
            {
                job.target.network = Some(net.to_string());
            }
            // Resolve the whole placement, not just the network: a `uses:` that
            // names a host or a VM this instance cannot reach is refused here,
            // at the client, rather than becoming a run whose jobs sit on a
            // queue nobody consumes.
            let placement = Self::place(&pool, job)?;
            // Warned, never refused. A host that is briefly unreachable is a
            // blip, and the job should sit on its subject until the host comes
            // back and its consumer binds — refusing here would turn a recovery
            // into a lost submit. The wait is bounded by CI_RUNNER_WAIT_SECS.
            if let Some(node) = placement.node
                && !node.status.is_dispatchable()
            {
                warnings.push(format!(
                    "{} is pinned to {} ({}), which is not online. The job will wait on \
                     that host's queue and run when it comes back, or fail after {}s.",
                    job.key,
                    node.name,
                    node.status.as_str(),
                    self.config.heyvm.runner_wait.as_secs()
                ));
            }
            // Canonical names, so the stored plan and the job row say what the
            // dashboard says rather than whichever of an id and a name somebody
            // typed.
            let network = placement.network.network_name.clone();
            let node = placement.node.map(|n| n.name.clone());
            job.target.network = Some(network);
            if let Some(node) = node {
                job.target.node = Some(node);
            }
        }
        Ok(())
    }

    /// The network a job runs in, resolved against the served pool.
    ///
    /// `plan.target.network` is set by `uses:` or, when the workflow does not
    /// say, stamped in at submit time from the repository's assignment. So by
    /// the time a job is routed the network is already decided — this only has
    /// to find it, and say so clearly when it is not something this instance
    /// serves.
    fn network_of<'a>(
        pool: &'a crate::runners::Pool,
        plan: &JobPlan,
    ) -> Result<&'a crate::runners::RunnerSet, DispatchError> {
        let Some(wanted) = plan.target.network.as_deref().map(str::trim) else {
            return pool.default_set().ok_or(DispatchError::NoNetwork);
        };
        match pool.find(wanted) {
            Some(set) if set.served => Ok(set),
            // The distinction is worth the extra variant: a network that exists
            // but is not served is a `CI_NETWORK` change, while one that does
            // not exist is a typo or a network somebody deleted.
            Some(set) => Err(DispatchError::UnservedNetwork {
                wanted: set.network_name.clone(),
                served: pool.served_names(),
            }),
            None => Err(DispatchError::UnknownNetwork {
                wanted: wanted.to_string(),
                served: pool.served_names(),
            }),
        }
    }

    /// Where a job actually runs: a network, optionally a pinned host, and
    /// optionally an existing VM on it.
    ///
    /// One function for all four `uses:` forms, because the four differ only in
    /// how much of the answer the author supplied — and because routing, runner
    /// selection and submit-time validation must agree. Three call sites reading
    /// `target` separately is how they drift.
    fn place<'a>(
        pool: &'a crate::runners::Pool,
        plan: &'a JobPlan,
    ) -> Result<Placement<'a>, DispatchError> {
        // `uses: default` names no network: it is whichever served network holds
        // this orchestrator's own host.
        if plan.target.local {
            if pool.default_node_id.is_empty() {
                return Err(DispatchError::NoDefaultNode);
            }
            let (network, node) = pool.locate(&pool.default_node_id).ok_or_else(|| {
                DispatchError::DefaultNodeUnserved {
                    node: pool.default_node_id.clone(),
                    served: pool.served_names(),
                }
            })?;
            return Ok(Placement {
                network,
                node: Some(node),
                vm: plan.target.vm.as_deref(),
            });
        }

        let network = Self::network_of(pool, plan)?;
        let Some(wanted) = plan.target.node.as_deref() else {
            return Ok(Placement {
                network,
                node: None,
                vm: None,
            });
        };

        match network.find(wanted) {
            Some(node) => Ok(Placement {
                network,
                node: Some(node),
                vm: plan.target.vm.as_deref(),
            }),
            // `fallback: any` cannot apply to a job that named a VM: the VM
            // exists on one host, and "any host" would run the steps somewhere
            // that does not have it.
            None if plan.fallback == Fallback::Any && plan.target.vm.is_none() => {
                tracing::warn!(
                    node = wanted,
                    network = network.network_name,
                    "no such node in this network; falling back to any host \
                     because the job set `fallback: any`"
                );
                Ok(Placement {
                    network,
                    node: None,
                    vm: None,
                })
            }
            None => Err(DispatchError::UnknownRunner {
                wanted: wanted.to_string(),
                network: network.network_name.clone(),
            }),
        }
    }

    /// Which queue a job goes on.
    ///
    /// A pinned job goes to its host's queue **even when that host is offline**,
    /// unless it opted into `fallback: any`. That is deliberate: the warm pool is
    /// host-local, so silently moving the job discards the cache the pin asked
    /// for. The job waits in that host's queue and the dashboard shows why.
    async fn route_for(&self, plan: &JobPlan) -> Result<Route, DispatchError> {
        let pool = self.runners.snapshot();
        let placement = Self::place(&pool, plan)?;

        // Movable jobs use the shared queue even before a drain, so queued
        // work does not become stranded when its preferred host goes away.
        // Explicit VM targets can never move to a different host.
        if let Some(node) = placement.node
            && (plan.fallback != Fallback::Any || placement.vm.is_some()) {
            return Ok(Route::Runner(node.id.clone()));
        }
        if placement.network.network_id.is_empty() {
            return Err(DispatchError::NoNetwork);
        }
        Ok(Route::Network(placement.network.network_id.clone()))
    }

    // ---- execution ------------------------------------------------------

    /// Run one job to completion. Returns the status it reached.
    pub async fn run_job(
        &self,
        msg: &JobMessage,
        attempt: i32,
    ) -> Result<JobStatus, DispatchError> {
        let Some(row) = self.store.get_job(&msg.job_id).await? else {
            return Err(DispatchError::UnknownJob(msg.job_id.clone()));
        };
        if matches!(
            row.status.as_str(),
            "success" | "failure" | "skipped" | "cancelled"
        ) {
            // A redelivery of work that finished just before its ack was lost.
            tracing::info!(job = %msg.job_key, "already {}; dropping redelivery", row.status);
            return Ok(JobStatus::Success);
        }
        let plan: JobPlan = serde_json::from_value(row.plan.clone())
            .map_err(|e| DispatchError::BadPlan(e.to_string()))?;

        if crate::host_maintenance::owns_job(&self.store, &msg.job_id).await
            .map_err(|e| DispatchError::StepFailed(e.to_string()))?
            || crate::host_heyvm_bootstrap_coordinator::owns_job(&self.store, &msg.job_id).await
            .map_err(|e| DispatchError::StepFailed(e.to_string()))? { return Ok(JobStatus::Running); }
        let (runner, existing_vm) = self.pick_runner(&plan, &msg.run_id).await?;

        // The one place a job's failure and its runner are both in hand. A
        // transport-level failure means the cached iroh tunnel is dead — the
        // daemon restarted, the host rebooted — and every request over it fails
        // identically, so without this the NAK'd retries only rediscover the
        // same dead local port four times. Evicting makes the next attempt
        // redial, which is the repair.
        let result = self
            .run_claimed(msg, attempt, plan, runner.clone(), existing_vm)
            .await;
        if let Err(e) = &result
            && e.is_tunnel_failure()
        {
            self.runners.evict(&runner).await;
        }
        result
    }

    /// The claimed half of [`Self::run_job`]: everything after a runner is
    /// chosen, split out so its errors can be inspected with the runner id
    /// still in hand.
    async fn run_claimed(
        &self,
        msg: &JobMessage,
        attempt: i32,
        mut plan: JobPlan,
        runner: String,
        existing_vm: Option<String>,
    ) -> Result<JobStatus, DispatchError> {
        // Said before the VM exists, not after. Getting one means an iroh dial
        // and a boot, and until this the job stayed `queued` with no runner for
        // the whole of it — so a build that was three minutes into booting and
        // one nothing had touched looked the same on every page, and the
        // waiting-for-a-runner reaper could not tell them apart either.
        //
        // Another delivery may already own this job. Redelivery cannot grant
        // a second execution, even if the first controller stopped heartbeating.
        // Use the reason recorded by the claim transaction. Re-reading drain
        // or cordon state here can race a resume and ACK an unclaimed job.
        match self.store.claim_job_for_boot(&msg.job_id, &runner, attempt, self.executor.boot_id()).await? {
            JobClaim::Claimed => {}
            JobClaim::InstanceDraining => return Err(DispatchError::InstanceDraining),
            JobClaim::RunnerCordoned => return Err(DispatchError::MaintenancePaused),
            JobClaim::Unavailable => {
                tracing::info!(job = %msg.job_key, "job already owned or no longer runnable; dropping duplicate delivery");
                return Ok(JobStatus::Running);
            }
        }
        let mut preparation_quiescent = false;
        let result = async {
        tracing::info!(job = %plan.key, runner = %runner, attempt, "acquiring a VM");

        // CI owns disposable job machines, not a stopped VM cache. Keep parsing
        // legacy `reuse` declarations, but never retain their disks or /30s.
        if !plan.target.is_existing_vm() {
            plan.vm.reuse = false;
        }
        let needs_source = existing_vm.is_none()
            && (plan.vm.build.is_some() || !plan.vm.cache_key_files.is_empty());
        let prepared = if needs_source {
            match self.prepare_source(&runner, &plan, msg, Duration::from_secs(40 * 60)).await {
                Ok(source) => Some(source),
                Err(error) => {
                    // At this first preparation call no image request exists.
                    // Credential resolution happens before contacting the runner,
                    // so even a secret transport failure leaves no host work.
                    // A terminal source failure or unsupported endpoint is
                    // conclusive; runner expiry/transport/protocol errors are not.
                    preparation_quiescent = matches!(&error, DispatchError::Secrets(_) | DispatchError::Image(
                        crate::image::ImageError::Source(_) | crate::image::ImageError::Capability));
                    return Err(error);
                }
            }
        } else { None };

        // `vm.build` becomes `vm.image` here, building the image on the runner
        // if that host does not have it yet. Resolved before the fingerprint is
        // taken, so the pool keys on the image that will actually be used — and
        // since that name is the hash of the Dockerfile and its context, editing
        // the Dockerfile busts the warm pool as well as the image, which is
        // exactly right: a VM built from the old rootfs is not reusable for a
        // job that asked for the new one.
        //
        // On the *local* plan only. The stored plan keeps what the author wrote,
        // so a redelivery re-derives the name rather than inheriting one.
        let disk_requirement = runner_disk_requirement(&plan.vm);
        if existing_vm.is_none() && let Some(build) = plan.vm.build.clone() {
            let image = match self
                .ensure_image(&runner, &plan, &build, prepared.as_ref().expect("build requires preparation"), msg)
                .await {
                    Ok(image) => image,
                    Err(error) => {
                        // Only the daemon's terminal build response settles
                        // image work. Source replay failures do not settle it.
                        preparation_quiescent = matches!(&error, DispatchError::Image(crate::image::ImageError::Build { .. }));
                        return Err(error);
                    }
                };
            plan.vm.image = Some(image);
            plan.vm.build = None;
        }
        preparation_quiescent = true;

        // Persist before acquire_vm (including disk reclamation), or opening
        // an existing VM. Cancellation and pre-VM finalization cannot race past
        // this boundary; instance drain still allows already-claimed work.
        if !self.store.begin_job_execution(&msg.job_id, attempt, self.executor.boot_id()).await? {
            return Err(DispatchError::Cancelled("job ended before VM acquisition".into()));
        }

        // Two ways to get a machine, and they share nothing but the handle.
        //
        // A job that named a VM in `uses:` runs in one that already exists: no
        // fingerprint, no pool, no creation, and — see `release_vm` — no
        // teardown. The `vm:` block is inert for it. Everything else builds or
        // claims one from the warm pool as usual.
        let (vm, reused, fingerprint) = match existing_vm.as_deref() {
            Some(wanted) => {
                let sandbox_id = self.resolve_existing_vm(&runner, wanted).await?;
                let options = self.runners.options_for(&runner).await?;
                let vm = self.vms.open(options, sandbox_id).await?;
                // It may simply be stopped, which is recoverable and worth
                // recovering: somebody pointed a job at this VM deliberately.
                vm.ensure_running(BOOT_TIMEOUT).await?;
                tracing::info!(
                    job = %plan.key, vm = vm.id(),
                    "using an existing VM; the `vm:` block is not applied to it"
                );
                // Not a pool fingerprint, because nothing about this VM was
                // decided by one. The column still has to say something, and
                // saying `existing` is more use than an unrelated hash.
                (vm, true, "existing".to_string())
            }
            None => {
                let empty = std::collections::BTreeMap::new();
                let cache_keys = prepared.as_ref().map(|p| &p.cache_keys).unwrap_or(&empty);
                let fingerprint = crate::pool::fingerprint(&plan.vm, cache_keys)?;
                let (vm, reused) = self
                    .acquire_vm(&runner, &plan, &fingerprint, &msg.job_id, disk_requirement)
                    .await?;
                (vm, reused, fingerprint)
            }
        };

        if !self
            .store
            .start_job_for_boot(&msg.job_id, &runner, vm.id(), &fingerprint, attempt,
                self.executor.boot_id())
            .await?
        {
            // Something else finished this job while we were booting a VM.
            if !plan.target.is_existing_vm() {
                crate::vm_cleanup::handoff(self, &msg.job_id, &runner, attempt, vm.id(),
                    JobStatus::Cancelled, None).await
                    .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
            } else if self.release_vm(&plan, &vm, false).await {
                self.store.end_host_work(&msg.job_id, &runner, attempt).await?;
            }
            return Ok(JobStatus::Success);
        }
        tracing::info!(
            job = %plan.key, runner = %runner, vm = vm.id(), reused,
            "running"
        );

        let outcome = async {
            vm.ensure_running(BOOT_TIMEOUT).await?;
            self.ensure_sized(&plan, &runner, &vm).await?;
            self.checkout(msg, &plan, &vm).await?;
            self.run_steps(msg, &plan, &vm, attempt).await
        }.await;
        // Durable maintenance owns strict VM stop/release and final job status.
        // Do not stop or repool here: another reconciler may already have done
        // so and that VM might now belong to a different job.
        if crate::host_maintenance::owns_job(&self.store, &msg.job_id).await
            .map_err(|e| DispatchError::StepFailed(e.to_string()))?
            || crate::host_heyvm_bootstrap_coordinator::owns_job(&self.store, &msg.job_id).await
            .map_err(|e| DispatchError::StepFailed(e.to_string()))? { return Ok(JobStatus::Running); }
        // Before the release, always: a VM with `reuse: false` is destroyed on
        // the next line, and the console of the boot that just failed is exactly
        // what somebody wants when a job dies before its first step.
        self.capture_vm_log(msg, &plan, &vm).await;
        let guest_corrupted = outcome
            .as_ref()
            .err()
            .is_some_and(DispatchError::indicates_guest_corruption);

        // A tunnel that dies mid-job fails the job rather than propagating —
        // the match below absorbs the error into a status — so the eviction in
        // `run_job` never sees it. Done here so the *next* job redials instead
        // of inheriting the dead port.
        if let Some(e) = outcome.as_ref().err()
            && e.is_tunnel_failure()
        {
            self.runners.evict(&runner).await;
        }

        let status = match &outcome {
            Ok(outputs) => {
                // Cancellation can win after the final step. It must suppress
                // outputs without skipping the VM's cleanup handoff below.
                self.store.set_job_outputs_for_boot(&msg.job_id, outputs, attempt,
                    self.executor.boot_id()).await?;
                JobStatus::Success
            }
            // Cancelled stays cancelled. `continue_on_error` is about a step
            // failing, not about somebody stopping the run — and writing
            // `failure` here would overwrite the status that cancelling just
            // set, making a deliberate stop look like a broken build.
            Err(DispatchError::Cancelled(_)) => JobStatus::Cancelled,
            Err(_) if plan.continue_on_error => JobStatus::Success,
            Err(_) => JobStatus::Failure,
        };
        let error = outcome.as_ref().err().map(|e| e.to_string());
        if !plan.target.is_existing_vm() {
            crate::vm_cleanup::handoff(self, &msg.job_id, &runner, attempt, vm.id(),
                status, error.as_deref()).await
                .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
            // The durable reconciler owns retries, including after restart.
            // No more guest commands or direct release after this handoff.
            if let Err(e) = crate::vm_cleanup::reconcile(self).await {
                tracing::warn!("could not reconcile VM cleanup: {e}");
            }
        } else {
            if self.release_vm(&plan, &vm, guest_corrupted).await && outcome.is_ok() {
                self.store.end_host_work(&msg.job_id, &runner, attempt).await?;
            }
            self.store.set_job_status_for_boot(&msg.job_id, status, error.as_deref(), attempt,
                self.executor.boot_id()).await?;
        }
        Ok(status)
        }.await;
        // Only the delivery that actually acquired this claim may finalize it.
        // A dropped outer future retains ownership: it did not reach this point.
        if let Err(error) = &result {
            if error.is_tunnel_failure() { self.runners.evict(&runner).await; }
            if let Some(status) = self.store.finish_job_preparation(&msg.job_id, attempt,
                self.executor.boot_id(), &error.to_string(), preparation_quiescent).await? {
                return Ok(status);
            }
        }
        result
    }

    /// Reconstruct this run's immutable source on a runner. This owns secret
    /// resolution so every replay gets a fresh job-scoped checkout credential.
    async fn prepare_source(
        &self,
        runner: &str,
        plan: &JobPlan,
        msg: &JobMessage,
        deadline: Duration,
    ) -> Result<crate::image::PreparedSource, DispatchError> {
        let descriptor = self.store.source_descriptor(&msg.run_id).await?;
        let run = self.store.get_run(&msg.run_id).await?.ok_or_else(|| {
            DispatchError::Checkout(format!("run {} disappeared before source preparation", msg.run_id))
        })?;
        if !production_repo_url(&run.repo_url) {
            return Err(DispatchError::Checkout("the canonical repository URL is not safe for runner checkout".into()));
        }
        let workflow_hashes = descriptor.workflows.iter().map(|(path, yaml)| {
            (path.clone(), hex::encode(sha2::Sha256::digest(yaml.as_bytes())))
        }).collect();
        let environment = plan.env.get("CI_ENVIRONMENT").cloned().unwrap_or_else(|| "default".into());
        let resolved = self.secrets.resolve(&crate::secrets::Secrets::prefix_for(&run, &environment))
            .await.map_err(|e| DispatchError::Secrets(format!("resolving source credential: {e}")))?;
        let git_auth_token = resolved.secrets.get("CI_GIT_AUTH_TOKEN")
            .or_else(|| resolved.secrets.get("GITHUB_TOKEN")).cloned();
        let mut cache_key_files = plan.vm.cache_key_files.clone();
        cache_key_files.sort();
        cache_key_files.dedup();
        let image_build = plan.vm.build.as_ref().map(|build| crate::image::PrepareImageBuild {
            dockerfile: build.dockerfile.clone(), context: build.context.clone(),
            size_mb: build.size_mb, driver: "firecracker",
        });
        let request = crate::image::PrepareRequest {
            repository_url: run.repo_url, base_revision: descriptor.base_revision,
            target_tree: descriptor.target_tree, patch_base64: descriptor.patch_base64,
            workflow_hashes, cache_key_files, image_build, git_auth_token,
        };
        let options = self.runners.options_for(runner).await?;
        Ok(crate::image::prepare_remote(options, &request, deadline).await?)
    }

    /// Resolve the plan's target to a concrete online runner, and the existing
    /// VM on it when `uses:` named one.
    ///
    /// Both come from one [`Self::place`] call rather than the caller re-reading
    /// `target`: the node and the VM are one decision, and reading the target
    /// twice is how the queue a job was routed to and the machine it runs on
    /// come to disagree.
    async fn pick_runner(&self, plan: &JobPlan, run: &str) -> Result<(String, Option<String>), DispatchError> {
        let pool = self.runners.snapshot();
        let placement = Self::place(&pool, plan)?;
        // `place` only ever yields a VM alongside the node holding it, so this
        // cannot name a VM without saying where it is.
        let vm = placement.vm.map(str::to_string);

        let driver = driver_name(plan.vm.driver);

        let mut pinned = placement.node;
        if let Some(node) = pinned {
            let cordoned = crate::host_maintenance::cordoned(&self.store, &node.id).await
                .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
            if (cordoned || !node.status.is_dispatchable()) && plan.fallback == Fallback::Any && vm.is_none() {
                pinned = None;
            } else if cordoned {
                return Err(DispatchError::MaintenancePaused);
            }
        }
        if let Some(node) = pinned {
            if !node.status.is_dispatchable() {
                return Err(DispatchError::RunnerOffline {
                    runner: node.name.clone(),
                    status: node.status.as_str(),
                });
            }
            // A pinned job still gets the capability check — a firecracker
            // job pinned to a macbook fails *here*, by name, rather than as
            // whatever the wrong daemon's create error happens to say. A VM
            // named by `uses:` skips it: the VM already exists there, so the
            // question is settled. "Cannot tell" and "cannot ask" both let the
            // pin stand; the pin was explicit, and the job's own failure will
            // be attributed to the runner either way.
            if vm.is_none()
                && let Ok(Some(supported)) = self.runners.supported_drivers(&node.id).await
                && !host_can_run(Some(&supported), driver)
            {
                return Err(DispatchError::RunnerCannotRun {
                    runner: node.name.clone(),
                    driver,
                    supported: supported.join(", "),
                });
            }
            if vm.is_none() {
                self.reclaim_disk_space(&node.id, runner_disk_requirement(&plan.vm)).await?;
            }
            return Ok((node.id.clone(), vm));
        }
        // Unpinned: compare fresh disk capacity on every compatible host.
        // Liveness alone does not make a full host eligible for a new VM.
        let required = runner_disk_requirement(&plan.vm);
        let mut candidates = Vec::new();
        let mut skipped: Vec<String> = Vec::new();
        let mut maintenance = false;
        for candidate in placement.network.dispatchable() {
            if crate::host_maintenance::cordoned(&self.store, &candidate.id).await
                .map_err(|e| DispatchError::StepFailed(e.to_string()))? { maintenance = true; continue; }
            match self.runners.supported_drivers(&candidate.id).await {
                Ok(Some(supported)) if !host_can_run(Some(&supported), driver) => {
                    skipped.push(format!(
                        "{} supports {}",
                        candidate.name,
                        supported.join(", ")
                    ));
                }
                Ok(_) => match self.reclaim_disk_space(&candidate.id, required).await {
                    Ok(free) => {
                        candidates.push((candidate.id.clone(), free));
                    }
                    Err(e) => skipped.push(format!("{} capacity unavailable: {e}", candidate.name)),
                },
                Err(e) => {
                    tracing::warn!(
                        runner = %candidate.name,
                        "skipping for this job; its capabilities could not be read: {e}"
                    );
                    skipped.push(format!("{} could not be reached", candidate.name));
                }
            }
        }
        // Keep successive jobs together when possible, without binding an
        // entire run to a server. Eligibility was checked above on every claim.
        let previous: Option<String> = sqlx::query_scalar("SELECT runner_hd_id FROM ci_job WHERE run_id=$1 AND runner_hd_id IS NOT NULL ORDER BY started_at DESC NULLS LAST,id DESC LIMIT 1")
            .bind(run).fetch_optional(self.store.pool()).await
            .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
        if let Some(previous) = previous
            && candidates.iter().any(|(id, _)| id == &previous) {
            return Ok((previous, vm));
        }
        if let Some(runner) = roomiest_runner(candidates, required) {
            return Ok((runner, vm));
        }
        if maintenance { return Err(DispatchError::MaintenancePaused); }
        if skipped.is_empty() {
            return Err(DispatchError::NoOnlineRunner(
                placement.network.network_name.clone(),
            ));
        }
        Err(DispatchError::NoCapableRunner {
            network: placement.network.network_name.clone(),
            driver,
            skipped: skipped.join("; "),
        })
    }

    /// Resolve `vm.build` to an image name, building it on `runner` if that
    /// host does not already have it.
    ///
    /// The name is the content hash of the Dockerfile and its context, so this
    /// is a cache lookup that happens to be able to fill itself: the same
    /// Dockerfile asks for an image the host already has, and any change asks
    /// for one it does not.
    ///
    /// The build itself runs on the runner — its daemon runs the same
    /// docker → export → mke2fs pipeline `heyvm mvm build` runs locally, so
    /// the host's docker layer cache applies and no builder VM is booted.
    /// This process sends only a signed descriptor and polls; repository and
    /// image-context bytes never pass through CI.
    ///
    /// Concurrency is settled twice, at two scopes. [`crate::image::Catalog::claim`]
    /// hands exactly one *job* the build and tells the rest to wait, so N jobs
    /// landing on a cold host produce one build request and not N. And the
    /// daemon's own route is idempotent by name, so even the claim being lost
    /// — a lapsed lease handing the build to a second dispatcher — collapses
    /// into one docker build rather than two racing for the same tag.
    async fn ensure_image(
        &self,
        runner: &str,
        plan: &JobPlan,
        build: &crate::vm::ImageBuild,
        prepared: &crate::image::PreparedSource,
        msg: &JobMessage,
    ) -> Result<String, DispatchError> {
        /// How long to wait — for somebody else's build of the same image, and
        /// for one this job runs itself. One bound for both, because a waiter
        /// that gives up before the builder finishes fails a job the next
        /// delivery would have found ready.
        const BUILD_BUDGET: Duration = Duration::from_secs(40 * 60);
        const WAIT_POLL: Duration = Duration::from_secs(10);

        let prepared_image = prepared.image.as_ref().ok_or_else(|| crate::image::ImageError::Protocol(
            "source preparation omitted image metadata".into()))?;
        let name = prepared_image.name.clone();
        let input_digest = prepared_image.input_digest.clone();

        let deadline = std::time::Instant::now() + BUILD_BUDGET;
        loop {
            match self
                .images
                .claim(
                    &name,
                    runner,
                    &plan.base_id,
                    &msg.job_id,
                    crate::image::BUILD_LEASE,
                )
                .await?
            {
                crate::image::Claim::Ready => {
                    tracing::info!(job = %plan.key, runner, "image {name} is already on this host");
                    // Validate with the source builder even on catalog hits.
                    // It rebuilds a missing file in this attempt, and joins an
                    // existing build instead of failing the job on stale state.
                    break;
                }
                crate::image::Claim::Build => break,
                crate::image::Claim::InProgress => {
                    if std::time::Instant::now() >= deadline {
                        return Err(crate::image::ImageError::WaitTimeout {
                            name,
                            waited: BUILD_BUDGET,
                        }
                        .into());
                    }
                    tracing::info!(
                        job = %plan.key,
                        "another job is building image {name} on {runner}; waiting"
                    );
                    tokio::time::sleep(WAIT_POLL).await;
                }
            }
        }

        // This job owns a build claim or is verifying a cached image. The
        // daemon collapses concurrent requests for identical verified inputs.
        tracing::info!(
            job = %plan.key, runner,
            "asking the runner to build image {name} from {}", build.dockerfile
        );
        let mut current = prepared.clone();
        let mut replays = 0usize;
        let outcome = loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break Err(crate::image::ImageError::BuildTimeout { name: name.clone(), after: BUILD_BUDGET });
            }
            let options = self.runners.options_for(runner).await?;
            let result = crate::image::build_remote(options, &current.source_id, &name, remaining, || async {
                if let Err(e) = self.images.renew(&name, runner, crate::image::BUILD_LEASE).await {
                    tracing::warn!("could not renew the image build claim: {e}");
                }
            }).await;
            if !matches!(result, Err(crate::image::ImageError::SourceExpired)) {
                break result;
            }
            if replays >= 2 {
                break Err(crate::image::ImageError::Source("prepared source repeatedly expired during image build".into()));
            }
            replays += 1;
            // Keep the shared image-name lock live while source is recreated.
            self.images.renew(&name, runner, crate::image::BUILD_LEASE).await?;
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break Err(crate::image::ImageError::BuildTimeout { name: name.clone(), after: BUILD_BUDGET });
            }
            let replay = self.prepare_source(runner, plan, msg, remaining);
            tokio::pin!(replay);
            let replayed = loop {
                tokio::select! {
                    result = &mut replay => break result?,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        self.images.renew(&name, runner, crate::image::BUILD_LEASE).await?;
                    }
                }
            };
            self.images.renew(&name, runner, crate::image::BUILD_LEASE).await?;
            let replayed_image = replayed.image.as_ref().ok_or_else(|| crate::image::ImageError::Protocol(
                "replayed source preparation omitted image metadata".into()))?;
            if replayed_image.name != name || replayed_image.input_digest != input_digest {
                break Err(crate::image::ImageError::Protocol(format!(
                    "replayed source changed image metadata from ({name}, {input_digest}) to ({}, {})",
                    replayed_image.name, replayed_image.input_digest
                )));
            }
            current = replayed;
        };

        match outcome {
            Ok(built) => {
                self.attach_build_log(msg, plan, &name, &built.log).await;
                self.images
                    .mark_ready(&name, runner, built.size_bytes)
                    .await?;
                tracing::info!(
                    job = %plan.key,
                    "image {name} is ready ({} bytes)", built.size_bytes
                );
                Ok(name)
            }
            Err(e) => {
                let detail = e.to_string();
                // Recorded before the job fails, so /vms says why rather than
                // leaving the reason only in this process's log.
                if let Err(e) = self.images.mark_failed(&name, runner, &detail).await {
                    tracing::warn!("could not record the failed image build: {e}");
                }
                self.attach_build_log(msg, plan, &name, &format!("[ci] {detail}\n"))
                    .await;
                Err(e.into())
            }
        }
    }

    /// Attach an image build's log to the job, as a step at index `-3`.
    ///
    /// The same trick checkout uses at `-1` and the VM console at `-2`: it needs
    /// a row, a file on disk and a place in the UI, and a step already is all
    /// three — including the retention sweep. Never fails the job; a log that
    /// could not be written must not turn a successful build into a failure.
    async fn attach_build_log(&self, msg: &JobMessage, plan: &JobPlan, name: &str, text: &str) {
        let sid = format!("{}.imglog", msg.job_id);
        if let Err(e) = self
            .store
            .create_step(&sid, &msg.job_id, -3, &format!("Image {name}"), None)
            .await
        {
            tracing::warn!(job = %plan.key, "could not record the image build step: {e}");
            return;
        }
        let path = self.store.log_path(&msg.run_id, &plan.key, -3, &sid);
        if let Err(e) = self.store.append_log(&sid, &path, text).await {
            tracing::warn!(job = %plan.key, "could not write the image build log: {e}");
        }
        let _ = self
            .store
            .finish_step(&sid, StepStatus::Success, Some(0), None)
            .await;
    }

    /// A VM for this job: an inherited one if the fingerprint matches, else new.
    async fn acquire_vm(
        &self,
        runner: &str,
        plan: &JobPlan,
        fingerprint: &str,
        job_id: &str,
        required: u64,
    ) -> Result<(Vm, bool), DispatchError> {
        let options = self.runners.options_for(runner).await?;

        if plan.vm.reuse
            && let Some(sandbox_id) = self
                .pool
                .claim(runner, fingerprint, job_id, self.lease())
                .await?
        {
            let vm = match self.vms.open(options.clone(), sandbox_id.clone()).await {
                Ok(vm) => vm,
                Err(e) => {
                    // Not a verdict on the VM: the dial failed before anything
                    // was asked of it. Hand the row back so the retry finds it.
                    let _ = self.pool.release(&sandbox_id).await;
                    return Err(e.into());
                }
            };
            // A pooled VM is *stopped* between jobs — `release_vm` parks it
            // that way on purpose — so starting it is the normal path here,
            // not a recovery. What is and is not recoverable:
            //
            // - A transport failure (the tunnel, the daemon not answering) says
            //   nothing about the machine. Discarding it on that would throw
            //   away a warm cache every time the runner blinked, which is the
            //   single most expensive thing this code can do; the row goes
            //   back to idle and the delivery fails so the ladder retries.
            // - Anything else — the daemon does not know the id, refuses to
            //   start it, reports it failed — means the VM is gone or broken.
            //   It is destroyed, not merely forgotten: a stopped VM is outside
            //   the daemon's TTL, so a forgotten one would keep its disks for
            //   ever with no row left to find them by.
            match vm.ensure_running(BOOT_TIMEOUT).await {
                Ok(()) => {
                    let _ = vm.renew_ttl(self.config.heyvm.vm_ttl).await;
                    // Checked on every claim, not only at creation: a restart
                    // is exactly when a daemon could bring a VM back at a
                    // different size, and a manual resize since the last job
                    // is what the page should show — and what must not start
                    // a build that cannot finish.
                    if let Err(e) = self.ensure_sized(plan, runner, &vm).await {
                        // Parked, not destroyed: the cache is intact, and the
                        // row on /vms is where somebody fixes the size.
                        self.release_vm(plan, &vm, false).await;
                        return Err(e);
                    }
                    return Ok((vm, true));
                }
                Err(e) if e.is_transport() => {
                    tracing::warn!(
                        vm = %sandbox_id,
                        "could not reach the pooled VM; keeping it for the retry: {e}"
                    );
                    let _ = self.pool.release(&sandbox_id).await;
                    return Err(e.into());
                }
                Err(e) => {
                    tracing::warn!(
                        vm = %sandbox_id,
                        "pooled VM is unusable; destroying it and building a fresh one: {e}"
                    );
                    match vm.destroy().await {
                        Ok(())
                            if matches!(
                                vm.info().await,
                                Err(VmError::Daemon {
                                    source: heyo_sdk::HeyoError::NotFound(_),
                                    ..
                                })
                            ) =>
                        {
                            self.pool.forget(&sandbox_id).await?;
                        }
                        Ok(()) => return Err(DispatchError::StepFailed(
                            format!("daemon did not confirm destruction of {sandbox_id}; retaining pool ownership")
                        )),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }

        // A warm claim above needs no new disks. A cold create must recheck:
        // image building or another job may have consumed admission headroom.
        self.reclaim_disk_space(runner, required).await?;

        let name = sandbox_name(
            &plan.base_id,
            fingerprint,
            NONCE.fetch_add(1, Ordering::Relaxed),
        );

        // Recorded before the attempt, so /vms shows the machine while it is
        // coming up rather than only once it has. This is the longest silent
        // stretch of a job — `create` waits out `BOOT_TIMEOUT` for a cold VM —
        // and it is also where a workflow naming an image the host does not have
        // fails, over and over on the redelivery ladder, with nothing on any
        // page to say so.
        //
        // Best-effort: a database hiccup here must not cost a build. The row is
        // for looking at.
        let building = match self
            .pool
            .begin_build(
                job_id,
                runner,
                fingerprint,
                &plan.base_id,
                plan.vm.size_class.map(|s| s.as_str()),
                self.lease(),
            )
            .await
        {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(job = %plan.key, "could not record the VM as building: {e}");
                None
            }
        };
        tracing::info!(
            job = %plan.key, runner = %runner, image = plan.vm.image.as_deref().unwrap_or("(default)"),
            "creating VM {name}"
        );

        let mut created = self
            .vms
            .create(
                options.clone(),
                &name,
                &plan.vm,
                self.config.heyvm.vm_ttl,
            )
            .await;

        // A /24 supplies only 64 /30 TAP links. Stopped reusable CI caches
        // retain those links, so an explicit capacity verdict may evict one
        // idle cache on this exact runner and retry this create once. Unknown,
        // transport and timeout failures are intentionally not destructive.
        if created.as_ref().is_err_and(VmError::is_subnet_capacity)
            && let Some(cache) = self.pool.take_oldest_idle(runner).await?
        {
            tracing::info!(
                runner,
                sandbox = %cache.sandbox_id,
                "evicting idle CI cache for VM subnet headroom"
            );
            let (destroyed, failed) = self.destroy_swept(vec![cache]).await;
            if destroyed == 1 && failed.is_empty() {
                created = self.vms.create(
                    options,
                    &name,
                    &plan.vm,
                    self.config.heyvm.vm_ttl,
                ).await;
            }
        }

        // Whichever way it went, the placeholder goes: it stands for an attempt
        // in flight, and on success `register` below writes the real row under
        // the id the daemon assigned. Dropped before `?` on the result, or a
        // failed create would leave it behind until the lease swept it.
        if let Some(id) = &building
            && let Err(e) = self.pool.forget(id).await
        {
            tracing::warn!(job = %plan.key, "could not clear the building row {id}: {e}");
        }

        // The catalog says this host has the image; the daemon says otherwise.
        // Somebody deleted the `.ext4` by hand, or the host was rebuilt. Forget
        // the row so the next delivery builds it again rather than failing on
        // the same missing file for ever — the same self-healing `claim` above
        // does for a pooled VM the daemon lost.
        if let Err(e) = &created
            && let Some(image) = plan.vm.image.as_deref()
            && image.starts_with("ci-img-")
            && e.to_string().contains("not found")
        {
            tracing::warn!(
                job = %plan.key,
                "{runner} does not have image {image} after all; forgetting it so the \
                 next attempt rebuilds: {e}"
            );
            let _ = self.images.forget(image, runner).await;
        }
        let vm = created?;

        self.pool
            .register(
                vm.id(),
                runner,
                fingerprint,
                &plan.base_id,
                plan.vm.size_class.map(|s| s.as_str()),
                job_id,
                self.lease(),
            )
            .await?;
        // Boot and sizing checks run after start_job records this exact VM;
        // their failures must enter the same durable cleanup as failed steps.
        Ok((vm, false))
    }

    /// Refuse to start a job on a VM smaller than its `size_class`.
    ///
    /// A `large` build on a `small` VM does not run slowly; it runs out its
    /// timeout, every time, and the 75 minutes that takes are the most
    /// expensive way there is to learn that the runner did not size the VM —
    /// which is what this used to cost: `observe_size` warned in the log and
    /// the build went ahead. Now a VM the daemon reports as smaller than
    /// declared is resized back to the declared class once — the daemon does
    /// that in place, disks kept, so a warm cache survives — and if it is
    /// still too small afterwards, or the resize failed, the job fails here
    /// naming both sizes and what was tried. The caller parks the VM; a retry
    /// on the ladder checks it again, so a resize from /vms in the meantime is
    /// enough.
    ///
    /// Only *smaller* is refused. A larger VM — a manual resize up from /vms —
    /// runs the build as the workflow expects and is left alone. A daemon
    /// that reports no size at all cannot be checked, and is warned about as
    /// before rather than refused: an old daemon is not a wrong-sized VM. A
    /// resize that failed in the *transport* is not a verdict on the VM either
    /// and is returned as the `VmError` it is, so the tunnel is evicted and the
    /// retry redials.
    async fn ensure_sized(
        &self,
        plan: &JobPlan,
        runner: &str,
        vm: &Vm,
    ) -> Result<(), DispatchError> {
        let wanted = plan.vm.size_class;
        let Some(size) = self.observe_size(&plan.key, vm, wanted).await else {
            return Ok(());
        };
        let Some(wanted) = wanted else {
            return Ok(());
        };
        if size.check(wanted) != SizeCheck::TooSmall {
            return Ok(());
        }
        let got = size.label();
        tracing::warn!(
            job = %plan.key,
            vm = vm.id(),
            "the VM is {got}, smaller than the {} the job declares; resizing it",
            wanted.as_str()
        );
        let resized = match vm.resize(wanted, BOOT_TIMEOUT).await {
            // An older daemon hands the VM back running; a newer one may
            // leave it stopped. Either way it must be up for the check and
            // the checkout that follows.
            Ok(()) => vm.ensure_running(BOOT_TIMEOUT).await,
            Err(e) => Err(e),
        };
        let then = match resized {
            Err(e) if e.is_transport() => return Err(e.into()),
            Err(e) => format!("the resize to {} failed: {e}", wanted.as_str()),
            Ok(()) => match self.observe_size(&plan.key, vm, Some(wanted)).await {
                Some(after) if after.check(wanted) != SizeCheck::TooSmall => {
                    tracing::info!(
                        job = %plan.key,
                        vm = vm.id(),
                        "resized to {}; the build can go ahead",
                        after.label()
                    );
                    return Ok(());
                }
                Some(after) => format!(
                    "the resize to {} did not take — the daemon still reports {}",
                    wanted.as_str(),
                    after.label()
                ),
                None => format!(
                    "after a resize to {} its size could not be read back",
                    wanted.as_str()
                ),
            },
        };
        Err(DispatchError::VmTooSmall(Box::new(UndersizedVm {
            job: plan.key.clone(),
            vm: vm.id().to_string(),
            runner: runner.to_string(),
            wanted: wanted.as_str(),
            got,
            then,
        })))
    }

    /// Read what the daemon says the VM was given, record it on the pool row,
    /// and say so if it is not what the job declared.
    ///
    /// `size_class` is passed straight through `POST /sandbox-deploy`, and a
    /// daemon that honours it sizes the VM from it — but until this nothing
    /// here could tell, and a `xlarge` job quietly running on the daemon's
    /// `small` default looks exactly like a slow build. The reading is the
    /// daemon's own (`Vm::size`): the class it named, or the tier the VM's
    /// cpus and memory match, or just the numbers from a daemon that names no
    /// class, or nothing from one too old to report sizing at all. Each of
    /// those is shown as such on /vms. This reads and records only; whether
    /// the build may start on what it got is [`Self::ensure_sized`]'s call.
    async fn observe_size(
        &self,
        job: &str,
        vm: &Vm,
        wanted: Option<heyo_sdk::SandboxSize>,
    ) -> Option<crate::vm::VmSize> {
        let size = match vm.size().await {
            Ok(size) => size,
            Err(e) => {
                tracing::warn!(job, vm = vm.id(), "could not read the VM's size: {e}");
                return None;
            }
        };
        if let Err(e) = self.pool.record_size(vm.id(), &size).await {
            tracing::warn!(job, vm = vm.id(), "could not record the VM's size: {e}");
        }
        let got = size.label();
        match wanted {
            None => tracing::info!(job, vm = vm.id(), size = %got, "VM size"),
            Some(wanted) => match size.check(wanted) {
                SizeCheck::AsDeclared => {
                    tracing::info!(job, vm = vm.id(), size = %got, "VM sized as declared")
                }
                SizeCheck::Larger => tracing::info!(
                    job,
                    vm = vm.id(),
                    size = %got,
                    "VM is larger than the {} declared; fine",
                    wanted.as_str()
                ),
                SizeCheck::TooSmall => tracing::warn!(
                    job,
                    vm = vm.id(),
                    "asked for a {} VM and got {got}; the build would not run as the \
                     workflow expects — check the runner's heyvmd, or resize it from /vms",
                    wanted.as_str()
                ),
                SizeCheck::Unreported => tracing::warn!(
                    job,
                    vm = vm.id(),
                    "asked for a {} VM; the runner's daemon does not report sizing, so \
                     whether it complied cannot be checked from here",
                    wanted.as_str()
                ),
            },
        }
        Some(size)
    }

    /// Attach the VM's own console to the run.
    ///
    /// Recorded as a step at index `-2`, the same trick checkout uses at `-1`:
    /// it needs a row, a log file on disk and a place in the UI, and a step
    /// already is all three — including the retention sweep, which walks step
    /// logs and would otherwise miss a log kept anywhere else.
    ///
    /// **Never fails the job.** By the time this runs the steps have already
    /// decided the outcome, and a job that passed must not be reported as failed
    /// because a diagnostic could not be fetched.
    async fn capture_vm_log(&self, msg: &JobMessage, plan: &JobPlan, vm: &Vm) {
        let sid = format!("{}.vmlog", msg.job_id);
        if let Err(e) = self
            .store
            .create_step(&sid, &msg.job_id, -2, "VM log", None)
            .await
        {
            tracing::warn!(job = %plan.key, "could not record the VM log step: {e}");
            return;
        }

        let capture = async {
            let run = self.store.get_run(&msg.run_id).await?
                .ok_or_else(|| anyhow::anyhow!("run no longer exists"))?;
            let environment = plan.env.get("CI_ENVIRONMENT").map(String::as_str).unwrap_or("default");
            let resolved = self.secrets.resolve(&crate::secrets::Secrets::prefix_for(&run, environment)).await?;
            let masker = resolved.masker();
            let mut text = match vm.info().await {
                Ok(info) => format!("[ci] VM {} status={:?} size={:?}\n", info.id, info.status, info.size_class),
                Err(error) => format!("[ci] VM metadata unavailable: {error}\n"),
            };
            text.push_str(&format!("[ci] console capture limit: {} lines\n", self.config.vm_log_lines));
            match vm.logs(self.config.vm_log_lines).await {
                Ok(log) => text.push_str(&log),
                Err(error) => text.push_str(&format!("[ci] VM console unavailable: {error}\n")),
            }
            Ok::<_, anyhow::Error>(masker.mask(&text))
        };
        let text = match tokio::time::timeout(Duration::from_secs(40), capture).await {
            Ok(Ok(text)) => text,
            // Do not archive an unredacted guest console when secret resolution
            // fails. Record the gap and continue resource cleanup.
            Ok(Err(_)) => "[ci] VM diagnostics unavailable: could not resolve safe redaction context\n".into(),
            Err(_) => "[ci] VM diagnostics timed out after 40s; cleanup will continue\n".into(),
        };

        let path = self.store.log_path(&msg.run_id, &plan.key, -2, &sid);
        if let Err(e) = self.store.append_log(&sid, &path, &text).await {
            tracing::warn!(job = %plan.key, "could not write the VM log: {e}");
        }
        // Always `success`: this step is a place to hang a log, not a verdict on
        // the job. A red row here would read as the build having failed.
        let _ = self
            .store
            .finish_step(&sid, StepStatus::Success, Some(0), None)
            .await;
    }

    /// Resolve the VM named by `uses: <network>/<node>/<vm>` to a sandbox id.
    ///
    /// By id or by name, the same two spellings a node accepts — `uses:` is
    /// written by hand and the dashboard shows both. Listed from the node the
    /// job is pinned to rather than searched for across the network, which is
    /// exactly what naming the node in the path bought.
    async fn resolve_existing_vm(
        &self,
        runner: &str,
        wanted: &str,
    ) -> Result<String, DispatchError> {
        let options = self.runners.options_for(runner).await?;
        let sandboxes = heyo_sdk::Sandbox::list(options.options.clone()).await.map_err(|e| {
            DispatchError::Vm(crate::vm::VmError::Daemon {
                sandbox: wanted.to_string(),
                what: "listing sandboxes on the node",
                source: e,
            })
        })?;

        if let Some(found) = sandboxes
            .iter()
            .find(|s| s.id == wanted || s.name.eq_ignore_ascii_case(wanted))
        {
            return Ok(found.id.clone());
        }
        Err(DispatchError::UnknownVm {
            wanted: wanted.to_string(),
            node: runner.to_string(),
            available: sandboxes
                .iter()
                .map(|s| {
                    if s.name.is_empty() {
                        s.id.clone()
                    } else {
                        format!("{} ({})", s.name, s.id)
                    }
                })
                .collect(),
        })
    }

    /// Hand the VM back, or destroy it when the workflow said not to reuse.
    ///
    /// Failures here are logged, never propagated: the job's result is already
    /// decided, and turning a green build red because a TTL renewal failed would
    /// be worse than a VM that expires on its own.
    /// `guest_corrupted` is the job's verdict on the VM itself, not on the
    /// work: the guest filesystem returned an error no retry can survive, so
    /// the VM is destroyed even though `reuse` asked for pooling. Repooling it
    /// would hand the next attempt — which prefers an idle VM with the same
    /// fingerprint on the same runner — the same broken ext4, and the job
    /// would burn every delivery on one sick machine.
    async fn release_vm(&self, plan: &JobPlan, vm: &Vm, guest_corrupted: bool) -> bool {
        // A VM named in `uses:` is not ours. It was not created for this job,
        // it is not in the pool, and somebody else's long-lived machine must not
        // be destroyed because a workflow happened to set `reuse: false` in a
        // `vm:` block that never applied to it. Its TTL is left alone for the
        // same reason — renewing it would be this app quietly extending the life
        // of something it does not own. That holds even for corruption: the
        // owner gets a warning, not a destroyed machine.
        if plan.target.is_existing_vm() {
            if guest_corrupted {
                tracing::warn!(
                    vm = vm.id(),
                    "this job saw guest filesystem corruption, but the VM is a `uses:` \
                     target this instance does not own — leaving it as it is"
                );
            }
            return true;
        }
        if guest_corrupted {
            tracing::warn!(
                vm = vm.id(),
                "guest filesystem corruption; destroying the VM instead of repooling it"
            );
        }
        if !plan.vm.reuse || guest_corrupted {
            if let Err(e) = vm.destroy().await {
                tracing::warn!(vm = vm.id(), "could not destroy: {e}");
                // An uncertain teardown is still active drain evidence.
                return false;
            }
            if let Err(e) = self.pool.forget(vm.id()).await {
                tracing::warn!(vm = vm.id(), "could not forget: {e}");
                return false;
            }
            return true;
        }
        // The TTL is what the VM boots with next time — `start` counts it from
        // then — and it honors the workflow's own `ttl_seconds` when that is
        // longer than `CI_VM_TTL_SECONDS`, for the reason app-obs.yml gives: a
        // build longer than the default must not be reaped mid-compile by a
        // runner whose daemon is too old to have its TTL renewed.
        let idle_ttl = idle_pool_ttl(plan.vm.ttl_seconds, self.config.heyvm.vm_ttl);
        if let Err(e) = vm.renew_ttl(idle_ttl).await {
            tracing::warn!(vm = vm.id(), "could not renew the TTL: {e}");
        }
        // Parked, not left running. A pooled VM used to idle *running* until
        // the daemon's TTL reaped it, which made the warm cache a matter of
        // cadence: the next push had to land inside the TTL — an hour by
        // default, four for app-obs.yml — or it booted a blank machine and paid
        // the full cold build. Every gap longer than that, which for a repo
        // pushed to a few times a day is most of them, was cold. Stopped, the
        // VM keeps its rootfs and its cache disk (the daemon removes those on
        // `destroy` only), is outside the TTL reaper (which skips stopped
        // sandboxes), and holds no memory or CPU on the host — an `xlarge`
        // left running is 16 GB nobody is using. `acquire_vm` starts it again
        // on the next claim; the idle sweep is what eventually retires it.
        //
        // Stopped *before* the row goes idle. The other order has a window in
        // which a concurrent claim sees the VM running, then has it stopped
        // out from under its first step.
        if let Err(e) = vm.stop().await {
            // Keep the claim: maintenance must not interpret an unverified
            // stop as a drained host. Its cordon also prevents orphan release.
            tracing::warn!(
                vm = vm.id(),
                "could not stop the VM; retaining its claim: {e}"
            );
            return false;
        }
        if let Err(e) = self.pool.release(vm.id()).await {
            tracing::warn!(vm = vm.id(), "could not release into the pool: {e}");
            return false;
        }
        true
    }

    /// Put the submitted tree into the guest.
    ///
    /// Recorded as a step at index `-1` so it sorts before the workflow's own
    /// steps and shows up in the UI. Checkout failing is the single most common
    /// "why did nothing run" cause, and burying it in the job's error field
    /// makes it the one thing with no log to read.
    ///
    /// The working directory is wiped first. A pooled VM arrives with the
    /// previous job's tree still in it, and a build that succeeds only because a
    /// deleted file is still on disk is the exact failure the pool must not
    /// introduce.
    async fn checkout(
        &self,
        msg: &JobMessage,
        plan: &JobPlan,
        vm: &Vm,
    ) -> Result<(), DispatchError> {
        let sid = format!("{}.checkout", msg.job_id);
        // A redelivery starts from the submitted source again. Do not retain
        // release provenance from a previous VM or attempt.
        sqlx::query("UPDATE ci_job SET release_sha=NULL WHERE id=$1")
            .bind(&msg.job_id).execute(self.store.pool()).await
            .map_err(|e| DispatchError::Checkout(e.to_string()))?;
        self.store
            .create_step(&sid, &msg.job_id, -1, "Checkout", None)
            .await?;
        self.store.start_step(&sid, &sid).await?;
        let log_path = self.store.log_path(&msg.run_id, &plan.key, -1, &sid);

        let descriptor = match self.store.source_descriptor(&msg.run_id).await {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let detail = error.to_string();
                self.store.append_log(&sid, &log_path, &format!("[ci] {detail}\n")).await?;
                self.store.finish_step(&sid, StepStatus::Failure, Some(1), Some(&detail)).await?;
                return Err(error.into());
            }
        };
        let run = self.store.get_run(&msg.run_id).await?.ok_or_else(|| {
            DispatchError::Checkout(format!("run {} disappeared before checkout", msg.run_id))
        })?;
        if !production_repo_url(&run.repo_url) {
            return Err(DispatchError::Checkout(
                "the canonical repository URL must be an https:// or ssh:// URL (or scp-style SSH); local filesystem repository URLs are forbidden".into(),
            ));
        }
        // Promotion executes the persisted operator plan, not a YAML file in
        // Git. Authorize that distinction from the retained bundle record,
        // never from a caller-supplied workflow name or source label. Checkout
        // still verifies the exact original revision and complete source tree.
        let promotion = crate::release_environment::bundle_for_run(&self.store, &msg.run_id)
            .await.map_err(|e| DispatchError::Checkout(e.to_string()))?;
        let workflow_hash = if let Some(bundle) = promotion {
            if plan.release_policy.is_none()
                || bundle["manifest"]["revision"].as_str() != Some(descriptor.base_revision.as_str())
                || !descriptor.patch_base64.is_empty()
            {
                return Err(DispatchError::Checkout("promotion requires its frozen operator plan and exact retained source".into()));
            }
            None
        } else {
            let text = descriptor.workflows.get(&run.workflow_path).ok_or_else(|| {
                DispatchError::Checkout(format!(
                    "planned workflow {} is absent from the durable source descriptor",
                    run.workflow_path
                ))
            })?;
            Some(hex::encode(sha2::Sha256::digest(text.as_bytes())))
        };
        let workdir = plan
            .vm
            .working_directory
            .clone()
            .unwrap_or_else(|| DEFAULT_WORKDIR.to_string());
        // Outside the working directory: checkout begins by deleting that
        // directory so a pooled VM cannot leak files from its previous job.
        let remote = format!("/tmp/ci-source-{}.patch", msg.job_id);
        let patch = descriptor.patch()?;

        // Checkout credentials use the same job-scoped HeyoSecret namespace as
        // steps. They travel only in exec env; neither the persisted command nor
        // the descriptor contains them.
        let environment = plan.env.get("CI_ENVIRONMENT").cloned().unwrap_or_else(|| "default".into());
        let resolved = self.secrets.resolve(&crate::secrets::Secrets::prefix_for(&run, &environment))
            .await.map_err(|e| DispatchError::Secrets(format!("resolving checkout credential: {e}")))?;
        let masker = resolved.masker();
        let mut checkout_env = HashMap::new();
        if let Some(token) = resolved.secrets.get("CI_GIT_AUTH_TOKEN").or_else(|| resolved.secrets.get("GITHUB_TOKEN")) {
            checkout_env.insert("CI_GIT_AUTH_TOKEN".to_string(), token.clone());
        }

        let result = async {
            vm.upload_bytes(&sid, &remote, &patch).await?;
            let workflow = workflow_hash.as_deref().map(|hash| (run.workflow_path.as_str(), hash));
            let script = checkout_script(&workdir, &remote, &run.repo_url, &descriptor, workflow);
            vm.exec(
                &format!("{sid}.x"),
                &script,
                &checkout_env,
                Duration::from_secs(300),
            )
            .await
        }
        .await;

        match result {
            Ok(out) if out.succeeded() => {
                self.store
                    .append_log(
                        &sid,
                        &log_path,
                        &format!(
                            "[ci] source reconstructed from {} patch bytes in {workdir}\n{}",
                            patch.len(),
                            masker.mask(&out.combined())
                        ),
                    )
                    .await?;
                self.store
                    .finish_step(&sid, StepStatus::Success, Some(0), None)
                    .await?;
                Ok(())
            }
            Ok(out) => {
                self.store
                    .append_log(&sid, &log_path, &masker.mask(&out.combined()))
                    .await?;
                self.store
                    .finish_step(&sid, StepStatus::Failure, Some(out.exit_code), None)
                    .await?;
                Err(DispatchError::Checkout(format!(
                    "reconstructing the source exited {}",
                    out.exit_code
                )))
            }
            Err(e) => {
                let detail = masker.mask(&e.to_string());
                self.store
                    .append_log(&sid, &log_path, &format!("[ci] {detail}\n"))
                    .await?;
                self.store
                    .finish_step(&sid, StepStatus::Failure, None, Some(&detail))
                    .await?;
                Err(checkout_error(e))
            }
        }
    }

    /// Run every step, stopping at the first failure that is not tolerated.
    ///
    /// Returns the job's outputs on success.
    async fn run_steps(
        &self,
        msg: &JobMessage,
        plan: &JobPlan,
        vm: &Vm,
        attempt: i32,
    ) -> Result<Value, DispatchError> {
        let needs = self.store.needs_context(&msg.run_id).await?;

        // Once per job, not per step: heyosecret has no batch read, so N secrets
        // is N round trips and doing that per step would multiply it by the step
        // count.
        let run = self.store.get_run(&msg.run_id).await?;
        let workflow_id = run
            .as_ref()
            .map(|r| r.workflow_id.clone())
            .unwrap_or_default();
        let namespace = run
            .as_ref()
            .map(|r| r.namespace.clone())
            .unwrap_or_default();
        // The same scope the scheduler evaluated the job's own `if:` against, so
        // a step condition and a job condition cannot disagree about which
        // commit they are looking at.
        let ci = Self::ci_scope(run.as_ref());
        let environment = plan
            .env
            .get("CI_ENVIRONMENT")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        let prefix = crate::secrets::Secrets::prefix_in(&namespace, &workflow_id, &environment);
        let resolved = self
            .secrets
            .resolve(&prefix)
            .await
            .map_err(|e| DispatchError::Secrets(format!("resolving {prefix}: {e}")))?;
        let masker = resolved.masker();
        let (secret_scope, vars_scope) = resolved.scopes();

        let mut step_outputs = serde_json::Map::new();
        let mut failed: Option<String> = None;

        for (idx, step) in plan.steps.iter().enumerate() {
            // Cancellation is cooperative, and this is where it takes effect.
            // The daemon has no route to abort an exec-operation in flight, so
            // a step that has started runs to its own end or its timeout; what
            // stops is everything after it.
            if self.store.is_job_cancelled(&msg.job_id).await? {
                return Err(DispatchError::Cancelled(plan.key.clone()));
            }
            let sid = step_id(&msg.job_id, idx);
            self.store
                .create_step(
                    &sid,
                    &msg.job_id,
                    idx as i32,
                    &step.label(idx),
                    step.uses.as_deref(),
                )
                .await?;

            let mut ctx = plan.base_context();
            ctx.set("needs", needs.clone());
            ctx.set("steps", Value::Object(step_outputs.clone()));
            ctx.set("secrets", secret_scope.clone());
            ctx.set("vars", vars_scope.clone());
            ctx.set("ci", ci.clone());
            ctx.set_status(if failed.is_some() {
                "failure"
            } else {
                "success"
            });

            // A step after a failure is skipped unless it says otherwise, so
            // `if: always()` is what gets teardown to run.
            let should = match &step.condition {
                Some(c) => ctx
                    .eval_condition(c)
                    .map_err(|e| DispatchError::Condition(e.to_string()))?,
                None => failed.is_none(),
            };
            if !should {
                self.store
                    .finish_step(&sid, StepStatus::Skipped, None, None)
                    .await?;
                continue;
            }

            let Some(run) = &step.run else {
                let action = step.uses.as_deref().unwrap_or("");
                let log_path = self
                    .store
                    .log_path(&msg.run_id, &plan.key, idx as i32, &sid);
                self.store.start_step(&sid, &sid).await?;
                // The submit-time policy already refused these; this is the
                // second door, for a plan that reached the queue another way.
                let outcome = if !namespace.is_empty() && !crate::tenancy::action_allowed(action) {
                    Err(DispatchError::StepFailed(format!(
                        "{action} is not available to namespace runs"
                    )))
                } else {
                    self.run_action(msg, plan, vm, action, step, &ctx, &sid, &log_path, &masker)
                        .await
                };
                match outcome {
                    Ok((note, outputs)) => {
                        if let Some(id) = &step.id {
                            step_outputs.insert(id.clone(), serde_json::json!({
                                "outputs": outputs, "outcome": "success"
                            }));
                        }
                        self.store
                            .append_log(&sid, &log_path, &masker.mask(&note))
                            .await?;
                        if action == "ci/host-heyvm-maintenance" { return Ok(json!({})); }
                        self.store
                            .finish_step(&sid, StepStatus::Success, Some(0), None)
                            .await?;
                    }
                    Err(e) => {
                        let detail = masker.mask(&e.to_string());
                        self.store
                            .append_log(&sid, &log_path, &format!("[ci] {detail}\n"))
                            .await?;
                        self.store
                            .finish_step(&sid, StepStatus::Failure, None, Some(&detail))
                            .await?;
                        if !step.continue_on_error {
                            failed = Some(detail);
                            break;
                        }
                    }
                }
                continue;
            };

            self.store.start_step(&sid, &sid).await?;
            let log_path = self
                .store
                .log_path(&msg.run_id, &plan.key, idx as i32, &sid);

            let env = self.step_env(plan, step, &ctx);
            let command = wrap_command(
                &ctx.substitute(run),
                step,
                &sid,
                plan.vm
                    .working_directory
                    .as_deref()
                    .unwrap_or(DEFAULT_WORKDIR),
            );
            let timeout = step_timeout(step, plan);

            // The exec is raced against a cancellation watch. The boundary
            // check above stops anything *after* a cancelled step; this stops
            // the waiting itself, which used to be the gap that mattered: a
            // cancelled two-hour build held this route's queue to the step's
            // own end, with the run page saying cancelled and the networks
            // page saying running. The daemon still has no way to abort the
            // exec, so the guest command runs on to its own timeout — but the
            // dispatcher stops waiting for it, releases the VM, and the queue
            // moves. The step is recorded cancelled with a line saying what
            // was left behind.
            let raced = {
                let watch = async {
                    let mut ticker = tokio::time::interval(CANCEL_POLL);
                    ticker.tick().await; // the immediate first tick
                    loop {
                        ticker.tick().await;
                        if matches!(self.store.is_job_cancelled(&msg.job_id).await, Ok(true)) {
                            break;
                        }
                    }
                };
                tokio::select! {
                    out = vm.exec(&sid, &command, &env, timeout) => Some(out),
                    _ = watch => None,
                }
            };
            let Some(executed) = raced else {
                let note = "\n[ci] cancelled while this step was running; the command in the \
                            guest is left to finish or hit its own timeout, and nothing after \
                            this step ran\n";
                let _ = self.store.append_log(&sid, &log_path, note).await;
                let _ = self
                    .store
                    .finish_step(&sid, StepStatus::Cancelled, None, Some("cancelled"))
                    .await;
                return Err(DispatchError::Cancelled(plan.key.clone()));
            };

            match executed {
                Ok(out) => {
                    let (text, outputs) = split_outputs(&out, &sid);
                    // Masked before it is persisted, not when it is rendered: a
                    // secret that reaches disk in plain text has leaked, and
                    // hiding it from one reader does not un-leak it.
                    let text = masker.mask(&text);
                    let ok = out.succeeded();
                    let status = if ok { StepStatus::Success } else { StepStatus::Failure };
                    // Retry only the atomic receipt write, never vm.exec. The
                    // remote command is already complete, even if the pooler
                    // it replaced briefly disconnected our own database.
                    retry_command_recording(Duration::from_secs(120), Duration::from_secs(2), || {
                        self.store.finish_command(&sid, status, out.exit_code, &text,
                            attempt, self.executor.boot_id())
                    }).await.map_err(|error| DispatchError::ResultRecording {
                        step: sid.clone(), exit_code: out.exit_code, error: masker.mask(&error),
                    })?;
                    if let Some(id) = &step.id {
                        step_outputs.insert(
                            id.clone(),
                            serde_json::json!({ "outputs": outputs, "outcome":
                                if out.succeeded() { "success" } else { "failure" } }),
                        );
                    }
                    if !ok && !step.continue_on_error {
                        failed = Some(format!(
                            "step {:?} exited {}",
                            step.label(idx),
                            out.exit_code
                        ));
                        break;
                    }
                }
                Err(e) => {
                    // The command never ran, or the daemon lost it. Distinct
                    // from a non-zero exit, and recorded as such.
                    let msg = masker.mask(&e.to_string());
                    self.store
                        .append_log(&sid, &log_path, &format!("\n[ci] {msg}\n"))
                        .await?;
                    self.store
                        .finish_step(&sid, StepStatus::Failure, None, Some(&msg))
                        .await?;
                    failed = Some(msg);
                    break;
                }
            }
        }

        if let Some(reason) = failed {
            return Err(DispatchError::StepFailed(reason));
        }

        // Job outputs are expressions over the step outputs collected above.
        let mut ctx = plan.base_context();
        ctx.set("needs", needs);
        ctx.set("steps", Value::Object(step_outputs));
        ctx.set("secrets", secret_scope);
        ctx.set("vars", vars_scope);
        ctx.set("ci", ci);
        // Masked as well: a job output is read by the next job's `if:` and shown
        // on the dashboard, so an output that interpolated a secret would put it
        // somewhere a log masker never sees.
        let outputs: serde_json::Map<String, Value> = plan
            .outputs
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(masker.mask(&ctx.substitute(v)))))
            .collect();
        Ok(Value::Object(outputs))
    }

    /// Run a built-in `uses:` action.
    ///
    /// Artifact publication and service deployment. Composite actions — fetching an
    /// `action.yml` from a repository and running its steps — are a different
    /// feature with a different trust model, and pretending to support them by
    /// silently doing nothing would be worse than saying so.
    #[allow(clippy::too_many_arguments)]
    async fn run_action(
        &self,
        msg: &JobMessage,
        plan: &JobPlan,
        vm: &Vm,
        action: &str,
        step: &Step,
        ctx: &Context,
        sid: &str,
        log_path: &std::path::Path,
        masker: &crate::secrets::Masker,
    ) -> Result<(String, Value), DispatchError> {
        let with = |k: &str| step.with.get(k).map(|v| ctx.substitute(v));
        let required = |key: &str| with(key).filter(|v| !v.trim().is_empty())
            .ok_or_else(|| DispatchError::StepFailed(format!("{action} requires with.{key}")));

        if matches!(action, "ci/merge-release" | "ci/publish-service-archive" |
            "ci/promote-service-archive" | "ci/deploy-service" | "ci/deploy-app-lb" | "ci/deploy-controller" | "ci/host-heyvm-maintenance" | "ci/bootstrap-host-heyvm" | "ci/rollout-host-heyvmd" | "ci/rollout-service" | "ci/rollout-host-app-lb") {
            crate::submission::authorize_publication(&self.store, &msg.run_id).await
                .map_err(DispatchError::StepFailed)?;
        }

        if matches!(action, "ci/rollout-service" | "ci/rollout-host-app-lb") {
            let completed: Option<String> = sqlx::query_scalar(
                "SELECT d.id FROM ci_release_carried_deployment c
                 JOIN ci_step s ON s.job_id=c.job_id AND s.idx=c.step_index
                 JOIN ci_service_deployment d ON d.id=c.deployment_id
                 WHERE s.id=$1 AND d.status='passed'",
            ).bind(sid).fetch_optional(self.store.pool()).await
                .map_err(|e| DispatchError::StepFailed(format!("read carried deployment receipt: {e}")))?;
            if let Some(id) = completed {
                return Ok((format!("[ci] retained completed deployment {id}; no deployment repeated\n"), json!({})));
            }
        }

        match action {
            "ci/merge-release" => {
                if let Some(policy) = &plan.release_policy {
                    crate::release_policy::check_targets(self, policy).await
                        .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                    if policy.token_expressions.iter().any(|expression| ctx.substitute(expression).trim().is_empty()) {
                        return Err(DispatchError::StepFailed("operator release policy has an unresolved credential; merge refused".into()));
                    }
                }
                let manifests: Vec<String> = serde_json::from_str(&required("manifests")?)
                    .map_err(|_| DispatchError::StepFailed("with.manifests must be a JSON array of manifest paths".into()))?;
                let tags = with("tags").map(|raw| serde_json::from_str(&raw)
                    .map_err(|_| DispatchError::StepFailed("with.tags must be a JSON object mapping manifest paths to tag prefixes".into())))
                    .transpose()?.unwrap_or_default();
                let release = crate::release::merge(&self.store, msg, plan,
                    &manifests, &tags, &required("token")?).await.map_err(DispatchError::StepFailed)?;
                Ok((format!("[ci] merged and published release {} on {}\nVersions: {}\n",
                    release.release_sha, release.git_ref, release.versions), serde_json::json!({
                        "sha": release.release_sha, "ref": release.git_ref, "versions": release.versions.to_string(),
                        "tags": release.tags
                    })))
            }
            "ci/checkout-release" => {
                let release = crate::release::get(&self.store, &msg.run_id).await
                    .map_err(DispatchError::StepFailed)?.filter(|r| r.status == "published")
                    .ok_or_else(|| DispatchError::StepFailed("release checkout requires a confirmed published release".into()))?;
                let workdir = plan.vm.working_directory.as_deref().unwrap_or(DEFAULT_WORKDIR);
                let run=self.store.get_run(&msg.run_id).await?.ok_or_else(||DispatchError::StepFailed("release run disappeared".into()))?;
                if !production_repo_url(&run.repo_url){return Err(DispatchError::StepFailed("release repository URL is not canonical".into()))}
                let wd=shell_quote(workdir);let repo=shell_quote(&run.repo_url);let sha=shell_quote(&release.prepared.release_sha);
                let command=format!("set -eu; test {wd} != /; find {wd} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +; git -C {wd} init --quiet; git -C {wd} remote add origin {repo}; git -C {wd} fetch --quiet --no-tags origin {sha}; git -C {wd} checkout --quiet --detach {sha}; test \"$(git -C {wd} rev-parse HEAD)\" = {sha}");
                let primary=ctx.substitute("${{ secrets.CI_GIT_AUTH_TOKEN }}");let fallback=ctx.substitute("${{ secrets.GITHUB_TOKEN }}");let token=if primary.is_empty(){fallback}else{primary};
                let mut env=HashMap::from([("GIT_TERMINAL_PROMPT".into(),"0".into()),("GIT_CONFIG_NOSYSTEM".into(),"1".into()),("GIT_CONFIG_GLOBAL".into(),"/dev/null".into()),("GCM_INTERACTIVE".into(),"Never".into())]);if !token.is_empty(){let basic=base64::Engine::encode(&base64::engine::general_purpose::STANDARD,format!("x-access-token:{token}"));env.insert("GIT_CONFIG_COUNT".into(),"3".into());env.insert("GIT_CONFIG_KEY_0".into(),"credential.helper".into());env.insert("GIT_CONFIG_VALUE_0".into(),"".into());env.insert("GIT_CONFIG_KEY_1".into(),"protocol.ext.allow".into());env.insert("GIT_CONFIG_VALUE_1".into(),"never".into());env.insert("GIT_CONFIG_KEY_2".into(),format!("http.{}.extraHeader",run.repo_url));env.insert("GIT_CONFIG_VALUE_2".into(),format!("Authorization: Basic {basic}"));}
                let out = vm.exec(&format!("{sid}.release"), &command, &env, step_timeout(step, plan)).await?;
                if !out.succeeded() { return Err(DispatchError::StepFailed("release checkout failed".into())); }
                sqlx::query("UPDATE ci_job SET release_sha=$2 WHERE id=$1")
                    .bind(&msg.job_id).bind(&release.prepared.release_sha).execute(self.store.pool()).await
                    .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                Ok((format!("[ci] clean checkout of release {}\n", release.prepared.release_sha),
                    serde_json::json!({"sha": release.prepared.release_sha})))
            }
            "ci/publish-service-archive" | "ci/promote-service-archive" => {
                let base = required("url")?;
                let path = required("path")?;
                let name = required("name")?;
                let user = required("user-id")?;
                let token = required("token")?;
                let (sha, bytes) = if action == "ci/promote-service-archive" {
                    let (release_sha, _) = crate::release::deployment_source(&self.store, &msg.run_id).await
                        .map_err(DispatchError::StepFailed)?;
                    let stored = crate::submission::artifact(&self.store, &msg.run_id,
                        &required("workflow")?, &required("artifact")?, with("job").as_deref())
                        .await.map_err(DispatchError::Artifact)?;
                    let bytes = self.artifacts.get(&stored).await
                        .map_err(|e| DispatchError::Artifact(e.to_string()))?;
                    if stored.digest.as_deref() != Some(hex::encode(sha2::Sha256::digest(&bytes)).as_str()) {
                        return Err(DispatchError::Artifact("validated promotion artifact digest mismatch".into()));
                    }
                    let archive = crate::service_archive::validated_archive(&bytes, &path)
                        .map_err(DispatchError::Artifact)?;
                    (release_sha, archive)
                } else {
                    let sha: Option<String> = sqlx::query_scalar("SELECT release_sha FROM ci_job WHERE id=$1")
                        .bind(&msg.job_id).fetch_one(self.store.pool()).await
                        .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                    let sha = sha.ok_or_else(|| DispatchError::StepFailed("service archive must be built after ci/checkout-release in this job".into()))?;
                    let workdir = plan.vm.working_directory.as_deref().unwrap_or(DEFAULT_WORKDIR);
                    if std::path::Path::new(&path).is_absolute() || std::path::Path::new(&path).components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir)) {
                        return Err(DispatchError::StepFailed("archive path must be relative to the job working directory".into()));
                    }
                    (sha, vm.download_file(&format!("{sid}.archive"), &format!("{workdir}/{path}"), step_timeout(step, plan)).await?)
                };
                let archive_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                let heyvm_sha256 = crate::host_maintenance::executable_digest(&bytes).ok();
                let archive = crate::service_archive::publish(&base, &token, &user, sid, &name, bytes)
                    .await.map_err(DispatchError::StepFailed)?;
                let mut tx = self.store.pool().begin().await.map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                sqlx::query("INSERT INTO ci_service_archive(step_id,run_id,job_id,archive_id,sha,orchestrator_url,archive_user_id,archive_sha256,heyvm_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(step_id) DO UPDATE SET archive_id=excluded.archive_id,sha=excluded.sha,orchestrator_url=excluded.orchestrator_url,archive_user_id=excluded.archive_user_id,archive_sha256=excluded.archive_sha256,heyvm_sha256=excluded.heyvm_sha256")
                    .bind(sid).bind(&msg.run_id).bind(&msg.job_id).bind(&archive).bind(&sha).bind(base.trim_end_matches('/'))
                    .bind(&user).bind(&archive_sha256).bind(&heyvm_sha256)
                    .execute(&mut *tx).await.map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                let event = Store::add_event(&mut tx, &msg.run_id, Some(&msg.job_id), Some(&msg.job_key), Some(sid),
                    "ci.service_archive.published.v1", "published", None).await?;
                sqlx::query("UPDATE ci_event_outbox SET payload=payload || $2 WHERE id=$1")
                    .bind(event).bind(serde_json::json!({"archive_id":archive,"release_sha":sha}))
                    .execute(&mut *tx).await.map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                tx.commit().await.map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                Ok((format!("[ci] finalized service archive {archive} for release {sha}\n"),
                    serde_json::json!({"archive-id":archive,"sha":sha})))
            }
            "ci/deploy-service" => {
                let required = |key: &str| with(key).filter(|v| !v.trim().is_empty())
                    .ok_or_else(|| DispatchError::StepFailed(format!("ci/deploy-service requires with.{key}")));
                let spec: Value = serde_json::from_str(&required("spec")?)
                    .map_err(|_| DispatchError::StepFailed("ci/deploy-service with.spec must be JSON".into()))?;
                crate::cd::deploy(&self.store, msg, sid, spec, &required("url")?,
                    &required("token")?, step_timeout(step, plan), masker)
                    .await.map(|note| (note, serde_json::json!({}))).map_err(DispatchError::StepFailed)
            }
            "ci/publish-rootfs" => {
                let path = required("path")?;
                let image = required("image")?;
                if std::path::Path::new(&path).is_absolute() || std::path::Path::new(&path).components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir)) {
                    return Err(DispatchError::Artifact("rootfs path must be relative to the job working directory".into()));
                }
                // Establish release provenance before handing a store credential
                // to the guest or causing any externally visible upload.
                let sha = crate::cd::publication_source_sha(&self.store, msg).await.map_err(DispatchError::StepFailed)?;
                let push = self.artifacts.guest_push().ok_or_else(|| DispatchError::Artifact(
                    "ci/publish-rootfs requires the artifacts HTTP sink; disk and S3 are not rootfs registries".into()))?;
                let workdir = plan.vm.working_directory.as_deref().unwrap_or(DEFAULT_WORKDIR);
                let file = format!("{}/{path}", workdir.trim_end_matches('/'));
                let budget = step_timeout(step, plan);
                let mut env = HashMap::new();
                env.insert("CI_ARTIFACT_URL".to_string(), push.url);
                if let Some(token) = &push.token { env.insert("CI_ARTIFACT_TOKEN".to_string(), token.clone()); }
                let out = vm.exec(&format!("{sid}.rootfs"), &guest_push_command(&file, push.token.is_some(), budget), &env, budget).await?;
                let (blob, size) = parse_guest_push(&out).map_err(DispatchError::Artifact)?;
                let published = self.artifacts.publish_pushed_rootfs(&blob, size, &image).await
                    .map_err(|e| DispatchError::Artifact(e.to_string()))?;
                let size: i64 = published.size_bytes.try_into().map_err(|_| DispatchError::Artifact("rootfs is too large to record".into()))?;
                let mut tx = self.store.pool().begin().await.map_err(|e| DispatchError::Artifact(e.to_string()))?;
                sqlx::query("INSERT INTO ci_app_lb_artifact(step_id,run_id,job_id,sha,store_url,manifest_digest,blob_digest,size_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(step_id) DO UPDATE SET sha=excluded.sha,store_url=excluded.store_url,manifest_digest=excluded.manifest_digest,blob_digest=excluded.blob_digest,size_bytes=excluded.size_bytes")
                    .bind(sid).bind(&msg.run_id).bind(&msg.job_id).bind(&sha).bind(&published.store_url)
                    .bind(&published.manifest_digest).bind(&published.blob_digest).bind(size)
                    .execute(&mut *tx).await.map_err(|e| DispatchError::Artifact(e.to_string()))?;
                let event = Store::add_event(&mut tx, &msg.run_id, Some(&msg.job_id), Some(&msg.job_key), Some(sid),
                    "ci.rootfs.published.v1", "published", None).await?;
                sqlx::query("UPDATE ci_event_outbox SET payload=payload || $2 WHERE id=$1").bind(event).bind(json!({
                    "sha":sha,"store_url":published.store_url,"manifest_digest":published.manifest_digest,
                    "blob_digest":published.blob_digest,"size_bytes":published.size_bytes
                })).execute(&mut *tx).await.map_err(|e| DispatchError::Artifact(e.to_string()))?;
                tx.commit().await.map_err(|e| DispatchError::Artifact(e.to_string()))?;
                Ok((format!("[ci] published rootfs manifest {} ({} bytes) for {sha}\n", published.manifest_digest, published.size_bytes),
                    json!({"manifest":published.manifest_digest,"blob":published.blob_digest,"size":published.size_bytes,"store":published.store_url,"sha":sha})))
            }
            "ci/deploy-app-lb" => {
                crate::cd::deploy_app_lb(&self.store, msg, sid, &required("url")?, &required("token")?,
                    &required("deployment")?, &required("namespace")?, &required("manifest")?, &required("store")?,
                    step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(DispatchError::StepFailed)
            }
            "ci/rollout-host-app-lb" => {
                crate::host_app_lb::deploy(self, msg, plan, sid, &required("target")?, &required("token")?,
                    &required("workflow")?, &required("artifact")?, step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/rollout-pooler" => {
                if plan.release_policy.is_none() {
                    return Err(DispatchError::StepFailed("pooler rollout requires frozen operator policy".into()));
                }
                let target = serde_json::from_str(&required("resolved-target")?)
                    .map_err(|e| DispatchError::StepFailed(format!("invalid frozen pooler target: {e}")))?;
                crate::pooler_rollout::deploy(self, msg, sid, target, &required("token")?,
                    &required("workflow")?, &required("artifact")?, step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/rollout-site" => {
                if plan.release_policy.is_none() {
                    return Err(DispatchError::StepFailed("site rollout requires frozen operator policy".into()));
                }
                let target = serde_json::from_str(&required("resolved-target")?)
                    .map_err(|e| DispatchError::StepFailed(format!("invalid frozen site target: {e}")))?;
                crate::site_rollout::deploy(self, msg, sid, target, &required("token")?,
                    &required("workflow")?, &required("artifact")?, step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/rollout-stateful-service" => {
                if plan.release_policy.is_none() {
                    return Err(DispatchError::StepFailed("stateful rollout requires frozen operator policy".into()));
                }
                let target = serde_json::from_str(&required("resolved-target")?)
                    .map_err(|e| DispatchError::StepFailed(format!("invalid frozen stateful target: {e}")))?;
                crate::stateful_rollout::deploy(self, msg, sid, target, &required("token")?,
                    &required("workflow")?, &required("artifact")?, step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/rollout-service" => {
                crate::host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))
                    .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                let mount_path = required("mount-path")?;
                let target = crate::service_rollout::Target {
                    url: required("url")?, deployment: required("deployment")?, namespace: required("namespace")?,
                    revision_env: required("revision-env")?, start_command: format!("{mount_path}/start.sh"),
                    working_directory: mount_path.clone(), mount_path,
                };
                crate::service_rollout::deploy(self, msg, sid, target, &required("token")?,
                    &required("workflow")?, &required("artifact")?, step_timeout(step, plan), masker).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/deploy-controller" => {
                if let Some(expected) = plan.release_policy.as_ref().and_then(|p| p.ci_application.as_ref()) {
                    let current = crate::release_policy::CiApplicationTarget::current(self)
                        .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                    if &current != expected {
                        return Err(DispatchError::StepFailed("CI application mapping changed since release admission".into()));
                    }
                }
                if self.config.managed_deployment.is_some() {
                    crate::managed_update::request(self,msg,sid,&required("archive-id")?).await
                        .map(|note|(note,json!({}))).map_err(|e|DispatchError::StepFailed(e.to_string()))
                } else {
                    crate::controller_rollout::request(self, msg, sid, &required("artifact")?, with("workflow").as_deref()).await
                        .map(|note| (note, json!({}))).map_err(DispatchError::StepFailed)
                }
            }
            "ci/host-heyvm-maintenance" => {
                required("token")?;
                let secret = crate::host_maintenance::token_secret(step.with.get("token").map(String::as_str).unwrap_or(""))
                    .map_err(|e| DispatchError::StepFailed(e.to_string()))?;
                // Persist outputs from earlier steps before handing completion
                // to the reconciler; downstream jobs may start immediately
                // after its atomic successful completion.
                let outputs: serde_json::Map<String, Value> = plan.outputs.iter()
                    .map(|(key, value)| (key.clone(), json!(masker.mask(&ctx.substitute(value))))).collect();
                self.store.set_job_outputs(&msg.job_id, &Value::Object(outputs)).await?;
                crate::host_maintenance::request(self, msg, plan, sid, &required("runner")?, &required("url")?,
                    &required("archive-id")?, &secret, step_timeout(step, plan)).await
                    .map(|note| (note, json!({}))).map_err(|e| DispatchError::StepFailed(e.to_string()))
            }
            "ci/bootstrap-host-heyvm" | "ci/rollout-host-heyvmd" => {
                required("token")?;
                let component=if step.uses.as_deref()==Some("ci/rollout-host-heyvmd"){"heyvmd"}else{"heyvm"};
                crate::host_heyvm_bootstrap_coordinator::request(self,msg,plan,sid,&required("target")?,
                    step.with.get("token").map(String::as_str).unwrap_or(""),&required("workflow")?,&required("artifact")?,step_timeout(step,plan),component).await
                    .map(|note|(note,json!({}))).map_err(|e|DispatchError::StepFailed(e.to_string()))
            }
            "ci/upload-artifact" => {
                let name = with("name").ok_or_else(|| {
                    DispatchError::Artifact("ci/upload-artifact needs `with.name`".into())
                })?;
                let path = with("path").ok_or_else(|| {
                    DispatchError::Artifact("ci/upload-artifact needs `with.path`".into())
                })?;
                // Optional, and only the `artifacts` sink has anywhere to put
                // it. Substituted like every other `with:` value, so a workflow
                // can write `${{ ci.branch }}` into it.
                let description = with("description").filter(|d| !d.trim().is_empty());
                // Optional. YAML's `true` arrives as the string "true", since
                // `with:` values are strings so they can be substituted. Only
                // the two spellings a person would write are accepted; a
                // typo must not silently mean "private".
                // The stable tag this upload should become, if the workflow
                // names one. Validated when it is set, not here, so one code
                // path decides what the store will accept.
                let alias = with("alias")
                    .map(|a| a.trim().to_string())
                    .filter(|a| !a.is_empty());
                let public = match with("public").as_deref().map(str::trim) {
                    None | Some("") | Some("false") => false,
                    Some("true") => true,
                    Some(other) => {
                        return Err(DispatchError::Artifact(format!(
                            "ci/upload-artifact `with.public` must be `true` or `false`, \
                             not {other:?}"
                        )));
                    }
                };

                // Packed to a file in the guest. Then, for a sink that offers
                // a `GuestPush`, the guest pushes the tarball to the store
                // over its own network; otherwise — or if that fails — it is
                // read out through exec and base64 the same way the source
                // went in, because the daemon's file routes address a
                // host-side mount, not the VM. That read is exec output, and
                // on firecracker exec output is the emulated serial console:
                // tens of KiB/s, which is why app-obs's 41 MB tarball spent a
                // quarter of an hour leaving its VM before the push existed.
                // The read is chunked, each chunk under its own guest timeout
                // and the whole under the step's — one exec for the whole
                // tarball met one fixed 600-second ceiling, which app-lb's
                // artifact fit under and app-obs's did not. See
                // `Vm::download_file` for the transfer and the guest-side
                // details it has to get right.
                //
                // `tar` from the working directory, so the archive holds
                // `dist/...` rather than an absolute path. The tarball is named
                // for the step so a redelivered job overwrites its own file
                // rather than a neighbour's, and it is removed win or lose.
                let workdir = plan
                    .vm
                    .working_directory
                    .as_deref()
                    .unwrap_or(DEFAULT_WORKDIR);
                let tarball = format!("/tmp/{sid}.artifact.tar.gz");
                let budget = step_timeout(step, plan);
                let started = Instant::now();
                let pack = vm
                    .exec(
                        &format!("{sid}.a"),
                        &format!(
                            "cd {} && tar -czf {} {} && wc -c < {}",
                            shell_quote(workdir),
                            shell_quote(&tarball),
                            shell_quote(&path),
                            shell_quote(&tarball)
                        ),
                        &HashMap::new(),
                        ARTIFACT_PACK_TIMEOUT.min(budget),
                    )
                    .await?;
                if !pack.succeeded() {
                    return Err(DispatchError::Artifact(format!(
                        "packing {path:?} exited {}: {}",
                        pack.exit_code,
                        pack.combined().trim()
                    )));
                }
                let packed: u64 = pack
                    .combined()
                    .split_whitespace()
                    .last()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                self.store
                    .append_log(
                        sid,
                        log_path,
                        &format!(
                            "[ci] packed {path:?} into {packed} bytes; reading it out of the \
                             guest in {} chunks of up to {} bytes, with {:?} of the step's \
                             budget left\n",
                            packed.div_ceil(crate::vm::DOWNLOAD_CHUNK),
                            crate::vm::DOWNLOAD_CHUNK,
                            budget.saturating_sub(started.elapsed())
                        ),
                    )
                    .await?;
                let run = self.store.get_run(&msg.run_id).await?;
                let aref = crate::artifacts::ArtifactRef {
                    run_id: msg.run_id.clone(),
                    job_key: plan.key.clone(),
                    workflow_id: run.map(|r| r.workflow_id).unwrap_or_default(),
                    name: name.clone(),
                    description,
                    public,
                    alias,
                };

                // The fast path: the guest pushes the tarball to the store
                // itself, over its own network, and the orchestrator only has
                // to verify and name it. Anything that stops the guest doing
                // that — no curl in the image, a store it cannot route to, a
                // refused upload — is logged and then paid for the slow way,
                // because an artifact that arrives late beats one that does not
                // arrive; but a blob the guest says it pushed and the store
                // says it has not got is an error, not a reason to try again.
                let pushed = match self.artifacts.guest_push() {
                    Some(push) => {
                        let timeout = ARTIFACT_GUEST_PUSH_TIMEOUT
                            .min(budget.saturating_sub(started.elapsed()));
                        let mut env = HashMap::new();
                        env.insert("CI_ARTIFACT_URL".to_string(), push.url.clone());
                        if let Some(t) = &push.token {
                            env.insert("CI_ARTIFACT_TOKEN".to_string(), t.clone());
                        }
                        let out = vm
                            .exec(
                                &format!("{sid}.ap"),
                                &guest_push_command(&tarball, push.token.is_some(), timeout),
                                &env,
                                timeout,
                            )
                            .await?;
                        match parse_guest_push(&out) {
                            Ok((digest, size)) => Some(
                                self.artifacts
                                    .put_pushed(&aref, &digest, size)
                                    .await
                                    .map(Fetched::Stored)
                                    .map_err(|e| DispatchError::Artifact(e.to_string())),
                            ),
                            Err(why) => {
                                self.store
                                    .append_log(
                                        sid,
                                        log_path,
                                        &format!(
                                            "[ci] the guest could not push the tarball to \
                                             {} ({why}); reading it out over the exec channel \
                                             instead, which is slow\n",
                                            push.url
                                        ),
                                    )
                                    .await?;
                                None
                            }
                        }
                    }
                    None => None,
                };

                let read = match pushed {
                    Some(result) => result,
                    None => vm
                        .download_file(
                            &format!("{sid}.a"),
                            &tarball,
                            budget.saturating_sub(started.elapsed()),
                        )
                        .await
                        .map(Fetched::Bytes)
                        .map_err(DispatchError::from),
                };
                // Cleanup is best effort and never the reported error: what
                // matters is whether the bytes arrived.
                if let Err(e) = vm
                    .exec(
                        &format!("{sid}.ar"),
                        &format!("rm -f {}", shell_quote(&tarball)),
                        &HashMap::new(),
                        Duration::from_secs(60),
                    )
                    .await
                {
                    tracing::warn!(step = sid, error = %e, "could not remove the packed artifact");
                }
                let (stored, how) = match read? {
                    Fetched::Stored(stored) => (stored, "pushed from the guest"),
                    Fetched::Bytes(bytes) => {
                        let stored = self
                            .artifacts
                            .put(&aref, bytes)
                            .await
                            .map_err(|e| DispatchError::Artifact(e.to_string()))?;
                        (stored, "read out of the guest")
                    }
                };
                let transfer = started.elapsed();

                self.store
                    .record_artifact(&msg.run_id, &msg.job_id, sid, &name, &stored)
                    .await?;
                // The link is the point of `public: true`, so it goes in the
                // log where a person reading the run will find it. A sink
                // that has no such thing says so in the same place rather
                // than dropping the request on the floor.
                let public = match (&stored.public_url, public) {
                    (Some(url), _) => format!("\n[ci] public link: {url}"),
                    (None, true) => format!(
                        "\n[ci] `public: true` was ignored: the {} sink has no public links",
                        stored.sink
                    ),
                    (None, false) => String::new(),
                };
                Ok((format!(
                    "[ci] stored artifact {name:?} ({} bytes) in the {} sink as {} — \
                     {how} in {transfer:.0?}{public}\n",
                    stored.size_bytes, stored.sink, stored.uri
                ), serde_json::json!({})))
            }
            "ci/download-artifact" => {
                let name = required("name")?;
                let path = required("path")?;
                let producer = with("job").filter(|v| !v.trim().is_empty());
                let artifact_run = match with("workflow") {
                    Some(workflow) => crate::submission::artifact_run(&self.store, &msg.run_id, &workflow)
                        .await.map_err(DispatchError::Artifact)?,
                    None => msg.run_id.clone(),
                };
                let workdir = plan.vm.working_directory.as_deref().unwrap_or(DEFAULT_WORKDIR);
                let remote = artifact_download_path(workdir, &path)?;
                // Scope at the query boundary: workflow input can name an
                // artifact and its producer, never an arbitrary run, URI or URL.
                // Cross-run lookup requires frozen successful submission membership.
                let rows = sqlx::query(
                    "SELECT a.run_id,a.name,a.sink,a.digest,a.size_bytes,a.uri,a.public_url,
                            j.job_key,j.status,j.finished_at IS NOT NULL AS finished
                       FROM ci_artifact a JOIN ci_job j ON j.id=a.job_id
                      WHERE a.run_id=$1 AND a.name=$2 ORDER BY a.created_at",
                ).bind(&artifact_run).bind(&name).fetch_all(self.store.pool()).await
                    .map_err(|e| DispatchError::Artifact(format!("looking up artifact {name:?}: {e}")))?;
                let candidates = rows.iter().map(|r| Ok(DownloadCandidate {
                    run_id: r.get("run_id"), name: r.get("name"), job_key: r.get("job_key"),
                    status: r.get("status"), finished: r.get("finished"),
                    stored: crate::artifacts::StoredArtifact {
                        sink: match r.get::<String,_>("sink").as_str() {
                            "disk" => "disk", "s3" => "s3", "artifacts" => "artifacts",
                            other => return Err(DispatchError::Artifact(format!("artifact {name:?} has unknown recorded sink {other:?}"))),
                        },
                        digest: r.get("digest"), size_bytes: r.get::<i64,_>("size_bytes").try_into()
                            .map_err(|_| DispatchError::Artifact(format!("artifact {name:?} has invalid recorded size")))?,
                        uri: r.get("uri"), public_url: r.get("public_url"),
                    },
                })).collect::<Result<Vec<_>, DispatchError>>()?;
                let selected = select_download(&artifact_run, &name, producer.as_deref(), &candidates)?;
                let bytes = self.artifacts.get(&selected.stored).await
                    .map_err(|e| DispatchError::Artifact(format!("downloading artifact {name:?}: {e}")))?;
                vm.upload_bytes(sid, &remote, &bytes).await?;
                Ok((format!("[ci] downloaded artifact {name:?} from job {:?} to {path:?} ({} bytes)\n",
                    selected.job_key, bytes.len()), serde_json::json!({})))
            }
            other => Err(DispatchError::Artifact(format!(
                "`uses: {other}` is not a built-in action. Available: \
                 ci/upload-artifact, ci/download-artifact, ci/merge-release, ci/checkout-release, ci/publish-service-archive, ci/deploy-service, ci/publish-rootfs, ci/deploy-app-lb, ci/deploy-controller. Composite actions from a repository are not \
                 supported."
            ))),
        }
    }

    /// The environment a step runs with: workflow, then job, then step, each
    /// overriding the last, plus the `CI_*` and `GITHUB_*` names a build expects.
    fn step_env(&self, plan: &JobPlan, step: &Step, ctx: &Context) -> HashMap<String, String> {
        let mut env: HashMap<String, String> = HashMap::new();
        for (k, v) in &self.config_env(plan) {
            env.insert(k.clone(), v.clone());
        }
        for (k, v) in &plan.env {
            env.insert(k.clone(), ctx.substitute(v));
        }
        for (k, v) in &step.env {
            env.insert(k.clone(), ctx.substitute(v));
        }
        env
    }

    fn config_env(&self, plan: &JobPlan) -> HashMap<String, String> {
        let mut env = HashMap::new();
        env.insert("CI".to_string(), "true".to_string());
        env.insert("CI_JOB".to_string(), plan.base_id.clone());
        env.insert("CI_JOB_KEY".to_string(), plan.key.clone());
        env
    }
}

fn production_repo_url(url: &str) -> bool {
    if url.chars().any(char::is_whitespace) || url.chars().any(char::is_control) {
        return false;
    }
    if url.starts_with("https://") || url.starts_with("ssh://") {
        return reqwest::Url::parse(url).is_ok_and(|u| u.host_str().is_some()
            && u.password().is_none() && u.query().is_none() && u.fragment().is_none()
            && (u.scheme() == "ssh" || u.username().is_empty()));
    }
    // SCP-style SSH, not arbitrary Git remote helpers such as ext::commands.
    let Some((user, rest)) = url.split_once('@') else { return false; };
    let Some((host, path)) = rest.split_once(':') else { return false; };
    !user.is_empty() && !user.starts_with('-') && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        && !path.is_empty() && !path.starts_with('-')
}

fn checkout_script(workdir: &str, patch_path: &str, repo_url: &str, source: &crate::trigger::GitPatchSource, workflow: Option<(&str, &str)>) -> String {
    let wd = shell_quote(workdir.trim_end_matches('/'));
    let patch = shell_quote(patch_path);
    let repo = shell_quote(repo_url);
    let base = shell_quote(&source.base_revision);
    let tree = shell_quote(&source.target_tree);
    let verify_workflow = workflow.map(|(path, hash)| {
        let path = shell_quote(&format!("{}/{}", workdir.trim_end_matches('/'), path));
        let hash = shell_quote(hash);
        format!("test \"$(sha256sum {path} | awk '{{print $1}}')\" = {hash}")
    }).unwrap_or_default();
    let apply = if source.patch_base64.is_empty() {
        format!("test \"$(git rev-parse HEAD^{{tree}})\" = {tree}")
    } else {
        format!("git apply --index --binary {patch}; test \"$(git write-tree)\" = {tree}; git -c core.hooksPath=/nonexistent -c user.name=CI -c user.email=ci@invalid commit --quiet -m 'CI synthetic patched tree'; test \"$(git rev-parse HEAD^{{tree}})\" = {tree}")
    };
    format!(r#"set -eu
command -v git >/dev/null
command -v sha256sum >/dev/null
# The workspace may be a mountpoint: clear its contents, not the mount itself.
test {wd} != / && test -n {wd}
mkdir -p {wd}
find {wd} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +
auth_dir=$(mktemp -d)
patch_file={patch}
trap 'rm -rf "$auth_dir"; rm -f "$patch_file"' EXIT
askpass="$auth_dir/askpass"
printf '%s\n' '#!/bin/sh' 'case "$1" in *Username*) printf %s x-access-token;; *) printf %s "${{CI_GIT_AUTH_TOKEN:-}}";; esac' > "$askpass"
chmod 700 "$askpass"
export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$askpass"
git -c core.hooksPath=/nonexistent init --quiet {wd}
git -C {wd} remote add origin {repo}
# Fetch history/tags for builds using git describe. Never use a fetched branch
# tip as the requested revision: the explicit checkout below remains mandatory.
git -C {wd} fetch --quiet --tags origin '+refs/heads/*:refs/remotes/origin/*'
if ! git -C {wd} cat-file -e {base}^{{commit}}; then
    git -C {wd} fetch --quiet origin {base}
fi
git -C {wd} -c core.hooksPath=/nonexistent checkout --quiet --detach {base}
test "$(git -C {wd} rev-parse HEAD)" = {base}
cd {wd}
{apply}
test "$(git rev-parse HEAD^{{tree}})" = {tree}
{verify_workflow}
git -c color.ui=never log --oneline -1
"#)
}

#[derive(Debug, Clone)]
struct DownloadCandidate {
    run_id: String,
    name: String,
    job_key: String,
    status: String,
    finished: bool,
    stored: crate::artifacts::StoredArtifact,
}

fn select_download<'a>(run_id: &str, name: &str, producer: Option<&str>, candidates: &'a [DownloadCandidate])
    -> Result<&'a DownloadCandidate, DispatchError>
{
    let matching = candidates.iter().filter(|a| a.run_id == run_id && a.name == name &&
        producer.is_none_or(|job| a.job_key == job)).collect::<Vec<_>>();
    match matching.as_slice() {
        [] => Err(DispatchError::Artifact(format!("no artifact named {name:?}{} exists in the current run",
            producer.map(|j| format!(" from job {j:?}")).unwrap_or_default()))),
        [one] if one.status != "success" || !one.finished => Err(DispatchError::Artifact(format!(
            "artifact {name:?} was produced by job {:?}, which is not completed successfully (status {:?})",
            one.job_key, one.status))),
        [one] => Ok(one),
        many => Err(DispatchError::Artifact(format!("artifact {name:?} is ambiguous: {} producers match; set with.job", many.len()))),
    }
}

fn artifact_download_path(workdir: &str, path: &str) -> Result<String, DispatchError> {
    let relative = std::path::Path::new(path);
    if path.trim().is_empty() || path.ends_with('/') || relative.file_name().is_none()
        || relative.is_absolute() || !relative.components().all(|c|
            matches!(c, std::path::Component::Normal(_) | std::path::Component::CurDir))
    {
        return Err(DispatchError::Artifact(
            "ci/download-artifact with.path must name a file relative to the job working directory".into(),
        ));
    }
    Ok(std::path::Path::new(workdir).join(relative).to_string_lossy().into_owned())
}

/// Run one job under `CI_MAX_JOB_SECONDS`, measured from now — the moment the
/// job was taken off the queue — and never from when it was queued.
///
/// Its own function so the property is testable without NATS: three jobs
/// taken one after another from one route each get the whole ceiling, however
/// long the ones before them took.
async fn bounded_from_pickup<F>(
    ceiling: Duration,
    job_key: &str,
    job: F,
) -> Result<JobStatus, DispatchError>
where
    F: std::future::Future<Output = Result<JobStatus, DispatchError>>,
{
    match tokio::time::timeout(ceiling, job).await {
        Ok(outcome) => outcome,
        Err(_) => Err(DispatchError::JobTimeout {
            job: job_key.to_string(),
            after: ceiling,
        }),
    }
}

/// The pull loop for one route.
///
/// One task per route rather than one shared task: a slow build on one runner
/// must not hold up another runner's queue, and JetStream's per-consumer
/// `num_pending` is only a useful backlog number if each consumer serves one
/// host.
async fn consume(dispatcher: Arc<Dispatcher>, route: Route) {
    let label = format!("{route:?}");
    /// How many unpinned jobs one network queue may be running at once — the
    /// fan-out bound for `Route::Network` below. Small: each slot can be a VM
    /// create somewhere in the fleet.
    const NETWORK_CONCURRENCY: usize = 4;
    let slots = Arc::new(tokio::sync::Semaphore::new(match &route {
        Route::Runner(_) => 1,
        Route::Network(_) => NETWORK_CONCURRENCY,
    }));
    loop {
        let consumer = match dispatcher.bus.consumer_for(&route).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("{label}: could not bind a consumer, retrying: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        loop {
            // Acquire before pulling: a draining boot must never remove a new
            // delivery from the shared consumer. The claim transaction repeats
            // this check under the durable boot-row lock.
            let admission = match dispatcher.executor.admission_permit().await {
                Ok(permit) => permit,
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            let (msg, permit) = match pull_with_capacity(&consumer, Arc::clone(&slots)).await {
                Ok(Some(delivery)) => delivery,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("{label}: message error, rebinding: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    break;
                }
            };
            let attempt = msg.info().map(|i| i.delivered as i32).unwrap_or(1);
            let Ok(job) = serde_json::from_slice::<JobMessage>(&msg.payload) else {
                // Undecodable: acking is right. Redelivering it forever would
                // block the queue on a message nothing can ever process.
                tracing::error!("{label}: undecodable job message, dropping");
                let _ = msg.ack().await;
                continue;
            };

            match &route {
                // A runner's own queue is strictly serial: one job on that
                // host at a time, each getting its full budget from pickup.
                Route::Runner(_) => {
                    let _permit = permit;
                    let _admission = admission;
                    process_delivery(Arc::clone(&dispatcher), msg, job, attempt).await;
                }
                // The network's shared queue is where "any host" jobs wait, and
                // consuming it serially made every unpinned job queue behind
                // whichever one happened to be running — on *any* runner. One
                // stuck placement (a host mid retry-ladder, a cancelled build
                // running out its step) then read as the whole network being
                // busy while other hosts sat idle. Bounded fan-out lets
                // unpinned jobs run on different runners at once; the bound
                // keeps a burst from starting more VM creates than a host
                // fleet wants concurrently.
                Route::Network(_) => {
                    let dispatcher = Arc::clone(&dispatcher);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _admission = admission;
                        process_delivery(dispatcher, msg, job, attempt).await;
                    });
                }
            }
        }
    }
}

/// Reserve capacity before JetStream delivers anything. The continuous stream
/// prefetches 200 messages, starting AckWait while buffered jobs have no worker
/// or progress heartbeat. A finite blocking batch avoids both that redelivery
/// race and an idle polling loop.
async fn pull_with_capacity(
    consumer: &async_nats::jetstream::consumer::PullConsumer,
    slots: Arc<tokio::sync::Semaphore>,
) -> Result<Option<(async_nats::jetstream::Message, tokio::sync::OwnedSemaphorePermit)>, async_nats::Error> {
    use futures::StreamExt;
    let permit = slots.acquire_owned().await?;
    let mut batch = consumer.batch().max_messages(1)
        .expires(Duration::from_secs(30)).messages().await?;
    match batch.next().await {
        Some(message) => Ok(Some((message?, permit))),
        None => Ok(None),
    }
}

/// One delivered job, end to end: heartbeat, execute, ack or retry, advance.
///
/// Split out of [`consume`] so the two route kinds can schedule it
/// differently — see the call sites there.
async fn process_delivery(
    dispatcher: Arc<Dispatcher>,
    msg: async_nats::jetstream::Message,
    job: JobMessage,
    attempt: i32,
) {
    // Tell JetStream this job is still being worked on, for as long as
    // it is. `ack_wait` is deliberately short so a dispatcher that dies
    // releases its job in about a minute; this is what stops that same
    // short window from redelivering a *healthy* long build underneath
    // itself and putting two dispatchers on one VM.
    let msg = Arc::new(msg);
    let heartbeat = {
        let msg = Arc::clone(&msg);
        let job_key = job.job_key.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(crate::bus::ACK_PROGRESS_EVERY);
            // The first tick is immediate and would be a no-op ack a
            // moment after delivery.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = msg.ack_with(AckKind::Progress).await {
                    // Logged, not fatal: one missed heartbeat still
                    // leaves most of the window, and the next tick may
                    // well land.
                    tracing::warn!(job = %job_key, "could not extend the ack window: {e}");
                }
            }
        })
    };

    // `CI_MAX_JOB_SECONDS` is enforced here, and only here. It used to
    // reach JetStream as `ack_wait` and nothing else, so once the ack
    // window stopped being derived from it the setting would have become
    // decorative — a documented ceiling on a job that bounded nothing.
    //
    // A job cut off this way leaves its VM claimed, because `run_job`
    // never reaches its own release. Its durable executor obligation blocks
    // reuse: dropping this future does not prove remote execution stopped.
    //
    // The clock starts *here*, on pickup. A job that sat on a queue
    // behind another build has spent none of its budget waiting: a
    // runner's queue is consumed one job at a time and the network
    // queue fans out, but either way the ceiling is measured from the
    // moment the job is taken, not from when it was submitted.
    let ceiling = dispatcher.config.max_job_duration;
    let outcome = loop {
        if dispatcher.executor.admission_permit().await.is_err() {
            break Err(DispatchError::InstanceDraining);
        }
        let result = bounded_from_pickup(ceiling, &job.job_key, dispatcher.run_job(&job, attempt)).await;
        if matches!(result, Err(DispatchError::MaintenancePaused)) {
            // Preserve this delivery and its retry budget. Re-select on every
            // pass so unpinned work can use another runner immediately.
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        break result;
    };
    // Before the ack, always — including on the error paths below, which
    // is why it is aborted here rather than in each arm.
    heartbeat.abort();

    match outcome {
        Err(DispatchError::InstanceDraining) => {
            // The job was never claimed. Return an outstanding pull to the
            // shared consumer so the other region can execute it.
            let _ = msg.ack_with(AckKind::Nak(Some(Duration::from_secs(1)))).await;
        }
        Ok(status) => {
            tracing::info!(job = %job.job_key, "finished: {}", status.as_str());
            let _ = msg.ack().await;
        }
        Err(DispatchError::Cancelled(_)) => {
            // Terminal, not retryable: redelivering a cancelled job
            // only makes `start_job` refuse it again in fifteen
            // minutes, and until then the message sits on the queue
            // reading as one more running job.
            tracing::info!(job = %job.job_key, "cancelled; releasing its queue slot");
            let _ = msg.ack().await;
        }
        Err(e) => {
            // Once an executor has claimed the job, even a timeout can mean
            // that a remote command is still running. Keep the claim and its
            // drain obligation; neither NATS redelivery nor lease expiry may
            // retry these effects. Pre-claim placement errors still use the
            // ordinary retry ladder below.
            match dispatcher.store.has_host_work(&job.job_id).await {
                Ok(true) => {
                    let detail = format!("Execution outcome requires reconciliation; automatic retry withheld: {e}");
                    tracing::warn!(job = %job.job_key, "{detail}");
                    if let Err(error) = dispatcher.store.set_job_status_for_boot(
                        &job.job_id, JobStatus::Running, Some(&detail), attempt, dispatcher.executor.boot_id(),
                    ).await {
                        tracing::error!(job = %job.job_key, %error, "could not persist unresolved execution");
                        return;
                    }
                    let _ = msg.ack().await;
                    return;
                }
                Err(error) => {
                    tracing::error!(job = %job.job_key, %error, "execution ownership unknown; refusing retry");
                    return;
                }
                Ok(false) => {}
            }
            // Drain handoffs and lost ACKs are deliveries, not failures.
            // Persist the actual failure count atomically with the ownership
            // check; a peer may have claimed this job since the error occurred.
            let failures = match dispatcher.store.record_unclaimed_job_error(&job.job_id, &e.to_string()).await {
                Ok(count) => count,
                Err(error) => {
                    tracing::error!(job = %job.job_key, %error, "could not persist delivery failure; refusing ACK");
                    return;
                }
            };
            if failures.is_none_or(|count| count >= crate::bus::MAX_PRECLAIM_FAILURES) {
                tracing::warn!(job = %job.job_key, ?failures, "no retry: job claimed, terminal, or failure budget exhausted: {e}");
                let _ = msg.ack().await;
            } else {
                let failures = failures.unwrap();
                let delay = crate::bus::backoff_for(failures as u32);
                tracing::warn!(job = %job.job_key, failures, retry_seconds = delay.as_secs(), "pre-claim failure: {e}");
                let _ = msg
                    .ack_with(async_nats::jetstream::AckKind::Nak(Some(delay)))
                    .await;
            }
        }
    }

    // Whatever happened, the run may now have newly-ready jobs — or be
    // finished. Advancing here is what turns a DAG into a sequence.
    if let Err(e) = dispatcher.advance_run(&job.run_id).await {
        tracing::warn!(run = %job.run_id, "could not advance: {e}");
    }
}

impl Dispatcher {
    /// Keep one consumer task per online runner, plus one per served network's
    /// unpinned queue.
    ///
    /// Reconciled on a ticker because the runner set changes underneath us: a
    /// host joins a network, or comes back after a reboot, and its queue needs
    /// an owner without restarting the process. A network added to the account —
    /// or brought into `CI_NETWORK=*`'s scope — is picked up the same way.
    pub fn spawn_consumers(self: Arc<Self>) {
        let interval = self.config.heyvm.refresh_interval;
        tokio::spawn(async move {
            // Said once, at the top, so "which ci am I reading" is answerable
            // from the first page of a log rather than inferred from behaviour.
            // Two instances that share a subject prefix share every durable
            // built from it; this line is where that becomes obvious.
            tracing::info!(
                instance = %self.config.instance_id,
                prefix = %self.config.nats_prefix,
                "binding job consumers; a second instance with this prefix would \
                 share these durables and compete for the same jobs"
            );

            let mut running: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                let pool = self.runners.snapshot();

                let mut wanted: Vec<Route> = Vec::new();
                for set in pool.served() {
                    wanted.extend(set.dispatchable().map(|r| Route::Runner(r.id.clone())));
                    if !set.network_id.is_empty() {
                        wanted.push(Route::Network(set.network_id.clone()));
                    }
                }
                // A host may be a member of two networks, which is legitimate —
                // but two consumers on one runner subject would fight over the
                // same messages.
                wanted.sort_by_key(|r| format!("{r:?}"));
                wanted.dedup_by_key(|r| format!("{r:?}"));

                for route in wanted {
                    let key = format!("{route:?}");
                    // A finished task means the loop returned, which it only
                    // does on a panic; respawn rather than leaving a queue with
                    // no consumer.
                    let alive = running.get(&key).is_some_and(|h| !h.is_finished());
                    if alive {
                        continue;
                    }
                    // The durable, not just the route. Durable names derive only
                    // from the route and CI_NATS_SUBJECT_PREFIX, so two instances
                    // sharing a prefix bind the *same* durable and compete for the
                    // same messages — silently, because neither is doing anything
                    // wrong from its own point of view. Printing the name each
                    // instance claims, next to who is claiming it, is what makes
                    // that collision visible in two log files side by side.
                    let durable = self
                        .bus
                        .durable_for(&route)
                        .unwrap_or_else(|_| "<unnameable>".to_string());
                    tracing::info!(
                        instance = %self.config.instance_id,
                        "starting a consumer for {key} on durable {durable}"
                    );
                    let d = self.clone();
                    let r = route.clone();
                    running.insert(key, tokio::spawn(consume(d, r)));
                }
            }
        });
    }

    /// This instance's claim on a VM: who, and for how long without renewal.
    fn lease(&self) -> crate::pool::Lease<'_> {
        crate::pool::Lease {
            instance: &self.config.instance_id,
            ttl: self.config.vm_lease,
        }
    }

    /// Re-run the scheduler for runs that still have something pending.
    ///
    /// `advance_run` is otherwise driven only by a submit and by jobs finishing,
    /// so a run whose jobs all failed to publish has nothing left to nudge it —
    /// the rollback above would return them to `pending` and there they would
    /// stay. Idempotent by construction: `queue_job` only moves a job that is
    /// still `pending`, and a job waiting on `needs:` is simply not ready yet.
    async fn nudge_stalled_runs(&self) {
        const BATCH: i64 = 100;
        let runs = match self.store.runs_with_pending_jobs(BATCH).await {
            Ok(runs) => runs,
            Err(e) => {
                tracing::warn!("could not look for stalled runs: {e}");
                return;
            }
        };
        for run_id in runs {
            if let Err(e) = self.advance_run(&run_id).await {
                tracing::warn!(run = %run_id, "could not advance a stalled run: {e}");
            }
        }
    }

    /// Fail jobs that have waited longer than `CI_RUNNER_WAIT_SECS` for a
    /// runner that was never going to take them.
    ///
    /// This is the behaviour the README has always described and nothing
    /// implemented: a job is pinned to its host's subject even when that host is
    /// offline — deliberately, since the warm pool is host-local and migrating
    /// discards the cache the pin asked for — but consumers are bound only for
    /// hosts that are *online*. A job pinned to one that is not therefore went
    /// to a subject nothing reads, and waited for ever with no steps and no
    /// error. `CI_RUNNER_WAIT_SECS` was dead configuration describing it.
    ///
    /// Failing is better than waiting silently: the job says which host it was
    /// waiting for, and the run stops being "running" for ever.
    ///
    /// **`queued` is the signal, and it only became a reliable one when
    /// [`crate::store::Store::claim_job`] did.** A job used to stay `queued`
    /// through the whole of VM acquisition, so this could not tell a job nobody
    /// had taken from one a consumer was several minutes into booting a machine
    /// for — and since `runner_hd_id` was also unset until then, the online
    /// check below could not save it either. It would fail a live build and
    /// blame a host that was up and working on it. A picked-up job now moves to
    /// `running` immediately, which leaves `queued` meaning exactly what this
    /// reaper needs it to: on a subject, unclaimed. A dispatcher that dies after
    /// claiming one is recovered by JetStream redelivery instead, which is the
    /// mechanism for that case and does not need a timer.
    async fn fail_jobs_waiting_for_a_runner(&self) {
        // Bounded per pass for the same reason the log sweep is: a backlog
        // built up during an outage should not become one enormous burst.
        const BATCH: i64 = 100;
        let wait = self.config.heyvm.runner_wait;
        let stuck = match self.store.jobs_waiting_longer_than(wait, BATCH).await {
            Ok(stuck) => stuck,
            Err(e) => {
                tracing::warn!("could not look for jobs waiting on a runner: {e}");
                return;
            }
        };

        let pool = self.runners.snapshot();
        let mut verdicts: HashMap<String, QueueVerdict> = HashMap::new();
        for job in stuck {
            // Where this job was actually routed, re-derived from its plan.
            //
            // NOT from `runner_hd_id`: that column is written only by
            // `claim_job`, and every row here is `queued` — never claimed — so
            // it is always NULL. Reading it made the pinned branch below dead
            // code and reported every stuck job as though it were waiting on a
            // network, whatever its `uses:` said.
            let plan: Option<JobPlan> = serde_json::from_value(job.plan.clone()).ok();
            let placed = plan.as_ref().and_then(|p| Self::place(&pool, p).ok());
            if let Some(placement) = &placed {
                let runners: Vec<_> = if let Some(node) = placement.node { vec![node] }
                    else { placement.network.runners.iter().collect() };
                let mut maintenance = false;
                for runner in runners {
                    // A database failure is uncertainty, not evidence that a
                    // deliberately held delivery should be discarded.
                    maintenance |= crate::host_maintenance::cordoned(&self.store, &runner.id).await.unwrap_or(true);
                }
                if maintenance { continue; }
            }

            // A host that came online between the query and now will take the
            // job, and failing it here would kill work about to start.
            //
            // Only a *pinned* job gets this reprieve. An unpinned one whose
            // network is full of online hosts and which still went unclaimed for
            // the whole window is not about to be taken — nothing is reading its
            // queue — and skipping it would leave the run queued for ever with
            // no error, which is the exact silence this reaper exists to end.
            if placed
                .as_ref()
                .and_then(|p| p.node)
                .is_some_and(|n| n.status.is_dispatchable())
            {
                continue;
            }

            // What the queue says, asked once per distinct route: the reaper
            // is batched, and one NATS round trip per job would turn a backlog
            // into a burst of them.
            let route = match &plan {
                Some(plan) => self.route_for(plan).await.ok(),
                None => None,
            };
            let verdict = match &route {
                None => QueueVerdict::Unknown,
                Some(r) => {
                    let key = format!("{r:?}");
                    if let Some(v) = verdicts.get(&key) {
                        *v
                    } else {
                        let v = match self.bus.depth(r).await {
                            Err(e) => {
                                tracing::warn!("could not read the queue for {key}: {e}");
                                QueueVerdict::Unknown
                            }
                            Ok(depth) => QueueVerdict::from_depth(depth),
                        };
                        verdicts.insert(key, v);
                        v
                    }
                }
            };

            // Behind a busy runner, not waiting on one that will never come.
            // The job has not been picked up, so its clock has not started;
            // CI_RUNNER_WAIT_SECS does not apply. Only an explicit
            // CI_QUEUE_WAIT_SECS bounds this wait, and by default nothing does.
            if verdict.is_capacity_wait() {
                let queued_for = job.queue_wait().unwrap_or_default();
                match Self::capacity_wait_exceeded(queued_for, self.config.heyvm.queue_wait) {
                    None => {
                        tracing::debug!(
                            job = %job.job_key,
                            waited = queued_for.as_secs(),
                            "queued behind a busy runner; its timeouts start at pickup"
                        );
                        continue;
                    }
                    Some(cap) => {
                        let detail = Self::capacity_wait_detail(queued_for, cap, verdict);
                        tracing::warn!(job = %job.job_key, "{detail}");
                        if let Err(e) = self
                            .store
                            .set_job_status(&job.id, JobStatus::Failure, Some(&detail))
                            .await
                        {
                            tracing::warn!(job = %job.job_key, "could not fail a stuck job: {e}");
                            continue;
                        }
                        if let Err(e) = self.advance_run(&job.run_id).await {
                            tracing::warn!(run = %job.run_id, "could not advance after failing: {e}");
                        }
                        continue;
                    }
                }
            }

            let detail = Self::stuck_job_detail(
                placed,
                job.network.as_deref(),
                &pool,
                wait,
                verdict,
                &self.config.instance_id,
            );
            tracing::warn!(job = %job.job_key, "{detail}");
            if let Err(e) = self
                .store
                .set_job_status(&job.id, JobStatus::Failure, Some(&detail))
                .await
            {
                tracing::warn!(job = %job.job_key, "could not fail a stuck job: {e}");
                continue;
            }
            if let Err(e) = self.advance_run(&job.run_id).await {
                tracing::warn!(run = %job.run_id, "could not advance after failing: {e}");
            }
        }
    }

    /// Whether a capacity wait has run past its configured cap, and what the
    /// cap was. `None` is the usual answer: with no `CI_QUEUE_WAIT_SECS` a job
    /// waits behind a busy runner for as long as it takes.
    fn capacity_wait_exceeded(queued_for: Duration, cap: Option<Duration>) -> Option<Duration> {
        cap.filter(|cap| queued_for > *cap)
    }

    /// The message for a job failed by `CI_QUEUE_WAIT_SECS`. Says what the
    /// job was waiting on so it is not misread as a dead runner.
    fn capacity_wait_detail(queued_for: Duration, cap: Duration, verdict: QueueVerdict) -> String {
        let behind = match verdict {
            QueueVerdict::Busy { in_flight, waiting } => {
                format!("{in_flight} job(s) in flight and {waiting} queued ahead of or with it")
            }
            _ => "other work".to_string(),
        };
        format!(
            "queued for {}s behind a busy runner ({behind}), past CI_QUEUE_WAIT_SECS ({}s). \
             The runner is up and working; this job never started, so none of its own \
             timeouts applied. Raise or unset CI_QUEUE_WAIT_SECS, add a host to the \
             network, or resubmit when the backlog clears.",
            queued_for.as_secs(),
            cap.as_secs()
        )
    }

    /// Why a job nobody took was never going to be taken.
    ///
    /// Takes the placement re-derived from the job's plan, because the routing
    /// decision is the thing being explained and no column records it. The
    /// earlier version read `runner_hd_id`, which `claim_job` alone writes, so
    /// for a `queued` row it was always NULL: the message printed the network
    /// name into a sentence claiming a host pin, and told the reader to bring
    /// back a host that had never been chosen.
    ///
    /// The cases have different fixes, so they get different sentences — and
    /// the one that matters most is a healthy network that still went unread,
    /// which means no consumer is bound to its queue.
    fn stuck_job_detail(
        placed: Option<Placement<'_>>,
        stored_network: Option<&str>,
        pool: &crate::runners::Pool,
        wait: std::time::Duration,
        verdict: QueueVerdict,
        instance: &str,
    ) -> String {
        let waited = format!("no runner took this job within {}s.", wait.as_secs());
        let stale = Self::staleness(pool);

        // The queue outranks the pool. A healthy pool cannot explain a message
        // that left the queue without this process ever seeing it, and that is
        // the case most likely to be misread as a runner problem.
        if let QueueVerdict::TakenElsewhere = verdict {
            return format!(
                "{waited} Its message was published and is no longer on the queue, yet \
                 this orchestrator never received it — so another consumer on the same \
                 durable acked it. Durable names come only from the route and \
                 CI_NATS_SUBJECT_PREFIX, so a second `ci` sharing that prefix competes \
                 for these messages and wins some of them. Check for a second running \
                 instance before looking at runners; this one is `{instance}`.{stale}"
            );
        }
        if let QueueVerdict::NoConsumer = verdict {
            return format!(
                "{waited} Nothing is bound to its subject at all — the message was \
                 published to a queue with no consumer. This instance binds consumers \
                 only for networks in CI_NETWORK and for hosts that are online, so \
                 either it does not serve this route or the bind is failing (it would \
                 log `could not bind a consumer, retrying`).{stale}"
            );
        }
        if let QueueVerdict::InFlightElsewhere(n) = verdict {
            return format!(
                "{waited} {n} message(s) on this route are delivered and unacked while \
                 this job's row still says `queued`, and this orchestrator logged \
                 nothing for it. Two things look identical here and both are worth \
                 checking: a second `ci` sharing CI_NATS_SUBJECT_PREFIX binds the same \
                 durable and competes for these messages; or this instance took the \
                 message and wedged before its first log line — the ack heartbeat \
                 keeps a held message in flight indefinitely, so a stuck consumer \
                 looks exactly like a rival one. `ps` for a second process, then look \
                 for a query with no timeout in pg_stat_activity.{stale}"
            );
        }

        let Some(p) = placed else {
            // The plan would not parse, or placement itself failed. Say only
            // what is known rather than inventing a cause.
            let where_to = stored_network.unwrap_or("its network");
            return format!(
                "{waited} It was routed to {where_to}, and this orchestrator could not \
                 work out a live target for it now. Check /runners for the network's \
                 hosts and CI_NETWORK for whether it is served.{stale}"
            );
        };

        // Pinned: a host was named, and a pin deliberately does not migrate.
        if let Some(node) = p.node {
            return format!(
                "{waited} It is pinned to host {} ({}) in network {}, which is {}. A \
                 pinned job waits for its own host rather than migrating, because the \
                 warm VM pool is host-local. Bring that host back, set `fallback: any` \
                 on the job, or point `uses:` elsewhere.{stale}",
                node.name,
                node.id,
                p.network.network_name,
                node.status.as_str()
            );
        }

        // Unpinned: it was on the network's shared queue.
        let set = p.network;
        let live: Vec<&str> = set.dispatchable().map(|r| r.name.as_str()).collect();

        // Served is checked before liveness, and the order is load-bearing: an
        // unserved network's hosts can all be online and it still gets no
        // consumer, so reporting their health would name a symptom that is not
        // the cause.
        if !set.served {
            return format!(
                "{waited} It was on the shared queue for network {}, not pinned to any \
                 host, and this orchestrator does not serve that network — CI_NETWORK \
                 selects {}. Nothing here binds a consumer to its queue, however \
                 healthy its hosts look on /runners.{stale}",
                set.network_name,
                Self::or_none(&pool.served_names())
            );
        }

        if !live.is_empty() {
            // The case that looks impossible from the dashboard and is the most
            // useful thing this message can say: hosts are up, so the job was
            // not waiting on capacity — nothing read its queue at all.
            return format!(
                "{waited} It was on the shared queue for network {} ({}), which has {} \
                 online host(s) — {}. Hosts being up means this was never a capacity \
                 problem: nothing consumed the queue. Check the Queue column on \
                 /networks — `no consumer` there is the proof, and a bind that keeps \
                 failing logs `could not bind a consumer, retrying`.{stale}",
                set.network_name,
                set.network_id,
                live.len(),
                live.join(", ")
            );
        }

        let why = if set.runners.is_empty() {
            let hint = match pool.unjoined.len() {
                0 => String::new(),
                1 => " One daemon is registered but in no network at all.".to_string(),
                n => format!(" {n} daemons are registered but in no network at all."),
            };
            format!("it has no hosts in it.{hint}")
        } else {
            let states: Vec<String> = set
                .runners
                .iter()
                .map(|r| format!("{} ({})", r.name, r.status.as_str()))
                .collect();
            format!("no host in it is online: {}", states.join(", "))
        };

        format!(
            "{waited} It was on the shared queue for network {}, not pinned to any host, \
             and {why}. Check /runners, then add a host with `heyvm network add-host` or \
             point `uses:` at a network that has one.{stale}",
            set.network_name
        )
    }

    /// A comma list, or an explicit "none" — an empty list rendered as nothing
    /// reads like the sentence was truncated.
    fn or_none(names: &[String]) -> String {
        if names.is_empty() {
            "no networks".to_string()
        } else {
            names.join(", ")
        }
    }

    /// Appended when the pool view is known to be stale, so a diagnosis drawn
    /// from it is not read as authoritative.
    fn staleness(pool: &crate::runners::Pool) -> String {
        match &pool.last_error {
            Some(e) => format!(" (this view of the pool may be stale: {e})"),
            None => String::new(),
        }
    }

    /// Every pooled VM on the runners this instance serves.
    pub async fn vm_inventory(&self) -> Result<Vec<crate::pool::PooledVmView>, DispatchError> {
        let ours = self.served_runner_ids();
        Ok(self.pool.inventory(&ours).await?)
    }

    /// Every VM image this instance has built on the runners it serves.
    pub async fn image_inventory(&self) -> Result<Vec<crate::image::CatalogEntry>, DispatchError> {
        let ours = self.served_runner_ids();
        Ok(self.images.inventory(&ours).await?)
    }

    /// The hosts this instance may act on. Scoping every pool operation to them
    /// is what keeps two orchestrators from destroying each other's machines.
    fn served_runner_ids(&self) -> Vec<String> {
        self.runners
            .snapshot()
            .all_runners()
            .map(|r| r.id.clone())
            .collect()
    }

    /// Reclaim only idle CI caches, oldest first, until this host can admit
    /// the requested VM. Never estimate recovered space from virtual disk size.
    async fn reclaim_disk_space(&self, runner: &str, required: u64) -> Result<u64, DispatchError> {
        let mut free = self.runners.free_disk_bytes(runner).await?;
        while free < required {
            let Some(vm) = self.pool.take_oldest_idle(runner).await? else {
                return Err(DispatchError::DiskPressure(format!(
                    "{runner} has {free} free disk bytes and no idle caches left; this job requires {required}"
                )));
            };
            tracing::info!(runner, sandbox = %vm.sandbox_id, free, required,
                "evicting idle CI cache for VM disk headroom");
            let (_, failed) = self.destroy_swept(vec![vm]).await;
            if !failed.is_empty() {
                return Err(DispatchError::DiskPressure(format!(
                    "{runner} idle-cache cleanup failed: {}", failed.join("; ")
                )));
            }
            free = self.runners.free_disk_bytes(runner).await?;
        }
        Ok(free)
    }

    /// Destroy VMs that have been taken out of circulation, and forget them.
    ///
    /// The row goes only once the daemon confirms — a row removed while the
    /// sandbox survives is a VM nothing will ever clean up again. A failure
    /// leaves it `draining`, which keeps it out of the pool and visible on the
    /// page rather than silently back in rotation.
    async fn destroy_swept(&self, taken: Vec<crate::pool::PooledVm>) -> (usize, Vec<String>) {
        let mut destroyed = 0;
        let mut failed = Vec::new();
        for vm in taken {
            let result = tokio::time::timeout(Duration::from_secs(30), async {
                // Serialize deletion across controller processes. Keep the
                // durable intent on error or cancellation, including after a
                // daemon delete succeeds but this transaction cannot commit.
                let mut tx = self.store.pool().begin().await?;
                let owned: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT last_job FROM ci_vm_pool WHERE sandbox_id=$1
                     AND runner_hd_id=$2 AND status='draining' AND eviction_requested
                     FOR UPDATE SKIP LOCKED",
                ).bind(&vm.sandbox_id).bind(&vm.runner_hd_id)
                    .fetch_optional(&mut *tx).await?;
                if owned.is_none() { return Ok::<_, anyhow::Error>(false); }
                if let Some(job) = owned.flatten() {
                    crate::debug_report::enqueue(&mut tx, &job, &vm.sandbox_id).await?;
                }
                let options = self.runners.options_for(&vm.runner_hd_id).await?;
                let handle = self.vms.open(options, vm.sandbox_id.clone()).await?;
                handle.destroy().await?;
                anyhow::ensure!(matches!(handle.info().await,
                    Err(VmError::Daemon { source: heyo_sdk::HeyoError::NotFound(_), .. })),
                    "daemon has not confirmed cache VM removal");
                sqlx::query("DELETE FROM ci_vm_pool WHERE sandbox_id=$1")
                    .bind(&vm.sandbox_id).execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(true)
            }).await;
            let result = result.unwrap_or_else(|_| Err(anyhow::anyhow!("cache eviction timed out")));

            match result {
                Ok(true) => {
                    destroyed += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    // Keep the durable eviction, but do not retry forever on
                    // the same dead loopback tunnel. Existing VM operations
                    // retain their own connection, just as in vm_cleanup.
                    self.runners.evict(&vm.runner_hd_id).await;
                    tracing::warn!(vm = %vm.sandbox_id, "could not destroy: {e}");
                    failed.push(format!("{}: {e}", vm.sandbox_id));
                }
            }
        }
        (destroyed, failed)
    }

    /// Destroy one pooled VM by id.
    pub async fn destroy_pooled_vm(&self, sandbox_id: &str) -> Result<String, DispatchError> {
        self.destroy_run_cache(sandbox_id, None).await
    }

    pub async fn destroy_run_cache(&self, sandbox_id: &str, run_id: Option<&str>) -> Result<String, DispatchError> {
        let ours = self.served_runner_ids();
        let Some(taken) = self.pool.take_run_cache_for_sweep(sandbox_id, &ours, run_id).await? else {
            return Err(DispatchError::VmNotSweepable(sandbox_id.to_string()));
        };
        let (destroyed, failed) = self.destroy_swept(vec![taken]).await;
        if destroyed == 1 {
            Ok(format!("{sandbox_id} is destroyed and out of the pool."))
        } else {
            Err(DispatchError::Artifact(failed.join("; ")))
        }
    }

    /// Resize one idle pooled VM in place, keeping its cache.
    ///
    /// The escape hatch for a VM that is not the size its job declared, and
    /// the only way to change a pooled VM's size *without* a cold build:
    /// `size_class` in the workflow is part of the fingerprint, so editing it
    /// there retires the warm VM. Idle only — the daemon restarts the VM to
    /// apply the change, and a job mid-step on it would die — and the row is
    /// held `draining` for the duration so no claim lands on it in between.
    /// Whatever the daemon answers, the row goes back to idle: a VM the
    /// resize failed on is still the VM it was. The VM is parked again
    /// afterwards, as `release_vm` leaves it, and the new size is read back
    /// from the daemon rather than assumed, so the page shows what happened.
    ///
    /// The workflow's own `size_class` is left as it is, on the row and in the
    /// file: this is an override, and the next claim will say so if the two
    /// disagree.
    pub async fn resize_pooled_vm(
        &self,
        sandbox_id: &str,
        class: heyo_sdk::SandboxSize,
    ) -> Result<String, DispatchError> {
        let ours = self.served_runner_ids();
        let Some(taken) = self.pool.take_idle(sandbox_id, &ours).await? else {
            return Err(DispatchError::VmNotResizable(sandbox_id.to_string()));
        };
        let result = async {
            let options = self.runners.options_for(&taken.runner_hd_id).await?;
            let vm = self.vms.open(options, sandbox_id.to_string()).await?;
            vm.resize(class, BOOT_TIMEOUT).await?;
            let size = self
                .observe_size("resize", &vm, Some(class))
                .await
                .map(|s| s.label())
                .unwrap_or_else(|| "a size the daemon did not report back".to_string());
            // An older daemon restarts the VM to apply the change and hands it
            // back running; park it again. A newer one leaves a stopped VM
            // stopped, and stopping a stopped VM is a no-op.
            if let Err(e) = vm.stop().await {
                tracing::warn!(vm = sandbox_id, "resized but could not stop: {e}");
            }
            Ok::<_, DispatchError>(size)
        }
        .await;
        if let Err(e) = self.pool.release(sandbox_id).await {
            tracing::warn!(vm = sandbox_id, "could not return the VM to the pool: {e}");
        }
        let size = result?;
        Ok(format!(
            "{sandbox_id} resized to {}: now {size}.",
            class.as_str()
        ))
    }

    /// Destroy every idle VM whose last run failed.
    pub async fn destroy_failed_vms(&self) -> Result<String, DispatchError> {
        let ours = self.served_runner_ids();
        let taken = self.pool.take_failed_for_sweep(&ours).await?;
        if taken.is_empty() {
            return Ok("No idle VM is left over from a failed run.".to_string());
        }
        let wanted = taken.len();
        let (destroyed, failed) = self.destroy_swept(taken).await;
        if failed.is_empty() {
            Ok(format!("Destroyed {destroyed} VM(s) left by failed runs."))
        } else {
            Ok(format!(
                "Destroyed {destroyed} of {wanted}. Still draining, and shown below: {}",
                failed.join("; ")
            ))
        }
    }

    /// Hold this instance's leases, and reclaim VMs whose holder stopped.
    ///
    /// Both halves on one timer because they are two views of the same fact.
    /// Renewing says "still here"; reclaiming acts on somebody else having
    /// stopped saying it.
    ///
    /// Periodic rather than startup-only, which is the second half of the fix: a
    /// sibling that dies is reclaimed within a lease period instead of leaking
    /// until somebody happens to restart this process.
    pub fn spawn_lease_loop(self: Arc<Self>) {
        let images = self.clone();
        // Slow image IO must not hold up VM lease/TTL renewal.
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Ok(_effect) = images.executor.effect_permit().await else { continue };
                for runner in images.served_runner_ids() {
                    let result = async {
                        let options = images.runners.options_for(&runner).await?;
                        images.images.evict_one(&runner, Duration::ZERO, options).await?;
                        Ok::<_, DispatchError>(())
                    };
                    match tokio::time::timeout(Duration::from_secs(30), result).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::warn!(%runner, "CI image cleanup unresolved: {e}"),
                        Err(_) => tracing::warn!(%runner, "CI image cleanup timed out; catalog retained"),
                    }
                }
            }
        });
        // Comfortably inside the lease, so a slow database or a paused process
        // gets several chances before its VMs are taken. Losing a lease that is
        // still in use would put two instances on one VM, which is much worse
        // than reclaiming a minute late.
        let every = self.config.vm_lease / 3;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every.max(Duration::from_secs(5)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Ok(_effect) = self.executor.effect_permit().await else { continue };
                if let Err(e) = self.pool.renew_leases(self.lease()).await {
                    // Not fatal, and not worth giving up a VM over: the lease
                    // has time left, and the next tick may well succeed.
                    tracing::warn!("could not renew VM leases: {e}");
                }
                self.renew_vm_ttls().await;
                self.fail_jobs_waiting_for_a_runner().await;
                self.nudge_stalled_runs().await;
                if let Err(e) = self.reclaim_pool().await {
                    tracing::warn!("could not reclaim expired VM leases: {e}");
                }
                self.sweep_idle_pool().await;
            }
        });
    }

    /// Retire pooled VMs nothing has wanted for `CI_VM_IDLE_SECS`.
    ///
    /// This is the pool's only clock now that idle VMs are stopped: the
    /// daemon's TTL reaper skips stopped sandboxes, so without this every VM
    /// this app ever parked would keep its rootfs and cache disk for ever.
    /// Two things qualify, and `take_for_sweep` states both: a VM idle longer
    /// than the window, and a VM whose fingerprint no job has touched in the
    /// window — the machine a retired `vm:` block or toolchain left behind,
    /// sitting beside the one that replaced it.
    ///
    /// Claimed VMs are refused in the query, and `draining` rows keep a VM out
    /// of circulation until the daemon confirms it is gone, so a sweep cannot
    /// fail a live build or forget a machine that still exists.
    async fn sweep_idle_pool(&self) {
        let ours = self.served_runner_ids();
        // Retire legacy idle job caches immediately; active/service ownership
        // remains protected by the pool's claim and maintenance checks.
        let idle_secs = 0;
        let taken = async {
            let live = self.pool.recent_fingerprints(&ours, idle_secs).await?;
            self.pool.take_for_sweep(&ours, &live, idle_secs).await
        }
        .await;
        let taken = match taken {
            Ok(taken) if taken.is_empty() => return,
            Ok(taken) => taken,
            Err(e) => {
                tracing::warn!("could not sweep the idle VM pool: {e}");
                return;
            }
        };
        let wanted = taken.len();
        let (destroyed, failed) = self.destroy_swept(taken).await;
        tracing::info!(
            "idle VM sweep: {destroyed} of {wanted} destroyed after {}s unused{}",
            idle_secs,
            if failed.is_empty() {
                String::new()
            } else {
                format!("; still draining: {}", failed.join(", "))
            }
        );
    }

    /// Push out the sandbox TTL of every VM this instance is running a job on.
    ///
    /// **A job may outlive its VM.** `CI_VM_TTL_SECONDS` defaults to an hour and
    /// `CI_MAX_JOB_SECONDS` to four, and the TTL was only ever set at creation
    /// and renewed when a VM was claimed or released — so a build longer than
    /// the TTL had its machine reaped mid-step, surfacing as a daemon error on a
    /// job that was doing nothing wrong.
    ///
    /// Safe to run while a step is executing because [`Vm::renew_ttl`] does not
    /// take the sandbox lock, unlike `exec` and `destroy`. If it did, this would
    /// queue behind the very build it is trying to keep alive.
    ///
    /// Only claimed VMs. An idle one is stopped, outside the reaper's reach, and
    /// retired by `sweep_idle_pool` on its own clock; renewing it would be a
    /// round trip per pooled VM per tick for nothing.
    async fn renew_vm_ttls(&self) {
        let held = match self.pool.leased_by(&self.config.instance_id).await {
            Ok(held) => held,
            Err(e) => {
                tracing::warn!("could not list held VMs to renew: {e}");
                return;
            }
        };
        if held.is_empty() {
            return;
        }

        let ttl = self.config.heyvm.vm_ttl;
        let renewals = held.iter().map(|(sandbox_id, runner)| async move {
            // Opened per pass rather than cached: the tunnel underneath is
            // cached by `Runners`, and a handle is a cheap wrapper over it.
            let options = self.runners.options_for(runner).await?;
            let vm = self.vms.open(options, sandbox_id.clone()).await?;
            vm.renew_ttl(ttl).await?;
            Ok::<_, DispatchError>(())
        });

        // Concurrent and bounded. One unreachable daemon must not hold up the
        // renewals of every other VM, nor stall the loop that also renews the
        // database leases — losing those would hand this instance's VMs away
        // while it is still using them.
        let batch = futures::future::join_all(renewals);
        let results = match tokio::time::timeout(self.config.vm_lease / 6, batch).await {
            Ok(results) => results,
            Err(_) => {
                tracing::warn!(
                    "renewing {} VM TTL(s) timed out; some may be reaped if this persists",
                    held.len()
                );
                return;
            }
        };
        for ((sandbox_id, _), result) in held.iter().zip(results) {
            if let Err(e) = result {
                // Not fatal and not a reason to discard the row: a VM that is
                // genuinely gone is caught by `acquire_vm`, which already
                // forgets an unusable pooled VM and builds a fresh one.
                tracing::warn!(vm = %sandbox_id, "could not renew the TTL: {e}");
            }
        }
    }

    /// Reclaim VMs whose lease has run out — a previous life of this process, or
    /// a sibling that died.
    pub async fn reclaim_pool(&self) -> Result<(), DispatchError> {
        let pool = self.runners.snapshot();
        let ours: Vec<String> = pool.all_runners().map(|r| r.id.clone()).collect();
        let released = self
            .pool
            .release_orphans(&ours, &self.config.instance_id)
            .await?;
        if released > 0 {
            tracing::info!("released {released} VM(s) held by jobs that are no longer running");
        }
        // A `building` row is an attempt in flight, and the process that made it
        // is the only thing that clears it. One that died holding some would
        // otherwise leave VMs "building" on /vms for ever — on a page whose
        // whole purpose is to say what is happening now.
        let swept = self
            .pool
            .sweep_stale_builds(&ours, &self.config.instance_id)
            .await?;
        if swept > 0 {
            tracing::info!("cleared {swept} abandoned VM creation(s)");
        }
        Ok(())
    }
}

/// Wrap a step's script so its exit code survives and its declared outputs come
/// back in the same exec.
///
/// GitHub gives a step a `$GITHUB_OUTPUT` file to append `name=value` lines to.
/// Reading it would normally be a second exec — but a second exec is a second
/// round trip over an iroh tunnel per step, and the daemon serializes execs per
/// sandbox anyway. Instead the file is printed after the command behind a marker
/// that is unique per step, and split back out of the combined stream.
///
/// The marker embeds the step id, so a build that happens to print the word
/// `CI_OUTPUT` cannot forge one.
fn wrap_command(script: &str, step: &Step, step_id: &str, default_wd: &str) -> String {
    let marker = output_marker(step_id);
    // A step with no `working-directory:` runs where the source was extracted,
    // not wherever the guest's shell happens to start. Without this a `run:` of
    // `cargo build` works only by luck of the image's default directory.
    let wd = step.working_directory.as_deref().unwrap_or(default_wd);
    let cd = format!("cd {} && ", shell_quote(wd));
    // `__ci_rc` is captured before anything else runs, so the step's own exit
    // code is what the job sees rather than `cat`'s.
    format!(
        "export CI_OUTPUT=\"${{CI_OUTPUT:-/tmp/ci-output-{step_id}}}\"; \
         : > \"$CI_OUTPUT\"; \
         {cd}{{ {script}
}}; __ci_rc=$?; \
         printf '\\n%s\\n' '{marker}'; cat \"$CI_OUTPUT\" 2>/dev/null; \
         exit $__ci_rc"
    )
}

fn output_marker(step_id: &str) -> String {
    format!("::ci-output::{step_id}::")
}

/// The wire spelling of a driver, as `/capabilities` lists them.
fn driver_name(driver: heyo_sdk::SandboxDriver) -> &'static str {
    match driver {
        heyo_sdk::SandboxDriver::Firecracker => "firecracker",
        heyo_sdk::SandboxDriver::FirecrackerContainerd => "firecracker_containerd",
        heyo_sdk::SandboxDriver::Kvm => "kvm",
        heyo_sdk::SandboxDriver::Libvirt => "libvirt",
    }
}

/// Whether a host's advertised drivers admit this job. `None` — a daemon that
/// could not say — admits: refusing a fleet that has not upgraded to enforce a
/// check it cannot answer would be worse than the occasional misplaced job.
fn host_can_run(supported: Option<&[String]>, driver: &str) -> bool {
    match supported {
        Some(list) => list.iter().any(|d| d == driver),
        None => true,
    }
}

/// A conservative lower bound: data disk, two declared rootfs copies (image
/// and VM), and 5 GiB left for host operation. Auto-sized images/build scratch
/// are unknown here; this is admission headroom, not a storage reservation.
fn runner_disk_requirement(spec: &crate::vm::VmSpec) -> u64 {
    let data = u64::from(spec.disk_size_gb.unwrap_or(0)) * (1 << 30);
    let rootfs = spec.build.as_ref().and_then(|b| b.size_mb).unwrap_or(0)
        .saturating_mul(1 << 20).saturating_mul(2);
    data.saturating_add(rootfs).saturating_add(5 * (1 << 30))
}

fn roomiest_runner(candidates: Vec<(String, u64)>, required: u64) -> Option<String> {
    candidates.into_iter().filter(|(_, free)| *free >= required).max_by(|a, b| {
        a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0))
    }).map(|(id, _)| id)
}

/// The TTL a VM is parked with, and so boots with on its next claim: the longer
/// of the instance default and the workflow's own `ttl_seconds`. It bounds a
/// *running* VM only — a parked VM is stopped, and its lifetime is the idle
/// sweep's — so this exists for the runner whose daemon cannot have its TTL
/// renewed mid-job. See the comment at the call site in `release_vm`.
fn idle_pool_ttl(spec_ttl_seconds: Option<u64>, default: Duration) -> Duration {
    Duration::from_secs(spec_ttl_seconds.unwrap_or(0).max(default.as_secs()))
}

/// Split the combined stream into the log text and the step's declared outputs.
fn split_outputs(out: &ExecOutput, step_id: &str) -> (String, Value) {
    let combined = out.combined();
    let marker = output_marker(step_id);
    let Some(pos) = combined.rfind(&marker) else {
        return (combined, Value::Object(Default::default()));
    };
    let (before, after) = combined.split_at(pos);
    let tail = &after[marker.len()..];
    let mut map = serde_json::Map::new();
    for line in tail.lines() {
        if let Some((k, v)) = line.split_once('=')
            && !k.trim().is_empty()
        {
            map.insert(k.trim().to_string(), Value::String(v.to_string()));
        }
    }
    (before.trim_end().to_string(), Value::Object(map))
}

/// A step's ceiling: its own `timeout-minutes`, else the default, and never
/// past the job's. The same number bounds a `run:` step's exec and a built-in
/// action's transfers, so a slow artifact fails as the step's timeout rather
/// than as some constant of its own.
fn step_timeout(step: &Step, plan: &JobPlan) -> Duration {
    step.timeout_minutes
        .map(|m| Duration::from_secs(m * 60))
        .unwrap_or(DEFAULT_STEP_TIMEOUT)
        .min(plan.timeout)
}

/// How a `ci/upload-artifact` tarball left the guest: already in the sink,
/// because the guest pushed it there itself, or in hand, read out over the
/// exec channel and still to be `put`.
enum Fetched {
    Stored(crate::artifacts::StoredArtifact),
    Bytes(Vec<u8>),
}

/// The guest-side push of a packed artifact: hash it, `curl -T` it to the
/// store's content-addressed blob route, and report what happened in a form
/// [`parse_guest_push`] reads.
///
/// The store's address and token arrive in the exec `env` as
/// `CI_ARTIFACT_URL` and `CI_ARTIFACT_TOKEN` rather than in this string, so
/// the token is never part of a command the orchestrator logs or stores. (The
/// daemon inlines exec env into the guest's serial command line, so it does
/// reach the runner host's console log — as every `env:` secret of a `run:`
/// step does. There is no narrower credential to send: the store has no scoped
/// or short-lived keys.) `with_token` says whether to send the header at all;
/// a store without auth gets none.
///
/// Written for the guest's `sh` and the serial line it arrives over: one
/// level of `$( )`, no backslashes, every line of output newline-terminated
/// (the serial protocol needs the last one). Exit 127 without curl, 1 when
/// curl or the store refused, 0 only when the store answered 2xx — and the
/// store checks the digest against the bytes, so a 2xx is the blob stored
/// under that name. The response body is printed on failure, so a `no_space`
/// or `unauthorized` from the store lands in the step log by name.
///
/// `--max-time` sits under the exec timeout so a stalled upload comes back as
/// curl's exit 28 with this script's output, rather than as the daemon's kill
/// with none.
fn guest_push_command(tarball: &str, with_token: bool, timeout: Duration) -> String {
    let auth = if with_token {
        " -H \"Authorization: Bearer $CI_ARTIFACT_TOKEN\""
    } else {
        ""
    };
    let max_time = timeout.as_secs().saturating_sub(10).max(5);
    format!(
        "f={f}; out={f}.push; \
         command -v curl >/dev/null 2>&1 || {{ echo 'the guest has no curl'; exit 127; }}; \
         d=$(sha256sum \"$f\" | cut -d' ' -f1) || {{ echo 'sha256sum failed'; exit 1; }}; \
         s=$(wc -c < \"$f\" | tr -d ' '); \
         code=$(curl -sS -o \"$out\" -w '%{{http_code}}' --connect-timeout 15 --max-time {max_time} \
         -X PUT -H 'Content-Type: application/octet-stream'{auth} -T \"$f\" \
         \"$CI_ARTIFACT_URL/blobs/$d\"); rc=$?; \
         echo \"digest=$d\"; echo \"size=$s\"; echo \"http=$code\"; echo \"curl=$rc\"; \
         if [ \"$rc\" -ne 0 ]; then head -c 600 \"$out\" 2>/dev/null; echo; rm -f \"$out\"; exit 1; fi; \
         case \"$code\" in 2*) rm -f \"$out\"; exit 0;; esac; \
         head -c 600 \"$out\" 2>/dev/null; echo; rm -f \"$out\"; exit 1",
        f = shell_quote(tarball),
    )
}

/// What [`guest_push_command`] reported: the digest and size of the blob the
/// store accepted, or why it did not — one line for the step log, with the
/// guest's own output folded in so the store's refusal is quoted rather than
/// summarized.
fn parse_guest_push(out: &crate::vm::ExecOutput) -> Result<(String, u64), String> {
    let text = out.combined();
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .map(str::trim)
    };
    if !out.succeeded() {
        let http = field("http").filter(|h| !h.is_empty() && *h != "000");
        let curl = field("curl").filter(|c| *c != "0");
        let mut why = match (http, curl, out.exit_code) {
            (Some(h), _, _) => format!("the store answered {h}"),
            (None, Some(c), _) => format!("curl exited {c}"),
            (None, None, 127) => "the guest has no curl".to_string(),
            (None, None, code) => format!("exit {code}"),
        };
        // Everything the script printed that is not one of its own fields:
        // curl's error, or the store's response body.
        let detail: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| {
                !l.is_empty()
                    && !["digest=", "size=", "http=", "curl="]
                        .iter()
                        .any(|k| l.starts_with(k))
            })
            .collect();
        if !detail.is_empty() {
            why.push_str(": ");
            why.push_str(&detail.join(" ").chars().take(400).collect::<String>());
        }
        return Err(why);
    }
    let digest = field("digest")
        .filter(|d| {
            d.len() == 64
                && d.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| "the guest did not report a sha256 digest".to_string())?;
    let size = field("size")
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .ok_or_else(|| "the guest did not report the tarball's size".to_string())?;
    Ok((digest.to_string(), size))
}

/// Single-quote a value for `sh`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A comma-separated list, or a phrase saying there is nothing to list.
///
/// "Currently serving: " followed by nothing reads as a truncated message, and
/// an empty served set is exactly the state someone needs told plainly.
fn or_none(items: &[String]) -> String {
    if items.is_empty() {
        "nothing — no network in CI_NETWORK resolved".to_string()
    } else {
        items.join(", ")
    }
}

/// The command is outside this retry boundary. Keeping the same completion
/// payload also makes retry after an ambiguous database COMMIT safe.
async fn retry_command_recording<F, Fut, E>(budget: Duration, delay: Duration, mut persist: F) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match tokio::time::timeout_at(deadline, persist()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => {
                tracing::warn!(%error, "command completed; retrying result recording without re-execution");
                if tokio::time::Instant::now() + delay >= deadline { return Err(error.to_string()); }
                tokio::time::sleep(delay).await;
            }
            Err(_) => return Err("database result recording exceeded its recovery deadline".into()),
        }
    }
}

#[derive(Debug)]
pub enum DispatchError {
    ResultRecording { step: String, exit_code: i32, error: String },
    InstanceDraining,
    MaintenancePaused,
    ControllerUnavailable(String),
    DiskPressure(String),
    Native(String),
    /// A namespace submit the tenant policy refuses. See [`crate::tenancy`].
    Tenancy(String),
    /// A namespace that has not installed the `ci` plugin, or whose install
    /// app-lb has since withdrawn. The submit route answers 403 for it.
    NotInstalled(String),
    /// A fleet submit to an instance that builds only for namespaces.
    TenantOnly,
    Store(crate::store::StoreError),
    Pool(crate::pool::PoolError),
    Bus(crate::bus::BusError),
    Runner(crate::runners::RunnerError),
    Vm(VmError),
    /// Building a runner's VM image from a Dockerfile.
    Image(crate::image::ImageError),
    BadPlan(String),
    Condition(String),
    UnknownJob(String),
    UnknownRunner {
        wanted: String,
        network: String,
    },
    RunnerOffline {
        runner: String,
        status: &'static str,
    },
    NoOnlineRunner(String),
    /// Every online host in the network was skipped — wrong driver, or
    /// unreadable capabilities. Carries the per-host reasons.
    NoCapableRunner {
        network: String,
        driver: &'static str,
        skipped: String,
    },
    /// A job pinned to a host whose daemon does not support its driver.
    RunnerCannotRun {
        runner: String,
        driver: &'static str,
        supported: String,
    },
    NoNetwork,
    /// `uses: default` with no resolvable local daemon.
    NoDefaultNode,
    /// The local daemon is known but is in no network this instance serves.
    DefaultNodeUnserved {
        node: String,
        served: Vec<String>,
    },
    /// The run was cancelled while this job was running.
    Cancelled(String),
    /// A VM cannot be swept: unknown, on another instance's host, or claimed.
    VmNotSweepable(String),
    /// A VM cannot be resized: unknown, on another instance's host, or not idle.
    VmNotResizable(String),
    /// The runner handed the job a VM smaller than its `size_class`, and one
    /// resize back to the declared class did not fix it. Boxed: five strings
    /// would otherwise make this the variant that sizes every `Result` in the
    /// module. See `Dispatcher::ensure_sized`.
    VmTooSmall(Box<UndersizedVm>),
    /// A job ran past `CI_MAX_JOB_SECONDS`.
    JobTimeout {
        job: String,
        after: Duration,
    },
    /// `uses:` named a VM that the pinned node does not have.
    UnknownVm {
        wanted: String,
        node: String,
        available: Vec<String>,
    },
    /// The network exists on the account but this instance does not serve it.
    UnservedNetwork {
        wanted: String,
        served: Vec<String>,
    },
    /// No network on the account answers to that name.
    UnknownNetwork {
        wanted: String,
        served: Vec<String>,
    },
    StepFailed(String),
    Checkout(String),
    Secrets(String),
    Artifact(String),
    Trigger(crate::trigger::TriggerError),
    Workflow(String),
}

impl From<crate::trigger::TriggerError> for DispatchError {
    fn from(e: crate::trigger::TriggerError) -> Self {
        Self::Trigger(e)
    }
}

macro_rules! from_err {
    ($t:ty, $v:ident) => {
        impl From<$t> for DispatchError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from_err!(crate::store::StoreError, Store);
from_err!(crate::pool::PoolError, Pool);
from_err!(crate::bus::BusError, Bus);
from_err!(crate::runners::RunnerError, Runner);
from_err!(VmError, Vm);
from_err!(crate::image::ImageError, Image);

impl DispatchError {
    /// The iroh tunnel to the runner, not the work: a transport-level failure
    /// to reach the daemon, never anything the daemon answered. The holder of
    /// the runner id should evict its cached tunnel on this — a NAK'd retry
    /// that redials can succeed, one that reuses the dead local port cannot.
    pub fn is_tunnel_failure(&self) -> bool {
        match self {
            Self::Vm(e) => e.is_transport(),
            Self::Image(e) => e.is_transport(),
            _ => false,
        }
    }

    /// The guest's own filesystem died underneath the job: its command output
    /// names an ext4 error no retry on the same VM can survive. The holder of
    /// the VM should destroy it on this rather than repool it.
    ///
    /// Only the plumbing variants are scanned — checkout and the VM transport,
    /// whose messages embed the output of commands *this app* ran (`mkdir`,
    /// `tar`, the chunked upload). A step failure carries its exit code and
    /// nothing else, so a build that merely *prints* one of these strings can
    /// never match.
    pub fn indicates_guest_corruption(&self) -> bool {
        let text = match self {
            Self::Checkout(_) | Self::Vm(_) => self.to_string(),
            _ => return false,
        };
        [
            // EBADMSG: ext4 metadata failed its checksum.
            "Bad message",
            // EUCLEAN: the filesystem is asking for fsck.
            "Structure needs cleaning",
            // EROFS: ext4 already hit an error and remounted itself read-only.
            "Read-only file system",
            // EIO: the virtio device refused the read or write outright.
            "Input/output error",
            // A transfer whose end-to-end hash check failed: every chunk exec
            // exited 0 and the assembled file still holds different bytes.
            // See `VmError::UploadCorrupted` — the guest acknowledged writes
            // it did not keep, which no ext4 errno ever surfaces — and its
            // mirror `VmError::DownloadCorrupted`, a guest handing back bytes
            // other than the ones it hashed.
            "sha256 mismatch",
        ]
        .iter()
        .any(|marker| text.contains(marker))
    }
}

/// The particulars of [`DispatchError::VmTooSmall`]: which VM, on which
/// runner, what it is against what the job declared, and what the one resize
/// attempt did (`then`).
#[derive(Debug)]
pub struct UndersizedVm {
    pub job: String,
    pub vm: String,
    pub runner: String,
    pub wanted: &'static str,
    pub got: String,
    pub then: String,
}

/// What a checkout that died in the VM transport reports.
///
/// A failure to *reach* the daemon keeps its `VmError`, because that is the
/// only shape [`DispatchError::is_tunnel_failure`] can see: flattened to a
/// `Checkout` string — which this used to do for every error — a dead tunnel
/// went unnoticed by the eviction in `run_job`, the runner kept the dead port
/// cached, and every following job on it inherited the same
/// `Connection reset by peer` before its first step. Everything else stays a
/// `Checkout`, which `indicates_guest_corruption` scans exactly as it scans
/// `Vm`, so nothing is lost by the split.
fn checkout_error(e: VmError) -> DispatchError {
    if e.is_transport() {
        DispatchError::Vm(e)
    } else {
        DispatchError::Checkout(e.to_string())
    }
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(e) => write!(f, "native runner: {e}"),
            Self::Tenancy(e) => write!(f, "namespace policy: {e}"),
            Self::TenantOnly => write!(f, "this ci builds only for namespaces; submit with a token minted on your namespace's CI page"),
            Self::NotInstalled(ns) => write!(f, "namespace {ns} has not installed ci; install it from its plugins page in app-lb"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Pool(e) => write!(f, "{e}"),
            Self::Bus(e) => write!(f, "{e}"),
            Self::Runner(e) => write!(f, "{e}"),
            Self::Vm(e) => write!(f, "{e}"),
            Self::Image(e) => write!(f, "{e}"),
            Self::BadPlan(e) => write!(f, "the stored plan could not be read: {e}"),
            Self::Condition(e) => write!(f, "an `if:` condition could not be evaluated: {e}"),
            Self::UnknownJob(id) => write!(f, "no job {id} exists"),
            Self::InstanceDraining => write!(f, "CI instance is draining; job returned to the shared queue"),
            Self::MaintenancePaused => write!(f, "runner is cordoned for host maintenance; job remains queued"),
            Self::UnknownRunner { wanted, network } => write!(
                f,
                "no runner {wanted:?} is a host member of network {network:?}. Add it \
                 with `heyvm network add-host`, or set `fallback: any` on the job."
            ),
            Self::RunnerOffline { runner, status } => write!(
                f,
                "runner {runner:?} is {status}. The job stays queued for that host \
                 because moving it would discard the warm VM the pin asked for; set \
                 `fallback: any` to allow migrating."
            ),
            Self::NoOnlineRunner(net) => {
                write!(f, "no host in network {net:?} is online to take this job")
            }
            Self::NoCapableRunner {
                network,
                driver,
                skipped,
            } => write!(
                f,
                "no host in network {network:?} can run this job's `driver: {driver}`: {skipped}. \
                 Pin the job with `uses: <network>/<node>`, or add a host whose daemon \
                 supports {driver}"
            ),
            Self::RunnerCannotRun {
                runner,
                driver,
                supported,
            } => write!(
                f,
                "this job is pinned to {runner:?}, whose daemon supports [{supported}] but not \
                 the job's `driver: {driver}`. Point `uses:` at a host that can run it"
            ),
            Self::NoNetwork => write!(
                f,
                "the runner pool has not resolved a network yet; check CI_NETWORK \
                 and the heyvm control plane"
            ),
            Self::NoDefaultNode => write!(
                f,
                "`uses: default` means the host this orchestrator runs on, and that \
                 host could not be identified. Set CI_DEFAULT_NODE to its daemon id \
                 or name — heyvmd reports its own id only when BACKEND_SERVER_ID is \
                 set in its environment, so it is often not discoverable."
            ),
            Self::Cancelled(job) => write!(
                f,
                "job {job:?} was cancelled. The dispatcher stopped waiting on the step \
                 that was running — the command in the guest finishes or hits its own \
                 timeout, since the daemon cannot abort it — and nothing after it ran."
            ),
            Self::DiskPressure(message) => write!(f, "{message}"),
            Self::VmNotSweepable(id) => write!(
                f,
                "{id} cannot be destroyed from here. It is either unknown, on a host \
                 this orchestrator does not serve, or currently running a job — a \
                 claimed VM is left alone so cleaning up cannot fail a live build."
            ),
            Self::VmNotResizable(id) => write!(
                f,
                "{id} cannot be resized from here. It is either unknown, on a host this \
                 orchestrator does not serve, still being created, or not idle — a \
                 resize restarts the VM, so one with a job on it is left alone."
            ),
            Self::VmTooSmall(u) => write!(
                f,
                "VM {} on {} is {}, smaller than the {} job {:?} declares, and {}. A \
                 build on it would not run as the workflow expects — it would time out \
                 rather than finish — so it was not started. Resize the VM from /vms, \
                 or check the runner's heyvmd.",
                u.vm, u.runner, u.got, u.wanted, u.job, u.then
            ),
            Self::JobTimeout { job, after } => write!(
                f,
                "job {job:?} ran past CI_MAX_JOB_SECONDS ({}s) and was cut off. Its VM \
                 is reclaimed once this dispatcher's lease on it lapses.",
                after.as_secs()
            ),
            Self::UnknownVm {
                wanted,
                node,
                available,
            } => write!(
                f,
                "no sandbox {wanted:?} exists on node {node:?}. `uses: \
                 <network>/<node>/<vm>` runs in a VM that is already there — it \
                 does not create one. On that node: {}",
                or_none(available)
            ),
            Self::DefaultNodeUnserved { node, served } => write!(
                f,
                "`uses: default` resolved to daemon {node:?}, but that host is in no \
                 network this orchestrator serves. Join it to one with \
                 `heyvm network add-host`. Currently serving: {}",
                or_none(served)
            ),
            Self::UnservedNetwork { wanted, served } => write!(
                f,
                "network {wanted:?} exists, but this orchestrator does not take work \
                 for it. Add it to CI_NETWORK (or set CI_NETWORK=*). Currently \
                 serving: {}",
                or_none(served)
            ),
            Self::UnknownNetwork { wanted, served } => write!(
                f,
                "no heyvm network is named {wanted:?}. Check the job's `uses:` or the \
                 repository's assigned network on /repos. Currently serving: {}",
                or_none(served)
            ),
            Self::StepFailed(r) => write!(f, "{r}"),
            Self::ResultRecording { step, exit_code, error } => write!(f,
                "result recording failed for {step}: command completed with exit code {exit_code}; command was not rerun; {error}"),
            Self::Checkout(r) => write!(f, "checkout failed: {r}"),
            Self::Secrets(r) => write!(f, "{r}"),
            Self::Artifact(r) => write!(f, "{r}"),
            Self::Trigger(e) => write!(f, "{e}"),
            Self::Workflow(e) => write!(f, "{e}"),
            Self::ControllerUnavailable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DispatchError {}

#[cfg(test)]
mod guest_push_tests {
    use super::*;

    fn output(exit_code: i32, text: &str) -> crate::vm::ExecOutput {
        crate::vm::ExecOutput {
            output: text.to_string(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code,
        }
    }

    /// The token travels in the exec env, never in the command the
    /// orchestrator logs; and a store without auth is sent no header at all.
    #[test]
    fn the_push_command_names_the_token_only_by_reference() {
        let with = guest_push_command("/tmp/s.artifact.tar.gz", true, Duration::from_secs(300));
        assert!(
            with.contains("Authorization: Bearer $CI_ARTIFACT_TOKEN"),
            "{with}"
        );
        assert!(with.contains("$CI_ARTIFACT_URL/blobs/$d"), "{with}");
        assert!(with.starts_with("f='/tmp/s.artifact.tar.gz'; "), "{with}");
        assert!(with.contains("-T \"$f\""), "{with}");
        let without = guest_push_command("/tmp/s.artifact.tar.gz", false, Duration::from_secs(300));
        assert!(!without.contains("Authorization"), "{without}");
    }

    /// What the serial line is known to mangle (see `Vm::download_file`):
    /// backslashes, nested `$( )`, output without a final newline.
    #[test]
    fn the_push_command_is_written_for_the_serial_line() {
        let cmd = guest_push_command("/tmp/s.artifact.tar.gz", true, Duration::from_secs(300));
        assert!(!cmd.contains('\\'), "{cmd}");
        assert!(!cmd.contains("$($("), "{cmd}");
        assert!(cmd.contains("--max-time 290"), "{cmd}");
        assert!(cmd.contains("'%{http_code}'"), "{cmd}");
        // Every exit path prints a newline-terminated line last.
        for tail in ["echo; rm -f \"$out\"; exit 1", "exit 127;", "exit 0;;"] {
            assert!(cmd.contains(tail), "missing {tail:?} in {cmd}");
        }
    }

    #[test]
    fn a_stored_push_yields_its_digest_and_size() {
        let out = output(
            0,
            "digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n\
             size=41237266\nhttp=201\ncurl=0\n",
        );
        assert_eq!(
            parse_guest_push(&out).unwrap(),
            (
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
                41237266
            )
        );
    }

    #[test]
    fn a_push_the_store_refused_quotes_the_store() {
        let out = output(
            1,
            "digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n\
             size=41237266\nhttp=507\ncurl=0\n\
             {\"error\":\"no_space\",\"message\":\"12 MB free\"}\n",
        );
        let why = parse_guest_push(&out).unwrap_err();
        assert!(why.starts_with("the store answered 507"), "{why}");
        assert!(why.contains("no_space"), "{why}");
    }

    #[test]
    fn a_push_that_never_reached_the_store_names_curl() {
        let out = output(
            1,
            "curl: (7) Failed to connect to art.internal port 443\n\
             digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n\
             size=41237266\nhttp=000\ncurl=7\n",
        );
        let why = parse_guest_push(&out).unwrap_err();
        assert!(why.starts_with("curl exited 7"), "{why}");
        assert!(why.contains("Failed to connect"), "{why}");
    }

    #[test]
    fn a_guest_without_curl_says_so() {
        let why = parse_guest_push(&output(127, "the guest has no curl\n")).unwrap_err();
        assert_eq!(why, "the guest has no curl: the guest has no curl");
    }

    /// A 2xx with a digest the store could not have accepted is a protocol
    /// fault, and must not be handed to `put_pushed` as if it were real.
    #[test]
    fn a_malformed_digest_is_not_trusted() {
        let out = output(0, "digest=DEADBEEF\nsize=3\nhttp=201\ncurl=0\n");
        assert!(parse_guest_push(&out).unwrap_err().contains("digest"));
        let out = output(0, "size=3\nhttp=201\ncurl=0\n");
        assert!(parse_guest_push(&out).unwrap_err().contains("digest"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::Step;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn command_recording_retries_until_database_recovers() {
        let mut writes = 0;
        retry_command_recording(Duration::from_secs(1), Duration::ZERO, || {
            writes += 1;
            let attempt = writes;
            async move {
                if attempt < 3 { Err("database unavailable") } else { Ok(()) }
            }
        }).await.unwrap();
        assert_eq!(writes, 3);
    }

    #[tokio::test]
    async fn command_recording_timeout_is_not_a_command_failure() {
        let error = retry_command_recording(Duration::from_millis(5), Duration::ZERO, || {
            std::future::pending::<Result<(), String>>()
        }).await.unwrap_err();
        let message = DispatchError::ResultRecording { step: "deploy.2".into(), exit_code: 0, error }.to_string();
        assert!(message.contains("result recording failed"));
        assert!(message.contains("command completed with exit code 0"));
        assert!(message.contains("command was not rerun"));
    }

    #[test]
    fn source_urls_exclude_local_paths_remote_helpers_and_embedded_secrets() {
        for url in ["https://github.com/org/repo.git", "ssh://git@example.com/repo", "git@example.com:org/repo.git"] {
            assert!(production_repo_url(url), "{url}");
        }
        for url in ["/tmp/repo", "file:///tmp/repo", "ext::sh -c command@host:repo", "https://user:secret@example.com/repo", "https:///", "-x@host:repo"] {
            assert!(!production_repo_url(url), "{url}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn checkout_reconstructs_exact_tree_and_rejects_wrong_revision_or_workflow() {
        use base64::Engine;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::process::Command;
        let root = std::env::temp_dir().join(format!("ci-checkout-{}", uuid::Uuid::new_v4()));
        let origin = root.join("origin");
        let workspace = root.join("worker's workspace");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let inode = std::fs::metadata(&workspace).unwrap().ino();
        let git = |dir: &std::path::Path, args: &[&str]| {
            let out = Command::new("git").arg("-C").arg(dir).args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Test").env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test").env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output().unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            out.stdout
        };
        let oid = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap().trim().to_owned();
        git(&origin, &["init", "-q"]);
        std::fs::write(origin.join("build.yml"), "jobs: {}\n").unwrap();
        std::fs::write(origin.join("deleted"), "old\n").unwrap();
        git(&origin, &["add", "."]);
        git(&origin, &["commit", "-qm", "base"]);
        git(&origin, &["tag", "v1"]);
        let base = oid(git(&origin, &["rev-parse", "HEAD"]));
        let base_tree = oid(git(&origin, &["rev-parse", "HEAD^{tree}"]));
        std::fs::remove_file(origin.join("deleted")).unwrap();
        std::fs::write(origin.join("binary"), b"\0\xff\x01payload").unwrap();
        std::fs::write(origin.join("executable"), "#!/bin/sh\necho patch\n").unwrap();
        std::fs::set_permissions(origin.join("executable"), std::fs::Permissions::from_mode(0o755)).unwrap();
        git(&origin, &["add", "-A"]);
        git(&origin, &["commit", "-qm", "target"]);
        let target = oid(git(&origin, &["rev-parse", "HEAD^{tree}"]));
        let patch = git(&origin, &["diff", "--binary", "--full-index", &base, "HEAD"]);
        // The remote branch advances after submission. It must not affect the build.
        std::fs::write(origin.join("not-submitted"), "later\n").unwrap();
        git(&origin, &["add", "."]);
        git(&origin, &["commit", "-qm", "later"]);
        let mut source = crate::trigger::GitPatchSource {
            base_revision: base.clone(), target_tree: base_tree, patch_base64: String::new(),
            workflows: BTreeMap::from([("build.yml".into(), "jobs: {}\n".into())]),
            changes: crate::paths::Changes::default(),
        };
        let hash = hex::encode(sha2::Sha256::digest(b"jobs: {}\n"));
        let execute = |source: &crate::trigger::GitPatchSource, hash: Option<&str>| {
            let path = root.join("source's patch");
            std::fs::write(&path, source.patch().unwrap()).unwrap();
            let script = checkout_script(workspace.to_str().unwrap(), path.to_str().unwrap(),
                origin.to_str().unwrap(), source, hash.map(|hash| ("build.yml", hash)));
            Command::new("sh").arg("-c").arg(script).env("GIT_CONFIG_GLOBAL", "/dev/null").output().unwrap()
        };
        let out = execute(&source, Some(&hash));
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(oid(git(&workspace, &["rev-parse", "HEAD"])), base);
        assert_eq!(oid(git(&workspace, &["describe", "--tags", "--exact-match"])), "v1");
        // Operator promotions have no workflow file in Git. Their checkout
        // must still select the retained revision, not the advanced branch.
        assert!(execute(&source, None).status.success());
        assert_eq!(oid(git(&workspace, &["rev-parse", "HEAD"])), base);
        source.target_tree = target.clone();
        source.patch_base64 = base64::engine::general_purpose::STANDARD.encode(patch);
        let out = execute(&source, Some(&hash));
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(oid(git(&workspace, &["rev-parse", "HEAD^{tree}"])), target);
        assert_eq!(std::fs::metadata(&workspace).unwrap().ino(), inode);
        assert_eq!(std::fs::read(workspace.join("binary")).unwrap(), b"\0\xff\x01payload");
        assert!(!workspace.join("deleted").exists() && !workspace.join("not-submitted").exists());
        assert_ne!(std::fs::metadata(workspace.join("executable")).unwrap().permissions().mode() & 0o111, 0);
        assert!(!execute(&source, Some(&"0".repeat(64))).status.success());
        source.target_tree = "a".repeat(40);
        assert!(!execute(&source, Some(&hash)).status.success());
        assert!(!execute(&source, None).status.success());
        source.base_revision = "b".repeat(40);
        assert!(!execute(&source, Some(&hash)).status.success());
        assert!(!execute(&source, None).status.success());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn step(run: &str) -> Step {
        Step {
            name: None,
            id: None,
            condition: None,
            uses: None,
            with: BTreeMap::new(),
            run: Some(run.to_string()),
            shell: None,
            working_directory: None,
            env: BTreeMap::new(),
            timeout_minutes: None,
            continue_on_error: false,
        }
    }

    fn output(combined: &str, exit: i32) -> ExecOutput {
        ExecOutput {
            output: combined.to_string(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: exit,
        }
    }

    fn download_candidate(run: &str, job: &str) -> DownloadCandidate {
        DownloadCandidate {
            run_id: run.into(), name: "bundle".into(), job_key: job.into(),
            status: "success".into(), finished: true,
            stored: crate::artifacts::StoredArtifact {
                sink: "disk", digest: None, size_bytes: 1, uri: "/recorded".into(), public_url: None,
            },
        }
    }

    #[test]
    fn artifact_download_selection_is_same_run_unique_and_explicit() {
        let wrong = vec![download_candidate("other-run", "build")];
        assert!(select_download("this-run", "bundle", None, &wrong).unwrap_err().to_string().contains("current run"));
        assert!(select_download("this-run", "missing", None, &[]).unwrap_err().to_string().contains("no artifact"));

        let two = vec![download_candidate("this-run", "mac"), download_candidate("this-run", "windows")];
        assert!(select_download("this-run", "bundle", None, &two).unwrap_err().to_string().contains("ambiguous"));
        assert_eq!(select_download("this-run", "bundle", Some("windows"), &two).unwrap().job_key, "windows");
    }

    #[test]
    fn artifact_download_requires_a_finished_successful_producer_and_safe_path() {
        let mut failed = download_candidate("run", "build");
        failed.status = "failure".into();
        assert!(select_download("run", "bundle", None, &[failed]).unwrap_err().to_string().contains("not completed successfully"));
        assert_eq!(artifact_download_path("/workspace", "dist/native.tar.gz").unwrap(), "/workspace/dist/native.tar.gz");
        assert_eq!(artifact_download_path("/workspace/", ".cache/native.tar.gz").unwrap(), "/workspace/.cache/native.tar.gz");
        for path in ["../secret", "dist/../../secret", "/etc/passwd", ".", "", "dist/"] {
            assert!(artifact_download_path("/workspace", path).is_err(), "{path:?}");
        }
    }

    // ---- the stuck-job diagnosis ----------------------------------------

    /// The failure that cost days: a healthy pool, a bound consumer, an empty
    /// queue, and a job nothing ran. Only the queue can explain it, and the
    /// answer must name the second instance rather than the runners.
    #[test]
    fn an_empty_queue_with_a_queued_row_blames_another_consumer() {
        let pool = healthy_ci_runners();
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            Some("ci-runners"),
            &pool,
            WAIT,
            QueueVerdict::TakenElsewhere,
            "ci-abc123",
        );
        assert!(detail.contains("no longer on the queue"), "{detail}");
        assert!(detail.contains("another consumer"), "{detail}");
        assert!(
            detail.contains("CI_NATS_SUBJECT_PREFIX"),
            "names the cause: {detail}"
        );
        assert!(
            detail.contains("ci-abc123"),
            "names this instance: {detail}"
        );
        // The pool is healthy and therefore irrelevant; saying anything about
        // hosts here is what sent the last investigation the wrong way.
        assert!(!detail.contains("online host(s)"), "{detail}");
        assert!(!detail.contains("add a host"), "{detail}");
    }

    /// Delivered and unacked is the same collision caught a moment earlier.
    #[test]
    fn an_in_flight_message_this_instance_does_not_hold_blames_the_same_thing() {
        let pool = healthy_ci_runners();
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            None,
            &pool,
            WAIT,
            QueueVerdict::InFlightElsewhere(2),
            "ci-abc123",
        );
        assert!(detail.contains("2 message(s)"), "{detail}");
        // Both causes named, because a wedged local consumer and a rival one
        // produce the same counters — the heartbeat holds a message in flight
        // for as long as the loop holds it.
        assert!(detail.contains("second `ci`"), "{detail}");
        assert!(
            detail.contains("wedged before its first log line"),
            "{detail}"
        );
    }

    /// Nothing bound is decisive on its own and outranks the pool.
    #[test]
    fn no_consumer_bound_says_so_rather_than_describing_hosts() {
        let pool = healthy_ci_runners();
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            None,
            &pool,
            WAIT,
            QueueVerdict::NoConsumer,
            "ci-abc123",
        );
        assert!(
            detail.contains("Nothing is bound to its subject"),
            "{detail}"
        );
        assert!(detail.contains("could not bind a consumer"), "{detail}");
        assert!(!detail.contains("online host(s)"), "{detail}");
    }

    /// A message still waiting is genuinely a pool question, so the pool-based
    /// reasoning must still be reachable.
    #[test]
    fn a_waiting_message_still_falls_through_to_the_pool_explanation() {
        let pool = healthy_ci_runners();
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            None,
            &pool,
            WAIT,
            QueueVerdict::Waiting(1),
            "ci-abc123",
        );
        assert!(detail.contains("online host(s)"), "{detail}");
        assert!(!detail.contains("another consumer"), "{detail}");
    }

    const WAIT: std::time::Duration = std::time::Duration::from_secs(900);

    // ---- timeouts start at pickup, not at enqueue ------------------------

    /// The bug: N jobs queued on one route, which is consumed one at a time.
    /// The first ran; the rest aged past CI_RUNNER_WAIT_SECS on the queue and
    /// were failed as "nothing consumed the queue". With work in flight and
    /// a backlog behind it the queue is busy, and a busy queue is a wait.
    #[test]
    fn a_backlog_behind_a_working_consumer_is_a_capacity_wait_not_a_fault() {
        let depth = crate::bus::QueueDepth {
            in_flight: 1,
            waiting: 2,
        };
        let verdict = QueueVerdict::from_depth(Some(depth));
        assert_eq!(
            verdict,
            QueueVerdict::Busy {
                in_flight: 1,
                waiting: 2
            }
        );
        assert!(verdict.is_capacity_wait());

        // The other readings are unchanged: these are real faults.
        assert_eq!(QueueVerdict::from_depth(None), QueueVerdict::NoConsumer);
        assert_eq!(
            QueueVerdict::from_depth(Some(crate::bus::QueueDepth {
                in_flight: 0,
                waiting: 3
            })),
            QueueVerdict::Waiting(3)
        );
        assert_eq!(
            QueueVerdict::from_depth(Some(crate::bus::QueueDepth {
                in_flight: 2,
                waiting: 0
            })),
            QueueVerdict::InFlightElsewhere(2)
        );
        assert_eq!(
            QueueVerdict::from_depth(Some(crate::bus::QueueDepth {
                in_flight: 0,
                waiting: 0
            })),
            QueueVerdict::TakenElsewhere
        );
        for v in [
            QueueVerdict::NoConsumer,
            QueueVerdict::Waiting(1),
            QueueVerdict::InFlightElsewhere(1),
            QueueVerdict::TakenElsewhere,
            QueueVerdict::Unknown,
        ] {
            assert!(!v.is_capacity_wait(), "{v:?}");
        }
    }

    /// Without CI_QUEUE_WAIT_SECS a capacity wait is never failed, however
    /// long it has gone on; with it, only once the cap is passed.
    #[test]
    fn a_capacity_wait_is_unbounded_unless_a_queue_wait_is_configured() {
        let days = Duration::from_secs(3 * 24 * 3600);
        assert_eq!(Dispatcher::capacity_wait_exceeded(days, None), None);
        let cap = Duration::from_secs(3600);
        assert_eq!(
            Dispatcher::capacity_wait_exceeded(Duration::from_secs(3599), Some(cap)),
            None
        );
        assert_eq!(
            Dispatcher::capacity_wait_exceeded(Duration::from_secs(3600), Some(cap)),
            None
        );
        assert_eq!(
            Dispatcher::capacity_wait_exceeded(Duration::from_secs(3601), Some(cap)),
            Some(cap)
        );
        let detail = Dispatcher::capacity_wait_detail(
            Duration::from_secs(3601),
            cap,
            QueueVerdict::Busy {
                in_flight: 1,
                waiting: 4,
            },
        );
        assert!(detail.contains("CI_QUEUE_WAIT_SECS (3600s)"), "{detail}");
        assert!(detail.contains("never started"), "{detail}");
        assert!(!detail.contains("no runner took"), "{detail}");
    }

    /// A job's queue wait is `queued_at → started_at`; its run time is
    /// `started_at → finished_at`. The two never overlap, so time on the queue
    /// is not charged to the job.
    #[test]
    fn queue_wait_is_measured_to_pickup_and_the_run_clock_starts_there() {
        use chrono::{TimeZone, Utc};
        let queued = Utc.with_ymd_and_hms(2026, 8, 22, 10, 0, 0).unwrap();
        let picked_up = queued + chrono::Duration::minutes(45);
        let done = picked_up + chrono::Duration::minutes(5);
        let job = crate::store::JobRow {
            id: "r.j".into(),
            run_id: "r".into(),
            job_key: "j".into(),
            base_id: "j".into(),
            display: "j".into(),
            network: None,
            runner_hd_id: None,
            fingerprint: None,
            sandbox_id: None,
            status: "success".into(),
            attempt: 1,
            executor_boot: None,
            matrix: serde_json::json!({}),
            outputs: serde_json::json!({}),
            plan: serde_json::json!({}),
            error: None,
            carried_from: None,
            queued_at: Some(queued),
            started_at: Some(picked_up),
            finished_at: Some(done),
        };
        assert_eq!(job.queue_wait(), Some(Duration::from_secs(45 * 60)));
        let ran = (done - picked_up).to_std().unwrap();
        assert_eq!(ran, Duration::from_secs(5 * 60));

        let never_queued = crate::store::JobRow {
            queued_at: None,
            started_at: None,
            ..job
        };
        assert_eq!(never_queued.queue_wait(), None);
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_NATS_URL; disposable JetStream"]
    async fn queued_jobs_are_not_delivered_before_capacity_or_prefetched() {
        let client = async_nats::connect(std::env::var("CI_TEST_NATS_URL").unwrap()).await.unwrap();
        let js = async_nats::jetstream::new(client);
        let name = format!("capacity_{}", uuid::Uuid::new_v4().simple());
        let stream = js.create_stream(async_nats::jetstream::stream::Config {
            name: name.clone(), subjects: vec![name.clone()], ..Default::default()
        }).await.unwrap();
        let mut consumer = stream.create_consumer(async_nats::jetstream::consumer::pull::Config {
            ack_wait: Duration::from_millis(100), ..Default::default()
        }).await.unwrap();
        for body in ["first", "second", "third"] {
            js.publish(name.clone(), body.into()).await.unwrap().await.unwrap();
        }
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (first, permit) = pull_with_capacity(&consumer, Arc::clone(&slots)).await.unwrap().unwrap();
        assert_eq!(first.payload.as_ref(), b"first");
        first.double_ack().await.unwrap();
        let waiting = {
            let consumer = consumer.clone();
            let slots = Arc::clone(&slots);
            tokio::spawn(async move { pull_with_capacity(&consumer, slots).await })
        };
        // Longer than AckWait: neither waiting job may have entered delivery.
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert!(!waiting.is_finished());
        let info = consumer.info().await.unwrap();
        assert_eq!(info.delivered.consumer_sequence, 1);
        assert_eq!(info.num_pending, 2);
        assert_eq!(info.num_ack_pending, 0);
        drop(permit);
        let (second, permit) = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await.unwrap().unwrap().unwrap().unwrap();
        assert_eq!(second.payload.as_ref(), b"second");
        assert_eq!(second.info().unwrap().delivered, 1);
        second.double_ack().await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(consumer.info().await.unwrap().num_pending, 1, "no background refill may take the third job");
        drop(permit);
        js.delete_stream(name).await.unwrap();
    }

    /// Three jobs on one route with capacity one. Each takes 90% of the
    /// ceiling, so the last one is taken long after the ceiling has elapsed
    /// since it was queued. All three must succeed: the ceiling is measured
    /// from pickup, and a job that overruns it from *pickup* is still cut off.
    #[tokio::test(start_paused = true)]
    async fn each_job_on_a_busy_route_gets_the_whole_ceiling_from_pickup() {
        let ceiling = Duration::from_secs(100);
        let queued_at = tokio::time::Instant::now();
        let mut outcomes = Vec::new();
        for key in ["job-1", "job-2", "job-3"] {
            // Picked up only now: the previous job ran to its end first.
            let picked_up = tokio::time::Instant::now();
            let outcome = bounded_from_pickup(ceiling, key, async {
                tokio::time::sleep(Duration::from_secs(90)).await;
                Ok(JobStatus::Success)
            })
            .await;
            outcomes.push((key, picked_up.duration_since(queued_at), outcome));
        }
        for (key, waited, outcome) in &outcomes {
            assert!(
                matches!(outcome, Ok(JobStatus::Success)),
                "{key} waited {}s and should have succeeded: {outcome:?}",
                waited.as_secs()
            );
        }
        // The third job was taken 180s after enqueue — well past the 100s
        // ceiling — and that did not count against it.
        assert_eq!(outcomes[2].1, Duration::from_secs(180));

        // The ceiling is real, from pickup: a job that runs past it is cut.
        let late = bounded_from_pickup(ceiling, "job-4", async {
            tokio::time::sleep(Duration::from_secs(101)).await;
            Ok(JobStatus::Success)
        })
        .await;
        assert!(
            matches!(late, Err(DispatchError::JobTimeout { ref job, after }) if job == "job-4" && after == ceiling),
            "{late:?}"
        );
    }

    /// A served network with online hosts, for the case that looks impossible.
    fn healthy_ci_runners() -> crate::runners::Pool {
        use crate::runners::{Runner, RunnerSet, RunnerStatus};
        let mut pool = test_pool();
        pool.networks.push(RunnerSet {
            network_id: "net-3".into(),
            network_name: "ci-runners".into(),
            is_default: false,
            served: true,
            runners: vec![
                Runner {
                    id: "hd-YdBcLuMVw4mA-zv9".into(),
                    name: "this host".into(),
                    status: RunnerStatus::Online,
                    last_seen_at: None,
                },
                Runner {
                    id: "hd-second".into(),
                    name: "builder-2".into(),
                    status: RunnerStatus::Online,
                    last_seen_at: None,
                },
            ],
        });
        pool
    }

    fn set_named<'a>(pool: &'a crate::runners::Pool, name: &str) -> &'a crate::runners::RunnerSet {
        pool.find(name).expect("network in the test pool")
    }

    /// Hosts up, job unread for the whole window. Capacity was never the
    /// problem, so the message must point at the queue's consumer rather than
    /// telling somebody to bring a host back that is already online — which is
    /// what sent the last investigation looking at host health for an hour.
    #[test]
    fn a_healthy_network_that_went_unread_blames_the_consumer_not_the_hosts() {
        let pool = healthy_ci_runners();
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            Some("ci-runners"),
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );

        assert!(detail.contains("2 online host(s)"), "{detail}");
        assert!(detail.contains("nothing consumed the queue"), "{detail}");
        // Deliberately NOT the `starting a consumer for …` line: that is logged
        // before the bind is attempted (dispatch.rs, `spawn_consumers`), and
        // `consume` retries a failing bind for ever without the task finishing —
        // so it prints once per route per process whether or not a consumer was
        // ever bound. `Bus::depth` returning `Ok(None)`, which is what the Queue
        // column renders as `no consumer`, is the signal that actually proves it.
        assert!(
            detail.contains("Queue column"),
            "names real evidence: {detail}"
        );
        assert!(detail.contains("could not bind a consumer"), "{detail}");
        assert!(
            !detail.contains("starting a consumer"),
            "that line proves nothing about binding: {detail}"
        );
        assert!(
            detail.contains("net-3"),
            "names the id the subject uses: {detail}"
        );
        assert!(
            !detail.contains("Bring that host back"),
            "the hosts are up: {detail}"
        );
        assert!(!detail.contains("is pinned to"), "not a pin: {detail}");
    }

    /// The pinned wording is reachable again — it was dead code before, since
    /// the column it keyed on is never set for a queued job.
    #[test]
    fn a_pinned_job_names_its_host_and_that_hosts_status() {
        use crate::runners::{Runner, RunnerStatus};
        let pool = healthy_ci_runners();
        let offline = Runner {
            id: "hd-gone".into(),
            name: "mac-mini".into(),
            status: RunnerStatus::Offline,
            last_seen_at: None,
        };
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: Some(&offline),
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            None,
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );

        assert!(
            detail.contains("pinned to host mac-mini (hd-gone)"),
            "{detail}"
        );
        assert!(detail.contains("is offline"), "{detail}");
        assert!(detail.contains("`fallback: any`"), "{detail}");
    }

    /// An unserved network is a config answer, not a dead host.
    #[test]
    fn an_unserved_network_names_ci_network_and_what_is_served() {
        let pool = test_pool();
        let placed = Placement {
            network: set_named(&pool, "lab"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            Some("lab"),
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );
        assert!(detail.contains("does not serve that network"), "{detail}");
        assert!(detail.contains("CI_NETWORK"), "{detail}");
        assert!(
            detail.contains("prod-runners"),
            "must say what it does serve: {detail}"
        );
        // The hosts in an unserved network are online and irrelevant; saying so
        // is what stops the reader chasing host health again.
        assert!(
            detail.contains("however healthy its hosts look"),
            "{detail}"
        );
    }

    /// The commonest cause is pointed at rather than left as an empty network.
    #[test]
    fn an_empty_network_mentions_daemons_that_joined_nothing() {
        use crate::runners::{Runner, RunnerSet, RunnerStatus};
        let mut pool = test_pool();
        pool.networks.push(RunnerSet {
            network_id: "net-3".into(),
            network_name: "ci-runners".into(),
            is_default: false,
            served: true,
            runners: vec![],
        });
        pool.unjoined.push(Runner {
            id: "hd-YdBcLuMVw4mA-zv9".into(),
            name: "this host".into(),
            status: RunnerStatus::Online,
            last_seen_at: None,
        });
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            Some("ci-runners"),
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );
        assert!(detail.contains("no hosts in it"), "{detail}");
        assert!(
            detail.contains("One daemon is registered but in no network"),
            "{detail}"
        );
    }

    /// Members present, none dispatchable: name them and their states.
    #[test]
    fn an_offline_network_lists_each_host_and_its_status() {
        use crate::runners::{Runner, RunnerSet, RunnerStatus};
        let mut pool = test_pool();
        pool.networks.push(RunnerSet {
            network_id: "net-3".into(),
            network_name: "ci-runners".into(),
            is_default: false,
            served: true,
            runners: vec![Runner {
                id: "hd-YdBcLuMVw4mA-zv9".into(),
                name: "this host".into(),
                status: RunnerStatus::Orphaned,
                last_seen_at: None,
            }],
        });
        let placed = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        let detail = Dispatcher::stuck_job_detail(
            Some(placed),
            Some("ci-runners"),
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );
        assert!(detail.contains("this host (orphaned)"), "{detail}");
        assert!(!detail.contains("is pinned to"), "{detail}");
    }

    /// An unplaceable job must not have a cause invented for it.
    #[test]
    fn an_unplaceable_job_says_only_what_is_known() {
        let detail = Dispatcher::stuck_job_detail(
            None,
            Some("ci-runners"),
            &test_pool(),
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );
        assert!(
            detail.contains("could not work out a live target"),
            "{detail}"
        );
        assert!(detail.contains("ci-runners"), "{detail}");
        assert!(!detail.contains("is pinned to"), "{detail}");
    }

    /// A diagnosis drawn from a stale pool must not read as authoritative.
    #[test]
    fn a_stale_pool_is_admitted_in_the_message() {
        let mut pool = test_pool();
        pool.last_error = Some("GET /me/daemons: timed out".into());
        let detail = Dispatcher::stuck_job_detail(
            None,
            Some("nope"),
            &pool,
            WAIT,
            QueueVerdict::Unknown,
            "ci-test",
        );
        assert!(detail.contains("may be stale"), "{detail}");
        assert!(detail.contains("timed out"), "{detail}");
    }

    /// How long it waited is the one fact every variant carries.
    #[test]
    fn every_variant_reports_the_wait() {
        let pool = healthy_ci_runners();
        let network = Placement {
            network: set_named(&pool, "ci-runners"),
            node: None,
            vm: None,
        };
        for detail in [
            Dispatcher::stuck_job_detail(
                Some(network),
                None,
                &pool,
                WAIT,
                QueueVerdict::Unknown,
                "ci-test",
            ),
            Dispatcher::stuck_job_detail(
                None,
                Some("x"),
                &pool,
                WAIT,
                QueueVerdict::Unknown,
                "ci-test",
            ),
        ] {
            assert!(detail.contains("within 900s"), "{detail}");
        }
    }

    // ---- network resolution ---------------------------------------------

    fn test_pool() -> crate::runners::Pool {
        use crate::runners::{Runner, RunnerSet, RunnerStatus};
        let host = |id: &str| Runner {
            id: id.into(),
            name: id.into(),
            status: RunnerStatus::Online,
            last_seen_at: None,
        };
        crate::runners::Pool {
            networks: vec![
                RunnerSet {
                    network_id: "net-1".into(),
                    network_name: "prod-runners".into(),
                    is_default: true,
                    served: true,
                    runners: vec![host("hd-1")],
                },
                RunnerSet {
                    network_id: "net-2".into(),
                    network_name: "lab".into(),
                    is_default: false,
                    served: false,
                    runners: vec![host("hd-2")],
                },
            ],
            unjoined: vec![],
            last_error: None,
            default_network_id: "net-1".into(),
            default_node_id: "hd-1".into(),
        }
    }

    /// A real one-job plan, built from a workflow rather than hand-assembled,
    /// so what is asserted about `uses:` is what `uses:` actually produces.
    fn plan_targeting(network: Option<&str>) -> JobPlan {
        let uses = match network {
            Some(n) => format!("    uses: \"{n}\"\n"),
            None => String::new(),
        };
        let yaml = format!(
            "name: t\njobs:\n  build:\n{uses}    vm: {{ driver: firecracker }}\n    \
             steps: [{{ run: \"true\" }}]\n"
        );
        let wf = crate::workflow::Workflow::parse("t.yml", &yaml).expect("workflow parses");
        crate::plan::Plan::build(&wf)
            .expect("plan builds")
            .jobs
            .remove(0)
    }

    /// A job with no network runs in the default one — which is what makes a
    /// workflow that says nothing about hardware still land somewhere chosen.
    #[test]
    fn a_job_naming_no_network_lands_in_the_default() {
        let pool = test_pool();
        let set = Dispatcher::network_of(&pool, &plan_targeting(None)).expect("resolves");
        assert_eq!(set.network_id, "net-1");
    }

    /// Either spelling, because `uses:` and a repository assignment are both
    /// written by hand.
    #[test]
    fn a_job_naming_a_served_network_by_id_or_name_resolves_to_it() {
        let pool = test_pool();
        for spelling in ["prod-runners", "net-1", "PROD-Runners", " prod-runners "] {
            let set = Dispatcher::network_of(&pool, &plan_targeting(Some(spelling)))
                .unwrap_or_else(|e| panic!("{spelling:?}: {e}"));
            assert_eq!(set.network_id, "net-1");
        }
    }

    /// The two failures a person actually hits, told apart — one is a
    /// `CI_NETWORK` change and the other is a typo, and the same message for
    /// both sends them to the wrong file.
    #[test]
    fn an_unserved_network_and_an_unknown_one_are_different_errors() {
        let pool = test_pool();

        let err = Dispatcher::network_of(&pool, &plan_targeting(Some("lab"))).unwrap_err();
        assert!(
            matches!(err, DispatchError::UnservedNetwork { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("CI_NETWORK"), "{err}");
        assert!(
            err.to_string().contains("prod-runners"),
            "names what is served: {err}"
        );

        let err = Dispatcher::network_of(&pool, &plan_targeting(Some("nope"))).unwrap_err();
        assert!(
            matches!(err, DispatchError::UnknownNetwork { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("nope"), "{err}");
    }

    /// `uses: default` resolves to the orchestrator's own host, and pins — the
    /// whole point is "this machine", so it must not land on the network's
    /// shared queue.
    #[test]
    fn default_places_the_job_on_this_orchestrators_host() {
        let pool = test_pool();
        let plan = plan_targeting(Some("default"));
        assert!(
            plan.target.local,
            "the fixture must exercise the local form"
        );

        let placed = Dispatcher::place(&pool, &plan).expect("resolves");
        assert_eq!(placed.network.network_id, "net-1");
        assert_eq!(placed.node.map(|n| n.id.as_str()), Some("hd-1"));
        assert!(placed.vm.is_none());
    }

    /// The two ways `default` fails, told apart: nothing identified the host at
    /// all, versus a host that is known but in no network we serve. One is
    /// CI_DEFAULT_NODE, the other is `heyvm network add-host`.
    #[test]
    fn an_unresolvable_default_names_which_fix_applies() {
        let plan = plan_targeting(Some("default"));

        let mut pool = test_pool();
        pool.default_node_id = String::new();
        let err = Dispatcher::place(&pool, &plan).unwrap_err();
        assert!(matches!(err, DispatchError::NoDefaultNode), "{err:?}");
        assert!(err.to_string().contains("CI_DEFAULT_NODE"), "{err}");

        // Known, but its only network is one this instance does not serve.
        let mut pool = test_pool();
        pool.default_node_id = "hd-2".into();
        let err = Dispatcher::place(&pool, &plan).unwrap_err();
        assert!(
            matches!(err, DispatchError::DefaultNodeUnserved { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("heyvm network add-host"), "{err}");
    }

    /// The three-segment form: a named VM on a named host. The host pins the
    /// queue and the VM rides along for the executor.
    #[test]
    fn naming_a_vm_pins_its_host_and_carries_the_vm() {
        let pool = test_pool();
        let plan = plan_targeting(Some("prod-runners/hd-1/sb-1a34"));

        let placed = Dispatcher::place(&pool, &plan).expect("resolves");
        assert_eq!(placed.node.map(|n| n.id.as_str()), Some("hd-1"));
        assert_eq!(placed.vm, Some("sb-1a34"));
        assert!(plan.target.is_existing_vm());
    }

    /// `fallback: any` moves a job to another host when the pinned one is gone.
    /// It must not do that for a job that named a VM — the VM lives on one host,
    /// and "any host" would run the steps somewhere it does not exist.
    #[test]
    fn fallback_any_does_not_relocate_a_job_that_named_a_vm() {
        let pool = test_pool();

        let mut plan = plan_targeting(Some("prod-runners/nosuchhost"));
        plan.fallback = Fallback::Any;
        let placed = Dispatcher::place(&pool, &plan).expect("falls back");
        assert!(placed.node.is_none(), "an unpinned fallback is the network");

        let mut plan = plan_targeting(Some("prod-runners/nosuchhost/sb-1a34"));
        plan.fallback = Fallback::Any;
        let err = Dispatcher::place(&pool, &plan).unwrap_err();
        assert!(
            matches!(err, DispatchError::UnknownRunner { .. }),
            "{err:?}"
        );
    }

    /// A VM named in `uses:` is somebody else's machine. The pool never created
    /// it, so teardown must not touch it — destroying a long-lived VM because a
    /// workflow set `reuse: false` in a `vm:` block that never applied to it
    /// would be the worst kind of surprise.
    #[test]
    fn an_existing_vm_is_never_torn_down_by_the_job_that_used_it() {
        let mut plan = plan_targeting(Some("prod-runners/hd-1/sb-1a34"));
        assert!(plan.target.is_existing_vm());
        // Even with the `vm:` block asking for destruction, which is exactly the
        // configuration that would otherwise delete it.
        plan.vm.reuse = false;

        // `release_vm` returns before touching the VM or the pool. Asserted on
        // the predicate it branches on, because the call itself needs a live
        // daemon; the branch is the whole behaviour.
        assert!(
            plan.target.is_existing_vm(),
            "release_vm returns early on exactly this"
        );

        let built = plan_targeting(Some("prod-runners/hd-1"));
        assert!(
            !built.target.is_existing_vm(),
            "a job that built its own VM must still be released"
        );
    }

    /// A guest whose ext4 has died must not go back into the pool — the next
    /// attempt prefers the same idle VM and would fail identically. The
    /// classification is on the plumbing's own errors, never a step's, so a
    /// build that merely prints one of the marker strings cannot get its
    /// healthy warm VM destroyed.
    #[test]
    fn only_the_plumbing_can_declare_the_guest_filesystem_dead() {
        // The observed failure, verbatim: chunked upload during checkout.
        let corrupt = DispatchError::Vm(VmError::UploadFailed {
            sandbox: "sb-2e3c4317".into(),
            path: "/workspace/.ci-source.tar.gz".into(),
            chunk: 26,
            of: 529,
            detail: "mkdir: cannot create directory '/workspace': Bad message".into(),
        });
        assert!(corrupt.indicates_guest_corruption());

        // The same output wrapped the way `checkout` reports it.
        let checkout = DispatchError::Checkout(
            "tar: dist/index.html: Cannot open: Structure needs cleaning".into(),
        );
        assert!(checkout.indicates_guest_corruption());

        // A checkout that failed for an ordinary reason keeps its VM.
        let plain = DispatchError::Checkout("extracting the source exited 2".into());
        assert!(!plain.indicates_guest_corruption());

        // An upload whose end-to-end hash check failed: every chunk landed
        // with exit 0 and the guest still holds different bytes. Silent
        // corruption — no errno string anywhere — and the strongest possible
        // reason not to hand this VM to the next attempt.
        let silent = DispatchError::Vm(VmError::UploadCorrupted {
            sandbox: "sb-2e3c4317".into(),
            path: "/workspace/.ci-source.tar.gz".into(),
            expected: "a".repeat(64),
            actual: "b".repeat(64),
        });
        assert!(silent.indicates_guest_corruption());

        // A step failure carries only the exit code — but even if output ever
        // leaked into it, a step is the user's code and must not match.
        let step = DispatchError::StepFailed(
            "step \"Build\" exited 1: cp: cannot stat 'x': Input/output error".into(),
        );
        assert!(!step.indicates_guest_corruption());

        // A dead tunnel is the runner being unreachable, not the guest dying;
        // it has its own remedy (evict and redial) and must not destroy VMs.
        let tunnel = DispatchError::Vm(VmError::Create {
            name: "vm".into(),
            source: heyo_sdk::HeyoError::Api {
                status: 0,
                message: "network error calling /sandbox-deploy".into(),
                body: None,
            },
        });
        assert!(!tunnel.indicates_guest_corruption());
        assert!(tunnel.is_tunnel_failure(), "still classified as transport");
    }

    /// The observed failure: a checkout's chunk poll dying with a connection
    /// reset. It must come out of `checkout` still recognisable as a tunnel
    /// failure, or the runner's dead tunnel is never evicted and the next job
    /// inherits it.
    /// The size verdict is a finding about the runner, not about the tunnel or
    /// the guest: it must not evict the tunnel, and it must not destroy the VM
    /// somebody is about to resize from /vms.
    #[test]
    fn an_undersized_vm_is_neither_a_tunnel_failure_nor_corruption() {
        let e = DispatchError::VmTooSmall(Box::new(UndersizedVm {
            job: "app-lb".into(),
            vm: "sb-0c5ddbbb".into(),
            runner: "hd-runner".into(),
            wanted: "large",
            got: "small (1 CPU, 2 GB)".into(),
            then: "the resize to large did not take — the daemon still reports small".into(),
        }));
        assert!(!e.is_tunnel_failure());
        assert!(!e.indicates_guest_corruption());
        let text = e.to_string();
        assert!(
            text.contains("sb-0c5ddbbb on hd-runner is small (1 CPU, 2 GB)"),
            "{text}"
        );
        assert!(text.contains("smaller than the large"), "{text}");
        assert!(text.contains("did not take"), "{text}");
        assert!(text.contains("/vms"), "{text}");
    }

    #[test]
    fn a_checkout_that_lost_the_tunnel_is_a_tunnel_failure() {
        let reset = checkout_error(VmError::Daemon {
            sandbox: "sb-704de5df".into(),
            what: "polling an exec operation",
            source: heyo_sdk::HeyoError::Api {
                status: 0,
                message: "network error calling /sandboxes/sb-704de5df/exec-operations/\
                          01a036000dd8-00000000.app-obs.checkout.u1: error sending request: \
                          connection error: Connection reset by peer (os error 104)"
                    .into(),
                body: None,
            },
        });
        assert!(reset.is_tunnel_failure(), "{reset}");
        assert!(!reset.indicates_guest_corruption(), "{reset}");

        // The daemon answered — a real HTTP status — so the tunnel works and
        // this is an ordinary checkout failure, reported as one.
        let refused = checkout_error(VmError::Daemon {
            sandbox: "sb-704de5df".into(),
            what: "starting an exec operation",
            source: heyo_sdk::HeyoError::Api {
                status: 500,
                message: "internal".into(),
                body: None,
            },
        });
        assert!(!refused.is_tunnel_failure(), "{refused}");
        assert!(
            matches!(refused, DispatchError::Checkout(_)),
            "a non-transport error still reports as a checkout failure"
        );

        // And the guest-corruption scan still reaches a checkout's output.
        let eio = checkout_error(VmError::UploadFailed {
            sandbox: "sb-704de5df".into(),
            path: "/workspace/.ci-source.tar.gz".into(),
            chunk: 3,
            of: 140,
            detail: "bash: /workspace/.ci-source.tar.gz: Input/output error".into(),
        });
        assert!(eio.indicates_guest_corruption(), "{eio}");
        assert!(!eio.is_tunnel_failure());
    }

    /// The node and the VM are one decision. Reading `target` twice is how the
    /// queue a job was routed to and the machine it runs on come to disagree.
    #[test]
    fn the_resolved_vm_travels_with_the_node_that_holds_it() {
        let pool = test_pool();

        let pinned = plan_targeting(Some("prod-runners/hd-1/sb-1a34"));
        let placed = Dispatcher::place(&pool, &pinned).expect("resolves");
        assert_eq!(placed.node.map(|n| n.id.as_str()), Some("hd-1"));
        assert_eq!(placed.vm, Some("sb-1a34"));

        // An unpinned job never carries a VM, so the exec-only branch cannot be
        // entered without a host to exec on.
        let unpinned = plan_targeting(Some("prod-runners"));
        let placed = Dispatcher::place(&pool, &unpinned).expect("resolves");
        assert!(placed.node.is_none());
        assert!(placed.vm.is_none());
    }

    /// A pool that has resolved nothing must refuse rather than pick, or a
    /// submit during a cloud outage is accepted onto a queue with no consumer.
    #[test]
    fn an_empty_pool_refuses_rather_than_guessing() {
        let pool = crate::runners::Pool::default();
        let err = Dispatcher::network_of(&pool, &plan_targeting(None)).unwrap_err();
        assert!(matches!(err, DispatchError::NoNetwork), "{err:?}");

        // And the "nothing is served" case says so in words rather than
        // trailing off after a colon.
        let err = DispatchError::UnservedNetwork {
            wanted: "lab".into(),
            served: vec![],
        };
        assert!(
            err.to_string().contains("no network in CI_NETWORK"),
            "{err}"
        );
    }

    /// The step's own exit code has to survive the trailing `cat`, or every
    /// failing step reports success.
    #[test]
    fn the_wrapper_preserves_the_scripts_exit_code() {
        let w = wrap_command("exit 3", &step("exit 3"), "s1", "/workspace");
        assert!(w.contains("__ci_rc=$?"), "{w}");
        assert!(w.trim_end().ends_with("exit $__ci_rc"), "{w}");
        // The capture must come immediately after the script block.
        let brace = w
            .find("}; __ci_rc=$?")
            .expect("captured right after the block");
        assert!(brace > 0);
    }

    /// The macbook problem: a network holding one macOS daemon and one Linux
    /// daemon must never hand a firecracker job to the mac. `None` — a daemon
    /// too old to say — admits, deliberately.
    #[test]
    fn a_host_takes_only_jobs_its_daemon_can_run() {
        let mac = vec!["apple_container".to_string(), "apple_virt".to_string()];
        let linux = vec![
            "firecracker_containerd".to_string(),
            "firecracker".to_string(),
            "kvm".to_string(),
        ];
        assert!(!super::host_can_run(Some(&mac), "firecracker"));
        assert!(super::host_can_run(Some(&linux), "firecracker"));
        assert!(super::host_can_run(Some(&linux), "kvm"));
        assert!(!super::host_can_run(Some(&mac), "kvm"));
        assert!(super::host_can_run(Some(&mac), "apple_virt"));
        assert!(
            super::host_can_run(None, "firecracker"),
            "an old daemon admits"
        );
        assert_eq!(
            super::driver_name(heyo_sdk::SandboxDriver::Firecracker),
            "firecracker"
        );
        assert_eq!(super::driver_name(heyo_sdk::SandboxDriver::Kvm), "kvm");
    }

    #[test]
    fn disk_placement_prefers_capacity_not_discovery_order() {
        let gib = 1 << 30;
        for eu1 in [0, 21 * gib, 80 * gib] {
            let hosts = vec![("eu1".into(), eu1), ("us3".into(), 2808 * gib)];
            let reverse = hosts.iter().cloned().rev().collect();
            assert_eq!(super::roomiest_runner(hosts, 65 * gib).as_deref(), Some("us3"));
            assert_eq!(super::roomiest_runner(reverse, 65 * gib).as_deref(), Some("us3"));
        }
        assert_eq!(super::roomiest_runner(vec![("full".into(), 64)], 65), None);
        assert_eq!(super::roomiest_runner(vec![("exact".into(), 65)], 65).as_deref(), Some("exact"));
        assert_eq!(super::roomiest_runner(vec![], 65), None);
        for hosts in [vec![("b".into(), 70), ("a".into(), 70)], vec![("a".into(), 70), ("b".into(), 70)]] {
            assert_eq!(super::roomiest_runner(hosts, 65).as_deref(), Some("a"));
        }
    }

    #[test]
    fn disk_placement_budgets_image_copy_data_and_host_headroom() {
        let mut spec = crate::vm::VmSpec::default();
        spec.disk_size_gb = Some(40);
        spec.build = Some(crate::vm::ImageBuild {
            dockerfile: "Dockerfile".into(), context: None, size_mb: Some(10240),
        });
        assert_eq!(super::runner_disk_requirement(&spec), 69_793_218_560);
        spec.build.as_mut().unwrap().size_mb = Some(u64::MAX);
        assert_eq!(super::runner_disk_requirement(&spec), u64::MAX);
    }

    /// A workflow that declares a long `ttl_seconds` keeps its warm VM that
    /// long while idle; one that declares nothing (or something shorter) gets
    /// the instance default. Repooling with the short default was how a warm
    /// cache died an hour after every run.
    #[test]
    fn the_pool_keeps_a_vm_as_long_as_the_workflow_asked() {
        use std::time::Duration;
        let default = Duration::from_secs(3600);
        assert_eq!(
            super::idle_pool_ttl(Some(14_400), default),
            Duration::from_secs(14_400)
        );
        assert_eq!(super::idle_pool_ttl(Some(60), default), default);
        assert_eq!(super::idle_pool_ttl(None, default), default);
    }

    #[test]
    fn a_working_directory_is_quoted_into_a_cd() {
        let mut s = step("make");
        s.working_directory = Some("/work/my project".into());
        let w = wrap_command("make", &s, "s1", "/workspace");
        assert!(w.contains("cd '/work/my project' && "), "{w}");
    }

    #[test]
    fn a_quote_in_a_working_directory_cannot_break_out() {
        let mut s = step("make");
        s.working_directory = Some("/work/'; rm -rf /; '".into());
        let w = wrap_command("make", &s, "s1", "/workspace");
        assert!(!w.contains("&& rm -rf /"), "{w}");
        assert!(w.contains(r"'\''"), "the quote is escaped: {w}");
    }

    /// A multi-line script must not have its last line swallowed by the closing
    /// brace — `{ cmd }` needs the newline or a `;` before `}`.
    #[test]
    fn a_multi_line_script_is_terminated_before_the_closing_brace() {
        let script = "echo one\necho two";
        let w = wrap_command(script, &step(script), "s1", "/workspace");
        assert!(w.contains("echo two\n}"), "{w}");
    }

    #[test]
    fn outputs_are_split_off_the_end_of_the_log() {
        let sid = "run.job.0";
        let combined = format!(
            "building\ndone\n\n{}\nversion=1.2.3\nsha=abc\n",
            output_marker(sid)
        );
        let (log, outputs) = split_outputs(&output(&combined, 0), sid);
        assert_eq!(log, "building\ndone");
        assert_eq!(outputs["version"], "1.2.3");
        assert_eq!(outputs["sha"], "abc");
    }

    /// A step that declares no outputs still logs normally.
    #[test]
    fn a_step_with_no_outputs_yields_an_empty_map() {
        let sid = "run.job.0";
        let combined = format!("building\n\n{}\n", output_marker(sid));
        let (log, outputs) = split_outputs(&output(&combined, 0), sid);
        assert_eq!(log, "building");
        assert_eq!(outputs.as_object().unwrap().len(), 0);
    }

    /// A build that prints something marker-shaped must not be able to inject
    /// outputs — the marker carries the step id, which the build does not know
    /// it needs to forge... and even if it prints one, the *last* marker wins,
    /// which is the one the wrapper emitted.
    #[test]
    fn a_forged_marker_earlier_in_the_log_does_not_win() {
        let sid = "run.job.0";
        let combined = format!(
            "sneaky\n{}\nadmin=true\nreal output\n\n{}\nversion=1\n",
            output_marker(sid),
            output_marker(sid)
        );
        let (_, outputs) = split_outputs(&output(&combined, 0), sid);
        assert_eq!(outputs["version"], "1");
        assert!(
            outputs.get("admin").is_none(),
            "only the trailing marker's block counts: {outputs}"
        );
    }

    /// A marker for a different step is not this step's marker.
    #[test]
    fn another_steps_marker_is_ignored() {
        let combined = format!("out\n{}\nx=1\n", output_marker("other.step.9"));
        let (log, outputs) = split_outputs(&output(&combined, 0), "run.job.0");
        assert!(log.contains("out"));
        assert_eq!(outputs.as_object().unwrap().len(), 0);
    }

    #[test]
    fn a_value_containing_an_equals_sign_survives() {
        let sid = "s";
        let combined = format!("{}\nurl=https://x/?a=1&b=2\n", output_marker(sid));
        let (_, outputs) = split_outputs(&output(&combined, 0), sid);
        assert_eq!(outputs["url"], "https://x/?a=1&b=2");
    }

    #[test]
    fn shell_quoting_handles_the_awkward_cases() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    // ---- end to end -----------------------------------------------------
    //
    // The whole path: a run is created, the scheduler queues its jobs, a
    // consumer pulls one, a real VM boots on the local heyvmd, the steps run,
    // and the results land in Postgres. A second run must use a fresh VM even
    // with the same fingerprint; changed inputs must change the fingerprint.
    //
    //   CI_TEST_DATABASE_URL=postgres://… CI_TEST_NATS_URL=nats://127.0.0.1:4222 \
    //     cargo test --bin ci -- --ignored --nocapture end_to_end

    async fn test_dispatcher(workspace_root: &std::path::Path) -> Arc<Dispatcher> {
        // So `--nocapture` shows what the dispatcher actually did; RUST_LOG
        // applies as usual. try_init because a second e2e in one process is
        // not an error.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn".into()),
            )
            .try_init();
        let db = std::env::var("CI_TEST_DATABASE_URL").expect("CI_TEST_DATABASE_URL");
        let nats =
            std::env::var("CI_TEST_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
        let daemon = std::env::var("CI_TEST_DAEMON")
            .unwrap_or_else(|_| heyo_sdk::DEFAULT_LOCAL_BASE_URL.to_string());

        unsafe {
            std::env::set_var("CI_HEYO_API_KEY", "unused-in-local-mode");
            std::env::set_var("CI_NETWORK", "unused-in-local-mode");
            std::env::set_var("CI_DATABASE_URL", &db);
            std::env::set_var("CI_WEBHOOK_SECRET", "0123456789abcdef");
            std::env::set_var("CI_LOCAL_RUNNER", &daemon);
            std::env::set_var("CI_NATS_URL", &nats);
            // A distinct prefix per run, so a test never shares a stream.
            std::env::set_var(
                "CI_NATS_SUBJECT_PREFIX",
                format!("e2e{}", crate::vm::new_id().replace('-', "")),
            );
            std::env::set_var("CI_WORKSPACE_DIR", workspace_root);
        }
        let config = Arc::new(Config::from_env().expect("config"));
        let store = crate::store::Store::connect(
            &config.database_url,
            std::env::temp_dir().join(format!("ci-e2e-logs-{}", crate::vm::new_id())),
            config.db_statement_timeout,
        )
        .await
        .expect("store");
        store.migrate().await.expect("migrations");

        let runners = Arc::new(Runners::new(config.clone()));
        runners.refresh().await.expect("local runner resolves");

        let bus = Arc::new(
            Bus::connect(&config.nats, &config.nats_prefix)
                .await
                .expect("nats"),
        );

        Arc::new(Dispatcher {
            executor: Arc::new(crate::executor::ExecutorInstance::register(store.pool().clone(), &format!("dispatch-test-{}", uuid::Uuid::new_v4())).await.expect("executor")),
            config: config.clone(),
            store: store.clone(),
            pool: Pool::new(store.pool().clone()),
            images: crate::image::Catalog::new(store.pool().clone()),
            bus,
            runners,
            vms: Arc::new(Vms::new()),
            secrets: crate::secrets::Secrets::new(&config),
            artifacts: Arc::from(crate::artifacts::sink_for(&config).expect("disk sink")),
            // Unconfigured: the e2e test drives workflows straight from the
            // submitted tree, which is the path an installation with no app-lb
            // takes anyway.
            objects: Arc::new(crate::objects::Workflows::new(&config)),
            tenants: Arc::new(crate::tenants::Tenants::new(&config)),
        })
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn delivery_racing_instance_drain_returns_to_shared_queue() {
        let base = std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin = sqlx::PgPool::connect(&base).await.unwrap();
        let schema = format!("delivery_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
        admin.close().await;
        let mut url = reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-c search_path={schema}"));
        unsafe { std::env::set_var("CI_TEST_DATABASE_URL", url.as_str()); }
        let root = tempfile::tempdir().unwrap();
        let d = test_dispatcher(root.path()).await;
        unsafe { std::env::set_var("CI_TEST_DATABASE_URL", base); }
        sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('run','test','ci.yml','running');
            INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('job','run','deploy','deploy','Deploy','queued');
            INSERT INTO ci_step(id,job_id,idx,name,uses,status) VALUES('step','job',0,'Request','ci/deploy-controller','success');
            INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES('op','step','run','job','ci','hash','running','source','main');
            INSERT INTO ci_controller_rollout(id,request,phase) VALUES('op','{}','quiesced');")
            .execute(d.store.pool()).await.unwrap();
        let route = Route::Network("handoff-network".into());
        let consumer = d.bus.consumer_for(&route).await.unwrap();
        let job = JobMessage { run_id: "run".into(), job_id: "job".into(), job_key: "deploy".into() };
        d.bus.publish_job(&route, &job).await.unwrap();
        // Cross the old four-delivery boundary using real drain handoffs.
        // No execution failure or claim may result from any of them.
        d.executor.pause(uuid::Uuid::new_v4()).await.unwrap();
        for expected_delivery in 1..=5 {
            let (message, _slot) = tokio::time::timeout(Duration::from_secs(5),
                pull_with_capacity(&consumer, Arc::new(tokio::sync::Semaphore::new(1)))).await.unwrap().unwrap().unwrap();
            assert_eq!(message.info().unwrap().delivered, expected_delivery);
            process_delivery(d.clone(), message, job.clone(), expected_delivery as i32).await;
        }
        let (message, _slot) = pull_with_capacity(&consumer, Arc::new(tokio::sync::Semaphore::new(1))).await.unwrap().unwrap();
        let effect = d.executor.effect_permit().await.unwrap();
        let running = d.clone();
        let task = tokio::spawn(async move {
            let _effect = effect;
            process_delivery(running, message, job, 1).await;
        });
        tokio::time::timeout(Duration::from_secs(2), task).await.expect("draining delivery must release its local work guard").unwrap();
        let fence = tokio::time::timeout(Duration::from_secs(2), d.executor.idle_guard()).await.unwrap().unwrap();
        assert_eq!(d.store.get_job("job").await.unwrap().unwrap().status, "queued");
        assert!(!d.store.has_host_work("job").await.unwrap());
        let failures: i32 = sqlx::query_scalar("SELECT preclaim_failures FROM ci_job WHERE id='job'")
            .fetch_one(d.store.pool()).await.unwrap();
        assert_eq!(failures, 0, "drain handoffs must not spend the failure budget");
        drop(fence);
        let (redelivery, _) = tokio::time::timeout(Duration::from_secs(5),
            pull_with_capacity(&consumer, Arc::new(tokio::sync::Semaphore::new(1)))).await.unwrap().unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<JobMessage>(&redelivery.payload).unwrap().job_id, "job");
        redelivery.ack().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; run alone; no VM execution"]
    async fn managed_release_reconciles_after_job_exit_and_replays_uncertain_submission() {
        use axum::{routing::{get,post},Router,Json,http::{HeaderMap,StatusCode}};
        use std::sync::atomic::{AtomicUsize,Ordering};
        let command=serde_json::json!({"operationId":"release","archiveId":"archive-v2",
            "archiveSha256":"a".repeat(64),"runtimeRevision":"revision-v2"});
        let posts=Arc::new(AtomicUsize::new(0));
        let mode=Arc::new(AtomicUsize::new(0));
        let receipt=serde_json::json!({"operationId":"release","serviceId":"ci","request":command,
            "status":"running","verified":false,"targets":[
                {"deploymentId":"new-us","region":"us3","revision":"revision-v2"},
                {"deploymentId":"new-eu","region":"eu1","revision":"revision-v2"}]});
        let p=posts.clone(); let expected=command.clone(); let submitted=receipt.clone();
        let m=mode.clone(); let mut completed=receipt.clone();
        completed["status"]=serde_json::json!("passed"); completed["verified"]=serde_json::json!(true);
        for t in completed["targets"].as_array_mut().unwrap() {
            t["bootId"]=serde_json::json!(uuid::Uuid::new_v4());
            t["backendServerId"]=serde_json::json!(format!("host-{}",t["region"]));
            t["backendSandboxId"]=t["deploymentId"].clone();
        }
        let api=Router::new().route("/orchestration/services/ci/managed-updates",post(move |headers:HeaderMap,Json(body):Json<serde_json::Value>| {
            let p=p.clone(); let expected=expected.clone(); let response=submitted.clone(); async move {
                assert_eq!(headers["authorization"],"Bearer lifecycle-test"); assert_eq!(body,expected);
                if p.fetch_add(1,Ordering::SeqCst)==0 {(StatusCode::SERVICE_UNAVAILABLE,Json(serde_json::Value::Null))}
                else {(StatusCode::ACCEPTED,Json(response))}
            }
        })).route("/orchestration/services/ci/managed-updates/release",get(move || {
            let mode=m.load(Ordering::SeqCst); let mut response=completed.clone(); async move {
                if mode==0 {response["targets"][1]["deploymentId"]=serde_json::json!("wrong-eu");}
                Json(response)
            }
        }));
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=format!("http://{}",listener.local_addr().unwrap());
        let server=tokio::spawn(async move {axum::serve(listener,api).await.unwrap()});
        let base=std::env::var("CI_TEST_DATABASE_URL").unwrap();
        let admin=sqlx::PgPool::connect(&base).await.unwrap();
        let schema=format!("managed_release_{}",uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.unwrap();
        let mut url=reqwest::Url::parse(&base).unwrap();
        url.query_pairs_mut().append_pair("options",&format!("-c search_path={schema}"));
        unsafe {
            std::env::set_var("CI_TEST_DATABASE_URL",url.as_str());
            std::env::set_var("HEYO_DEPLOYMENT_ID","old-us");
            std::env::set_var("HEYO_SERVICE_ID","ci");
            std::env::set_var("CI_APPLICATION_ORCHESTRATOR_URL",address);
            std::env::set_var("CI_APPLICATION_LIFECYCLE_TOKEN","lifecycle-test");
        }
        let root=tempfile::tempdir().unwrap(); let d=test_dispatcher(root.path()).await;
        unsafe {
            std::env::set_var("CI_TEST_DATABASE_URL",base);
            for key in ["HEYO_DEPLOYMENT_ID","HEYO_SERVICE_ID","CI_APPLICATION_ORCHESTRATOR_URL","CI_APPLICATION_LIFECYCLE_TOKEN"] {std::env::remove_var(key);}
        }
        sqlx::raw_sql("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES('run','test','ci.yml','running');
            INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES('job','run','deploy','deploy','Deploy','running');
            INSERT INTO ci_step(id,job_id,idx,name,status) VALUES('step','job',0,'Request','success');")
            .execute(d.store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_managed_update(operation_id,step_id,run_id,job_id,service_id,request) VALUES('release','step','run','job','ci',$1)")
            .bind(&command).execute(d.store.pool()).await.unwrap();
        crate::managed_update::reconcile(&d).await.unwrap(); assert_eq!(posts.load(Ordering::SeqCst),0);
        d.store.set_job_status("job",crate::store::JobStatus::Success,None).await.unwrap();
        assert!(crate::managed_update::reconcile(&d).await.is_err());
        assert_eq!(posts.load(Ordering::SeqCst),1);
        // The failed HTTP observation must not retain the local effect permit.
        drop(tokio::time::timeout(Duration::from_secs(1),d.executor.idle_guard()).await.unwrap().unwrap());
        crate::managed_update::reconcile(&d).await.unwrap(); assert_eq!(posts.load(Ordering::SeqCst),2);
        assert_eq!(d.store.get_run("run").await.unwrap().unwrap().status,"running");
        assert!(crate::managed_update::reconcile(&d).await.is_err(),"changed regional identity cannot complete the release");
        mode.store(1,Ordering::SeqCst);
        crate::managed_update::reconcile(&d).await.unwrap();
        assert_eq!(d.store.get_run("run").await.unwrap().unwrap().status,"success");
        crate::managed_update::reconcile(&d).await.unwrap(); assert_eq!(posts.load(Ordering::SeqCst),2);
        server.abort();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&admin).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn published_release_failed_only_retry_preserves_identity_and_single_flight() {
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let validation = crate::workflow::Workflow::parse("build.yml", "jobs:\n  build:\n    steps: [{run: cargo test}]\n").unwrap();
        let release = crate::workflow::Workflow::parse("release.yml", r#"
on: release
jobs:
  merge:
    steps: [{uses: ci/merge-release, with: {manifests: '[]'}}]
  us:
    needs: [merge]
    steps: [{uses: ci/rollout-service}]
  eu:
    needs: [us]
    steps: [{uses: ci/rollout-host-app-lb}, {uses: ci/rollout-service}]
"#).unwrap();
        let validation_plan = crate::plan::Plan::build(&validation).unwrap();
        let release_plan = crate::plan::Plan::build(&release).unwrap();
        let source_run = format!("release-{}", crate::vm::new_id());
        let validation_run = format!("validation-{}", crate::vm::new_id());
        let sha = "a".repeat(40);
        let request = crate::store::RunRequest { repo_url: "https://example.test/repo.git".into(),
            git_ref: "refs/heads/main".into(), sha: sha.clone(), changes: crate::paths::Changes::unknown("frozen"), ..Default::default() };
        let mut tx = d.store.pool().begin().await.unwrap();
        Store::create_run_in(&mut tx, &validation_run, &request, &validation_plan).await.unwrap();
        Store::create_run_in(&mut tx, &source_run, &request, &release_plan).await.unwrap();
        sqlx::query("INSERT INTO ci_run_source(run_id,descriptor) VALUES($1,'frozen-source'),($2,'frozen-source')")
            .bind(&validation_run).bind(&source_run).execute(&mut *tx).await.unwrap();
        crate::submission::record(&mut tx, &source_run, std::slice::from_ref(&validation_run)).await.unwrap();
        tx.commit().await.unwrap();
        let validation_job = d.store.jobs_of(&validation_run).await.unwrap().remove(0);
        d.store.create_step(&crate::store::step_id(&validation_job.id, 0), &validation_job.id, 0, "test", None).await.unwrap();
        d.store.finish_step(&crate::store::step_id(&validation_job.id, 0), StepStatus::Success, Some(0), None).await.unwrap();
        d.store.set_job_status(&validation_job.id, JobStatus::Success, None).await.unwrap();
        sqlx::query("UPDATE ci_run SET status='success' WHERE id=$1").bind(&validation_run).execute(d.store.pool()).await.unwrap();
        let jobs = d.store.jobs_of(&source_run).await.unwrap();
        for job in &jobs {
            d.store.set_job_status(&job.id, if job.job_key == "eu" { JobStatus::Failure } else { JobStatus::Success }, None).await.unwrap();
        }
        let eu_job = jobs.iter().find(|j| j.job_key == "eu").unwrap();
        let completed_step = crate::store::step_id(&eu_job.id, 0);
        d.store.create_step(&completed_step, &eu_job.id, 0, "app-lb", Some("ci/rollout-host-app-lb")).await.unwrap();
        d.store.finish_step(&completed_step, StepStatus::Success, Some(0), None).await.unwrap();
        let operation = format!("host-{source_run}");
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,sha,git_ref) VALUES($1,$2,$3,$4,'app-lb-eu1','hash','passed',$5,'refs/heads/main')")
            .bind(&operation).bind(&completed_step).bind(&source_run).bind(&eu_job.id).bind(&sha)
            .execute(d.store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1").bind(&source_run).execute(d.store.pool()).await.unwrap();
        let prepared = json!({"source_sha":sha,"release_sha":sha,"git_ref":"refs/heads/main","versions":{},"tags":[]});
        sqlx::query("INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status) VALUES($1,'request',$2,$2,'refs/heads/main','{}',$2,$3,'published')")
            .bind(&source_run).bind(&sha).bind(&prepared).execute(d.store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_artifact(id,run_id,job_id,name,sink,digest,size_bytes,uri) VALUES('frozen-artifact',$1,$2,'bundle','artifacts',$3,17,'blob')")
            .bind(&validation_run).bind(&validation_job.id).bind("b".repeat(64)).execute(d.store.pool()).await.unwrap();

        assert!(d.rerun(&source_run, false, None).await.err().unwrap().to_string().contains("full release reruns are unsupported"));
        let admitted = d.retry_published_release(&source_run, None).await.unwrap();
        let retry = &admitted.run_ids[0];
        assert_eq!(crate::submission::validations(&d.store, retry).await.unwrap(), [validation_run.clone()]);
        assert_eq!(crate::submission::artifact_run(&d.store, retry, "build.yml").await.unwrap(), validation_run);
        assert_eq!(d.store.source_bytes(retry).await.unwrap(), b"frozen-source");
        let copied = crate::release::get(&d.store, retry).await.unwrap().unwrap();
        assert_eq!(copied.status, "published");
        assert_eq!(copied.prepared.release_sha, sha);
        let retry_jobs = d.store.jobs_of(retry).await.unwrap();
        assert_eq!(retry_jobs.iter().find(|j| j.job_key == "us").unwrap().status, "success");
        assert_eq!(retry_jobs.iter().find(|j| j.job_key == "eu").unwrap().status, "pending");
        let retry_eu = retry_jobs.iter().find(|j| j.job_key == "eu").unwrap();
        let retained: Vec<(i32, String)> = sqlx::query_as("SELECT step_index,deployment_id FROM ci_release_carried_deployment WHERE job_id=$1")
            .bind(&retry_eu.id).fetch_all(d.store.pool()).await.unwrap();
        assert_eq!(retained, vec![(0, operation.clone())], "retain only app-lb, not the failed service step");
        assert!(d.retry_published_release(&source_run, None).await.err().unwrap().to_string().contains("latest descendant"));

        d.store.set_job_status(&retry_eu.id, JobStatus::Failure, None).await.unwrap();
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1").bind(retry).execute(d.store.pool()).await.unwrap();
        let (first, duplicate) = tokio::join!(d.retry_published_release(retry, None), d.retry_published_release(retry, None));
        assert_ne!(first.is_ok(), duplicate.is_ok(), "only one concurrent retry may be admitted");
        let descendant = first.or(duplicate).unwrap().run_ids.remove(0);
        let inherited: String = sqlx::query_scalar("SELECT deployment_id FROM ci_release_carried_deployment WHERE job_id=$1 AND step_index=0")
            .bind(crate::store::job_id(&descendant, "eu")).fetch_one(d.store.pool()).await.unwrap();
        assert_eq!(inherited, operation, "receipt survives more than one retry");

        sqlx::query("UPDATE ci_release SET status='unknown' WHERE run_id=$1").bind(retry).execute(d.store.pool()).await.unwrap();
        sqlx::query("UPDATE ci_run SET status='failure' WHERE id=$1").bind(retry).execute(d.store.pool()).await.unwrap();
        assert!(d.retry_published_release(retry, None).await.err().unwrap().to_string().contains("confirmed published"));
        assert!(crate::submission::authorize_publication(&d.store, &validation_run).await.is_err(),
            "reusing validation membership must not relax validation-only publication restrictions");
    }

    /// `--only` runs the named workflow and nothing else. The release workflow
    /// is not planned, so a release job pinned somewhere this instance does not
    /// serve cannot refuse the submit, and no submission is recorded.
    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn only_submit_does_not_plan_the_release_workflow() {
        unsafe { std::env::set_var("CI_NATIVE_RUNNER_SECRET", "test-only-skips-release"); }
        let disk = tempfile::tempdir().unwrap();
        let d = test_dispatcher(disk.path()).await;
        let release = "on: release\njobs:\n  merge:\n    steps: [{uses: ci/merge-release, with: {manifests: '[]'}}]\n  host:\n    needs: [merge]\n    uses: not-served/some-host\n    steps: [{run: echo host}]\n";
        let source = serde_json::to_vec(&json!({
            "baseRevision": "a".repeat(40), "targetTree": "b".repeat(40), "patchBase64": "AAEC",
            "workflows": {
                ".ci/workflows/demo.yml": "name: demo\non:\n  submit:\n    paths: ['.ci/manual-only']\njobs:\n  build:\n    runs-on: [macos-intel]\n    steps: [{run: echo demo}]\n",
                ".ci/workflows/release.yml": release,
            }
        })).unwrap();
        let mut req: crate::trigger::SubmitRequest = serde_json::from_value(json!({
            "repository": {"url": "https://example.test/only.git", "name": "only"},
            "ref": "refs/heads/main", "after": "a".repeat(40),
            "source": {"format": "git-patch", "contentBase64": ""},
            "only": ["demo"]
        })).unwrap();
        req.source.bytes = Some(source);
        let accepted = d.submit(&req, None, None).await.unwrap();
        assert_eq!(accepted.run_ids.len(), 1);
        assert!(accepted.submission.is_none());
        assert_eq!(d.store.get_run(&accepted.run_ids[0]).await.unwrap().unwrap().workflow_path, ".ci/workflows/demo.yml");
        assert!(accepted.warnings.iter().any(|w| w.starts_with("validation only")), "{:?}", accepted.warnings);
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn accepted_source_can_be_rerun_from_another_controller_without_its_disk() {
        unsafe { std::env::set_var("CI_NATIVE_RUNNER_SECRET", "test-shared-source"); }
        let first_disk = tempfile::tempdir().unwrap();
        let second_disk = tempfile::tempdir().unwrap();
        let first = test_dispatcher(first_disk.path()).await;
        let second = test_dispatcher(second_disk.path()).await;
        let source = serde_json::to_vec(&json!({
            "baseRevision": "a".repeat(40), "targetTree": "b".repeat(40), "patchBase64": "AAEC",
            "workflows": {".ci/workflows/build.yml": "name: shared-source\njobs:\n  build:\n    runs-on: [macos-intel]\n    steps: [{run: echo shared}]\n"}
        })).unwrap();
        let mut req: crate::trigger::SubmitRequest = serde_json::from_value(json!({
            "repository": {"url": "https://example.test/shared.git", "name": "shared"},
            "ref": "refs/heads/main", "after": "a".repeat(40),
            "source": {"format": "git-patch", "contentBase64": ""}
        })).unwrap();
        req.source.bytes = Some(source.clone());
        let accepted = first.submit(&req, None, None).await.unwrap();
        assert_eq!(accepted.run_ids.len(), 1);
        let run = &accepted.run_ids[0];
        assert_eq!(second.store.source_bytes(run).await.unwrap(), source);
        first.store.cancel_run(run).await.unwrap();
        drop(first_disk);
        let rerun = second.rerun(run, false, None).await.unwrap();
        assert_eq!(rerun.run_ids.len(), 1);
        assert_eq!(second.store.source_bytes(&rerun.run_ids[0]).await.unwrap(), source);
        assert_eq!(second.store.get_run(&rerun.run_ids[0]).await.unwrap().unwrap().rerun_of.as_deref(), Some(run.as_str()));
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn cancellation_cannot_bypass_execution_ownership_by_rerunning() {
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let wf = crate::workflow::Workflow::parse("retry.yml", "jobs:\n  build:\n    steps: [{run: echo test}]\n").unwrap();
        let plan = crate::plan::Plan::build(&wf).unwrap();
        for native in [false, true] {
            let run = crate::vm::new_id();
            d.store.create_run(&run, &crate::store::RunRequest::default(), &plan).await.unwrap();
            let job = d.store.jobs_of(&run).await.unwrap().remove(0);
            if native {
                sqlx::query("INSERT INTO ci_native_job(job_id,run_id,required_labels,state,lease_expires_at) VALUES($1,$2,'{}','leased',now()-interval '1 hour')")
                    .bind(&job.id).bind(&run).execute(d.store.pool()).await.unwrap();
            } else {
                assert!(d.store.claim_job(&job.id, "hd-local", 1).await.unwrap());
            }
            d.store.cancel_run(&run).await.unwrap();
            assert!(d.rerun(&run, false, None).await.err().expect("rerun must be refused").to_string().contains("unresolved execution"));
            assert!(d.store.reruns_of(&run).await.unwrap().is_empty());
            // Model verified release to exercise both sides of the barrier.
            if native {
                sqlx::query("UPDATE ci_native_job SET state='completed' WHERE job_id=$1")
                    .bind(&job.id).execute(d.store.pool()).await.unwrap();
            } else { d.store.end_host_work(&job.id, "hd-local", 1).await.unwrap(); }
            assert!(!d.store.has_unresolved_execution(&run).await.unwrap());
            let error = d.rerun(&run, false, None).await.err().expect("fixture source is absent").to_string();
            assert!(error.contains("source of run"), "ownership cleared, so the absent fixture source is now the blocker: {error}");
        }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; no VM execution"]
    async fn failed_dependency_settles_transitive_jobs_without_skipping_cleanup() {
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let wf = crate::workflow::Workflow::parse("cascade.yml", r#"
jobs:
  z-build:
    strategy:
      matrix:
        cell: [one, two]
    steps: [{run: 'true'}]
  y-first:
    needs: [z-build]
    steps: [{run: 'true'}]
  b-second:
    needs: [y-first]
    steps: [{run: 'true'}]
  a-third:
    needs: [b-second]
    steps: [{run: 'true'}]
  cleanup:
    needs: [a-third]
    if: ${{ always() }}
    steps: [{run: 'true'}]
  independent:
    steps: [{run: 'true'}]
"#).unwrap();
        let plan = crate::plan::Plan::build(&wf).unwrap();
        let run = format!("cascade-{}", crate::vm::new_id());
        d.store.create_run(&run, &crate::store::RunRequest {
            workflow_id: "cascade".into(), source: "test".into(), ..Default::default()
        }, &plan).await.unwrap();
        let jobs = d.store.jobs_of(&run).await.unwrap();
        let cells: Vec<_> = jobs.iter().filter(|j| j.base_id == "z-build").collect();
        assert_eq!(cells.len(), 2);
        d.store.set_job_status(&cells[0].id, JobStatus::Failure, Some("build failed")).await.unwrap();
        d.store.set_job_status(&cells[1].id, JobStatus::Running, None).await.unwrap();
        d.advance_run(&run).await.unwrap();
        let states = d.store.jobs_of(&run).await.unwrap();
        assert_eq!(states.iter().find(|j| j.base_id == "y-first").unwrap().status, "pending", "wait for all matrix cells");
        assert_eq!(states.iter().find(|j| j.base_id == "independent").unwrap().status, "queued");
        d.store.set_job_status(&cells[1].id, JobStatus::Success, None).await.unwrap();
        d.advance_run(&run).await.unwrap();
        let states = d.store.jobs_of(&run).await.unwrap();
        for name in ["y-first", "b-second", "a-third"] {
            assert_eq!(states.iter().find(|j| j.base_id == name).unwrap().status, "skipped", "{name}");
        }
        assert_eq!(states.iter().find(|j| j.base_id == "cleanup").unwrap().status, "queued");
        assert!(!states.iter().any(|j| j.status == "pending"));
        assert_eq!(d.store.get_run(&run).await.unwrap().unwrap().status, "failure");
        // A failed run is still unsafe to rerun while independent/cleanup jobs run.
        assert!(d.rerun(&run, true, None).await.err().unwrap().to_string().contains("still active"));
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; fake source builder"]
    async fn failed_preparation_does_not_block_ci_app_drain() {
        use axum::{Json, Router, http::StatusCode, routing::{get, post}};
        let terminal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mode = terminal.clone();
        let unexpected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = unexpected.clone();
        let app = Router::new()
            .route("/sources/prepare", post(move || {
                let failed = mode.load(Ordering::SeqCst);
                async move { Json(json!({"sourceId":"src-test", "status":if failed {"failed"} else {"preparing"}, "error":"checkout rejected"})) }
            }))
            .route("/sources/src-test", get(|| async { StatusCode::NOT_FOUND }))
            .fallback(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { StatusCode::INTERNAL_SERVER_ERROR }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        unsafe { std::env::set_var("CI_TEST_DAEMON", format!("http://{}", listener.local_addr().unwrap())); }
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        for failed in [false, true] {
            terminal.store(failed, Ordering::SeqCst);
            let workspace = tempfile::tempdir().unwrap();
            let d = test_dispatcher(workspace.path()).await;
            let yaml = "jobs:\n  build:\n    vm:\n      driver: firecracker\n      build: {dockerfile: Dockerfile}\n    steps: [{run: echo test}]\n";
            let workflow = crate::workflow::Workflow::parse("prep.yml", yaml).unwrap();
            let plan = crate::plan::Plan::build(&workflow).unwrap();
            let run = crate::vm::new_id();
            let mut tx = d.store.pool().begin().await.unwrap();
            crate::store::Store::create_run_in(&mut tx, &run, &crate::store::RunRequest {
                repo_url: "https://github.com/example/ci-test.git".into(), ..Default::default()
            }, &plan).await.unwrap();
            crate::store::Store::record_source_in(&mut tx, &run, &serde_json::to_vec(&json!({
                "baseRevision":"a".repeat(40), "targetTree":"b".repeat(40),
                "patchBase64":"", "workflows":{"prep.yml":yaml}
            })).unwrap()).await.unwrap();
            tx.commit().await.unwrap();
            let job = d.store.jobs_of(&run).await.unwrap().remove(0);
            let msg = JobMessage { run_id: run.clone(), job_id: job.id.clone(), job_key: job.job_key.clone() };
            let status = d.run_claimed(&msg, 1, plan.jobs[0].clone(), "hd-local".into(), None).await.unwrap();
            assert_eq!(status, JobStatus::Failure);
            let job = d.store.get_job(&job.id).await.unwrap().unwrap();
            assert_eq!(job.status, "failure");
            assert!(job.error.as_deref().unwrap().contains(if failed { "checkout rejected" } else { "prepared source expired" }));
            assert!(job.sandbox_id.is_none());
            assert_eq!(d.store.has_host_work(&job.id).await.unwrap(), !failed);
            let operation = uuid::Uuid::new_v4();
            d.executor.pause(operation).await.unwrap();
            d.executor.quiesce(operation).await.unwrap();
            assert_eq!(unexpected.load(Ordering::SeqCst), 0, "preparation failure must never reach VM APIs");
            d.store.end_host_work(&job.id, "hd-local", 1).await.unwrap();
            sqlx::query("DELETE FROM ci_run WHERE id=$1").bind(&run).execute(d.store.pool()).await.unwrap();
            d.bus.js_delete_streams().await.unwrap();
        }
        server.abort();
        unsafe { std::env::remove_var("CI_TEST_DAEMON"); }
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; fake source builder"]
    async fn cached_image_is_rebuilt_before_the_current_job_creates_a_vm() {
        use axum::{Json, Router, routing::post};
        let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = posts.clone();
        let name = "ci-img-012345abcdef";
        let app = Router::new().route("/sources/src-rebuild/image", post(move || {
            let calls = calls.clone();
            async move {
                let prior = calls.fetch_add(1, Ordering::SeqCst);
                Json(json!({"name":name,"status":if prior==0 { "building" } else { "ready" }}))
            }
        }).get(move || async move { Json(json!({"name":name,"status":"ready","size_bytes":8192})) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        unsafe { std::env::set_var("CI_TEST_DAEMON", format!("http://{}", listener.local_addr().unwrap())); }
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let workflow = crate::workflow::Workflow::parse("rebuild.yml", "jobs:\n  build:\n    steps: [{run: echo test}]\n").unwrap();
        let plan = crate::plan::Plan::build(&workflow).unwrap();
        let run = crate::vm::new_id();
        d.store.create_run(&run, &crate::store::RunRequest { repo_url: "https://example.test/repo.git".into(), ..Default::default() }, &plan).await.unwrap();
        let job = d.store.jobs_of(&run).await.unwrap().remove(0);
        assert!(d.store.claim_job(&job.id, "hd-local", 1).await.unwrap());
        d.images.claim(name, "hd-local", "wf", &job.id, crate::image::BUILD_LEASE).await.unwrap();
        d.images.mark_ready(name, "hd-local", 1024).await.unwrap();
        let prepared = crate::image::PreparedSource { source_id: "src-rebuild".into(), cache_keys: Default::default(),
            image: Some(crate::image::PreparedImage { name: name.into(), input_digest: "0".repeat(64) }) };
        let build = serde_json::from_value(json!({"dockerfile":"Dockerfile"})).unwrap();
        let msg = JobMessage { run_id: run.clone(), job_id: job.id.clone(), job_key: job.job_key.clone() };
        let resolved = d.ensure_image("hd-local", &plan.jobs[0], &build, &prepared, &msg).await.unwrap();
        assert_eq!(resolved, name);
        assert_eq!(posts.load(Ordering::SeqCst), 1, "a ready DB row must not bypass the daemon");
        assert_eq!(d.images.inventory(&["hd-local".into()]).await.unwrap()[0].size_bytes, 8192);
        // Active executor evidence blocks retention even with a zero window.
        d.images.evict_one("hd-local", Duration::ZERO, d.runners.options_for("hd-local").await.unwrap()).await.unwrap();
        assert_eq!(d.images.status_of(name, "hd-local").await.unwrap().as_deref(), Some("ready"));
        d.ensure_image("hd-local", &plan.jobs[0], &build, &prepared, &msg).await.unwrap();
        assert_eq!(posts.load(Ordering::SeqCst), 2);
        assert_eq!(d.images.inventory(&["hd-local".into()]).await.unwrap()[0].size_bytes, 8192,
            "a ready receipt without size must not erase known accounting");
        d.store.end_host_work(&job.id, "hd-local", 1).await.unwrap();
        d.images.forget(name, "hd-local").await.unwrap();
        sqlx::query("DELETE FROM ci_run WHERE id=$1").bind(&run).execute(d.store.pool()).await.unwrap();
        d.bus.js_delete_streams().await.unwrap();
        server.abort();
        unsafe { std::env::remove_var("CI_TEST_DAEMON"); }
    }

    #[tokio::test]
    #[ignore = "needs empty disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; tests global drain with fake heyvm HTTP"]
    async fn durable_vm_cleanup_recovers_without_guessing_ownership() {
        use crate::vm_cleanup::{handoff, reconcile};
        use axum::{Json, Router, extract::{Path, State}, http::StatusCode, response::IntoResponse, routing::{get, post}};
        #[derive(Default)]
        struct Remote { stopped: bool, removed: bool, wrong: bool, lost: bool, ineffective: bool, stops: usize, deletes: usize }
        let remote = Arc::new(std::sync::Mutex::new(Remote::default()));
        let app = Router::new()
            .route("/storage", get(|| async { Json(json!({"free_bytes":1u64 << 50})) }))
            .route("/capabilities", get(|| async { Json(json!({"supportedDrivers":["firecracker"]})) }))
            .route("/deployed-sandboxes/{id}", get(|State(remote): State<Arc<std::sync::Mutex<Remote>>>, Path(id): Path<String>| async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let r = remote.lock().unwrap();
                if r.removed { return StatusCode::NOT_FOUND.into_response(); }
                Json(json!({"id":if r.wrong { "another-vm".to_string() } else { id },
                    "status":if r.stopped { "stopped" } else { "running" }, "status_changed_at":"2026-09-17T00:00:00Z"})).into_response()
            }).delete(|State(remote): State<Arc<std::sync::Mutex<Remote>>>| async move {
                let mut r = remote.lock().unwrap();
                assert!(r.stopped, "deletion requires verified stop");
                r.deletes += 1; r.removed = true;
                if r.lost { StatusCode::BAD_GATEWAY.into_response() } else { Json(json!({})).into_response() }
            }))
            .route("/sandbox/{id}/stop", post(|State(remote): State<Arc<std::sync::Mutex<Remote>>>| async move {
                let mut r = remote.lock().unwrap(); r.stops += 1;
                if !r.ineffective { r.stopped = true; }
                if r.lost { StatusCode::BAD_GATEWAY.into_response() } else { Json(json!({})).into_response() }
            })).with_state(remote.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        unsafe { std::env::set_var("CI_TEST_DAEMON", format!("http://{}", listener.local_addr().unwrap())); }
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        for scenario in ["lost-stop", "ineffective-stop", "wrong-id", "changed-owner", "changed-attempt", "cancel", "destroy-loss", "concurrent"] {
            *remote.lock().unwrap() = Remote::default();
            let workflow = crate::workflow::Workflow::parse("cleanup.yml", "jobs:\n  build:\n    steps: [{run: echo test}]\n").unwrap();
            let plan = crate::plan::Plan::build(&workflow).unwrap();
            let run = crate::vm::new_id(); let sandbox = format!("sb-{run}");
            d.store.create_run(&run, &crate::store::RunRequest { repo_url: "https://example.test/repo.git".into(), ..Default::default() }, &plan).await.unwrap();
            let job = d.store.jobs_of(&run).await.unwrap().remove(0);
            assert_eq!(d.store.claim_job_for_boot(&job.id, "hd-local", 1, d.executor.boot_id()).await.unwrap(), JobClaim::Claimed);
            d.store.start_job(&job.id, "hd-local", &sandbox, "fp", 1).await.unwrap();
            d.pool.register(&sandbox, "hd-local", "fp", "wf", None, &job.id, d.lease()).await.unwrap();
            // A bad handoff must not publish a terminal job or a cleanup intent.
            assert!(handoff(&d, &job.id, "hd-local", 2, &sandbox, JobStatus::Failure, None).await.is_err());
            let status: String = sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1").bind(&job.id).fetch_one(d.store.pool()).await.unwrap();
            assert_eq!(status, "running");
            if scenario == "cancel" {
                d.store.set_job_status(&job.id, JobStatus::Cancelled, None).await.unwrap();
                reconcile(&d).await.unwrap();
                assert_eq!(remote.lock().unwrap().stops, 0, "cancellation is not a handoff");
            }
            handoff(&d, &job.id, "hd-local", 1, &sandbox, JobStatus::Failure, Some("executor finished")).await.unwrap();
            // An intent written by the prior controller requested a stopped
            // cache; after upgrade it must still be deleted, not repooled.
            sqlx::query("UPDATE ci_vm_cleanup SET destroy=false WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap();
            d.pool.renew_leases(d.lease()).await.unwrap();
            assert!(sqlx::query_scalar::<_,bool>("SELECT leased_until='infinity'::timestamptz FROM ci_vm_pool WHERE sandbox_id=$1")
                .bind(&sandbox).fetch_one(d.store.pool()).await.unwrap(), "process heartbeat must not replace cleanup ownership");
            let status: String = sqlx::query_scalar("SELECT status FROM ci_job WHERE id=$1").bind(&job.id).fetch_one(d.store.pool()).await.unwrap();
            assert_eq!(status, if scenario == "cancel" { "cancelled" } else { "failure" });
            assert!(handoff(&d, &job.id, "hd-local", 1, &sandbox, JobStatus::Success, None).await.is_err());
            assert_eq!(sqlx::query_scalar::<_,String>("SELECT status FROM ci_job WHERE id=$1").bind(&job.id).fetch_one(d.store.pool()).await.unwrap(), status);
            let drain = uuid::Uuid::new_v4();
            d.executor.pause(drain).await.unwrap();
            assert!(d.executor.effect_permit().await.is_ok(), "cleanup is allowed during drain");
            assert!(d.executor.quiesce(drain).await.is_err());
            // Restart + expired lease must not hand a cleanup-owned VM to a job.
            sqlx::query("UPDATE ci_vm_pool SET leased_until=now()-interval '1 hour' WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap();
            assert_eq!(d.pool.release_orphans(&["hd-local".into()], "restarted-instance").await.unwrap(), 0);
            match scenario {
                "lost-stop" => remote.lock().unwrap().lost = true,
                "ineffective-stop" => remote.lock().unwrap().ineffective = true,
                "wrong-id" => remote.lock().unwrap().wrong = true,
                "destroy-loss" => { let mut r = remote.lock().unwrap(); r.stopped = true; r.lost = true; }
                "changed-owner" => { sqlx::query("UPDATE ci_vm_pool SET claimed_by_job=NULL WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap(); }
                "changed-attempt" => { sqlx::query("UPDATE ci_job SET attempt=2 WHERE id=$1").bind(&job.id).execute(d.store.pool()).await.unwrap(); }
                _ => {}
            }
            if scenario == "concurrent" {
                let (a,b) = tokio::join!(reconcile(&d), reconcile(&d)); a.unwrap(); b.unwrap();
                assert_eq!(remote.lock().unwrap().stops, 1);
            } else { reconcile(&d).await.unwrap(); }
            if !matches!(scenario, "cancel" | "concurrent") {
                let error: Option<String> = sqlx::query_scalar("SELECT last_error FROM ci_vm_cleanup WHERE sandbox_id=$1").bind(&sandbox).fetch_one(d.store.pool()).await.unwrap();
                assert!(error.is_some(), "retry must explain failure: {scenario}");
                assert_eq!(sqlx::query_scalar::<_,String>("SELECT status FROM ci_vm_pool WHERE sandbox_id=$1").bind(&sandbox).fetch_one(d.store.pool()).await.unwrap(), "claimed");
                if matches!(scenario, "wrong-id" | "changed-owner" | "changed-attempt") { assert_eq!(remote.lock().unwrap().stops, 0); }
                { let mut r = remote.lock().unwrap(); r.lost = false; r.ineffective = false; r.wrong = false; }
                // Restore only deliberately corrupted disposable test evidence.
                sqlx::query("UPDATE ci_vm_pool SET claimed_by_job=$2 WHERE sandbox_id=$1").bind(&sandbox).bind(&job.id).execute(d.store.pool()).await.unwrap();
                sqlx::query("UPDATE ci_job SET attempt=1 WHERE id=$1").bind(&job.id).execute(d.store.pool()).await.unwrap();
                sqlx::query("UPDATE ci_vm_cleanup SET next_attempt_at=now() WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap();
                let restarted = test_dispatcher(workspace.path()).await;
                reconcile(&restarted).await.unwrap();
                if scenario == "lost-stop" { assert_eq!(remote.lock().unwrap().stops, 1, "readback recovers lost stop without repeating it"); }
                if scenario == "destroy-loss" { assert_eq!(remote.lock().unwrap().deletes, 1); }
            }
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM ci_vm_cleanup WHERE sandbox_id=$1").bind(&sandbox).fetch_one(d.store.pool()).await.unwrap(), 0);
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM ci_host_work WHERE job_id=$1").bind(&job.id).fetch_one(d.store.pool()).await.unwrap(), 0);
            let status: Option<String> = sqlx::query_scalar("SELECT status FROM ci_vm_pool WHERE sandbox_id=$1").bind(&sandbox).fetch_optional(d.store.pool()).await.unwrap();
            assert_eq!(status, None, "even legacy reuse handoffs must delete the VM");
            let report: serde_json::Value = sqlx::query_scalar("SELECT payload FROM ci_debug_report WHERE job_id=$1 AND sandbox_id=$2")
                .bind(&job.id).bind(&sandbox).fetch_one(d.store.pool()).await.unwrap();
            assert_eq!(report["job"]["status"], if scenario == "cancel" { "cancelled" } else { "failure" });
            assert_eq!(report["job"]["sandbox"], sandbox);
            assert!(sqlx::query_scalar::<_,bool>("SELECT uploaded_at IS NULL FROM ci_debug_report WHERE job_id=$1 AND sandbox_id=$2")
                .bind(&job.id).bind(&sandbox).fetch_one(d.store.pool()).await.unwrap(), "S3 unavailability must not retain the VM");
            d.executor.quiesce(drain).await.expect("verified cleanup unblocks instance drain");
            d.executor.resume(drain).await.unwrap();
            sqlx::query("DELETE FROM ci_vm_pool WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap();
            sqlx::query("DELETE FROM ci_debug_report WHERE job_id=$1").bind(&job.id).execute(d.store.pool()).await.unwrap();
            sqlx::query("DELETE FROM ci_run WHERE id=$1").bind(&run).execute(d.store.pool()).await.unwrap();
        }
        server.abort();
    }

    #[tokio::test]
    #[ignore = "needs disposable CI_TEST_DATABASE_URL and CI_TEST_NATS_URL; fake Cloud and heyvm HTTP"]
    async fn host_maintenance_drains_recovers_and_fails_closed() {
        use crate::host_maintenance as maintenance;
        use axum::{Json, Router, extract::{Path, State}, http::StatusCode, response::IntoResponse, routing::{get, post}};
        #[derive(Default)]
        struct Remote { posts: Vec<Value>, stops: Vec<String>, status: String, wrong: bool, lost: bool, hidden: bool, old: bool, stop_failure: bool }
        let remote = Arc::new(std::sync::Mutex::new(Remote::default()));
        let app = Router::new()
            .route("/v1/secrets", get(|axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>| async move {
                Json(json!({"secrets":[{"path":format!("{}/CLOUD_KEY",q["prefix"])}]}))
            }))
            .route("/v1/secrets/read", post(|| async { Json(json!({"valueBase64":"ZmFrZS1rZXk="})) }))
            .route("/storage", get(|| async { Json(json!({"free_bytes":1u64 << 50})) }))
            .route("/capabilities", get(|| async { Json(json!({"supportedDrivers":["firecracker","kvm","avf"]})) }))
            .route("/sandbox/{id}/stop", post(|State(remote): State<Arc<std::sync::Mutex<Remote>>>, Path(id): Path<String>| async move {
                let mut r = remote.lock().unwrap();
                if r.stop_failure { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                r.stops.push(id); Json(json!({})).into_response()
            }))
            .route("/internal/mvm-ctrl/backend-servers/host-heyvm/upgrades", post(
                |State(remote): State<Arc<std::sync::Mutex<Remote>>>, headers: axum::http::HeaderMap, Json(body): Json<Value>| async move {
                    assert_eq!(headers["authorization"], "Bearer fake-key");
                    let mut r = remote.lock().unwrap();
                    if r.old { return StatusCode::NOT_FOUND.into_response(); }
                    assert!(!r.stops.is_empty(), "own VM must stop before POST");
                    assert_eq!(body["backendServerId"], "cloud-backend-982");
                    assert_ne!(body["backendServerId"], "hd-local");
                    assert_eq!(body["sha256"], "b".repeat(64));
                    if let Some(previous) = r.posts.first() { assert_eq!(&body, previous, "retry payload must be exact"); }
                    r.posts.push(body.clone());
                    if r.lost { return StatusCode::BAD_GATEWAY.into_response(); }
                    Json(json!({"maintenanceId":body["maintenanceId"],"backendServerId":body["backendServerId"],"status":"accepted"})).into_response()
                }))
            .route("/internal/mvm-ctrl/backend-servers/host-heyvm/upgrade/{id}", get(
                |State(remote): State<Arc<std::sync::Mutex<Remote>>>, Path(id): Path<String>| async move {
                    // Give competing reconcilers time to contend for ownership.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let r = remote.lock().unwrap();
                    if r.hidden || r.posts.is_empty() { return StatusCode::NOT_FOUND.into_response(); }
                    let p = &r.posts[0]; assert_eq!(id, p["maintenanceId"]);
                    Json(json!({"maintenanceId":id,"backendServerId":p["backendServerId"],"operationType":"host_heyvm_upgrade_receipt_v1",
                        "target":p["target"],"requestedBy":p["requestedBy"],"targetSha256":if r.wrong { json!("wrong") } else { p["sha256"].clone() },
                        "artifactArchiveId":p["artifactArchiveId"],"artifactUserId":p["artifactUserId"],"status":r.status,
                        "completedAt":if matches!(r.status.as_str(), "completed" | "failed") { json!("2026-09-16T00:00:00Z") } else { Value::Null }})).into_response()
                })).with_state(remote.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let target = maintenance::Target { repository: "https://example.test/repo.git".into(), runner_hd_id: "hd-local".into(),
            backend_server_id: "cloud-backend-982".into(), cloud_url: base.clone(), orchestrator_url: "https://orch.test".into(),
            artifact_user_id: "archive-owner".into(), target: "stage-eu1-host-heyvm".into(), region: Some("eu1".into()) };
        unsafe {
            std::env::set_var("CI_TEST_DAEMON", &base);
            std::env::set_var("CI_HOST_MAINTENANCE_TARGETS", json!({"selected":target}).to_string());
            std::env::set_var("CI_HEYOSECRET_URL", &base);
            std::env::set_var("CI_HEYOSECRET_TOKEN", "test-only");
        }
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let mut networks = d.runners.snapshot().networks.clone();
        networks[0].runners.push(crate::runners::Runner { id: "hd-other".into(), name: "other".into(), status: crate::runners::RunnerStatus::Online, last_seen_at: None });
        d.runners.set_test_pool(crate::runners::Pool { networks, default_network_id: "local".into(), default_node_id: "hd-local".into(), ..Default::default() });
        // A dependent job is not tied to its predecessor's server. Choose the
        // lexically later host first so this also distinguishes affinity from
        // the equal-capacity tie breaker (which would choose hd-local).
        let workflow = crate::workflow::Workflow::parse("drain.yml", "jobs:\n  build:\n    steps: [{run: echo build}]\n  test:\n    needs: [build]\n    steps: [{run: echo test}]\n").unwrap();
        let plan = crate::plan::Plan::build(&workflow).unwrap();
        let run = crate::vm::new_id();
        d.store.create_run(&run, &crate::store::RunRequest::default(), &plan).await.unwrap();
        let build = crate::store::job_id(&run, "build");
        let test = crate::store::job_id(&run, "test");
        assert!(d.store.claim_job(&build, "hd-other", 1).await.unwrap());
        let test_plan = plan.jobs.iter().find(|p| p.key == "test").unwrap();
        assert_eq!(d.pick_runner(test_plan, &run).await.unwrap().0, "hd-other");
        let drain = uuid::Uuid::new_v4();
        maintenance::runner_drain(&d.store, "hd-other", drain, true).await.unwrap();
        d.advance_run(&run).await.unwrap();
        assert_eq!(d.store.get_job(&test).await.unwrap().unwrap().status, "pending", "wait for build results");
        d.store.set_job_outputs(&build, &json!({"artifact":"shared-build-digest"})).await.unwrap();
        d.store.set_job_status(&build, JobStatus::Success, None).await.unwrap();
        d.store.end_host_work(&build, "hd-other", 1).await.unwrap();
        d.advance_run(&run).await.unwrap();
        assert_eq!(d.store.get_job(&test).await.unwrap().unwrap().status, "queued");
        assert_eq!(d.store.needs_context(&run).await.unwrap()["build"]["outputs"]["artifact"], "shared-build-digest");
        assert_eq!(d.pick_runner(test_plan, &run).await.unwrap().0, "hd-local");
        assert!(d.store.claim_job(&test, "hd-local", 1).await.unwrap());
        assert_eq!(maintenance::runner_drain_status(&d.store, "hd-other").await.unwrap()["drained"], true);
        d.store.set_job_status(&test, JobStatus::Success, None).await.unwrap();
        d.store.end_host_work(&test, "hd-local", 1).await.unwrap();
        maintenance::runner_drain(&d.store, "hd-other", drain, false).await.unwrap();
        for scenario in ["success", "failed", "identity", "cancel-before", "cancel-after", "deadline", "old-cloud"] {
            *remote.lock().unwrap() = Remote { status: "maintenance".into(), lost: true, ..Default::default() };
            let workflow = crate::workflow::Workflow::parse("maintenance.yml", "jobs:\n  upgrade:\n    steps: [{uses: ci/promote-service-archive}, {uses: ci/host-heyvm-maintenance}]\n  existing:\n    steps: [{run: echo existing}]\n  waiting:\n    steps: [{run: echo waiting}]\n  other:\n    steps: [{run: echo other}]\n").unwrap();
            let plan = crate::plan::Plan::build(&workflow).unwrap();
            let run = crate::vm::new_id(); let sha = "a".repeat(40);
            d.store.create_run(&run, &crate::store::RunRequest { repo_url: target.repository.clone(), git_ref: "refs/heads/main".into(), sha: sha.clone(), ..Default::default() }, &plan).await.unwrap();
            let jobs = d.store.jobs_of(&run).await.unwrap();
            let job = jobs.iter().find(|j| j.job_key == "upgrade").unwrap();
            let existing = jobs.iter().find(|j| j.job_key == "existing").unwrap();
            let waiting = jobs.iter().find(|j| j.job_key == "waiting").unwrap();
            let other = jobs.iter().find(|j| j.job_key == "other").unwrap();
            let job_plan: JobPlan = serde_json::from_value(job.plan.clone()).unwrap();
            let msg = crate::bus::JobMessage { run_id: run.clone(), job_id: job.id.clone(), job_key: job.job_key.clone() };
            let sandbox = format!("sb-{run}");
            assert!(d.store.claim_job(&job.id, "hd-local", 1).await.unwrap());
            d.store.start_job(&job.id, "hd-local", &sandbox, "fp", 1).await.unwrap();
            d.pool.register(&sandbox, "hd-local", "fp", "wf", None, &job.id, d.lease()).await.unwrap();
            assert!(d.store.claim_job(&existing.id, "hd-local", 1).await.unwrap());
            let publication = crate::store::step_id(&job.id, 0); let sid = crate::store::step_id(&job.id, 1);
            d.store.create_step(&publication, &job.id, 0, "Publish", Some("ci/promote-service-archive")).await.unwrap();
            d.store.create_step(&sid, &job.id, 1, "Maintenance", Some("ci/host-heyvm-maintenance")).await.unwrap();
            d.store.start_step(&sid, &sid).await.unwrap();
            let prepared = json!({"source_sha":sha,"release_sha":sha,"git_ref":"refs/heads/main","versions":{}});
            sqlx::query("INSERT INTO ci_release(run_id,request_hash,source_sha,base_sha,git_ref,versions,candidate_sha,prepared,status) VALUES($1,'test',$2,$2,'refs/heads/main','{}',$2,$3,'published')")
                .bind(&run).bind(&sha).bind(prepared).execute(d.store.pool()).await.unwrap();
            sqlx::query("INSERT INTO ci_service_archive(step_id,run_id,job_id,archive_id,sha,orchestrator_url,archive_user_id,archive_sha256,heyvm_sha256) VALUES($1,$2,$3,$4,$5,'https://orch.test','archive-owner',$6,$7)")
                .bind(&publication).bind(&run).bind(&job.id).bind(&run).bind(&sha).bind("c".repeat(64)).bind("b".repeat(64)).execute(d.store.pool()).await.unwrap();
            // An existing row isn't publication success; caller-supplied IDs and unknown mappings also fail before cordon.
            assert!(maintenance::request(&d, &msg, &job_plan, &sid, "selected", &base, &run, "CLOUD_KEY", Duration::from_secs(120)).await.is_err());
            d.store.finish_step(&publication, StepStatus::Success, Some(0), None).await.unwrap();
            for (alias, archive, url) in [("unknown", run.as_str(), base.as_str()), ("selected", "external-archive", base.as_str()), ("selected", run.as_str(), "https://wrong-cloud.test")] {
                assert!(maintenance::request(&d, &msg, &job_plan, &sid, alias, url, archive, "CLOUD_KEY", Duration::from_secs(120)).await.is_err());
            }
            for (revision, owner, orch) in [("wrong-sha", "archive-owner", "https://orch.test"),
                (sha.as_str(), "wrong-owner", "https://orch.test"), (sha.as_str(), "archive-owner", "https://wrong-orch.test")] {
                sqlx::query("UPDATE ci_service_archive SET sha=$2,archive_user_id=$3,orchestrator_url=$4 WHERE step_id=$1")
                    .bind(&publication).bind(revision).bind(owner).bind(orch).execute(d.store.pool()).await.unwrap();
                assert!(maintenance::request(&d, &msg, &job_plan, &sid, "selected", &base, &run, "CLOUD_KEY", Duration::from_secs(120)).await.is_err());
            }
            sqlx::query("UPDATE ci_service_archive SET sha=$2,archive_user_id='archive-owner',orchestrator_url='https://orch.test' WHERE step_id=$1")
                .bind(&publication).bind(&sha).execute(d.store.pool()).await.unwrap();
            assert!(!maintenance::cordoned(&d.store, "hd-local").await.unwrap());
            // Serialize competing maintenance admission/claims using the real shared lock.
            let mut gate = d.store.pool().begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('hd-local',222))").execute(&mut *gate).await.unwrap();
            let release_gate = async { tokio::time::sleep(Duration::from_millis(30)).await; gate.commit().await.unwrap(); };
            let (a,b,claimed,()) = tokio::join!(
                maintenance::request(&d, &msg, &job_plan, &sid, "selected", &base, &run, "CLOUD_KEY", Duration::from_secs(120)),
                maintenance::request(&d, &msg, &job_plan, &sid, "selected", &base, &run, "CLOUD_KEY", Duration::from_secs(120)),
                d.store.claim_job(&waiting.id, "hd-local", 1), release_gate);
            a.unwrap(); b.unwrap(); let claimed = claimed.unwrap();
            let id = hex::encode(sha2::Sha256::digest(sid.as_bytes()));
            assert_eq!(id.len(), 64);
            assert!(maintenance::cordoned(&d.store, "hd-local").await.unwrap());
            assert!(!d.store.claim_job(&other.id, "hd-local", 1).await.unwrap());
            assert!(d.store.claim_job(&other.id, "hd-other", 1).await.unwrap(), "another runner remains usable");
            let mut pinned = job_plan.clone(); pinned.target.node = Some("local".into());
            assert!(matches!(d.pick_runner(&pinned, &run).await, Err(DispatchError::MaintenancePaused)), "pinned placement must honor the fence");
            assert_eq!(d.pick_runner(&job_plan, &run).await.unwrap().0, "hd-other", "unpinned placement must choose the unfenced runner");
            pinned.fallback = Fallback::Any;
            assert!(matches!(d.route_for(&pinned).await.unwrap(), Route::Network(_)));
            assert_eq!(d.pick_runner(&pinned, &run).await.unwrap().0, "hd-other", "fallback jobs must leave a drained host");
            assert_eq!(d.run_job(&msg, 2).await.unwrap(), JobStatus::Running, "duplicate delivery must not reacquire a VM");
            maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap();
            assert!(remote.lock().unwrap().posts.is_empty());
            // Expired own lease must not be reclaimed before a verified stop.
            sqlx::query("UPDATE ci_vm_pool SET leased_by='dead-process',leased_until=now()-interval '1 hour' WHERE sandbox_id=$1").bind(&sandbox).execute(d.store.pool()).await.unwrap();
            d.reclaim_pool().await.unwrap();
            assert_eq!(d.pool.get(&sandbox).await.unwrap().unwrap().status, "claimed");
            if scenario == "success" {
                // Simulate process loss after stop but before the atomic pool
                // release/phase commit. Retry must still own this exact VM.
                sqlx::query("ALTER TABLE ci_host_maintenance ADD CONSTRAINT test_release_crash CHECK (phase<>'draining')").execute(d.store.pool()).await.unwrap();
                assert!(maintenance::release(&d, &id).await.is_err());
                sqlx::query("ALTER TABLE ci_host_maintenance DROP CONSTRAINT test_release_crash").execute(d.store.pool()).await.unwrap();
                assert_eq!(d.pool.get(&sandbox).await.unwrap().unwrap().status, "claimed");
                assert!(remote.lock().unwrap().posts.is_empty());
            }
            let (a,b) = tokio::join!(maintenance::release(&d, &id), maintenance::release(&d, &id)); a.unwrap(); b.unwrap();
            assert_eq!(remote.lock().unwrap().stops, vec![sandbox.clone(); if scenario == "success" { 2 } else { 1 }]);
            assert_eq!(d.pool.get(&sandbox).await.unwrap().unwrap().status, "idle");
            assert_eq!(d.store.get_job(&job.id).await.unwrap().unwrap().status, "running");
            if scenario == "success" { d.store.migrate().await.unwrap(); } // restart must not recreate released work
            maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap();
            assert!(remote.lock().unwrap().posts.is_empty(), "existing running work must drain");
            d.store.set_job_status(&existing.id, JobStatus::Cancelled, None).await.unwrap();
            d.store.set_job_status(&other.id, JobStatus::Success, None).await.unwrap();
            if claimed { d.store.set_job_status(&waiting.id, JobStatus::Success, None).await.unwrap(); }
            else { d.store.set_job_status(&waiting.id, JobStatus::Skipped, None).await.unwrap(); }
            d.store.end_host_work(&other.id, "hd-other", 1).await.unwrap();
            d.store.end_host_work(&waiting.id, "hd-local", 1).await.unwrap();
            d.store.end_host_work(&existing.id, "hd-local", 99).await.unwrap();
            maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap();
            let phase: String = sqlx::query_scalar("SELECT phase FROM ci_host_maintenance WHERE id=$1").bind(&id).fetch_one(d.store.pool()).await.unwrap();
            assert_eq!(phase, "draining", "cancellation during VM acquisition and a stale delivery must not erase active host work");
            d.store.end_host_work(&existing.id, "hd-local", 1).await.unwrap();
            d.store.set_job_status(&existing.id, JobStatus::Success, None).await.unwrap();
            if scenario == "success" {
                let active = format!("sb-active-{run}");
                d.pool.register(&active, "hd-local", "fp", "wf", None, &existing.id, d.lease()).await.unwrap();
                let vm = d.vms.open(d.runners.options_for("hd-local").await.unwrap(), active.clone()).await.unwrap();
                let mut reusable = job_plan.clone(); reusable.vm.reuse = true;
                remote.lock().unwrap().stop_failure = true;
                d.release_vm(&reusable, &vm, false).await;
                assert_eq!(d.pool.get(&active).await.unwrap().unwrap().status, "claimed", "failed stop must retain drain evidence even when job finished");
                maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap();
                assert!(remote.lock().unwrap().posts.is_empty());
                assert!(d.pool.take_for_sweep(&["hd-local".into()], &[], 0).await.unwrap().is_empty(), "maintenance does not delete idle caches");
                remote.lock().unwrap().stop_failure = false;
                d.release_vm(&reusable, &vm, false).await;
                assert_eq!(d.pool.get(&active).await.unwrap().unwrap().status, "idle");
                d.pool.forget(&active).await.unwrap();
            }
            if scenario == "cancel-before" { d.store.cancel_run(&run).await.unwrap(); }
            if scenario == "deadline" { sqlx::query("UPDATE ci_host_maintenance SET deadline=now()-interval '1 second' WHERE id=$1").bind(&id).execute(d.store.pool()).await.unwrap(); }
            if scenario == "old-cloud" { remote.lock().unwrap().old = true; }
            maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap(); // durable submitting boundary
            let (a,b) = tokio::join!(maintenance::poll(&d.store, &id, "fake-key", Some(&target)), maintenance::poll(&d.store, &id, "fake-key", Some(&target))); a.unwrap(); b.unwrap();
            if matches!(scenario, "cancel-before" | "deadline" | "old-cloud") {
                assert!(remote.lock().unwrap().posts.is_empty());
            } else {
                assert_eq!(remote.lock().unwrap().posts.len(), 1, "concurrent reconcilers issue one attempt");
                // Reconnect after lost POST response; even a transient missing GET
                // replays only the persisted ID and exact semantic payload.
                let restarted = Store::connect(&std::env::var("CI_TEST_DATABASE_URL").unwrap(), workspace.path().join("restart"), Duration::from_secs(30)).await.unwrap();
                remote.lock().unwrap().hidden = true;
                maintenance::poll(&restarted, &id, "fake-key", Some(&target)).await.unwrap();
                assert_eq!(remote.lock().unwrap().posts.len(), 2);
                { let mut r = remote.lock().unwrap(); r.hidden = false; r.status = if scenario == "failed" { "failed" } else { "completed" }.into(); r.wrong = scenario == "identity"; }
                if scenario == "cancel-after" { d.store.cancel_run(&run).await.unwrap(); }
                let (a,b) = tokio::join!(maintenance::poll(&restarted, &id, "fake-key", Some(&target)), maintenance::poll(&restarted, &id, "fake-key", Some(&target))); a.unwrap(); b.unwrap();
            }
            let success = scenario == "success";
            assert_eq!(maintenance::cordoned(&d.store, "hd-local").await.unwrap(), !success, "{scenario}");
            let expected = if success { "success" } else if scenario.starts_with("cancel") { "cancelled" } else { "failure" };
            assert_eq!(d.store.get_job(&job.id).await.unwrap().unwrap().status, expected, "{scenario}");
            assert_eq!(d.store.get_run(&run).await.unwrap().unwrap().status, expected, "{scenario}");
            let posts = remote.lock().unwrap().posts.len();
            remote.lock().unwrap().status = "completed".into();
            maintenance::poll(&d.store, &id, "fake-key", Some(&target)).await.unwrap();
            assert_eq!(remote.lock().unwrap().posts.len(), posts);
            assert_eq!(maintenance::cordoned(&d.store, "hd-local").await.unwrap(), !success, "failure must be sticky");
            if scenario == "identity" {
                assert!(maintenance::recover(&d, "wrong-run", &id).await.is_err());
                assert!(maintenance::recover(&d, &run, &id).await.is_err(), "foreign receipt cannot release fence");
                remote.lock().unwrap().wrong = false;
                // An executed skipped job must not be reset, even with a valid receipt.
                sqlx::query("UPDATE ci_job SET status='skipped' WHERE id=$1").bind(&existing.id).execute(d.store.pool()).await.unwrap();
                assert!(maintenance::recover(&d, &run, &id).await.is_err());
                sqlx::query("UPDATE ci_job SET status='success' WHERE id=$1").bind(&existing.id).execute(d.store.pool()).await.unwrap();
                sqlx::query("UPDATE ci_job SET status='skipped',started_at=NULL,queued_at=NULL,sandbox_id=NULL WHERE id=$1")
                    .bind(&waiting.id).execute(d.store.pool()).await.unwrap();
                let result = maintenance::recover(&d, &run, &id).await.unwrap();
                assert_eq!(result["status"], "recovered");
                assert!(!maintenance::cordoned(&d.store, "hd-local").await.unwrap());
                assert_eq!(d.store.get_job(&job.id).await.unwrap().unwrap().status, "success");
                assert_eq!(d.store.get_job(&waiting.id).await.unwrap().unwrap().status, "queued");
                assert_eq!(remote.lock().unwrap().posts.len(), posts, "recovery must never re-POST upgrade");
                assert_eq!(maintenance::recover(&d, &run, &id).await.unwrap()["status"], "already_passed");
                let events: i64 = sqlx::query_scalar("SELECT count(*) FROM ci_event_outbox WHERE run_id=$1 AND event_type='ci.host.maintenance.recovered.v1'")
                    .bind(&run).fetch_one(d.store.pool()).await.unwrap();
                assert_eq!(events, 1, "recovery is idempotent and audited");
            }
            // Disposable fixture cleanup only; production has no automatic uncordon.
            sqlx::query("DELETE FROM ci_host_maintenance WHERE id=$1").bind(&id).execute(d.store.pool()).await.unwrap();
            d.pool.forget(&sandbox).await.unwrap();
        }
        server.abort();
        unsafe {
            std::env::remove_var("CI_HEYOSECRET_URL");
            std::env::remove_var("CI_HEYOSECRET_TOKEN");
        }
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn subnet_pressure_retries_only_after_confirmed_cache_deletion() {
        use axum::{Json, Router, extract::Path, http::StatusCode, routing::{get, post}};
        for (capacity, confirmed, expected_creates, expected_deletes) in [
            (true, true, 2, 1), (true, false, 1, 1), (false, true, 1, 0),
        ] {
            let creates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let deletes = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let calls = creates.clone();
            let removed = deletes.clone();
            let app = Router::new()
                .route("/storage", get(|| async { Json(serde_json::json!({"free_bytes": 1000})) }))
                .route("/sandbox-deploy", post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // The second rejection bounds the retry. This fixture
                        // must never need a real guest to prove admission order.
                        let error = if capacity { "Firecracker virtual network test has no usable /30 TAP subnet" }
                            else { "image not found" };
                        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": error})))
                    }
                }))
                .route("/deployed-sandboxes/{id}", get(move || async move {
                    if confirmed { StatusCode::NOT_FOUND } else { StatusCode::SERVICE_UNAVAILABLE }
                }).delete(move |Path(id): Path<String>| {
                    let removed = removed.clone();
                    async move {
                        removed.lock().unwrap().push(id);
                        StatusCode::NO_CONTENT
                    }
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            unsafe { std::env::set_var("CI_TEST_DAEMON", format!("http://{}", listener.local_addr().unwrap())); }
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let workspace = tempfile::tempdir().unwrap();
            let d = test_dispatcher(workspace.path()).await;
            let run = format!("capacity-{}", crate::vm::new_id());
            let job = format!("{run}-job");
            let cache = format!("{run}-cache");
            let foreign = format!("{run}-foreign");
            let runner = format!("{run}-runner");
            sqlx::query("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES($1,'test','test.yml','success')")
                .bind(&run).execute(d.store.pool()).await.unwrap();
            sqlx::query("INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES($1,$2,$1,$1,$1,'success')")
                .bind(&job).bind(&run).execute(d.store.pool()).await.unwrap();
            for (id, runner) in [(&cache, runner.as_str()), (&foreign, "hd-other")] {
                d.pool.register(id, runner, "old-fp", "test", None, &job, d.lease()).await.unwrap();
                d.pool.release(id).await.unwrap();
            }
            let mut plan = plan_targeting(None);
            plan.vm.reuse = false;
            assert!(d.acquire_vm(&runner, &plan, "new-fp", &job, 1).await.is_err());
            assert_eq!(creates.load(Ordering::SeqCst), expected_creates);
            assert_eq!(deletes.lock().unwrap().len(), expected_deletes);
            if expected_deletes == 1 { assert_eq!(*deletes.lock().unwrap(), vec![cache.clone()]); }
            assert_eq!(d.pool.get(&cache).await.unwrap().is_none(), capacity && confirmed);
            assert_eq!(d.pool.get(&foreign).await.unwrap().unwrap().status, "idle");
            d.pool.forget(&cache).await.unwrap();
            d.pool.forget(&foreign).await.unwrap();
            server.abort();
        }
        unsafe { std::env::remove_var("CI_TEST_DAEMON"); }
    }

    #[tokio::test]
    #[ignore = "needs CI_TEST_DATABASE_URL and CI_TEST_NATS_URL"]
    async fn disk_pressure_rechecks_space_and_stops_at_budget() {
        use axum::{Json, Router, extract::Path, http::StatusCode, routing::get};
        use std::sync::atomic::AtomicU64;
        let free = Arc::new(AtomicU64::new(50));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let confirm = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let confirmed = confirm.clone();
        let deleted = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let storage = free.clone();
        let disk = free.clone();
        let errors = fail.clone();
        let calls = deleted.clone();
        let app = Router::new()
            .route("/storage", get(move || {
                let storage = storage.clone();
                async move { Json(serde_json::json!({"free_bytes": storage.load(Ordering::SeqCst)})) }
            }))
            .route("/deployed-sandboxes/{id}", get(move || {
                let confirmed = confirmed.clone();
                async move {
                    if confirmed.load(Ordering::SeqCst) { StatusCode::NOT_FOUND }
                    else { StatusCode::SERVICE_UNAVAILABLE }
                }
            }).delete(move |Path(id): Path<String>| {
                let (disk, errors, calls) = (disk.clone(), errors.clone(), calls.clone());
                async move {
                    calls.lock().unwrap().push(id);
                    if errors.load(Ordering::SeqCst) { return StatusCode::FORBIDDEN; }
                    disk.fetch_add(25, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        unsafe {
            std::env::set_var("CI_TEST_DAEMON", url);
            std::env::set_var("CI_LOCAL_RUNNER_TOKEN", "disposable-test-token");
        }
        let workspace = tempfile::tempdir().unwrap();
        let d = test_dispatcher(workspace.path()).await;
        let runner = format!("pressure-{}", crate::vm::new_id());
        let cached = heyo_sdk::HeyoClient::new(heyo_sdk::HeyoClientOptions {
            base_url: Some(std::env::var("CI_TEST_DAEMON").unwrap()),
            api_key: None, timeout: None,
        }).unwrap();
        d.runners.tunnel_cache_for_test().await.insert(runner.clone(), cached.clone());
        d.runners.tunnel_cache_for_test().await.insert("unrelated-runner".into(), cached);
        let run = format!("run-{runner}");
        sqlx::query("INSERT INTO ci_run(id,workflow_id,workflow_path,status) VALUES($1,'test','test.yml','success')")
            .bind(&run).execute(d.store.pool()).await.unwrap();
        for (id, age) in [("new", 1.0), ("middle", 2.0), ("old", 3.0)] {
            let id = format!("{runner}-{id}");
            let job = format!("job-{id}");
            sqlx::query("INSERT INTO ci_job(id,run_id,job_key,base_id,display,status) VALUES($1,$2,$1,$1,$1,'success')")
                .bind(&job).bind(&run).execute(d.store.pool()).await.unwrap();
            d.pool.register(&id, &runner, "fp", "wf", None, &job, d.lease()).await.unwrap();
            d.pool.release(&id).await.unwrap();
            sqlx::query("UPDATE ci_vm_pool SET last_used_at = now() - make_interval(secs => $2) WHERE sandbox_id = $1")
                .bind(id).bind(age).execute(d.store.pool()).await.unwrap();
        }
        assert_eq!(d.reclaim_disk_space(&runner, 50).await.unwrap(), 50);
        assert!(deleted.lock().unwrap().is_empty(), "exactly enough space must not evict");
        assert_eq!(d.reclaim_disk_space(&runner, 100).await.unwrap(), 100);
        assert_eq!(*deleted.lock().unwrap(), vec![format!("{runner}-old"), format!("{runner}-middle")]);
        assert!(d.runners.tunnel_cache_for_test().await.contains_key(&runner));
        assert!(d.pool.get(&format!("{runner}-old")).await.unwrap().is_none());
        assert_eq!(d.pool.get(&format!("{runner}-new")).await.unwrap().unwrap().status, "idle");
        // Failure must retain ownership and stop rather than deleting more caches.
        fail.store(true, Ordering::SeqCst);
        assert!(d.reclaim_disk_space(&runner, 101).await.is_err());
        assert!(!d.runners.tunnel_cache_for_test().await.contains_key(&runner), "failed eviction must reconnect on retry");
        assert!(d.runners.tunnel_cache_for_test().await.contains_key("unrelated-runner"));
        assert_eq!(d.pool.get(&format!("{runner}-new")).await.unwrap().unwrap().status, "draining");
        let error = d.reclaim_disk_space(&runner, 101).await.unwrap_err();
        assert!(error.to_string().contains("no idle caches left"), "{error}");

        // Maintenance starts after the failed deletion. It must not prevent
        // the durable eviction from completing on a fresh connection.
        let job = format!("job-{runner}-new");
        let step = format!("{job}.maintenance");
        let operation = crate::vm::new_id();
        d.store.create_step(&step, &job, 0, "maintenance", None).await.unwrap();
        sqlx::query("INSERT INTO ci_service_deployment(id,step_id,run_id,job_id,service_id,request_hash,status,phase,sha,git_ref) VALUES($1,$2,$3,$4,'host','test','running','draining','test','main')")
            .bind(&operation).bind(&step).bind(&run).bind(&job).execute(d.store.pool()).await.unwrap();
        sqlx::query("INSERT INTO ci_host_maintenance(id,runner_hd_id,request,deadline,phase) VALUES($1,$2,'{}',now()+interval '1 hour','draining')")
            .bind(&operation).bind(&runner).execute(d.store.pool()).await.unwrap();

        // A new controller finds the persistent eviction even though it is
        // fresh and its fingerprint is still wanted. A successful DELETE is
        // not enough if the follow-up absence check fails.
        let restarted = test_dispatcher(workspace.path()).await;
        fail.store(false, Ordering::SeqCst);
        confirm.store(false, Ordering::SeqCst);
        let retry = restarted.pool.take_for_sweep(&[runner.clone()], &["fp".into()], 86400)
            .await.unwrap();
        assert_eq!(retry.len(), 1);
        let (count, errors) = restarted.destroy_swept(retry).await;
        assert_eq!(count, 0);
        assert_eq!(errors.len(), 1);
        assert!(restarted.pool.get(&format!("{runner}-new")).await.unwrap().is_some());
        confirm.store(true, Ordering::SeqCst);
        let retry = restarted.pool.take_for_sweep(&[runner.clone()], &["fp".into()], 86400)
            .await.unwrap();
        let (count, errors) = restarted.destroy_swept(retry).await;
        assert_eq!(count, 1);
        assert!(errors.is_empty());
        assert!(restarted.pool.get(&format!("{runner}-new")).await.unwrap().is_none());
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM ci_vm_pool WHERE runner_hd_id=$1 AND status IN ('claimed','building','draining'))")
            .bind(&runner).fetch_one(d.store.pool()).await.unwrap();
        assert!(!blocked, "confirmed cache deletion must clear the pool drain blocker");
        server.abort();
        unsafe {
            std::env::remove_var("CI_TEST_DAEMON");
            std::env::remove_var("CI_LOCAL_RUNNER_TOKEN");
        }
    }

    /// Lay down a run's workflow workspace and source descriptor, the way a real
    /// submit does.
    ///
    /// Writing workflow YAML alone is not enough: checkout also consumes the
    /// immutable revisions and patch from the descriptor.
    fn seed_workspace(d: &Arc<Dispatcher>, run_id: &str, files: &[(&str, &str)]) {
        use base64::Engine;
        use std::io::Write;

        let mut ar = tar::Builder::new(Vec::new());
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            ar.append_data(&mut header, name, content.as_bytes())
                .unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&ar.into_inner().unwrap()).unwrap();
        let gz = gz.finish().unwrap();

        std::fs::create_dir_all(&d.config.workspace_dir).unwrap();
        let ws = crate::trigger::Workspace::for_run(&d.config, run_id);
        crate::trigger::materialize(
            &crate::trigger::SourceArchive {
                format: "tar.gz".into(),
                content_base64: base64::engine::general_purpose::STANDARD.encode(&gz),
                bytes: None,
            },
            &ws,
            1 << 20,
        )
        .expect("workspace seeded");
    }

    /// Destroy whatever the pool still holds, so a test does not leave VMs on
    /// the developer's machine.
    async fn cleanup(d: &Arc<Dispatcher>) {
        let Ok(vms) = d.pool.all().await else { return };
        for v in vms.iter().filter(|v| v.runner_hd_id == "hd-local") {
            if let Ok(opts) = d.runners.options_for(&v.runner_hd_id).await
                && let Ok(vm) = d.vms.open(opts, v.sandbox_id.clone()).await
            {
                let _ = vm.destroy().await;
            }
            let _ = d.pool.forget(&v.sandbox_id).await;
        }
        let _ = d.bus.js_delete_streams().await;
    }

    const E2E_YAML: &str = r#"
name: e2e
jobs:
  build:
    vm:
      driver: firecracker
      image: debian
      size_class: micro
      cache_key_files: [lockfile.txt]
    steps:
      - name: Say hello
        id: greet
        run: |
          echo "hello from ci"
          echo "greeting=hi" >> "$CI_OUTPUT"
      - name: Use the step output
        run: echo "greeting was ${{ steps.greet.outputs.greeting }}"
      # The only coverage `ci/upload-artifact` has. It reads out of the guest
      # through exec and base64, which is a different transport from every
      # `run:` step above — the guest has to have `tar` and `base64`, the output
      # has to end with a newline or the serial path hangs forever, and the
      # bytes have to survive the round trip. None of that is exercised by a
      # workflow made only of `run:` steps, which is what this was.
      - name: Produce something to upload
        run: mkdir -p dist && echo "artifact-body" > dist/hello.txt
      - uses: ci/upload-artifact
        with:
          name: e2e-dist
          path: dist
  after:
    needs: [build]
    vm:
      driver: firecracker
      image: debian
      size_class: micro
      cache_key_files: [lockfile.txt]
    steps:
      - name: Depends on build
        run: echo "build said ${{ needs.build.result }}"
"#;

    /// A workflow that builds its own image instead of naming one the host has.
    const E2E_IMAGE_YAML: &str = r#"
name: e2e-image
jobs:
  build:
    vm:
      driver: firecracker
      build:
        dockerfile: img/Dockerfile
      size_class: micro
    steps:
      - name: Prove the image was built
        run: cat /etc/ci-marker; echo "marker=$CI_IMAGE_MARKER"
"#;

    /// The whole `vm.build` path against a real daemon: upload a Dockerfile
    /// and its context to `POST /images/build`, let the daemon run docker →
    /// export → mke2fs into its catalog, and run a job on the result — then
    /// prove the second run reuses the image rather than building it again.
    ///
    /// The Dockerfile ships its own `/init.sh`, and that is not test
    /// scaffolding: docker-built images boot `init=/init.sh` and must print
    /// `HEYVM_READY`, exactly like a hand-built one. The in-guest assertions
    /// cover what has to survive `docker export`: a COPY'd file, a RUN layer,
    /// and an environment variable — which does NOT survive as OCI `ENV` and
    /// must be written to `/etc/profile.d` by a RUN, which is exactly what the
    /// test's Dockerfile does.
    #[tokio::test]
    #[ignore = "needs Postgres, NATS and a local heyvmd"]
    async fn end_to_end_an_image_is_built_from_a_dockerfile_and_then_reused() {
        let root = std::env::temp_dir().join(format!("ci-e2e-img-{}", crate::vm::new_id()));
        let d = test_dispatcher(&root).await;

        let outcome = tokio::spawn({
            let d = d.clone();
            async move { e2e_image_body(d).await }
        })
        .await;

        // Built images are not swept by the pool cleanup — they are files in
        // the runner's catalog — so this test removes its own.
        if let Ok(entries) = d.image_inventory().await {
            for e in entries {
                let _ = d.images.forget(&e.name, &e.runner_hd_id).await;
                let path = dirs_image_path(&e.name);
                let _ = std::fs::remove_file(&path);
            }
        }
        cleanup(&d).await;
        std::fs::remove_dir_all(&root).ok();
        if let Err(e) = outcome {
            std::panic::resume_unwind(e.into_panic());
        }
    }

    /// Where the daemon installs a built image, mirroring
    /// `get_firecracker_images_dir`. Test-only: the app never touches the
    /// runner's filesystem, which is the whole reason `/images/build` exists.
    fn dirs_image_path(name: &str) -> std::path::PathBuf {
        let base = std::env::var("MVM_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".heyo")
            });
        base.join("images/firecracker").join(format!("{name}.ext4"))
    }

    async fn e2e_image_body(d: Arc<Dispatcher>) {
        // A docker-built image boots `init=/init.sh` with no catalog base to
        // inherit one from, so the Dockerfile ships its own — the same
        // obligation deploy/image/Dockerfile discharges for the real build
        // image. The `ENV` is written through `RUN` into /etc/profile.d
        // because `docker export` discards OCI metadata; an `ENV` directive
        // would build fine and silently vanish.
        const DOCKERFILE: &str = "FROM debian:bookworm-slim\n\
             COPY marker.txt /etc/ci-marker\n\
             RUN echo 'and-a-run-layer' >> /etc/ci-marker\n\
             RUN mkdir -p /etc/profile.d \\\n\
              && printf 'export CI_IMAGE_MARKER=from-the-image\\n' > /etc/profile.d/10-e2e.sh\n\
             COPY init.sh /init.sh\n\
             RUN chmod +x /init.sh\n";

        /// PID 1 for the built VM: the minimum that satisfies the heyvm boot
        /// contract. Mount the API filesystems, quiet the serial console the
        /// exec protocol runs over, print the ready marker, and keep a shell
        /// alive on the console — bash specifically, as the serial exec
        /// protocol's output framing is exercised against bash and a dash
        /// console loses step output.
        const INIT_SH: &str = "#!/bin/sh\n\
             mount -t proc proc /proc\n\
             mount -t sysfs sysfs /sys\n\
             mount -t devtmpfs devtmpfs /dev 2>/dev/null\n\
             mkdir -p /dev/pts && mount -t devpts devpts /dev/pts\n\
             dmesg -n 1 2>/dev/null\n\
             mkdir -p /workspace\n\
             echo HEYVM_READY\n\
             while :; do /bin/bash --login; sleep 0.1; done\n";

        let files: &[(&str, &str)] = &[
            ("img/Dockerfile", DOCKERFILE),
            ("img/init.sh", INIT_SH),
            ("img/marker.txt", "a-copied-file\n"),
        ];

        let run1_id = crate::vm::new_id();
        seed_workspace(&d, &run1_id, files);
        let (run1, status1) = run_workflow_with_id(&d, E2E_IMAGE_YAML, &run1_id).await;
        assert_eq!(
            status1,
            crate::store::RunStatus::Success,
            "the image build run must pass; jobs: {:?}",
            d.store.jobs_of(&run1).await.unwrap()
        );

        // One image, ready, on this runner.
        let images = d.image_inventory().await.unwrap();
        assert_eq!(images.len(), 1, "{images:?}");
        let built = images[0].clone();
        assert_eq!(built.status, "ready", "{built:?}");
        assert!(built.name.starts_with("ci-img-"), "{}", built.name);
        assert!(
            dirs_image_path(&built.name).exists(),
            "the daemon must have written {}",
            dirs_image_path(&built.name).display()
        );

        // Every directive survived the snapshot, checked inside the guest.
        let job = d.store.jobs_of(&run1).await.unwrap().remove(0);
        let steps = d.store.steps_of(&job.id).await.unwrap();
        let proof = steps
            .iter()
            .find(|s| s.name == "Prove the image was built")
            .expect("the step ran");
        let log = d.store.read_log(proof).await.unwrap().unwrap_or_default();
        assert!(log.contains("a-copied-file"), "COPY did not land: {log:?}");
        assert!(log.contains("and-a-run-layer"), "RUN did not land: {log:?}");
        assert!(
            log.contains("marker=from-the-image"),
            "the profile.d environment did not survive into the image: {log:?}"
        );

        // The build log is attached to the job, so a failing Dockerfile is
        // readable where somebody is already looking.
        let img_step = steps
            .iter()
            .find(|s| s.name.starts_with("Image ci-img-"))
            .expect("the build log is attached to the job");
        let build_log = d.store.read_log(img_step).await.unwrap().unwrap_or_default();
        for want in ["building image ci-img-", "is ready after"] {
            assert!(
                build_log.contains(want),
                "build log is missing {want:?}: {build_log:?}"
            );
        }

        // ---- run 2: the same Dockerfile must not build a second image.
        let run2_id = crate::vm::new_id();
        seed_workspace(&d, &run2_id, files);
        let (run2, status2) = run_workflow_with_id(&d, E2E_IMAGE_YAML, &run2_id).await;
        assert_eq!(status2, crate::store::RunStatus::Success, "run 2: {run2}");

        let after = d.image_inventory().await.unwrap();
        assert_eq!(
            after.len(),
            1,
            "an unchanged Dockerfile must reuse the image, not build another: {after:?}"
        );
        assert_eq!(after[0].name, built.name);
        assert_eq!(
            after[0].ready_at, built.ready_at,
            "the image must not have been rebuilt"
        );

        // ---- run 3: editing the context busts it.
        let run3_id = crate::vm::new_id();
        let mut changed: Vec<(&str, &str)> = files.to_vec();
        changed[2] = ("img/marker.txt", "a-changed-file\n");
        seed_workspace(&d, &run3_id, &changed);
        let (_run3, status3) = run_workflow_with_id(&d, E2E_IMAGE_YAML, &run3_id).await;
        assert_eq!(status3, crate::store::RunStatus::Success);

        let after = d.image_inventory().await.unwrap();
        assert_eq!(
            after.len(),
            2,
            "a changed COPY source must build a new image: {after:?}"
        );
    }

    #[tokio::test]
    #[ignore = "needs Postgres, NATS and a local heyvmd"]
    async fn end_to_end_runs_use_disposable_vms_and_fingerprint_changed_files() {
        let root = std::env::temp_dir().join(format!("ci-e2e-{}", crate::vm::new_id()));
        let d = test_dispatcher(&root).await;

        // Cleanup must survive a failed assertion, or a panicking test strands
        // VMs on the machine and streams on the NATS.
        let outcome = tokio::spawn({
            let d = d.clone();
            let root = root.clone();
            async move { e2e_body(d, root).await }
        })
        .await;

        cleanup(&d).await;
        std::fs::remove_dir_all(&root).ok();
        if let Err(e) = outcome {
            std::panic::resume_unwind(e.into_panic());
        }
    }

    async fn e2e_body(d: Arc<Dispatcher>, root: std::path::PathBuf) {
        // ---- run 1: everything runs, on a VM that did not exist before.
        let run1_id = crate::vm::new_id();
        seed_workspace(&d, &run1_id, &[("lockfile.txt", "v1")]);
        let (run1, status1) = run_workflow_with_id(&d, E2E_YAML, &run1_id).await;

        assert_eq!(
            status1,
            crate::store::RunStatus::Success,
            "run 1 must pass; jobs: {:?}",
            d.store.jobs_of(&run1).await.unwrap()
        );

        // The DAG really ran in order, and outputs really flowed.
        let jobs = d.store.jobs_of(&run1).await.unwrap();
        assert_eq!(jobs.len(), 2);
        for j in &jobs {
            assert_eq!(j.status, "success", "{} failed: {:?}", j.job_key, j.error);
        }
        let build = jobs.iter().find(|j| j.base_id == "build").unwrap();
        let steps = d.store.steps_of(&build.id).await.unwrap();
        // Checkout at index -1, then the workflow's own two. Looked up by name
        // rather than position, so adding an implicit step does not silently
        // shift what this is asserting about.
        let named = |name: &str| {
            steps.iter().find(|s| s.name == name).unwrap_or_else(|| {
                panic!(
                    "no step {name:?} in {:?}",
                    steps.iter().map(|s| &s.name).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(named("Checkout").status, "success");

        let log0 = d
            .store
            .read_log(named("Say hello"))
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(log0.contains("hello from ci"), "step 1 log: {log0:?}");
        let log1 = d
            .store
            .read_log(named("Use the step output"))
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(
            log1.contains("greeting was hi"),
            "a step output must reach the next step: {log1:?}"
        );

        // `ci/upload-artifact` goes out through a different transport from every
        // `run:` step — exec + tar + base64 — so a green run above proves
        // nothing about it. The row has to exist and the bytes have to be real.
        let artifacts = d.store.artifacts_of(&run1).await.unwrap();
        let uploaded = artifacts
            .iter()
            .find(|a| a.name == "e2e-dist")
            .unwrap_or_else(|| panic!("no e2e-dist artifact; got {artifacts:?}"));
        assert!(
            uploaded.size_bytes > 0,
            "an artifact recorded with no bytes is a report that something was \
             stored when it was not: {uploaded:?}"
        );
        assert_eq!(named("ci/upload-artifact").status, "success");

        let vm1 = build.sandbox_id.clone().expect("a sandbox was used");
        let fp1 = build.fingerprint.clone().expect("a fingerprint");

        // ---- run 2: same lockfile, but CI must not retain or reuse the VM.
        let run2_id = crate::vm::new_id();
        seed_workspace(&d, &run2_id, &[("lockfile.txt", "v1")]);
        let (run2, status2) = run_workflow_with_id(&d, E2E_YAML, &run2_id).await;
        assert_eq!(status2, crate::store::RunStatus::Success);

        let build2 = d
            .store
            .jobs_of(&run2)
            .await
            .unwrap()
            .into_iter()
            .find(|j| j.base_id == "build")
            .unwrap();
        assert_eq!(
            build2.fingerprint.as_deref(),
            Some(fp1.as_str()),
            "an unchanged lockfile must produce the same fingerprint"
        );
        assert_ne!(
            build2.sandbox_id.as_deref(),
            Some(vm1.as_str()),
            "even an unchanged fingerprint must get a disposable VM"
        );

        // ---- run 3: changed source still changes the recorded fingerprint.
        let run3_id = crate::vm::new_id();
        seed_workspace(&d, &run3_id, &[("lockfile.txt", "v2-changed")]);
        let (run3, status3) = run_workflow_with_id(&d, E2E_YAML, &run3_id).await;
        assert_eq!(status3, crate::store::RunStatus::Success);

        let build3 = d
            .store
            .jobs_of(&run3)
            .await
            .unwrap()
            .into_iter()
            .find(|j| j.base_id == "build")
            .unwrap();
        assert_ne!(
            build3.fingerprint.as_deref(),
            Some(fp1.as_str()),
            "a changed cache_key_files entry must change the fingerprint"
        );
        assert_ne!(
            build3.sandbox_id.as_deref(),
            Some(vm1.as_str()),
            "and must therefore get a different VM"
        );

        let _ = root;
    }

    /// `run_workflow`, but with the run id chosen by the caller so the workspace
    /// can be populated first.
    async fn run_workflow_with_id(
        d: &Arc<Dispatcher>,
        yaml: &str,
        run_id: &str,
    ) -> (String, crate::store::RunStatus) {
        use futures::StreamExt;

        let wf = crate::workflow::Workflow::parse("e2e.yml", yaml).expect("workflow");
        let plan = crate::plan::Plan::build(&wf).expect("plan");
        d.store
            .create_run(
                run_id,
                &crate::store::RunRequest {
                    workflow_id: "e2e".into(),
                    source: "test".into(),
                    ..Default::default()
                },
                &plan,
            )
            .await
            .expect("run created");
        d.advance_run(run_id).await.expect("scheduled");

        // Both routes: a job with no `uses:` goes to the network queue, one
        // that pins a host goes to that host's. In production `spawn_consumers`
        // binds both for the same reason.
        let mut consumers = Vec::new();
        for route in [
            Route::Runner("hd-local".into()),
            Route::Network("local".into()),
        ] {
            consumers.push(d.bus.consumer_for(&route).await.expect("consumer"));
        }

        for _ in 0..20 {
            let run = d.store.get_run(run_id).await.unwrap().unwrap();
            if matches!(run.status.as_str(), "success" | "failure" | "cancelled") {
                break;
            }
            for consumer in &consumers {
                let mut batch = consumer
                    .fetch()
                    .max_messages(4)
                    .expires(Duration::from_secs(2))
                    .messages()
                    .await
                    .expect("fetch");
                while let Some(Ok(m)) = batch.next().await {
                    let job: JobMessage = serde_json::from_slice(&m.payload).expect("decode");
                    let attempt = m.info().map(|i| i.delivered as i32).unwrap_or(1);
                    if let Err(e) = d.run_job(&job, attempt).await {
                        eprintln!("job {} failed: {e}", job.job_key);
                    }
                    m.ack().await.ok();
                    d.advance_run(run_id).await.expect("advanced");
                }
            }
        }

        let run = d.store.get_run(run_id).await.unwrap().unwrap();
        let status = match run.status.as_str() {
            "success" => crate::store::RunStatus::Success,
            "failure" => crate::store::RunStatus::Failure,
            "cancelled" => crate::store::RunStatus::Cancelled,
            _ => crate::store::RunStatus::Running,
        };
        (run_id.to_string(), status)
    }
}
