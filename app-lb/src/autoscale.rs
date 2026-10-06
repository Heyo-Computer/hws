//! The control loop: owns every VM lifecycle decision.
//!
//! The daemon offers no event stream, so this polls. It hits `Sandbox::list()`
//! exactly once per tick and indexes the result, because `Sandbox::info()`
//! fetches that same full list and filters client-side — polling per-VM would be
//! quadratic in fleet size.
//!
//! All VM creation happens here and never in a proxy filter, so a slow boot can
//! never stall request handling.

use crate::config::{IdleAction, IngressSpec};
use crate::deployment::{BootOrigin, Deployment, PendingVm, VmBackend, now_secs};
use crate::health;
use crate::metrics::Metrics;
use crate::registry::Registry;
use crate::vm::{self, VmManager};
use crate::workspace::{Then, Workspaces};
use async_trait::async_trait;
use futures::StreamExt;
use heyo_sdk::SandboxInfo;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const TICK: Duration = Duration::from_secs(2);

/// How long a still-booting VM may go without a log line. Chosen far above
/// [`TICK`]: the point is to prove a stuck boot is still stuck, not to narrate
/// every poll of a VM that will be up in ten seconds.
const BOOT_HEARTBEAT: u64 = 30;

/// How long a pending VM may be absent from the daemon's fleet listing before
/// the pool gives up on it.
///
/// The value is a statement about the *daemon*, not the guest: it bounds how
/// long a sandbox this LB created may take to show up in `GET /sandboxes`.
/// Ninety seconds because a create is acknowledged (202, `provisioning`) before
/// its rootfs copy finishes, and that copy is a full byte-for-byte read/write
/// on any filesystem without reflink — tens of seconds for a multi-gigabyte
/// image on a busy host, and worse when the disk is near full.
///
/// Far more important than the exact number is that it is not zero. Treating
/// the first miss as death is what let a single replica slot create sandboxes
/// every [`TICK`] without bound: each miss freed the slot, and each freed slot
/// bought another VM and another data disk that nothing was tracking.
const MISSING_GRACE: u64 = 90;

/// How many deployments reconcile at once.
///
/// The bound exists because the daemon is one process on one host: a fleet of
/// thousands of sandboxes would otherwise open thousands of simultaneous
/// connections to it and to guest health endpoints. High enough that one slow
/// VM cannot stall the tick, low enough to stay a polite client.
const RECONCILE_CONCURRENCY: usize = 32;

/// How many VM creates may be in flight across the *whole fleet* at once.
///
/// Separate from — and much smaller than — [`RECONCILE_CONCURRENCY`], because a
/// create is not just a request: it allocates a tap device, copies a rootfs and
/// starts a hypervisor. Thirty-two concurrent reconciles each deciding to scale
/// up is a host problem, not a loop problem, so the limit is on the expensive
/// operation rather than on the loop that reaches it.
const CREATE_CONCURRENCY: usize = 8;

/// Holds every create slot while an admin replacement fences and swaps a
/// workspace deployment. This makes the persisted workspace fence cover even
/// a create that had already selected the old seed.
pub(crate) struct WorkspaceReplacementGuard<'a> {
    _creates: tokio::sync::SemaphorePermit<'a>,
}

impl WorkspaceReplacementGuard<'_> {
    pub(crate) fn finish(self) {}
}

/// How many lines of the guest's own output to attach to a boot timeout.
///
/// The tail, because a boot that fails says so at the end: the last thing a
/// dying server printed is the reason, and everything before it is the startup
/// it got through. Twenty is enough for a stack trace or a connection refusal
/// with the lines around it, and short enough to stay one log record.
const GUEST_LOG_LINES: usize = 20;

/// How often to look for suspended VMs no deployment claims.
///
/// Slow on purpose. The daemon answers `GET /sandboxes/inactive` by walking its
/// persistence directory and loading metadata for every sandbox it has ever
/// created, so this is the most expensive question app-lb asks it. It is also a
/// backstop, not a control loop: what it catches is the residue of a crash
/// between stopping a VM and recording that we did.
const SUSPENDED_SWEEP: Duration = Duration::from_secs(300);

pub struct Autoscaler {
    rollout_gate: tokio::sync::RwLock<()>,
    registry: Arc<Registry>,
    /// Both runtimes: heyvmd for microVMs, Incus for containers. See
    /// [`crate::runtime`] for why this is an enum-shaped struct rather than a
    /// trait object.
    runtime: crate::runtime::Runtime,
    metrics: Arc<Metrics>,
    /// Monotonic source for replica-name nonces. Not for addressing — the
    /// daemon assigns sandbox ids — just to keep our names unique.
    nonce: AtomicU64,
    /// Fleet-wide budget for simultaneous VM creates. See
    /// [`CREATE_CONCURRENCY`].
    creates: tokio::sync::Semaphore,
    /// The per-namespace event feed. Publishing is opt-in per spec — see
    /// [`Feed::issue`](crate::feed::Feed::issue) — so calls are unconditional
    /// here and the feed itself decides whether anyone hears about it.
    feed: Arc<crate::feed::Feed>,
    /// Deployment-owned workspaces. Every path that retires a VM goes through
    /// it when the deployment has one, so a workspace is captured before the
    /// VM that holds it is destroyed; see [`crate::workspace`].
    workspaces: Arc<Workspaces>,
    /// Resolves a template's `env_from` into values at create time. Held here
    /// rather than by the VM manager so that a missing secret fails the
    /// *create* and travels the create-failure path — counted, fed, embargoed
    /// — instead of being discovered as a guest that boots without its token.
    secrets: Arc<crate::secrets::SecretStore>,
    /// The image inventory, asked before a VM is created whether its image is
    /// on heyvm. Unset (tests, and a host with no inventory) creates as before.
    images: std::sync::OnceLock<Arc<crate::images::ImageCatalog>>,
}

impl Autoscaler {
    pub fn new(
        registry: Arc<Registry>,
        runtime: crate::runtime::Runtime,
        metrics: Arc<Metrics>,
        feed: Arc<crate::feed::Feed>,
        workspaces: Arc<Workspaces>,
        secrets: Arc<crate::secrets::SecretStore>,
    ) -> Self {
        Self {
            rollout_gate: tokio::sync::RwLock::new(()),
            registry,
            runtime,
            metrics,
            nonce: AtomicU64::new(now_secs()),
            creates: tokio::sync::Semaphore::new(CREATE_CONCURRENCY),
            feed,
            workspaces,
            secrets,
            images: std::sync::OnceLock::new(),
        }
    }

    /// See [`Autoscaler::images`]. Set once at startup.
    pub fn set_images(&self, images: Arc<crate::images::ImageCatalog>) {
        let _ = self.images.set(images);
    }

    /// The values a template's `env_from` names, keyed by variable name.
    ///
    /// Resolved at create rather than at registration so rotating a secret
    /// reaches the next replica without re-registering the deployment — the
    /// same reason a build reads its git token when it runs.
    pub async fn rollout_guard(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.rollout_gate.write().await
    }

    pub async fn create_candidate(&self, spec: &crate::config::DeploymentSpec, name: &str) -> Result<String, String> {
        let _permit = self.creates.acquire().await;
        let env = self.secret_env(spec.vm_spec()).map_err(|e| e.to_string())?;
        self.runtime.create(spec.vm_spec(), name.to_string(), None, &vm::VmOwner::of(spec), env).await.map_err(|e| e.to_string())
    }

    fn secret_env(&self, spec: &crate::config::VmSpec) -> Result<HashMap<String, String>, vm::VmError> {
        let mut env = HashMap::with_capacity(spec.env_from.len());
        for from in &spec.env_from {
            let value = self
                .secrets
                .resolve(&from.secret_ref())
                .map_err(|e| vm::VmError::SecretUnresolved {
                    env: from.env_name(),
                    detail: e.to_string(),
                })?;
            env.insert(from.env_name(), value);
        }
        Ok(env)
    }

    /// The workspace store, for the admin API's status view.
    pub fn workspaces(&self) -> &Arc<Workspaces> {
        &self.workspaces
    }

    pub(crate) async fn workspace_recovery_guard(&self) -> WorkspaceReplacementGuard<'_> {
        WorkspaceReplacementGuard { _creates: self.creates.acquire_many(CREATE_CONCURRENCY as u32).await.expect("create semaphore open") }
    }

    /// A record may own resources absent from its in-memory pool. Removing it
    /// would turn those resources into orphans for a later sweep. The caller
    /// holds rollout, registry and allocation guards through removal.
    pub(crate) async fn has_owned_resources(&self, id: &str) -> Result<bool, String> {
        let fleet = self.runtime.list().await;
        fleet.heyvm?;
        if let Some(result) = fleet.lxc { result?; }
        let inactive = self.vms().list_inactive().await.map_err(|e| e.to_string())?;
        Ok(fleet.sandboxes.iter().chain(inactive.iter())
            .any(|vm| vm::owner_of(&vm.name) == Some(id)))
    }

    /// Fence a workspace rollout before its replacement becomes live.
    /// Acquiring all slots first waits out creates already using the old seed;
    /// the durable fence then prevents both the old and new objects creating.
    pub(crate) async fn fence_workspace_replacement<'a>(
        &'a self,
        d: &Arc<Deployment>,
    ) -> Result<Option<WorkspaceReplacementGuard<'a>>, String> {
        if !Self::has_workspace(d) {
            return Ok(None);
        }
        let creates = self
            .creates
            .acquire_many(CREATE_CONCURRENCY as u32)
            .await
            .expect("autoscaler create semaphore is never closed");
        let expected_captures = d.backends().len()
            + d.pending()
                .iter()
                .filter(|p| p.origin != BootOrigin::Created)
                .count()
            + d.state().suspended.len();
        self.workspaces
            .begin_replacement(&d.spec.id, expected_captures)?;
        Ok(Some(WorkspaceReplacementGuard {
            _creates: creates,
        }))
    }

    /// Whether a deployment's VMs carry a workspace that must be captured
    /// before they are destroyed.
    fn has_workspace(d: &Deployment) -> bool {
        d.spec
            .vm
            .as_ref()
            .is_some_and(|vm| vm.workspace.is_some())
    }

    /// Destroy a VM — or, for a workspace deployment, stop it and queue its
    /// capture, after which the worker destroys it. The VM is not running by
    /// the time this returns either way.
    async fn kill_or_capture(&self, d: &Arc<Deployment>, sandbox_id: &str, what: &str) {
        if Self::has_workspace(d) {
            if let Err(e) = self.workspaces.retire(d, sandbox_id, Then::Kill).await {
                tracing::warn!(
                    deployment = %d.spec.id,
                    sandbox = %sandbox_id,
                    error = %e,
                    "could not stop the VM to capture its workspace; killing it would lose \
                     whatever it wrote since the last capture, so it is left for the next \
                     tick to retry",
                );
            }
            return;
        }
        if let Err(e) = self.kill_vm(d, sandbox_id).await {
            tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill {what}");
        }
    }

    /// The heyvm daemon client, for callers that need the heyvm-only surface —
    /// trees, catalog images, proxy binds, disks. Kept as its own accessor so
    /// those callers say which runtime they mean rather than discovering it.
    pub fn vms(&self) -> &VmManager {
        self.runtime.heyvm()
    }

    /// Destroy one of `d`'s replicas, on whichever runtime `d` runs on.
    ///
    /// Every kill that still has its deployment in hand goes through here. The
    /// two that do not — the orphan sweeps, where the deployment is already
    /// gone — use [`crate::runtime::Runtime::kill_unknown`] instead.
    async fn kill_vm(&self, d: &Arc<Deployment>, sandbox_id: &str) -> Result<(), vm::VmError> {
        if self.registry.allocation_protects(sandbox_id) {return Ok(());}
        if self.registry.retirement_protects(sandbox_id,Some(&d.spec.id)) || self.workspaces.retirement_protects(sandbox_id) {return Ok(());}
        if self.workspaces.recovery_pinned(sandbox_id) { return Ok(()); }
        if Self::has_workspace(d) && self.workspaces.source_retained(sandbox_id) {
            return self.vms().suspend(sandbox_id).await;
        }
        let driver = d.spec.driver().unwrap_or_default();
        self.runtime.kill(driver, sandbox_id).await
    }

    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::Relaxed)
    }

    /// Whether `d` is still the registry's object for its id.
    ///
    /// It may not be. `reconcile` works from a snapshot taken at the top of the
    /// tick, and then awaits — on a VM create, on a health probe — for long
    /// enough that an admin request can deregister the deployment or rebuild it
    /// underneath us. `Registry::remove`, `upsert` and `update` all install a
    /// *different* `Arc<Deployment>` (or none), so pointer identity is the test.
    fn is_live(&self, d: &Arc<Deployment>) -> bool {
        self.registry
            .get(&d.spec.id)
            .is_some_and(|live| Arc::ptr_eq(&live, d) && live.state().retirement.is_none())
    }

    /// Which of `ids` no live deployment is tracking any more.
    ///
    /// This is the fix for a leak with no other backstop than the VM's TTL: a
    /// sandbox created (or promoted) against a `Deployment` the registry has
    /// since dropped is published to an object nothing reads, so no `prune`,
    /// `reap_drained` or `teardown` will ever see it. It keeps running, unrouted,
    /// until `ttl_seconds` expires — potentially an hour later.
    ///
    /// Whether that has happened cannot be decided from the stale object alone,
    /// because one of the replacement paths is benign: a pool-preserving edit
    /// (`Registry::update`) copies the pending and backend lists onto the new
    /// object, which then owns those VMs. So ask the registry what the live
    /// deployment claims; anything left over is unreachable and must be killed.
    ///
    /// Pure, so the decision is testable without a daemon; [`kill_unclaimed`]
    /// acts on it.
    ///
    /// [`kill_unclaimed`]: Self::kill_unclaimed
    fn unclaimed(&self, d: &Arc<Deployment>, ids: &[String]) -> Vec<String> {
        if ids.is_empty() {
            return Vec::new();
        }
        let live = self.registry.get(&d.spec.id);
        if live.as_ref().is_some_and(|l| Arc::ptr_eq(l, d)) {
            return Vec::new(); // still ours: the ids are tracked where we put them
        }

        let claimed: HashSet<String> = live
            .iter()
            .flat_map(|l| {
                let (pending, backends) = (l.pending(), l.backends());
                pending
                    .iter()
                    .map(|p| p.sandbox_id.clone())
                    .chain(backends.iter().map(|b| b.sandbox_id.clone()))
                    .chain(crate::rollout::protected_ids(&l.state()).cloned())
                    .collect::<Vec<_>>()
            })
            .collect();

        ids.iter()
            .filter(|id| !claimed.contains(*id))
            .cloned()
            .collect()
    }

    /// Kill the VMs [`unclaimed`](Self::unclaimed) identifies as abandoned.
    async fn kill_unclaimed(&self, d: &Arc<Deployment>, ids: &[String]) {
        for id in self.unclaimed(d, ids) {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %id,
                "deployment was deregistered or rebuilt while this VM was being created; killing it",
            );
            self.kill_or_capture(d, &id, "abandoned VM").await;
        }
    }

    /// Take back replicas the daemon is running that this deployment is not
    /// tracking.
    ///
    /// The other half of the duplicate-VM fix, for the case the grace window in
    /// `promote_pending` cannot reach: a `create` whose *id was never learned*.
    /// `VmManager::create` can fail client-side — the SDK gives it a bounded
    /// timeout — after the daemon has already accepted the sandbox and begun
    /// building it. `scale_up` sees an `Err`, records no pending VM, and breaks;
    /// nothing here has any idea that sandbox exists. The slot stays empty, the
    /// next tick creates another, and each attempt strands one more VM and one
    /// more data disk. That is the shape observed in production: ten sandboxes
    /// and ten disks alive on the daemon, none of them in any pool.
    ///
    /// Adoption closes it without a single extra daemon call — `fleet` is the
    /// listing `reconcile` already fetched — and it is self-healing: whatever
    /// was stranded is counted against `desired` on the very next tick, so the
    /// pool stops creating replacements for capacity it already has.
    ///
    /// Ownership comes from the sandbox *name* ([`vm::owner_of`]), which is the
    /// same rule `adopt_existing` uses at startup; this is that logic made
    /// continuous rather than once-per-process.
    ///
    /// Three exclusions, each load-bearing:
    /// * anything already in `backends` or `pending` — that is the normal case,
    ///   not an orphan;
    /// * suspended sandboxes, which are stopped deliberately and whose data disk
    ///   *is* the deployment's retained state;
    /// * terminal states, which the stopped-VM sweep owns; adopting one would
    ///   mean waiting out a boot timeout on a VM that is already dead.
    fn adopt_untracked(&self, d: &Arc<Deployment>, fleet: &HashMap<String, SandboxInfo>) {
        let pending = d.pending();
        let backends = d.backends();
        let tracked: HashSet<&str> = backends
            .iter()
            .map(|b| b.sandbox_id.as_str())
            .chain(pending.iter().map(|p| p.sandbox_id.as_str()))
            .collect();
        let state = d.state();

        let mut adopted = Vec::new();
        for (id, info) in fleet {
            if vm::owner_of(&info.name) != Some(d.spec.id.as_str())
                || !crate::rollout::adoptable(d, &info.name, id)
                || self.workspaces.recovery_pinned(id)
                || self.workspaces.recovery_active(&d.spec.id)
                || tracked.contains(id.as_str())
                || state.suspended.contains(id)
                || vm::is_terminal(&info.status)
            {
                continue;
            }
            // Dated from the daemon's own uptime, not from now: this VM may have
            // been booting for minutes already, and starting its clock here
            // would hand it a fresh `boot_timeout_secs` on every adoption.
            if !state.create_attempts.iter().any(|a|a.sandbox_id.as_ref()==Some(id)) {
                d.mutate_state(|s|s.allocation_history_complete=false);
                let _=self.registry.persist_one(&d.spec.id);
            }
            let created_at = now_secs().saturating_sub(info.uptime_secs);
            adopted.push(PendingVm {
                created_at,
                // `Resumed`, deliberately, though most of these will in fact be
                // fresh creates. The origin decides whether the give-up path may
                // delete the data disk, and an adopted VM's history is exactly
                // what was lost — so take the conservative branch and keep the
                // disk. A genuinely orphaned one is still reclaimed later by the
                // disk sweep; the reverse mistake destroys retained state.
                origin: BootOrigin::Resumed,
                ..PendingVm::new(id.clone())
            });
        }

        if adopted.is_empty() {
            return;
        }
        tracing::warn!(
            deployment = %d.spec.id,
            count = adopted.len(),
            sandboxes = %adopted.iter().map(|p| p.sandbox_id.as_str()).collect::<Vec<_>>().join(","),
            "adopting running VMs this deployment was not tracking; they count against \
             desired capacity now, so the pool stops creating duplicates for them",
        );
        let mut next = (*pending).clone();
        next.extend(adopted);
        d.set_pending(next);
    }

    /// One full pass over every deployment.
    ///
    /// Concurrent, not sequential. A fleet of agent sandboxes is thousands of
    /// deployments; awaiting each one's health probes and daemon calls in turn
    /// meant a single slow VM held up every other deployment's tick, and the
    /// pass could outrun [`TICK`] entirely. Bounded by
    /// [`RECONCILE_CONCURRENCY`] so a large fleet cannot open thousands of
    /// simultaneous connections to the daemon.
    pub(crate) async fn reconcile(&self) {
        let _retirement = self.registry.retirement_gate.read().await;
        let _rollout = self.rollout_gate.read().await;
        let deployments = self.registry.deployments();
        // Sites are excluded outright rather than partitioned: they have no VMs
        // to reconcile *and* no upstreams to probe, so there is nothing for this
        // loop to do about one. Filtering here is what keeps a fleet of sites
        // from costing a tick.
        let (statics, managed): (Vec<_>, Vec<_>) = deployments
            .values()
            .filter(|d| !d.spec.is_site())
            .cloned()
            .partition(|d| d.spec.is_static());

        // Static (proxy_pass) deployments need no daemon interaction — health-
        // re-probe them first, and unconditionally, so they keep working even
        // when the daemon is unreachable (or app-lb runs with no VM deployments
        // at all and heyvmd isn't running).
        futures::stream::iter(&statics)
            .for_each_concurrent(RECONCILE_CONCURRENCY, |d| self.reconcile_static(d))
            .await;

        // The daemon is listed even when no deployment needs it. A host with
        // no VM deployments is not a host with no VMs — sandboxes created
        // through the CLI, the cloud API or the desktop live there too, and
        // the point of `host_sandboxes` is that they show up on the dashboard
        // whether or not app-lb has anything of its own to run. What changes
        // when nothing is managed is the volume: a missing daemon is then a
        // fact about the host rather than a failure of the control plane, so
        // it is not shouted every two seconds.
        let listing = self.runtime.list().await;

        // Each runtime is judged on its own. Folding them together would let an
        // unreachable heyvmd strand every container deployment — and a briefly
        // restarting Incus strand every microVM — for as long as the other one
        // was down.
        match &listing.heyvm {
            Ok(()) => self.metrics.record_daemon_reachable(),
            Err(e) => {
                if managed.is_empty() {
                    tracing::debug!(error = %e, "failed to list sandboxes; no VM deployments to reconcile");
                } else {
                    tracing::error!(error = %e, "failed to list sandboxes from heyvmd");
                }
                // Recorded because every pool then reads `ready: 0` with a row
                // of zeroes beside it, which is indistinguishable from an idle
                // fleet unless something says the daemon is the thing missing.
                self.metrics.record_daemon_unreachable(e);
            }
        }
        if let Some(Err(e)) = &listing.lxc {
            // Same volume rule the heyvm branch follows, for the same reason: on
            // a host whose deployments are all microVMs, a broken Incus is a
            // fact about the host and not a failure of anything app-lb is doing.
            // Shouting it every two seconds would bury the log that matters.
            if managed.iter().any(|d| d.spec.driver().is_some_and(|dr| dr.is_lxc())) {
                tracing::error!(error = %e, "failed to list containers from incus");
            } else {
                tracing::debug!(error = %e, "failed to list containers; no lxc deployments to reconcile");
            }
        }

        // Only when *nothing* answered is there nothing to reconcile. This
        // `return` abandons the tick for every managed deployment, so it is
        // reached on a total outage and not a partial one.
        if listing.total_outage() {
            return;
        }
        let listing = vm::Listing::from_infos(listing.sandboxes);

        // Fetch host + per-VM resource usage alongside the fleet list. It is a
        // best-effort gauge: a failure here must not derail scaling, so we log
        // and carry on with an empty index (VMs keep their last sample).
        let usage = self.sample_usage().await;

        self.metrics
            .record_host_sandboxes(host_sandboxes(&listing, &usage));
        let fleet = vm::index_by_id(listing.sandboxes);

        if managed.is_empty() {
            return; // nothing else needs the daemon this tick
        }

        // Split before dispatching: a deployment sitting at its desired size
        // with nothing booting and nothing draining needs no `await` at all, and
        // at fleet scale that is nearly all of them. Doing their bookkeeping
        // inline keeps the concurrent stream carrying only real work.
        // How many non-terminal sandboxes the daemon is running per owner, built
        // once for the whole fleet. `at_rest` compares it against what each
        // deployment tracks, so a VM that exists but is in no pool cannot hide
        // behind the fast path.
        let mut owned_running: HashMap<&str, usize> = HashMap::new();
        for info in fleet.values() {
            if vm::is_terminal(&info.status) {
                continue;
            }
            if let Some(owner) = vm::owner_of(&info.name) {
                *owned_running.entry(owner).or_default() += 1;
            }
        }

        let mut busy = Vec::new();
        for d in &managed {
            if !self.is_live(d) {
                continue;
            }
            self.recover_allocations(d, &fleet).await;
            if crate::rollout::reserved(d) {
                // Keep source health recovery, but do not prune, adopt, scale
                // or persist over the rollout's durable generation record.
                busy.push(d);
                continue;
            }
            self.prune(d, &fleet);
            if at_rest(d, &fleet, &owned_running) {
                self.apply_usage(d, &usage);
            } else {
                busy.push(d);
            }
        }

        futures::stream::iter(busy)
            .for_each_concurrent(RECONCILE_CONCURRENCY, |d| {
                self.reconcile_one(d, &fleet, &usage)
            })
            .await;
    }

    /// Re-admit Ready managed backends after a transient service failure.
    ///
    /// Connect failures mark a backend unhealthy in the proxy. Unlike static
    /// upstreams, these backends used to remain excluded forever. Probe only
    /// already-running VMs that are still in the Ready pool; this never starts
    /// or resumes a sandbox, and health is restored only after a successful
    /// probe. Calls are sequential within a deployment and deployments are
    /// already bounded by `RECONCILE_CONCURRENCY`.
    async fn reprobe_unhealthy_managed(
        &self,
        d: &Arc<Deployment>,
        fleet: &HashMap<String, SandboxInfo>,
    ) {
        for backend in d.backends().iter().filter(|b| !b.is_healthy()) {
            let Some(info) = fleet.get(&backend.sandbox_id) else {
                continue;
            };
            let Ok(addr) = vm::routable_addr(info, d.spec.vm_spec().port) else {
                continue;
            };
            if health::probe(addr, &d.spec.health).await {
                backend.set_healthy(true);
                d.ready_signal.notify_waiters();
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %backend.sandbox_id,
                    %addr,
                    "managed backend recovered",
                );
            }
        }
    }

    // (`at_rest` is a free function below — it needs no autoscaler state, and
    // being pure is what makes the fast path testable without a daemon.)

    /// Read the daemon's cached usage snapshot, push the host figures into the
    /// metrics gauge, and return a per-sandbox index for `apply_usage`.
    async fn sample_usage(&self) -> HashMap<String, vm::SandboxUsage> {
        let usage = match self.vms().system_usage().await {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!(error = %e, "failed to fetch system usage; skipping this tick");
                return HashMap::new();
            }
        };

        match usage.snapshot {
            Some(snap) => {
                self.metrics.record_host_usage(
                    usage.available,
                    snap.host.cpu_count,
                    snap.host.cpu_percent,
                    snap.host.memory_total_bytes,
                    snap.host.memory_used_bytes,
                    snap.sampled_at_ms,
                );
                snap.sandboxes
                    .into_iter()
                    .map(|s| (s.sandbox_id.clone(), s))
                    .collect()
            }
            None => {
                // Poller not ready yet: mark the host gauge unavailable so the
                // dashboard shows "—" rather than stale numbers.
                self.metrics.record_host_usage(false, 0, 0.0, 0, 0, 0);
                HashMap::new()
            }
        }
    }

    async fn reconcile_one(
        &self,
        d: &Arc<Deployment>,
        fleet: &HashMap<String, SandboxInfo>,
        usage: &HashMap<String, vm::SandboxUsage>,
    ) {
        // Managed-only: static deployments are reconciled separately in
        // `reconcile` (they own no VMs and need no daemon interaction).
        debug_assert!(d.spec.is_managed(), "reconcile_one called on a deployment with no VM pool");

        // The tick's snapshot can already be stale: an admin request may have
        // deregistered or rebuilt this deployment while a *sibling* deployment
        // was reconciling. Everything below would then act on an object nobody
        // reads — including booting VMs that nothing would ever reap. Checked
        // again here even though `reconcile` checked before dispatching,
        // because the dispatch itself yields.
        if !self.is_live(d) {
            return;
        }

        if crate::rollout::reserved(d) {
            self.reprobe_unhealthy_managed(d, fleet).await;
            return;
        }

        // Before anything counts capacity: a VM the daemon is running for this
        // deployment but that nothing here tracks is still capacity, and still
        // costs a data disk. Counting it is what stops `scale_up` buying a
        // duplicate for a slot that is already filled.
        self.adopt_untracked(d, fleet);

        // `prune` already ran in `reconcile`, which needed a current backend
        // list to decide this deployment had work at all.
        self.reprobe_unhealthy_managed(d, fleet).await;
        self.promote_pending(d, fleet).await;

        let desired = d.desired_replicas();
        let ready = d.backends().len();
        let pending = d.pending().len();
        let live = ready + pending;

        if live < desired as usize {
            // `debug`, not a per-tick warning: the embargo was announced once,
            // loudly, when it was set.
            match d.boot_backoff_remaining(now_secs()) {
                Some(wait) => tracing::debug!(
                    deployment = %d.spec.id,
                    resume_in_secs = wait,
                    "scale-up suppressed by the boot-failure backoff",
                ),
                None => self.scale_up(d, desired as usize - live).await,
            }
        } else if ready > desired as usize {
            self.scale_down(d, ready - desired as usize).await;
        }

        self.snapshot_if_due(d).await;

        // After promotion and drain marking, before reaping: a replica is
        // bound the tick it becomes ready and unbound the tick it starts
        // draining, so the cloud stops sending it new requests before the
        // kill rather than after.
        self.reconcile_ingress(d).await;

        self.reap_drained(d).await;
        self.renew_ttls(d, fleet).await;
        self.apply_usage(d, usage);
    }

    /// Start a scheduled workspace snapshot, if one is due.
    ///
    /// A snapshot can only be taken of a stopped VM (the daemon replays the
    /// image's journal and reads it offline), so "periodic" means recycling:
    /// the same graceful eviction `heyctl restart` performs. The replica drains,
    /// `reap_drained` retires it into the capture, and the replacement — the
    /// same VM resumed under `idle_action: retain`, else a fresh one — boots
    /// from the result. Nothing is started while the workspace is busy or a
    /// rollout holds the deployment.
    async fn snapshot_if_due(&self, d: &Arc<Deployment>) {
        let interval = snapshot_interval(d);
        if interval.is_none() || !d.pending().is_empty() || crate::rollout::reserved(d) {
            return;
        }
        if let Some(why) = self.workspaces.blocked(d) {
            tracing::debug!(deployment = %d.spec.id, %why, "scheduled workspace snapshot waits");
            return;
        }
        let Some(sandbox) = snapshot_candidate(interval, &d.backends()) else {
            return;
        };
        tracing::info!(
            deployment = %d.spec.id,
            sandbox = %sandbox,
            interval_secs = interval.unwrap_or_default(),
            "scheduled workspace snapshot: recycling the replica so its workspace is captured",
        );
        self.evict(d, &sandbox, false).await;
    }

    /// Keep the daemon-side binds in step with `ingress.cloud`: every ready,
    /// non-draining backend bound when the spec asks for a cloud URL, none
    /// bound when it does not. A bind that fails is retried next tick; the
    /// VM keeps serving the proxy's own routes meanwhile.
    async fn reconcile_ingress(&self, d: &Arc<Deployment>) {
        let want = IngressSpec::wants_cloud(d.spec.ingress.as_ref());
        let public = d.spec.ingress.as_ref().is_none_or(|i| i.public);
        let port = d.spec.vm_spec().port;
        let tag = vm::ProxyDeployment {
            namespace: d.spec.namespace.clone(),
            id: d.spec.id.clone(),
        };
        for b in d.backends().iter() {
            match (want && !b.is_draining(), b.bind()) {
                (true, None) => match self.vms().bind(&b.sandbox_id, port, public, &tag).await {
                    Ok(subdomain) => {
                        tracing::info!(
                            deployment = %d.spec.id,
                            sandbox = %b.sandbox_id,
                            %subdomain,
                            port,
                            "bound VM port on the daemon for the cloud URL",
                        );
                        b.set_bind(Some(subdomain));
                    }
                    Err(e) => tracing::warn!(
                        deployment = %d.spec.id,
                        sandbox = %b.sandbox_id,
                        error = %e,
                        "could not bind VM port on the daemon; will retry next tick",
                    ),
                },
                (false, Some(_)) => self.unbind(d, b).await,
                _ => {}
            }
        }
    }

    /// Withdraw a VM's bind so the cloud stops routing the deployment's URL to
    /// it. Nothing to do for a VM that has none.
    async fn unbind(&self, d: &Arc<Deployment>, b: &VmBackend) {
        let Some(subdomain) = b.bind() else {
            return;
        };
        match self.vms().unbind(&b.sandbox_id, &subdomain).await {
            Ok(()) => {
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %b.sandbox_id,
                    %subdomain,
                    "unbound VM port on the daemon",
                );
                b.set_bind(None);
            }
            // Kept as bound and retried: the daemon drops every bind of a
            // sandbox it deletes anyway, so a VM on its way out cannot leak
            // one — this only matters for a VM that stays.
            Err(e) => tracing::warn!(
                deployment = %d.spec.id,
                sandbox = %b.sandbox_id,
                %subdomain,
                error = %e,
                "could not unbind VM port on the daemon",
            ),
        }
    }

    /// Health-re-probe the fixed upstreams of a static (proxy_pass) deployment.
    ///
    /// A static deployment has no VM lifecycle, but its upstreams can still come
    /// and go. `select` skips backends that `fail_to_connect` marked unhealthy;
    /// this is what brings a recovered upstream back — and what proactively skips
    /// one that is down but hasn't been dialed since. A hostname is re-resolved
    /// each tick, so a name that fails to resolve reads as unhealthy.
    async fn reconcile_static(&self, d: &Arc<Deployment>) {
        for b in d.backends().iter() {
            let healthy = if let Some(gateway) = d.spec.gateway.as_ref()
                .filter(|g| g.mode == crate::gateway::GatewayMode::Forward) {
                crate::gateway::probe(gateway, &b.peer,
                    d.spec.routes[0].host.as_deref().expect("validated gateway host"),
                    &d.spec.health, &self.secrets).await
            } else if b.tls {
                health::probe_https(&b.address, &b.sni, &d.spec.health).await
            } else {
                match tokio::net::lookup_host(&b.address).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => health::probe(addr, &d.spec.health).await,
                        None => false, // resolved to nothing
                    },
                    Err(e) => {
                    tracing::debug!(
                        deployment = %d.spec.id,
                        upstream = %b.peer,
                        error = %e,
                        "static upstream did not resolve; marking unhealthy",
                    );
                    false
                    }
                }
            };
            let was = b.is_healthy();
            b.set_healthy(healthy);
            if was != healthy {
                tracing::info!(
                    deployment = %d.spec.id,
                    upstream = %b.peer,
                    healthy,
                    "static upstream health changed",
                );
                let (title, detail) = if healthy {
                    (
                        format!("{}: upstream recovered", d.spec.id),
                        format!("upstream {} is answering health checks again", b.peer),
                    )
                } else {
                    (
                        format!("{}: upstream unhealthy", d.spec.id),
                        format!("upstream {} stopped answering health checks", b.peer),
                    )
                };
                self.feed.issue(&d.spec, title, detail, now_secs());
            }
        }
    }

    /// Copy the latest per-VM CPU/memory sample onto each live backend.
    fn apply_usage(&self, d: &Arc<Deployment>, usage: &HashMap<String, vm::SandboxUsage>) {
        if usage.is_empty() {
            return;
        }
        for b in d.backends().iter() {
            if let Some(u) = usage.get(&b.sandbox_id) {
                b.set_usage(u.cpu_percent, u.memory_bytes);
            }
        }
    }

    /// Keep long-lived VMs from hitting their TTL backstop.
    ///
    /// The TTL exists so VMs self-destruct if this LB dies without reaping them.
    /// While we *are* alive, renew it past the halfway mark so a healthy VM
    /// under steady traffic doesn't get culled out from under us.
    async fn renew_ttls(&self, d: &Arc<Deployment>, fleet: &HashMap<String, SandboxInfo>) {
        let ttl = d.spec.vm_spec().ttl_seconds;
        for b in d.backends().iter() {
            let Some(info) = fleet.get(&b.sandbox_id) else {
                continue;
            };
            let remaining = info.ttl_seconds.unwrap_or(ttl);
            if info.uptime_secs < remaining / 2 {
                continue;
            }
            if let Err(e) = self.vms().renew_ttl(&b.sandbox_id, ttl).await {
                tracing::warn!(sandbox = %b.sandbox_id, error = %e, "failed to renew TTL");
            }
        }
    }

    /// Drop backends the daemon no longer reports as running.
    ///
    /// This is what catches a VM killed out-of-band: it disappears from the
    /// fleet list, and we stop routing to it.
    fn prune(&self, d: &Arc<Deployment>, fleet: &HashMap<String, SandboxInfo>) {
        let backends = d.backends();
        let kept: Vec<_> = backends
            .iter()
            .filter(|b| match fleet.get(&b.sandbox_id) {
                Some(info) => {
                    let alive = !vm::is_terminal(&info.status);
                    if !alive {
                        tracing::info!(
                            deployment = %d.spec.id,
                            sandbox = %b.sandbox_id,
                            status = ?info.status,
                            "dropping backend: VM is no longer running",
                        );
                    }
                    alive
                }
                None => {
                    tracing::info!(
                        deployment = %d.spec.id,
                        sandbox = %b.sandbox_id,
                        "dropping backend: VM is gone from the daemon",
                    );
                    false
                }
            })
            .cloned()
            .collect();

        if kept.len() != backends.len() {
            d.set_backends(kept);
        }
    }

    /// Move booted VMs into the pool, and say what the rest are waiting on.
    ///
    /// A VM is only promoted when the daemon says `Running`, it has a
    /// `guest_ip`, *and* it answers a probe. The first two are not sufficient:
    /// `wait_for_ready` reports `Ok` for stopped VMs, and `Running` says nothing
    /// about whether the guest's server is listening yet.
    ///
    /// The other half of this function is the case where that never happens. A VM
    /// whose guest boots but whose *server* doesn't — a bad `start_command`, an
    /// env var pointing at a directory that isn't there, a binary that exits — is
    /// `Running` with a `guest_ip` and fails the probe forever. Without the
    /// progress logging and the deadline below, that is completely invisible:
    /// nothing is logged, `min_replicas` is silently never met, and the only
    /// symptom is requests timing out on a cold start that will never end.
    async fn promote_pending(&self, d: &Arc<Deployment>, fleet: &HashMap<String, SandboxInfo>) {
        let pending = d.pending();
        if pending.is_empty() {
            return;
        }

        let boot_timeout = d.spec.scaling.boot_timeout_secs;
        let mut still_pending = Vec::new();
        let mut promoted = Vec::new();
        // Paired with the origin, because by the time these are killed the
        // `PendingVm` that knew where each came from is gone — `set_pending`
        // below keeps only what is still booting.
        let mut doomed: Vec<(String, BootOrigin)> = Vec::new();
        // Sandbox ids of the promoted VMs, for the post-publish ownership check:
        // the probes below are awaits, so this deployment can be replaced while
        // they run, and a VM promoted onto a dropped object is unreachable.
        let mut promoted_ids = Vec::new();

        for p in pending.iter() {
            let Some(info) = fleet.get(&p.sandbox_id) else {
                // Missing from the listing is *not* treated as gone, and this is
                // the fix for an unbounded VM-creation loop that was observed in
                // production: ten sandboxes and ten data disks for a single
                // replica slot, none of them tracked here.
                //
                // The old code dropped the VM on the first miss. That freed the
                // slot — `live = ready + pending` fell below `desired` — so the
                // next tick created a replacement, 2s later, and the tick after
                // that, for as long as the condition lasted. Meanwhile the
                // sandbox it forgot was still the daemon's, still holding a
                // `disk_size_gb` data disk nothing would ever reclaim.
                //
                // Absence is not proof of death: a sandbox still provisioning —
                // copying a multi-gigabyte rootfs onto a loaded host — may not
                // be listed yet. So it keeps its slot for [`MISSING_GRACE`],
                // which is what stops the duplication, and only then is handed
                // to the doomed path, which kills it *before* reclaiming its
                // disks rather than unlinking under a VM that may still exist.
                let now = now_secs();
                if let Some(since) = hold_missing(p.missing_since, now) {
                    if p.missing_since.is_none() {
                        tracing::warn!(
                            deployment = %d.spec.id,
                            sandbox = %p.sandbox_id,
                            age_secs = p.age_secs(),
                            grace_secs = MISSING_GRACE,
                            "pending VM is missing from the daemon's listing; holding its \
                             slot rather than creating a replacement",
                        );
                    }
                    still_pending.push(PendingVm {
                        missing_since: Some(since),
                        ..p.clone()
                    });
                    continue;
                }
                tracing::error!(
                    deployment = %d.spec.id,
                    sandbox = %p.sandbox_id,
                    age_secs = p.age_secs(),
                    missing_secs = now.saturating_sub(p.missing_since.unwrap_or(now)),
                    "pending VM never came back to the daemon's listing; giving up on it",
                );
                doomed.push((p.sandbox_id.clone(), p.origin));
                continue;
            };
            let age = p.age_secs();

            let addr = match vm::routable_addr(info, d.spec.vm_spec().port) {
                Ok(addr) => health::probe(addr, &d.spec.health).await.then_some(addr),
                // Provisioning, or a status the daemon hasn't classified yet.
                Err(vm::VmError::NotRunning { status, .. }) if !vm::is_terminal(&status) => None,
                Err(e) => {
                    // Terminal, or unroutable (no guest_ip). Either way it will
                    // never serve, so stop waiting on it and reclaim the slot.
                    tracing::error!(
                        deployment = %d.spec.id,
                        sandbox = %p.sandbox_id,
                        age_secs = age,
                        error = %e,
                        "giving up on VM",
                    );
                    self.feed.issue(
                        &d.spec,
                        format!("{}: VM failed to boot", d.spec.id),
                        format!("gave up on VM {} after {age}s: {e}", p.sandbox_id),
                        now_secs(),
                    );
                    doomed.push((p.sandbox_id.clone(), p.origin));
                    continue;
                }
            };

            if let Some(addr) = addr {
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %p.sandbox_id,
                    %addr,
                    boot_secs = age,
                    "VM ready",
                );
                self.metrics.record_cold_start(&d.spec.id, age);
                promoted_ids.push(p.sandbox_id.clone());
                promoted.push(Arc::new(VmBackend::new(p.sandbox_id.clone(), addr)));
                continue;
            }

            // Still booting. Either it gets a deadline or it gets a heartbeat,
            // but it does not get silence.
            if boot_timeout > 0 && age >= boot_timeout {
                // Fetched *before* the kill below, because the daemon's capture
                // buffer belongs to the sandbox and goes when it does. This is
                // the last moment the guest can say why it never came up, and
                // for a long time this line reported the whole failure without
                // it: `waiting_on` says the server never answered, and the
                // reason the server never answered was sitting in a ring buffer
                // that app-lb then threw away with the VM.
                let guest_log = self
                    .vms()
                    .guest_log_tail(&p.sandbox_id, GUEST_LOG_LINES)
                    .await;
                tracing::error!(
                    deployment = %d.spec.id,
                    sandbox = %p.sandbox_id,
                    age_secs = age,
                    boot_timeout_secs = boot_timeout,
                    status = ?info.status,
                    waiting_on = %boot_stall(info, &d.spec.health, d.spec.vm_spec().port),
                    guest_log = guest_log.as_deref().unwrap_or(
                        "unavailable — the daemon captured no output for this sandbox. A guest \
                         with no socat or /dev/vsock never starts the forwarders heyvmd \
                         collects it through, and its output stays in the guest's own \
                         /var/log/heyvm-start.err.log",
                    ),
                    "VM never became ready inside its boot timeout; killing it so the pool \
                     can try again",
                );
                self.metrics.record_boot_timeout(&d.spec.id);
                self.feed.issue(
                    &d.spec,
                    format!("{}: VM failed to boot", d.spec.id),
                    format!(
                        "VM {} never became ready inside its {boot_timeout}s boot timeout",
                        p.sandbox_id
                    ),
                    now_secs(),
                );
                doomed.push((p.sandbox_id.clone(), p.origin));
                continue;
            }
            still_pending.push(self.note_boot_progress(d, p, info, age));
        }

        d.set_pending(still_pending);

        if !promoted.is_empty() {
            let mut backends = (*d.backends()).clone();
            backends.extend(promoted);
            d.set_backends(backends);
            // Release anything blocked on a cold start.
            d.ready_signal.notify_waiters();
            // A boot made it all the way to healthy, so the image works; any
            // failure streak ends here rather than being aged out.
            if d.note_boot_success() {
                tracing::info!(
                    deployment = %d.spec.id,
                    "a VM became ready; clearing the boot-failure backoff",
                );
            }
        } else if !doomed.is_empty() {
            // Only when *nothing* was promoted this tick: a doomed sibling next
            // to a successful boot is capacity noise, not a broken image, and
            // must not delay its replacement. Counted per VM, so a warm pool
            // failing wholesale backs off faster than one flaky boot.
            let now = now_secs();
            let (mut failures, mut delay) = (0, 0);
            for _ in &doomed {
                (failures, delay) = d.note_boot_failure(now);
            }
            tracing::warn!(
                deployment = %d.spec.id,
                doomed = doomed.len(),
                consecutive_failures = failures,
                backoff_secs = delay,
                "backing off VM creation after failed boots; without this the next tick \
                 replaces the VM immediately, and a guest that can never become ready \
                 churns a fresh sandbox per cycle forever",
            );
        }

        for (id, origin) in doomed {
            // A resumed replica of a workspace deployment holds the
            // deployment's state; give the capture a chance before it goes.
            // A fresh one that never came up holds nothing worth keeping.
            if Self::has_workspace(d) {
                if origin == BootOrigin::Created {
                    self.workspaces.forget(&d.spec.id, &id);
                } else {
                    self.kill_or_capture(d, &id, "failed resume").await;
                    continue;
                }
            }
            match self.kill_vm(d, &id).await {
                // The kill is what makes reclamation safe: the disks below are
                // only unlinked once the daemon says the hypervisor holding
                // them is gone.
                Ok(()) => self.discard_failed_boot_of(d, &id, origin).await,
                Err(e) => {
                    // Deliberately no reclamation on this path. The VM may well
                    // still be running — a timed-out or refused delete says
                    // nothing either way — and unlinking a live Firecracker's
                    // backing files is worse than the leak. The disk sweep is
                    // the backstop, and it is safe there because it re-checks
                    // the fleet listing first.
                    tracing::warn!(
                        sandbox = %id,
                        error = %e,
                        "failed to kill doomed VM; leaving its disks for the sweep rather \
                         than unlinking them under a VM that may still be running",
                    );
                }
            }
        }

        // A promotion moves a VM out of `pending` and into `backends`; if the
        // deployment was replaced between those two stores, the replacement
        // inherited neither and the VM is now tracked nowhere.
        self.kill_unclaimed(d, &promoted_ids).await;
    }

    /// Log a still-booting VM's progress when there is something new to say, and
    /// return it with the bookkeeping for the next tick.
    ///
    /// "Something new" is a status transition or [`BOOT_HEARTBEAT`] elapsed —
    /// a line per pending VM per 2s tick would drown the log it is meant to make
    /// readable, and a warm pool booting normally has nothing to report. The first
    /// sighting always logs, because until then nothing anywhere has named this
    /// sandbox id: `scale_up` only counts what it created.
    fn note_boot_progress(
        &self,
        d: &Arc<Deployment>,
        p: &PendingVm,
        info: &SandboxInfo,
        age: u64,
    ) -> PendingVm {
        // `missing_since` is cleared unconditionally: reaching here means this
        // VM was in the listing this tick, so any earlier absence was the
        // transient the grace window exists to absorb, and a later one starts
        // its own window rather than inheriting a stale timestamp.
        let next = PendingVm {
            status: Some(info.status.clone()),
            missing_since: None,
            ..p.clone()
        };
        let changed = p.status.as_ref() != Some(&info.status);
        if !changed && age.saturating_sub(p.reported_at_secs) < BOOT_HEARTBEAT {
            return next;
        }

        // Past the request budget this boot has already cost somebody a 503, so
        // it stops being routine progress.
        if age >= d.spec.scaling.cold_start_timeout_secs {
            tracing::warn!(
                deployment = %d.spec.id,
                sandbox = %p.sandbox_id,
                age_secs = age,
                status = ?info.status,
                waiting_on = %boot_stall(info, &d.spec.health, d.spec.vm_spec().port),
                "VM is taking longer to boot than a request will wait for",
            );
        } else {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %p.sandbox_id,
                age_secs = age,
                status = ?info.status,
                waiting_on = %boot_stall(info, &d.spec.health, d.spec.vm_spec().port),
                "VM is still booting",
            );
        }
        PendingVm {
            reported_at_secs: age,
            ..next
        }
    }

    /// Recover only the saved operation, never re-POST or infer an ID by name.
    /// A receipt reserves capacity even when the daemon has not started it yet.
    async fn recover_allocations(&self, d: &Arc<Deployment>, fleet: &HashMap<String, SandboxInfo>) {
        let Some(_change) = self.registry.try_change_guard() else { return; };
        if !self.is_live(d) { return; }
        for (index, attempt) in d.state().create_attempts.clone().iter().enumerate() {
            let Some(intent) = &attempt.allocation else { continue; };
            if attempt.runtime_observed { continue; }
            let receipt = match &attempt.receipt {
                Some(receipt) if intent.transport == self.vms().transport() && intent.accepts(receipt) => receipt.clone(),
                _ => match self.vms().recover_allocation(intent).await {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        tracing::warn!(deployment=%d.spec.id, operation=%intent.operation_id, %error, "allocation remains unresolved");
                        continue;
                    }
                },
            };
            let id = receipt.sandbox_id.clone();
            if attempt.sandbox_id.as_ref().is_some_and(|saved| saved != &id) {
                tracing::error!(deployment=%d.spec.id, operation=%intent.operation_id, "allocation receipt changed sandbox identity");
                continue;
            }
            let observed = fleet.get(&id).is_some_and(|info| info.status == heyo_sdk::SandboxStatus::Running);
            d.mutate_state(|s| {
                let saved = &mut s.create_attempts[index];
                saved.sandbox_id = Some(id.clone());
                saved.receipt = Some(receipt);
                saved.runtime_observed = observed;
            });
            if self.registry.persist_one(&d.spec.id).is_err() {
                d.mutate_state(|s| s.create_attempts[index] = attempt.clone());
                continue;
            }
            if d.spec.vm_spec().workspace.is_some() {
                self.workspaces.note_seeded(&d.spec.id, &id, attempt.seed_digest.clone(), attempt.seed_mount_index);
            }
            if !d.backends().iter().any(|b| b.sandbox_id == id)
                && !d.pending().iter().any(|p| p.sandbox_id == id)
                && !d.state().suspended.contains(&id) {
                let mut pending = (*d.pending()).clone();
                pending.push(PendingVm::new(id));
                d.set_pending(pending);
            }
        }
    }

    async fn allocate_replica(&self, d: &Arc<Deployment>, name: String,
        seed: Option<&vm::WorkspaceSeed>, seed_digest: Option<String>, owner: &vm::VmOwner,
    ) -> Result<String, vm::VmError> {
        let secret_env = self.secret_env(d.spec.vm_spec())?;
        let prepared = if d.spec.vm_spec().correlated_creates {
            let request = self.vms().prepare_create(d.spec.vm_spec(), name.clone(), seed, owner, secret_env.clone()).await?;
            Some(self.vms().prepare_allocation(&request, &format!("{}:{}:{}", d.spec.namespace, d.spec.id, d.state().rollout_revision))?)
        } else { None };
        let attempt = d.state().create_attempts.len();
        let history_was_complete = d.state().allocation_history_complete;
        d.mutate_state(|s| {
            if prepared.is_none() { s.allocation_history_complete = false; }
            s.create_attempts.push(crate::retirement::CreateAttempt {
                name:name.clone(), allocation:prepared.as_ref().map(|p| p.intent.clone()),
                seed_digest, seed_mount_index:d.spec.vm_spec().mounts.len(), ..Default::default()
            });
        });
        self.registry.persist_one(&d.spec.id).map_err(|_| vm::VmError::Runtime("cannot persist allocation intent".into()))?;
        let attempt_name = name.clone();
        let result = match prepared {
            Some(prepared) => self.vms().submit_allocation(&prepared).await.map(|r| (r.sandbox_id.clone(), Some(r))),
            None => self.runtime.create(d.spec.vm_spec(), name, seed, owner, secret_env).await.map(|id| (id,None)),
        };
        match result {
            Ok((id, receipt)) => {
                d.mutate_state(|s| { s.create_attempts[attempt].sandbox_id=Some(id.clone()); s.create_attempts[attempt].receipt=receipt.clone(); });
                if self.registry.persist_one(&d.spec.id).is_err() {
                    d.mutate_state(|s| { s.create_attempts[attempt].sandbox_id=None; s.create_attempts[attempt].receipt=None; });
                    return Err(vm::VmError::Runtime("cannot persist allocation receipt".into()));
                }
                self.settle_in_successor(d, |attempts| {
                    if let Some(a) = attempts.iter_mut().find(|a| a.name == attempt_name && a.sandbox_id.is_none()) {
                        a.sandbox_id = Some(id.clone());
                        a.receipt = receipt.clone();
                    }
                });
                Ok(id)
            }
            Err(error) => {
                if matches!(error, vm::VmError::SecretUnresolved {..} | vm::VmError::MountNotPulled {..}
                    | vm::VmError::WrongRuntime {..} | vm::VmError::RuntimeUnavailable {..}) {
                    d.mutate_state(|s| { s.create_attempts.remove(attempt); s.allocation_history_complete=history_was_complete; });
                    let _ = self.registry.persist_one(&d.spec.id);
                    self.settle_in_successor(d, |attempts| {
                        attempts.retain(|a| !(a.name == attempt_name && a.sandbox_id.is_none()));
                    });
                }
                Err(error)
            }
        }
    }

    /// Apply a create's outcome to the deployment's successor, if it has one.
    ///
    /// A rollover — an image pull or build landing, a spec edit — replaces the
    /// deployment object through `Registry::upsert`, which copies
    /// `create_attempts` into the new object while this create is still
    /// awaiting the daemon. The outcome is recorded on the object that started
    /// the create; unless it also lands in the successor, the successor keeps
    /// an attempt with no sandbox id, and `scale_up` refuses to create while
    /// one exists — so the pool stays empty, silently, until a restart. Only
    /// known outcomes are carried over: an attempt whose result is genuinely
    /// unknown still blocks until `recover_allocations` resolves it.
    fn settle_in_successor(
        &self,
        d: &Arc<Deployment>,
        settle: impl FnOnce(&mut Vec<crate::retirement::CreateAttempt>),
    ) {
        let Some(live) = self.registry.get(&d.spec.id) else { return };
        if Arc::ptr_eq(&live, d) {
            return;
        }
        live.mutate_state(|s| settle(&mut s.create_attempts));
        if let Err(e) = self.registry.persist_one(&d.spec.id) {
            tracing::warn!(deployment = %d.spec.id, error = %e, "could not persist a create outcome carried to the replacement deployment");
        }
    }

    async fn scale_up(&self, d: &Arc<Deployment>, count: usize) {
        let _change = if d.spec.vm_spec().correlated_creates {
            let Some(guard) = self.registry.try_change_guard() else { return; };
            Some(guard)
        } else { None };
        if !self.is_live(d) || d.state().create_attempts.iter().any(|a|a.sandbox_id.is_none()) {return;}
        // A VM is created only once its image is on heyvm: a missing one is
        // pulled or thawed first, instead of booting heyvm's default image.
        if let Some(images) = self.images.get()
            && !images.ensure_image(d).await
        {
            return;
        }
        tracing::info!(deployment = %d.spec.id, count, "scaling up");
        // Keep the slot until the resulting pending pool has been published,
        // not just until the daemon answered. A replacement draining these
        // slots must see every VM it needs to retire before exposing a new pool.
        let _permit = self.creates.acquire().await;
        let mut pending = (*d.pending()).clone();
        let mut created = Vec::new();

        for _ in 0..count {
            // Each create is a slow await, so re-check between boots: an admin
            // request can have deregistered this deployment since the last one,
            // and every further VM would be born abandoned.
            if !self.is_live(d) {
                tracing::info!(
                    deployment = %d.spec.id,
                    "deployment is no longer registered; stopping scale-up",
                );
                break;
            }

            // A workspace deployment boots from its last capture, so while a
            // capture or restore is in flight there is nothing correct to boot
            // from. Not a failure and not backed off: the worker nudges the
            // scale signal when the tree is ready.
            let seeded = match self.workspaces.seed_for_create(d) {
                Ok(seeded) => seeded,
                Err(why) => {
                    tracing::info!(deployment = %d.spec.id, "not creating a replica yet: {why}");
                    break;
                }
            };

            // A suspended sandbox is preferred over a fresh one, and not just to
            // save a boot: it *is* the deployment's state. Creating a new VM
            // while one sits stopped would strand that VM's `/workspace` disk
            // and hand the caller an empty sandbox in its place.
            if let Some(sandbox_id) = self.take_suspended(d) {
                match self.vms().resume(&sandbox_id).await {
                    Ok(_) => {
                        tracing::info!(
                            deployment = %d.spec.id,
                            sandbox = %sandbox_id,
                            "resumed suspended VM",
                        );
                        created.push(sandbox_id.clone());
                        self.workspaces.note_resumed(&d.spec.id, &sandbox_id);
                        // `resumed`, not `new`: this sandbox's data disk is the
                        // deployment's retained state, so if the boot never
                        // finishes the give-up path must not reclaim it.
                        pending.push(PendingVm::resumed(sandbox_id));
                        continue;
                    }
                    Err(e) => {
                        // It is already forgotten, so it will not be resumed
                        // again. Kill it rather than leave it stopped forever
                        // holding a disk nothing tracks.
                        tracing::warn!(
                            deployment = %d.spec.id,
                            sandbox = %sandbox_id,
                            error = %e,
                            "failed to resume suspended VM; destroying it and booting a fresh one",
                        );
                        if let Err(e) = self.kill_vm(d, &sandbox_id).await {
                            tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill VM");
                        }
                    }
                }
            }

            let name = d.state().active_prefix.as_ref().map(|p| format!("{p}{:016x}", self.next_nonce()))
                .unwrap_or_else(|| vm::replica_name(&d.spec.id, self.next_nonce()));
            let seed = seeded.as_ref().map(|s| s.seed());
            let owner = vm::VmOwner::of(&d.spec);
            let created_vm = self.allocate_replica(d, name, seed.as_ref(),
                seeded.as_ref().and_then(|s| s.digest.clone()), &owner).await;
            match created_vm {
                Ok(sandbox_id) => {
                    if let Some(seeded) = &seeded {
                        self.workspaces.note_seeded(
                            &d.spec.id,
                            &sandbox_id,
                            seeded.digest.clone(),
                            d.spec.vm_spec().mounts.len(),
                        );
                    }
                    created.push(sandbox_id.clone());
                    pending.push(PendingVm::new(sandbox_id));
                }
                Err(e) => {
                    tracing::error!(deployment = %d.spec.id, error = %e, "failed to create VM");
                    // Counted *and* kept verbatim. Before this the only trace of
                    // a refused create was this log line, so a pool stuck at
                    // `ready: 0` showed `vms_created: 0, scale_up_events: 0,
                    // boot_timeouts: 0` — three zeroes that read as "idle" and
                    // sent every investigation to the guest image, which in this
                    // failure mode never runs at all.
                    self.metrics.record_create_failure(&d.spec.id, &e.to_string());
                    self.feed.issue(
                        &d.spec,
                        format!("{}: VM create failed", d.spec.id),
                        // A missing mount tree is refused *here*, before the
                        // daemon is asked anything, so blaming the daemon for it
                        // would send the reader to the wrong host's logs. Both
                        // are still create failures, and both are counted: a
                        // deployment whose mounts never land is exactly the
                        // silent `ready: 0` this metric exists to explain.
                        match &e {
                            crate::vm::VmError::MountNotPulled { .. }
                            | crate::vm::VmError::SecretUnresolved { .. } => {
                                format!("this deployment cannot boot yet: {e}")
                            }
                            _ => format!("the VM daemon refused to create a VM: {e}"),
                        },
                        now_secs(),
                    );
                    // The same embargo a failed *boot* earns, for the same
                    // reason. `break` alone only ends this tick, and the next
                    // one is 2s away: a daemon that is down, out of disk or
                    // rejecting this spec turns into a create attempt every 2s
                    // for as long as it stays broken, each one logged and fed.
                    // A refused create is also the cheapest failure to repeat,
                    // which is exactly why it needs the embargo the most.
                    let (failures, delay) = d.note_boot_failure(now_secs());
                    tracing::warn!(
                        deployment = %d.spec.id,
                        consecutive_failures = failures,
                        backoff_secs = delay,
                        "backing off VM creation after a refused create",
                    );
                    break; // daemon is unhappy; don't hammer it this tick
                }
            }
        }

        // Record only VMs the daemon actually accepted, so the dashboard's
        // create count matches what booted rather than what was attempted.
        self.metrics.record_scale_up(&d.spec.id, created.len() as u64);

        // Publish *before* the ownership check, never after: a pool-preserving
        // edit copies whatever is visible here, so anything already published is
        // safely inherited and must not be killed. Whatever the replacement did
        // not take, `kill_unclaimed` reaps.
        d.set_pending(pending);
        self.kill_unclaimed(d, &created).await;
    }

    /// Retire surplus VMs, most-idle first, by marking them draining.
    ///
    /// Draining stops new requests without cutting off in-flight ones; the
    /// actual kill happens in `reap_drained` once they finish.
    async fn scale_down(&self, d: &Arc<Deployment>, count: usize) {
        let backends = d.backends();
        let mut candidates: Vec<_> = backends
            .iter()
            .filter(|b| !b.is_draining())
            .cloned()
            .collect();
        // Prefer idle VMs so draining finishes quickly.
        candidates.sort_by_key(|b| (b.in_flight(), b.last_active()));

        let mut drained = 0u64;
        for b in candidates.iter().take(count) {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %b.sandbox_id,
                in_flight = b.in_flight(),
                "draining VM",
            );
            b.set_draining(true);
            drained += 1;
        }
        self.metrics.record_scale_down(&d.spec.id, drained);
    }

    /// Kill drained VMs, and force-kill any that overstay the drain deadline.
    async fn reap_drained(&self, d: &Arc<Deployment>) {
        let backends = d.backends();
        let deadline = d.spec.scaling.drain_timeout_secs;

        let (done, keep): (Vec<_>, Vec<_>) = backends.iter().cloned().partition(|b| {
            if !b.is_draining() {
                return false;
            }
            let idle = b.in_flight() == 0;
            let expired = now_secs().saturating_sub(b.last_active()) >= deadline;
            if !idle && expired {
                tracing::warn!(
                    deployment = %d.spec.id,
                    sandbox = %b.sandbox_id,
                    in_flight = b.in_flight(),
                    "drain deadline exceeded; killing VM with requests in flight",
                );
            }
            idle || expired
        });

        if done.is_empty() {
            return;
        }
        d.set_backends(keep);

        self.metrics.record_reaped(&d.spec.id, done.len() as u64);
        let retain = d.spec.scaling.idle_action == IdleAction::Retain;
        let mut suspended = Vec::new();
        for b in done {
            // Normally already withdrawn by `reconcile_ingress` the tick the
            // drain began; this is for a VM drained and reaped in one tick.
            self.unbind(d, &b).await;
            if Self::has_workspace(d) {
                // Stopped and queued for capture. What happens afterwards —
                // kept suspended for `retain`, or destroyed — is the worker's
                // to do once the tree is out; recording it as suspended now
                // would let the next tick resume it mid-capture.
                let then = if retain { Then::Suspend } else { Then::Kill };
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %b.sandbox_id,
                    ?then,
                    "retiring VM for workspace capture",
                );
                if let Err(e) = self.workspaces.retire(d, &b.sandbox_id, then).await {
                    tracing::warn!(
                        deployment = %d.spec.id,
                        sandbox = %b.sandbox_id,
                        error = %e,
                        "could not stop the VM for capture; it is still running and will be \
                         adopted and drained again next tick",
                    );
                }
                continue;
            }
            if retain {
                tracing::info!(deployment = %d.spec.id, sandbox = %b.sandbox_id, "suspending VM");
                match self.vms().suspend(&b.sandbox_id).await {
                    // Recorded only on success. A sandbox we failed to stop is
                    // still running and still in the fleet list, so recording it
                    // as suspended would make the next tick skip a live VM.
                    Ok(()) => {
                        // The rootfs copy is dead weight while the VM sleeps:
                        // a replica's real state lives on its /workspace data
                        // disk, and the daemon recreates a missing rootfs from
                        // the base image on resume. Discarded now rather than
                        // parked — a KVM replica's copy is ~1 GiB, held for
                        // however long the deployment stays scaled to zero.
                        self.discard_rootfs_of(d, &b.sandbox_id).await;
                        suspended.push(b.sandbox_id.clone());
                    }
                    Err(e) => {
                        tracing::warn!(
                            deployment = %d.spec.id,
                            sandbox = %b.sandbox_id,
                            error = %e,
                            "failed to suspend VM; killing it instead so it cannot leak",
                        );
                        if let Err(e) = self.kill_vm(d, &b.sandbox_id).await {
                            tracing::warn!(sandbox = %b.sandbox_id, error = %e, "failed to kill VM");
                        }
                    }
                }
            } else {
                tracing::info!(deployment = %d.spec.id, sandbox = %b.sandbox_id, "killing VM");
                if let Err(e) = self.kill_vm(d, &b.sandbox_id).await {
                    tracing::warn!(sandbox = %b.sandbox_id, error = %e, "failed to kill VM");
                }
            }
        }
        self.remember_suspended(d, suspended);
    }

    /// Drop the rootfs copy of a replica the autoscaler just suspended.
    ///
    /// Autoscale replicas only: this runs on `applb-*` sandboxes retired by
    /// `reap_drained`, never on a sandbox somebody made by hand — a person's
    /// stopped VM may well be *about* its rootfs, and the daemon deliberately
    /// preserves it for them. A pool replica's contract is the opposite
    /// (persistent state lives under `/workspace`, the rootfs is rebuilt from
    /// the image), so keeping its copy through a suspend buys nothing but the
    /// gigabyte it occupies.
    ///
    /// Best-effort: a failure leaves the copy where it was, which is exactly
    /// what happened before this existed, and the resume path does not care
    /// either way.
    async fn discard_rootfs_of(&self, d: &Arc<Deployment>, sandbox_id: &str) {
        if self.workspaces.source_retained(sandbox_id) { return; }
        let (removed, failed) = crate::disks::discard_rootfs(self.vms(), sandbox_id).await;
        if !removed.is_empty() {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                removed = removed.len(),
                "discarded the suspended VM's rootfs copy; the daemon rebuilds it from \
                 the base image on resume",
            );
        }
        if !failed.is_empty() {
            tracing::warn!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                detail = %failed.join("; "),
                "could not discard a suspended VM's rootfs copy; it stays until the \
                 sandbox is resumed or purged",
            );
        }
    }

    /// Reclaim the disks of a VM the pool has given up on.
    ///
    /// The counterpart of [`discard_rootfs_of`](Self::discard_rootfs_of) for
    /// boots that never finished, and the reason [`BootOrigin`] exists: this
    /// takes the `/workspace` data disk too, so it runs for
    /// [`BootOrigin::Created`] only. A resumed replica is returned to the
    /// caller untouched — its data disk is the state the pool suspended it to
    /// keep, and a resume can fail for reasons that have nothing to do with
    /// what is on it (a daemon restart, a full host, a transient refusal).
    ///
    /// What this fixes: a deployment that cannot boot used to kill each failed
    /// VM and move on, and every attempt left a rootfs copy and a data disk
    /// behind. With `disk_size_gb: 60` and a preallocated data disk, a guest
    /// whose `start_command` does not exist bought 60 GB per attempt until the
    /// seven-day sweep — while the backoff below kept it attempting.
    ///
    /// Best-effort by design: a failure here leaves exactly what was left
    /// before this existed, and [`DiskStore::sweep`](crate::disks::DiskStore)
    /// still catches it later.
    async fn discard_failed_boot_of(
        &self,
        d: &Arc<Deployment>,
        sandbox_id: &str,
        origin: BootOrigin,
    ) {
        if self.workspaces.source_retained(sandbox_id) { return; }
        if origin != BootOrigin::Created {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                "keeping the disks of a resumed replica that failed to come up; its \
                 /workspace is the deployment's retained state",
            );
            return;
        }
        let (removed, failed) = crate::disks::discard_failed_boot(self.vms(), sandbox_id).await;
        if !removed.is_empty() {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                removed = removed.len(),
                "reclaimed the disks of a VM that never came up",
            );
        }
        if !failed.is_empty() {
            tracing::warn!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                detail = %failed.join("; "),
                "could not reclaim the disks of a VM that never came up; they stay until \
                 the disk sweep reclaims them",
            );
        }
    }

    /// Record sandboxes we stopped, and persist that immediately.
    ///
    /// Immediately, and not on some later flush, because between the stop and
    /// the write this id exists in exactly one place: memory. The daemon drops a
    /// stopped sandbox from `GET /sandboxes`, so a crash in that window leaves a
    /// VM holding a disk that nothing knows to resume or reap.
    fn remember_suspended(&self, d: &Arc<Deployment>, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let changed = d.mutate_state(|s| {
            for id in ids {
                if !s.suspended.contains(&id) {
                    s.suspended.push(id);
                }
            }
        });
        if changed && let Err(e) = self.registry.persist_one(&d.spec.id) {
            tracing::error!(
                deployment = %d.spec.id,
                error = %e,
                "failed to persist suspended sandboxes; they may be leaked on restart",
            );
        }
    }

    /// Forget a sandbox we suspended — it has been resumed, or destroyed.
    fn forget_suspended(&self, d: &Arc<Deployment>, sandbox_id: &str) {
        let changed = d.mutate_state(|s| s.suspended.retain(|id| id != sandbox_id));
        if changed && let Err(e) = self.registry.persist_one(&d.spec.id) {
            tracing::error!(deployment = %d.spec.id, error = %e, "failed to persist state");
        }
    }

    /// Claim the oldest suspended sandbox, removing it from the record.
    ///
    /// Claimed *before* the resume rather than after, so two concurrent
    /// scale-ups cannot both try to start the same VM. The cost of that choice
    /// is that a failed resume has already been forgotten, which is why
    /// `scale_up` kills it rather than leaving it stopped and untracked.
    fn take_suspended(&self, d: &Arc<Deployment>) -> Option<String> {
        let mut taken = None;
        let changed = d.mutate_state(|s| {
            if let Some(index) = s.suspended.iter().position(|id| !self.workspaces.recovery_pinned(id)) {
                taken = Some(s.suspended.remove(index));
            }
        });
        if changed && let Err(e) = self.registry.persist_one(&d.spec.id) {
            tracing::error!(deployment = %d.spec.id, error = %e, "failed to persist state");
        }
        taken
    }

    /// Reclaim or destroy stopped sandboxes of ours that no deployment claims.
    ///
    /// The backstop for `idle_action: retain`. A stopped sandbox is invisible to
    /// every other mechanism here — it is absent from the fleet list, so `prune`
    /// and `adopt_existing` cannot see it, and its TTL does not run while it is
    /// stopped. If the record of it is lost (a crash between the stop and the
    /// state write, a state file deleted by hand), it keeps its disk forever with
    /// nothing to reclaim it.
    ///
    /// Unclaimed does not mean unwanted. A `retain` deployment that finds one of
    /// its own stopped sandboxes here has, by definition, lost track of a VM it
    /// asked to keep — and destroying it means the next scale-up creates a *new*
    /// sandbox, with a new id, a new directory under the daemon's data dir and a
    /// fresh rootfs, while the old one's disks stay on the host forever. So it is
    /// taken back into `state.suspended` instead, up to `max_replicas`, and only
    /// the surplus is destroyed. Reclaiming is deliberately limited to `retain`:
    /// under `destroy` a stopped sandbox is one this LB already decided it did
    /// not want.
    ///
    /// A reclaimed sandbox is matched by *name*, exactly as `adopt_existing`
    /// matches a running one, so it can predate an image change the same way an
    /// adopted running VM can. The `update` path guards that case for both: a
    /// changed `VmSpec` tears the pool down instead of preserving it.
    ///
    /// Only sandboxes named `applb-<deployment>-<nonce>` are touched, and only
    /// when their deployment either does not exist or does not list them. A
    /// sandbox somebody else made is never destroyed.
    pub(crate) async fn sweep_suspended(&self) {
        let _retirement = self.registry.retirement_gate.read().await;
        let _rollout = self.rollout_gate.read().await;
        // Both listings, because *where* a stopped sandbox turns up depends on
        // the backend. mvm-ctrl re-adds every persisted **KVM** sandbox to
        // `GET /sandboxes` on each call, so a stopped one appears there with
        // status `Stopped` — and is therefore excluded from the inactive
        // listing, which subtracts whatever the active list holds. A stopped
        // **Firecracker** sandbox is the other way round: absent from the fleet
        // list, present in the inactive one. Reading only one would sweep half
        // the fleet and silently ignore the other.
        let fleet = match self.vms().list().await {
            Ok(list) => list,
            Err(e) => {
                tracing::debug!(error = %e, "no fleet list; skipping the suspended sweep");
                return;
            }
        };
        let inactive = match self.vms().list_inactive().await {
            Ok(list) => list,
            Err(e) => {
                // `warn`, not `debug`: this is the only backstop for a stopped
                // sandbox nothing claims, and it is invisible when it is not
                // running. A daemon that answers this call with a payload the
                // client cannot parse switches the backstop off silently, which
                // is exactly how it went unnoticed before.
                tracing::warn!(
                    error = %e,
                    "could not list inactive sandboxes; the suspended-VM sweep is not running, \
                     so stopped VMs no deployment claims will not be reclaimed",
                );
                return;
            }
        };

        let deployments = self.registry.deployments();

        // Everything of ours the daemon does not report as running, from either
        // listing. A *running* VM is out of scope here: `adopt_existing` and
        // `kill_unclaimed` own that case, and killing one on this path would
        // race them.
        let stopped = inactive
            .iter()
            .chain(fleet.iter().filter(|i| vm::is_terminal(&i.status)));

        let mut orphans: Vec<(String, String)> = Vec::new();
        // Candidates for reclaim, grouped so each deployment's budget is applied
        // once rather than per sandbox. Ordered, so which ones survive the cap is
        // stable across ticks instead of depending on hash iteration order.
        let mut reclaimable: Vec<(String, Vec<String>)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for info in stopped {
            if self.registry.allocation_protects(&info.id) {continue;}
            if self.registry.retirement_protects(&info.id,vm::owner_of(&info.name)) || self.workspaces.retirement_protects(&info.id) {continue;}
            let Some(owner) = vm::owner_of(&info.name) else {
                continue; // not ours
            };
            // The two listings overlap for KVM; count each sandbox once.
            if !seen.insert(info.id.clone()) {
                continue;
            }
            let d = deployments.get(owner);
            // Named for a deployment this LB does not have (or one that no
            // longer owns VMs): not this sweep's to destroy. `leave_unowned`
            // documents why; the disk sweep's TTL reclaims it.
            if !d.is_some_and(|d| d.spec.is_managed()) {
                continue;
            }
            if d.is_some_and(|d| crate::rollout::protected_ids(&d.state()).any(|id| id == &info.id)
                || d.state().rollouts.iter().any(|o| info.name.starts_with(&o.prefix))) { continue; }
            if d.is_some_and(|d| d.state().suspended.contains(&info.id)) {
                continue; // claimed: nothing to decide
            }
            // A stopped VM of a workspace deployment is either waiting for its
            // capture, or is one the capture refused (an older lineage) and
            // kept for a person. Neither is this sweep's to resume or destroy.
            if d.is_some_and(|d| Self::has_workspace(d) && self.workspaces.holds(owner, &info.id))
            {
                continue;
            }
            if d.is_some_and(|d| d.spec.is_managed() && d.spec.scaling.idle_action == IdleAction::Retain)
            {
                match reclaimable.iter_mut().find(|(o, _)| o == owner) {
                    Some((_, ids)) => ids.push(info.id.clone()),
                    None => reclaimable.push((owner.to_string(), vec![info.id.clone()])),
                }
            } else {
                orphans.push((info.id.clone(), owner.to_string()));
            }
        }

        for (owner, ids) in reclaimable {
            let Some(d) = deployments.get(owner.as_str()) else {
                continue;
            };
            let budget = reclaim_budget(d);
            let take = ids.len().min(budget);
            let (keep, surplus) = ids.split_at(take);
            if !keep.is_empty() {
                tracing::info!(
                    deployment = %owner,
                    count = keep.len(),
                    "reclaiming stopped VMs this LB had lost track of; the next scale-up \
                     resumes these instead of creating new sandboxes",
                );
                self.remember_suspended(d, keep.to_vec());
                // The same trim a fresh suspend gets: these were spun down by a
                // previous run (or out of band), so their rootfs copies are
                // sitting exactly as unused as a just-suspended replica's.
                for id in keep {
                    self.discard_rootfs_of(d, id).await;
                }
            }
            for id in surplus {
                tracing::info!(
                    deployment = %owner,
                    sandbox = %id,
                    max_replicas = d.spec.scaling.max_replicas,
                    "more stopped VMs than this deployment may hold; destroying the surplus",
                );
                orphans.push((id.clone(), owner.clone()));
            }
        }

        for (sandbox_id, owner) in &orphans {
            if self.registry.allocation_protects(sandbox_id) { continue; }
            if self.workspaces.source_retained(sandbox_id) { continue; }
            tracing::warn!(deployment = %owner, sandbox = %sandbox_id, "destroying unclaimed suspended VM");
            if let Err(e) = self.runtime.kill_unknown(sandbox_id).await {
                tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill suspended VM");
            }
        }

        // And the other direction: ids we still think are suspended that the
        // daemon has no record of at all — deleted out of band, or lost with the
        // host's state. Left in place they would cost a doomed resume attempt on
        // every scale-up.
        let known: HashSet<&str> = inactive
            .iter()
            .chain(fleet.iter())
            .map(|i| i.id.as_str())
            .collect();
        for d in deployments.values() {
            let stale: Vec<String> = d
                .state()
                .suspended
                .iter()
                .filter(|id| !known.contains(id.as_str()))
                .cloned()
                .collect();
            for id in stale {
                tracing::warn!(
                    deployment = %d.spec.id,
                    sandbox = %id,
                    "forgetting a suspended VM the daemon no longer has",
                );
                self.forget_suspended(d, &id);
            }
        }
    }

    /// Adopt VMs from a previous run of this LB.
    ///
    /// Without this, a restart would leave old VMs running while booting a fresh
    /// set — the orphans would only die when their TTL expired.
    pub async fn adopt_existing(&self) {
        let _retirement = self.registry.retirement_gate.read().await;
        let _rollout = self.rollout_gate.read().await;
        let fleet = match self.vms().list().await {
            Ok(list) => list,
            Err(e) => {
                tracing::error!(error = %e, "could not list sandboxes for adoption");
                return;
            }
        };

        let deployments = self.registry.deployments();
        let mut adopted: HashMap<String, Vec<Arc<VmBackend>>> = HashMap::new();
        // Replicas of a deployment this LB still has: unroutable or unhealthy,
        // so destroyed and replaced exactly as before.
        let mut orphans = Vec::new();
        // Sandboxes named for a deployment this LB does *not* have. Stopped,
        // never destroyed — see `leave_unowned`.
        let mut unowned = Vec::new();

        let indexed = vm::index_by_id(fleet.clone());
        for d in deployments.values().filter(|d| d.spec.is_managed()) {
            self.recover_allocations(d, &indexed).await;
        }
        for info in &fleet {
            if self.registry.allocation_protects(&info.id) { continue; }
            if self.registry.retirement_protects(&info.id,vm::owner_of(&info.name)) || self.workspaces.retirement_protects(&info.id) {continue;}
            if self.workspaces.recovery_pinned(&info.id) { continue; }
            let Some(owner) = vm::owner_of(&info.name) else {
                continue; // not ours; leave it alone
            };
            let Some(d) = deployments.get(owner) else {
                // Named for a deployment this LB's state does not hold: deleted
                // from the state file, or — the case that destroyed a fleet —
                // owned by a *different* app-lb whose state this is not.
                unowned.push((info.id.clone(), owner.to_string()));
                continue;
            };
            if !crate::rollout::adoptable(d, &info.name, &info.id) { continue; }
            if !d.spec.is_managed() {
                // The id was reused for a static deployment or a site since this
                // VM was created; neither owns VMs, so nothing here will ever
                // adopt it. Its disk is still the old deployment's data.
                unowned.push((info.id.clone(), owner.to_string()));
                continue;
            }
            if !d.state().create_attempts.iter().any(|a|a.sandbox_id.as_ref()==Some(&info.id)) {
                d.mutate_state(|s|s.allocation_history_complete=false);
                let _=self.registry.persist_one(&d.spec.id);
            }
            // A VM this deployment deliberately suspended is neither adoptable
            // nor an orphan: it is stopped on purpose and its data disk *is* the
            // deployment's state. Without this it fails `routable_addr` and gets
            // killed here — losing the sandbox on every restart, which is the
            // exact opposite of what `idle_action: retain` was asked for.
            //
            // Checked rather than assumed absent, because whether a stopped
            // sandbox appears in the fleet list at all is backend-dependent:
            // mvm-ctrl re-adds every persisted *KVM* sandbox to `GET /sandboxes`
            // on each call, while a stopped *Firecracker* one is simply missing.
            if d.state().suspended.contains(&info.id) {
                tracing::info!(
                    deployment = %owner,
                    sandbox = %info.id,
                    "leaving a suspended VM stopped; it will be resumed on demand",
                );
                continue;
            }
            match vm::routable_addr(info, d.spec.vm_spec().port) {
                Ok(addr) if health::probe(addr, &d.spec.health).await => {
                    tracing::info!(
                        deployment = %owner,
                        sandbox = %info.id,
                        %addr,
                        "adopting existing VM",
                    );
                    adopted
                        .entry(owner.to_string())
                        .or_default()
                        .push(Arc::new(VmBackend::new(info.id.clone(), addr)));
                }
                _ if !d.state().rollouts.is_empty() => {}, // uncertain service generation: retain
                _ => orphans.push(info.id.clone()),
            }
        }

        for (id, backends) in adopted {
            if let Some(d) = deployments.get(id.as_str()) {
                d.set_backends(backends);
            }
        }

        for id in orphans {
            if self.registry.allocation_protects(&id) { continue; }
            if self.workspaces.source_retained(&id) { continue; }
            tracing::info!(sandbox = %id, "killing orphaned VM from a previous run");
            if let Err(e) = self.runtime.kill_unknown(&id).await {
                tracing::warn!(sandbox = %id, error = %e, "failed to kill orphan");
            }
        }

        self.leave_unowned(deployments.is_empty(), unowned).await;
    }

    /// Deal with sandboxes named for deployments this LB does not have.
    ///
    /// They used to be destroyed — `kill_unknown`, which purges the disk — on
    /// the theory that "ours, but not in the state file" can only mean a
    /// deployment deleted while this LB was down. It can also mean this is not
    /// the LB that owns them. On 2026-09-29 `app-lb --version`, run on a host
    /// whose app-lb was live, started a second instance with an empty state
    /// file (arguments were ignored then; see `cli`), and this sweep purged
    /// every sandbox the first one was serving — workspaces uncaptured.
    ///
    /// So, two rules:
    ///
    /// - **An LB with no deployments touches nothing.** Empty state is
    ///   indistinguishable from "the wrong state file", and a fresh install on
    ///   a host with leftovers loses nothing by leaving them: each still has
    ///   the daemon's TTL, which nobody is renewing.
    /// - **Otherwise stop, never destroy.** A stopped sandbox keeps its disk;
    ///   `/disks` lists it and the disk sweep reclaims it after
    ///   `APP_LB_DISK_TTL_SECS`, the same as any other unclaimed disk. A
    ///   mistake becomes an outage a person can undo, not data loss.
    async fn leave_unowned(&self, registry_empty: bool, unowned: Vec<(String, String)>) {
        if unowned.is_empty() {
            return;
        }
        if registry_empty {
            tracing::warn!(
                count = unowned.len(),
                "this LB has no deployments but the daemon runs sandboxes named for some; \
                 leaving every one of them alone (another app-lb may own them, or this is \
                 the wrong APP_LB_STATE_PATH)",
            );
            return;
        }
        for (id, owner) in unowned {
            if self.registry.allocation_protects(&id) { continue; }
            if self.workspaces.source_retained(&id) { continue; }
            tracing::warn!(
                deployment = %owner,
                sandbox = %id,
                "stopping a VM whose deployment this LB does not have; its disk is kept \
                 until the disk sweep's TTL",
            );
            if let Err(e) = self.runtime.stop_unknown(&id).await {
                tracing::warn!(sandbox = %id, error = %e, "failed to stop unowned VM");
            }
        }
    }

    /// Drain and kill every VM of a deployment, e.g. on DELETE.
    pub async fn teardown(&self, d: &Arc<Deployment>) {
        // Only a managed deployment's backends are sandboxes. A static one's are
        // addresses and a site has none at all, so for both there is nothing to
        // kill on the daemon — just drop them from routing.
        if !d.spec.is_managed() {
            d.set_backends(Vec::new());
            return;
        }
        let workspace = Self::has_workspace(d);
        for b in d.backends().iter() {
            b.set_draining(true);
            self.unbind(d, b).await;
            self.kill_or_capture(d, &b.sandbox_id, "VM").await;
        }
        for p in d.pending().iter() {
            // A fresh boot that never became ready wrote nothing worth keeping;
            // a resumed replica is the deployment's state.
            if workspace && p.origin == BootOrigin::Created {
                self.workspaces.forget(&d.spec.id, &p.sandbox_id);
            }
            if workspace && p.origin != BootOrigin::Created {
                self.kill_or_capture(d, &p.sandbox_id, "pending VM").await;
            } else if let Err(e) = self.kill_vm(d, &p.sandbox_id).await {
                tracing::warn!(sandbox = %p.sandbox_id, error = %e, "failed to kill pending VM");
            }
        }
        // Suspended sandboxes are not in either list and are absent from the
        // daemon's fleet list, so nothing else would ever find them. Teardown is
        // the last moment this deployment's record of them exists.
        for sandbox_id in &d.state().suspended {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                "destroying suspended VM as its deployment goes away",
            );
            if workspace {
                // Already stopped; the worker skips the extraction if nothing
                // was written since the capture that suspended it.
                if let Err(e) = self.workspaces.retire_stopped(d, sandbox_id, Then::Kill) {
                    tracing::warn!(sandbox = %sandbox_id, error = %e, "could not queue the capture");
                }
                continue;
            }
            if let Err(e) = self.kill_vm(d, sandbox_id).await {
                tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill suspended VM");
            }
        }
        d.set_backends(Vec::new());
        d.set_pending(Vec::new());
        d.mutate_state(|s| s.suspended.clear());
    }

    /// Evict a single VM from a deployment's pool.
    ///
    /// Two modes, both consistent with the rule that the autoscaler is the only
    /// writer of the `backends`/`pending` vecs — this never mutates them, it
    /// flips the backend's atomic drain flag and/or kills the sandbox, and lets
    /// the next reconcile tick reconcile the vecs:
    ///
    /// - **graceful** (`force = false`): mark the VM draining so it stops taking
    ///   new requests but finishes in-flight ones; `reap_drained` kills it once
    ///   idle or at `drain_timeout_secs`. Returns [`EvictOutcome::Draining`].
    /// - **force** (`force = true`): kill the sandbox now, dropping in-flight
    ///   requests (they fail over to another VM via the proxy's retry). Returns
    ///   [`EvictOutcome::Killed`].
    ///
    /// A pending (still-booting) VM holds no traffic, so it is simply killed in
    /// either mode. After eviction the autoscaler is nudged, so a replacement
    /// boots immediately if the scaling policy still wants the capacity.
    pub async fn evict(&self, d: &Arc<Deployment>, sandbox_id: &str, force: bool) -> EvictOutcome {
        // A ready backend.
        if let Some(b) = d
            .backends()
            .iter()
            .find(|b| b.sandbox_id == sandbox_id)
            .cloned()
        {
            // Stop new traffic regardless of mode; a draining VM is skipped by
            // `select`, so no request is routed to it after this point — and
            // the cloud's URL stops picking it once its bind is gone.
            b.set_draining(true);
            self.unbind(d, &b).await;

            if !force {
                tracing::info!(
                    deployment = %d.spec.id,
                    sandbox = %sandbox_id,
                    in_flight = b.in_flight(),
                    "evicting VM (draining)",
                );
                d.scale_signal.notify_one();
                return EvictOutcome::Draining;
            }

            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                in_flight = b.in_flight(),
                "evicting VM (force kill)",
            );
            if Self::has_workspace(d) {
                // Stopped now, destroyed after its capture. `prune` drops the
                // backend next tick, when the daemon stops listing it.
                return match self.workspaces.retire(d, sandbox_id, Then::Kill).await {
                    Ok(()) => {
                        self.metrics.record_reaped(&d.spec.id, 1);
                        d.scale_signal.notify_one();
                        EvictOutcome::Killed
                    }
                    Err(e) => EvictOutcome::KillFailed(e),
                };
            }
            if let Err(e) = self.kill_vm(d, sandbox_id).await {
                tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill evicted VM");
                return EvictOutcome::KillFailed(e.to_string());
            }
            // `prune` removes the now-dead backend next tick and won't record a
            // reap, so count it here to keep the dashboard's reaped total honest.
            self.metrics.record_reaped(&d.spec.id, 1);
            d.scale_signal.notify_one();
            return EvictOutcome::Killed;
        }

        // A pending, still-booting VM: nothing in-flight, so just kill it. The
        // next `promote_pending` drops it from the pending vec.
        if d.pending().iter().any(|p| p.sandbox_id == sandbox_id) {
            tracing::info!(
                deployment = %d.spec.id,
                sandbox = %sandbox_id,
                "evicting pending VM",
            );
            if let Err(e) = self.kill_vm(d, sandbox_id).await {
                tracing::warn!(sandbox = %sandbox_id, error = %e, "failed to kill evicted pending VM");
                return EvictOutcome::KillFailed(e.to_string());
            }
            d.scale_signal.notify_one();
            return EvictOutcome::Killed;
        }

        EvictOutcome::NotFound
    }
}

/// The result of an [`Autoscaler::evict`] call.
#[derive(Debug)]
pub enum EvictOutcome {
    /// The sandbox was killed and is gone now.
    Killed,
    /// The VM was marked draining; the autoscaler will reap it once idle.
    Draining,
    /// No VM with that id is in the deployment's pool (ready or pending).
    NotFound,
    /// The VM was found but the daemon refused to kill it.
    KillFailed(String),
}

#[async_trait]
impl BackgroundService for Autoscaler {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        tracing::info!("autoscaler starting");

        // Ask Incus whether it is there and whether it trusts us, once. Not a
        // gate — a later call fails on its own with the same explanation — but
        // the two failure modes here are the ones an operator cannot guess:
        // a socket at a path app-lb was never told about, and a group
        // membership app-lb's user does not have.
        //
        // Volume follows the same rule the daemon listing uses: on a host with
        // no container deployments, a missing Incus is a fact about the host
        // rather than a problem, and is not worth a warning every restart.
        if let Some(result) = self.runtime.probe_lxc().await {
            let wanted = self
                .registry
                .deployments()
                .values()
                .any(|d| d.spec.driver().is_some_and(|dr| dr.is_lxc()));
            match result {
                Ok(version) => tracing::info!(version = %version, "incus ready"),
                Err(e) if wanted => {
                    tracing::error!(error = %e, "incus is not usable; `driver: lxc` deployments cannot scale")
                }
                Err(e) => tracing::debug!(error = %e, "no usable incus (no lxc deployments)"),
            }
        }

        self.adopt_existing().await;

        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Deliberately a separate, much slower ticker: the sweep asks the daemon
        // to walk its persistence directory, which is not something to do every
        // two seconds. See `sweep_suspended`.
        let mut sweeper = tokio::time::interval(SUSPENDED_SWEEP);
        sweeper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        sweeper.tick().await; // the first tick is immediate; skip it

        loop {
            // A cold-start request nudges `scale_signal`, so a scaled-to-zero
            // deployment reacts immediately instead of waiting out the tick.
            let nudged = wait_for_any_scale_signal(&self.registry);

            tokio::select! {
                _ = ticker.tick() => self.reconcile().await,
                _ = nudged => self.reconcile().await,
                _ = sweeper.tick() => self.sweep_suspended().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("autoscaler shutting down");
                        return;
                    }
                }
            }
        }
    }
}

/// Why a VM that has not joined the pool yet has not joined the pool yet.
///
/// This one string is the whole diagnosis, and it is not derivable from a status:
/// `Provisioning` means the daemon hasn't finished starting the VM and there is
/// nothing to do but wait, while `Running` plus a failing probe means the *guest*
/// is the problem — the start command, an env var, a binary that exited — and
/// waiting will not fix it. Naming the probe target is what turns "it hangs" into
/// something to go and check.
/// `vm_port` is the deployment's proxied port, which the health check's own `port`
/// overrides when set — the same resolution `health::probe` does, so the message
/// names the port actually dialled rather than the one in the spec.
/// Whether a pending VM that is absent from the fleet listing keeps its slot,
/// and the timestamp to remember if so.
///
/// `Some(since)` means keep waiting and record `since` as when the absence
/// began; `None` means the grace has elapsed and the pool should give up. Pure,
/// so the rule that stops duplicate VM creation is testable without a daemon —
/// the same reason [`Autoscaler::unclaimed`] is a separate function.
///
/// The first call for a given VM passes `None` and starts the clock at `now`,
/// which is why a fresh absence always holds rather than being measured against
/// a zero timestamp.
fn hold_missing(missing_since: Option<u64>, now: u64) -> Option<u64> {
    let since = missing_since.unwrap_or(now);
    (now.saturating_sub(since) < MISSING_GRACE).then_some(since)
}

/// The sandboxes in a listing that no deployment owns, as the dashboard shows
/// them.
///
/// Ownership is the name rule ([`vm::owner_of`]) — the same one adoption uses,
/// so a sandbox is never both in a pool and in this list. Everything else the
/// daemon reports is included, stopped ones too: a stopped sandbox still holds
/// a disk on the host, and "what is on this machine" is the question this
/// answers. Sorted by name so the table holds still between polls.
fn host_sandboxes(
    listing: &vm::Listing,
    usage: &HashMap<String, vm::SandboxUsage>,
) -> Vec<crate::metrics::HostSandboxView> {
    let mut out: Vec<_> = listing
        .sandboxes
        .iter()
        .filter(|info| vm::owner_of(&info.name).is_none())
        .map(|info| {
            let detail = listing.details.get(&info.id);
            let sample = usage.get(&info.id);
            crate::metrics::HostSandboxView {
                sandbox_id: info.id.clone(),
                name: info.name.clone(),
                status: info.status.clone(),
                image: info.image.clone(),
                size_class: info.size_class.clone(),
                guest_ip: info.guest_ip.clone(),
                uptime_secs: info.uptime_secs,
                cpu_percent: sample.map(|s| s.cpu_percent),
                memory_bytes: sample.map(|s| s.memory_bytes),
                account_id: detail.and_then(|d| d.account_id.clone()),
                created_at: detail.and_then(|d| d.created_at.clone()),
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.sandbox_id.cmp(&b.sandbox_id)));
    out
}

/// `vm.workspace.snapshot_interval_secs`, when `d` has a workspace and sets one.
fn snapshot_interval(d: &Deployment) -> Option<u64> {
    d.spec
        .vm
        .as_ref()
        .and_then(|vm| vm.workspace.as_ref())
        .and_then(|w| w.snapshot_interval_secs)
}

/// The replica a scheduled workspace snapshot should recycle now, if any.
///
/// Measured by the replica's own uptime, not the age of the last snapshot:
/// what is at risk is what *this* replica has written since it was seeded or
/// resumed, and a replica just booted from a months-old snapshot has written
/// nothing yet. Recycling resumes it (or boots a fresh one) as a new backend,
/// so the clock restarts there. Nothing while any replica is already
/// draining — that one's capture is the snapshot.
///
/// Pure, so the schedule is testable without a daemon.
fn snapshot_candidate(interval: Option<u64>, backends: &[Arc<VmBackend>]) -> Option<String> {
    let interval = interval?;
    if backends.iter().any(|b| b.is_draining()) {
        return None;
    }
    backends
        .iter()
        .find(|b| b.uptime_secs() >= interval)
        .map(|b| b.sandbox_id.clone())
}

/// Whether `d` needs nothing this tick beyond a usage sample.
///
/// This is the fast path that makes a fleet of thousands viable: at rest, a
/// sandbox deployment is one healthy VM sitting at its desired size, and
/// deciding that must not cost a daemon round trip. Every condition here is a
/// count or a flag already in memory.
///
/// Call after `prune`, so the backend list reflects the fleet snapshot.
fn at_rest(
    d: &Arc<Deployment>,
    fleet: &HashMap<String, SandboxInfo>,
    owned_running: &HashMap<&str, usize>,
) -> bool {
    let backends = d.backends();
    if !d.pending().is_empty() || backends.iter().any(|b| b.is_draining() || !b.is_healthy()) {
        return false;
    }
    if backends.len() != d.desired_replicas() as usize {
        return false;
    }
    // A scheduled workspace snapshot is due: only `reconcile_one` starts one.
    if snapshot_candidate(snapshot_interval(d), &backends).is_some() {
        return false;
    }
    // The daemon runs more replicas for this deployment than it is tracking, so
    // something was created that never made it into a pool — see
    // `adopt_untracked`. Not at rest: those VMs are real, they hold real data
    // disks, and only `reconcile_one` can take them back. Counted once per tick
    // for the whole fleet, so this stays a hashmap lookup on the fast path.
    if owned_running
        .get(d.spec.id.as_str())
        .is_some_and(|n| *n > backends.len())
    {
        return false;
    }
    // A TTL past its halfway mark needs a renewal call, which is an await. A
    // backend the fleet snapshot doesn't mention is *not* at rest either: it
    // vanished between the snapshot and now, which `reconcile_one` must see.
    backends.iter().all(|b| {
        fleet.get(&b.sandbox_id).is_some_and(|info| {
            info.uptime_secs < info.ttl_seconds.unwrap_or(d.spec.vm_spec().ttl_seconds) / 2
        })
    })
}

/// How many stopped sandboxes a deployment may take back.
///
/// A reclaimed sandbox is one this deployment will hold and may resume, so it
/// counts against `max_replicas` exactly as a running or booting one does.
/// Without the cap, a host carrying a hundred stale sandboxes from before a
/// restart would hand all hundred to one deployment, which would then never
/// destroy any of them — the leak this is meant to close, wearing a different
/// hat.
///
/// Pure, so the cap is testable without a daemon.
fn reclaim_budget(d: &Arc<Deployment>) -> usize {
    let held = d.backends().len() + d.pending().len() + d.state().suspended.len();
    (d.spec.scaling.max_replicas as usize).saturating_sub(held)
}

fn boot_stall(info: &SandboxInfo, check: &crate::config::HealthCheck, vm_port: u16) -> String {
    if info.status != heyo_sdk::SandboxStatus::Running {
        return match info.error_message.as_deref() {
            Some(e) => format!("the daemon reports {:?}: {e}", info.status),
            None => format!("the daemon has not reported it Running yet ({:?})", info.status),
        };
    }
    let port = check.port.unwrap_or(vm_port);
    let where_ = match info.guest_ip.as_deref() {
        Some(ip) => format!("{ip}:{port}"),
        None => format!("port {port}"),
    };
    match check.path.as_deref() {
        Some(path) => format!("the guest is up but has not answered GET {path} on {where_}"),
        None => format!("the guest is up but is not accepting TCP connections on {where_}"),
    }
}

/// Resolve as soon as *any* deployment asks to be scaled.
async fn wait_for_any_scale_signal(registry: &Arc<Registry>) {
    let deployments = registry.deployments();
    if deployments.is_empty() {
        // Nothing to wait on; let the ticker drive the loop.
        std::future::pending::<()>().await;
    }
    let waits: Vec<_> = deployments
        .values()
        .cloned()
        .map(|d| {
            Box::pin(async move { d.scale_signal.notified().await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        })
        .collect();
    let _ = futures::future::select_all(waits).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DeploymentSpec, HealthCheck, RouteRule, ScalingPolicy, VmSpec};
    use crate::deployment::VmBackend;
    use crate::metrics::Metrics;
    use crate::config::Driver;

    fn spec() -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "demo".into(),
            routes: vec![RouteRule {
                host: Some("demo.local".into()),
                host_suffix: None,
                path_prefix: None,
                strip_prefix: false,
            }],
            vm: Some(VmSpec {
                correlated_creates: false,
                env_from: vec![],
                workspace_archive: None,
                image_download_url: None,
                image_size_bytes: None,
                image_sha256: None,
                driver: Driver::Firecracker,
                image: None,
                rootfs: Default::default(),
                port: 8080,
                start_command: None,
                size_class: None,
                disk_size_gb: None,
                working_directory: None,
                env_vars: None,
                setup_hooks: None,
                open_ports: vec![],
                mounts: vec![],
                workspace: None,
                ttl_seconds: 3600,
            }),
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: vec![],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    /// A static (proxy_pass) deployment with fixed upstreams.
    fn static_spec() -> DeploymentSpec {
        DeploymentSpec {
            ingress: None,
            account_id: None,
            user_id: None,
            namespace: "default".into(),
            feed: None,
            id: "proxy".into(),
            routes: vec![RouteRule {
                host: None,
                host_suffix: None,
                path_prefix: Some("/legacy".into()),
                strip_prefix: false,
            }],
            vm: None,
            scaling: ScalingPolicy::default(),
            maintenance: false,
            health: HealthCheck::default(),
            upstreams: vec!["127.0.0.1:9".into()],
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        }
    }

    /// A registry whose state directory is scratch space. The suspended-VM
    /// bookkeeping persists on every change, so this must not be the CWD — and
    /// must not be shared, since tests run in parallel against the same id.
    fn autoscaler() -> (Autoscaler, Arc<Registry>) {
        // A daemon URL nothing listens on: fine, because the graceful and
        // not-found paths never call it.
        autoscaler_against("http://127.0.0.1:1", spec())
    }

    /// An autoscaler over one registered deployment, talking to the daemon
    /// at `daemon_url`.
    fn autoscaler_against(daemon_url: &str, initial: DeploymentSpec) -> (Autoscaler, Arc<Registry>) {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "app-lb-as-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
        ));
        let registry = Arc::new(Registry::new(dir.join("state.json")));
        let api_key = initial.vm.as_ref().is_some_and(|vm| vm.correlated_creates).then(|| "allocation-test-key".to_string());
        registry.upsert(initial);
        let vms = VmManager::new(
            Some(daemon_url.into()),
            api_key,
            crate::mounts::MountStore::new(dir.join("mounts"), 0),
        )
        .unwrap();
        let workspaces = Arc::new(crate::workspace::Workspaces::new(
            crate::workspace::WorkspaceConfig {
                root: dir.join("workspaces"),
                tar_bin: "tar".into(),
                aws_bin: "aws".into(),
                art_bin: "art".into(),
                s3_endpoint: None,
                home: None,
                timeout: Duration::from_secs(60),
            },
            vms.clone(),
            registry.clone(),
            Arc::new(crate::secrets::SecretStore::new(
                dir.join("secrets.json"),
                None,
            )),
        ));
        (
            Autoscaler::new(
                registry.clone(),
                // Incus off: these tests are about the autoscaler's own logic,
                // and a host running them may or may not have Incus on it. The
                // seam still dispatches, it just has one runtime to dispatch to.
                crate::runtime::Runtime::new(
                    vms,
                    crate::config::LxcConfig {
                        enabled: false,
                        ..Default::default()
                    },
                ),
                Arc::new(Metrics::new()),
                Arc::new(crate::feed::Feed::new()),
                workspaces,
                Arc::new(crate::secrets::SecretStore::new(
                    dir.join("autoscaler-secrets.json"),
                    None,
                )),
            ),
            registry,
        )
    }

    /// Live on us5 (2026-10-06): a pull landed while the pool's first create
    /// was awaiting the daemon. The rollover copied that unresolved attempt
    /// into the new deployment object, the outcome was recorded only on the
    /// old one, and the new pool never scaled up — `scale_up` refuses while
    /// any attempt lacks a sandbox id. The outcome must reach the successor.
    #[test]
    fn a_create_that_lands_after_a_rollover_does_not_freeze_the_new_pool() {
        let (scaler, registry) = autoscaler_against("http://127.0.0.1:1", spec());
        let old = registry.get("demo").unwrap();
        old.mutate_state(|s| s.create_attempts.push(crate::retirement::CreateAttempt {
            name: "applb-demo-r1-0".into(),
            ..Default::default()
        }));
        let new = registry.upsert(old.spec.clone());
        assert!(!Arc::ptr_eq(&old, &new));
        let blocked = |d: &Deployment| d.state().create_attempts.iter().any(|a| a.sandbox_id.is_none());
        assert!(blocked(&new), "the rollover carries the in-flight attempt over");

        // The create's outcome, as allocate_replica records it.
        scaler.settle_in_successor(&old, |attempts| {
            if let Some(a) = attempts.iter_mut().find(|a| a.name == "applb-demo-r1-0" && a.sandbox_id.is_none()) {
                a.sandbox_id = Some("sb-landed".into());
            }
        });
        assert!(!blocked(&new), "the new pool may scale up again");
        assert_eq!(new.state().create_attempts[0].sandbox_id.as_deref(), Some("sb-landed"));

        // A known failure removes it from the successor instead.
        let failing = registry.get("demo").unwrap();
        failing.mutate_state(|s| s.create_attempts.push(crate::retirement::CreateAttempt {
            name: "applb-demo-r1-1".into(),
            ..Default::default()
        }));
        let newer = registry.upsert(failing.spec.clone());
        scaler.settle_in_successor(&failing, |attempts| {
            attempts.retain(|a| !(a.name == "applb-demo-r1-1" && a.sandbox_id.is_none()));
        });
        assert!(!blocked(&newer));

        // On the live object itself there is no successor to settle.
        scaler.settle_in_successor(&newer, |attempts| attempts.clear());
        assert_eq!(newer.state().create_attempts.len(), 1, "a live object is left to its own caller");
    }

    mod correlated_allocations {
        use super::*;
        use axum::{Json, Router, extract::Path, http::{HeaderMap, StatusCode}, response::IntoResponse, routing::post};
        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};
        use std::sync::{Mutex, atomic::AtomicUsize};

        const ID: &str = "sb-0123456789abcdef0123456789abcdef";

        #[derive(Default)]
        struct Backend {
            posts: AtomicUsize,
            reads: AtomicUsize,
            mode: AtomicUsize,
            receipt: Mutex<Option<Value>>,
            journal: Mutex<Option<std::path::PathBuf>>,
        }

        async fn fixture(mode: usize) -> (Autoscaler, Arc<Registry>, Arc<Backend>, tokio::task::JoinHandle<()>) {
            let b = Arc::new(Backend::default());
            b.mode.store(mode, Ordering::SeqCst);
            let write = b.clone(); let read = b.clone();
            let app = Router::new().route("/sandbox-creations/:id", post(move |Path(id):Path<String>, headers:HeaderMap, Json(body):Json<Value>| {
                let b = write.clone(); async move {
                    assert_eq!(headers["authorization"], "Bearer allocation-test-key");
                    let journal = b.journal.lock().unwrap().clone().unwrap();
                    let persisted = Registry::new(journal.with_extension("json"));
                    persisted.load().unwrap();
                    let saved = persisted.get("demo").unwrap().state();
                    assert_eq!(saved.create_attempts[0].allocation.as_ref().unwrap().operation_id, id);
                    assert!(saved.create_attempts[0].receipt.is_none());
                    assert!(saved.create_attempts[0].sandbox_id.is_none());
                    assert_eq!(body["request"]["backend_type"], "firecracker");
                    assert_eq!(body["request"]["size_class"], "small");
                    let mut bound = json!({"kind":body["kind"],"request":body["request"]});
                    bound.sort_all_objects();
                    let receipt = json!({"operationId":id,"sandboxId":ID,"requestDigest":body["requestDigest"],
                        "backendRequestDigest":format!("{:x}",Sha256::digest(serde_json::to_vec(&bound).unwrap()))});
                    if b.mode.load(Ordering::SeqCst) != 2 { *b.receipt.lock().unwrap() = Some(receipt.clone()); }
                    b.posts.fetch_add(1,Ordering::SeqCst);
                    if b.mode.load(Ordering::SeqCst) != 0 { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                    (StatusCode::ACCEPTED, Json(receipt)).into_response()
                }
            }).get(move |Path(id):Path<String>, headers:HeaderMap| {
                let b = read.clone(); async move {
                    assert_eq!(headers["authorization"], "Bearer allocation-test-key");
                    b.reads.fetch_add(1,Ordering::SeqCst);
                    let Some(mut receipt) = b.receipt.lock().unwrap().clone() else { return StatusCode::NOT_FOUND.into_response(); };
                    assert_eq!(receipt["operationId"],id);
                    if b.mode.load(Ordering::SeqCst) == 3 { receipt["requestDigest"] = json!("wrong"); }
                    Json(receipt).into_response()
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}",listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener,app).await.unwrap(); });
            let mut s = spec(); s.vm.as_mut().unwrap().correlated_creates = true;
            let (scaler, registry) = autoscaler_against(&url,s);
            *b.journal.lock().unwrap() = Some(registry.state_dir());
            (scaler,registry,b,server)
        }

        #[tokio::test]
        async fn lost_reply_restart_recovers_exact_receipt_and_holds_queued_capacity() {
            let (mut scaler,r,b,server) = fixture(1).await;
            let d = r.get("demo").unwrap();
            scaler.scale_up(&d,1).await;
            assert_eq!(b.posts.load(Ordering::SeqCst),1);
            assert!(d.state().create_attempts[0].sandbox_id.is_none());
            assert!(d.state().allocation_history_complete);
            let reopened = Arc::new(Registry::new(r.state_dir().with_extension("json")));
            reopened.load().unwrap();
            scaler.registry = reopened.clone();
            let d = reopened.get("demo").unwrap();
            scaler.recover_allocations(&d,&HashMap::new()).await;
            assert_eq!(b.reads.load(Ordering::SeqCst),1);
            assert_eq!(d.state().create_attempts[0].sandbox_id.as_deref(),Some(ID));
            assert!(d.state().create_attempts[0].receipt.is_some());
            assert_eq!(d.pending()[0].sandbox_id,ID);
            assert!(crate::rollout::reserved(&d));
            assert!(reopened.allocation_protects(ID));
            assert!(!reopened.allocation_protects("sb-unrelated"));
            assert!(reopened.remove("demo").is_none());
            // The grace timer may expire, but it cannot prove queued work ended.
            let mut p = (*d.pending()).clone();p[0].missing_since=Some(0);d.set_pending(p);
            scaler.reconcile_one(&d,&HashMap::new(),&HashMap::new()).await;
            assert_eq!(d.pending().len(),1);
            assert_eq!(b.posts.load(Ordering::SeqCst),1);
            let mut running = info(heyo_sdk::SandboxStatus::Running,Some("172.16.0.2"));
            running.id=ID.into();
            scaler.recover_allocations(&d,&HashMap::from([(ID.into(),running)])).await;
            assert!(d.state().create_attempts[0].runtime_observed);
            assert!(!crate::rollout::reserved(&d));
            assert!(d.state().allocation_history_complete);
            server.abort();
        }

        #[tokio::test]
        async fn missing_or_mismatched_receipts_never_repost_or_repair_legacy_history() {
            for mode in [2,3] {
                let (scaler,r,b,server) = fixture(mode).await;
                let d = r.get("demo").unwrap();
                d.mutate_state(|s|s.allocation_history_complete=false);
                scaler.scale_up(&d,1).await;
                for _ in 0..2 {
                    scaler.recover_allocations(&d,&HashMap::new()).await;
                    scaler.scale_up(&d,1).await;
                }
                assert_eq!(b.posts.load(Ordering::SeqCst),1);
                assert_eq!(b.reads.load(Ordering::SeqCst),2);
                assert!(d.state().create_attempts[0].sandbox_id.is_none());
                assert!(!d.state().allocation_history_complete);
                assert!(crate::rollout::reserved(&d));
                assert!(r.allocation_protects("unknown-id"));
                server.abort();
            }
        }

        #[tokio::test]
        async fn persistence_failure_and_concurrent_edit_prevent_dispatch() {
            let (scaler,r,b,server) = fixture(0).await;
            let d = r.get("demo").unwrap();
            let edit = r.change_guard().await;
            tokio::time::timeout(Duration::from_secs(1),scaler.scale_up(&d,1)).await.unwrap();
            assert!(d.state().create_attempts.is_empty());
            drop(edit);
            std::fs::create_dir_all(r.state_dir().parent().unwrap()).unwrap();
            std::fs::write(r.state_dir(),b"not a directory").unwrap();
            scaler.scale_up(&d,1).await;
            assert_eq!(b.posts.load(Ordering::SeqCst),0);
            assert!(d.state().create_attempts[0].sandbox_id.is_none());
            assert!(crate::rollout::reserved(&d));
            server.abort();
        }
    }

    /// app-lb's part of a cloud URL: bind a ready replica's port on the
    /// daemon, tagged with the deployment; withdraw it when the replica
    /// drains. The daemon is faked over its three `/sandboxes/:id/proxy`
    /// verbs, holding the bind list in memory so what app-lb asked for can
    /// be read back.
    mod cloud_ingress {
        use super::*;
        use crate::config::IngressSpec;
        use axum::extract::{Path, Query, State};
        use axum::http::StatusCode;
        use axum::routing::get;
        use axum::{Json, Router};
        use serde_json::{Value, json};
        use std::sync::Mutex;
        use std::sync::atomic::AtomicUsize;

        #[derive(Clone, Default)]
        struct FakeDaemon {
            binds: Arc<Mutex<Vec<Value>>>,
            posts: Arc<AtomicUsize>,
        }

        async fn serve(daemon: FakeDaemon) -> String {
            let app = Router::new()
                .route("/sandboxes/:id/proxy", get(list).post(create).delete(remove))
                .with_state(daemon);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{addr}")
        }

        async fn list(State(d): State<FakeDaemon>, Path(id): Path<String>) -> Json<Value> {
            let proxies: Vec<Value> = d
                .binds
                .lock()
                .unwrap()
                .iter()
                .filter(|b| b["sandbox_id"] == id)
                .cloned()
                .collect();
            Json(json!({ "proxies": proxies }))
        }

        async fn create(
            State(d): State<FakeDaemon>,
            Path(id): Path<String>,
            Json(body): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            let n = d.posts.fetch_add(1, Ordering::Relaxed);
            let bind = json!({
                "sandbox_id": id,
                "subdomain": format!("bind{n}"),
                "hostname": format!("bind{n}.localhost"),
                "port": body["port"],
                "is_public": body["is_public"],
                "deployment": body["deployment"],
            });
            d.binds.lock().unwrap().push(bind.clone());
            (StatusCode::CREATED, Json(bind))
        }

        async fn remove(
            State(d): State<FakeDaemon>,
            Path(id): Path<String>,
            Query(q): Query<HashMap<String, String>>,
        ) -> StatusCode {
            let sub = q.get("subdomain").cloned().unwrap_or_default();
            let mut binds = d.binds.lock().unwrap();
            let before = binds.len();
            binds.retain(|b| !(b["sandbox_id"] == id && b["subdomain"] == sub));
            if binds.len() == before {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::NO_CONTENT
            }
        }

        fn ready_backend(id: &str) -> Arc<VmBackend> {
            Arc::new(VmBackend::new(id.into(), "10.0.0.2:8080".parse().unwrap()))
        }

        fn cloud_spec(public: bool) -> DeploymentSpec {
            let mut s = spec();
            s.ingress = Some(IngressSpec { cloud: true, public });
            s
        }

        #[tokio::test]
        async fn binds_ready_replicas_and_unbinds_them_when_they_drain() {
            let daemon = FakeDaemon::default();
            let url = serve(daemon.clone()).await;
            let (a, reg) = autoscaler_against(&url, cloud_spec(false));
            let d = reg.get("demo").unwrap();
            let b = ready_backend("sb-1");
            d.set_backends(vec![b.clone()]);

            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind().as_deref(), Some("bind0"));
            let binds = daemon.binds.lock().unwrap().clone();
            assert_eq!(binds.len(), 1);
            assert_eq!(binds[0]["port"], 8080, "the spec's vm.port is what gets bound");
            assert_eq!(binds[0]["is_public"], false, "ingress.public rides the bind");
            assert_eq!(
                binds[0]["deployment"],
                json!({"namespace": "default", "id": "demo"}),
                "the bind is tagged with the deployment so the cloud can group it",
            );

            // Settled: another tick asks the daemon for nothing new.
            a.reconcile_ingress(&d).await;
            assert_eq!(daemon.posts.load(Ordering::Relaxed), 1);

            b.set_draining(true);
            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind(), None, "a draining replica is withdrawn");
            assert!(daemon.binds.lock().unwrap().is_empty());
        }

        /// After a restart app-lb has forgotten its binds; the daemon has
        /// not. The one it finds is reused, not doubled — the daemon mints a
        /// fresh subdomain per create.
        #[tokio::test]
        async fn reuses_the_bind_the_daemon_already_holds() {
            let daemon = FakeDaemon::default();
            daemon.binds.lock().unwrap().push(json!({
                "sandbox_id": "sb-1", "subdomain": "kept", "port": 8080, "is_public": true,
                "deployment": {"namespace": "default", "id": "demo"},
            }));
            let url = serve(daemon.clone()).await;
            let (a, reg) = autoscaler_against(&url, cloud_spec(true));
            let d = reg.get("demo").unwrap();
            let b = ready_backend("sb-1");
            d.set_backends(vec![b.clone()]);

            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind().as_deref(), Some("kept"));
            assert_eq!(daemon.posts.load(Ordering::Relaxed), 0);
        }

        /// A bind for another deployment, or another port, is not this one's.
        #[tokio::test]
        async fn does_not_adopt_a_bind_that_is_not_its_own() {
            let daemon = FakeDaemon::default();
            daemon.binds.lock().unwrap().push(json!({
                "sandbox_id": "sb-1", "subdomain": "theirs", "port": 8080, "is_public": true,
                "deployment": {"namespace": "default", "id": "other"},
            }));
            daemon.binds.lock().unwrap().push(json!({
                "sandbox_id": "sb-1", "subdomain": "debug", "port": 9229, "is_public": true,
                "deployment": {"namespace": "default", "id": "demo"},
            }));
            let url = serve(daemon.clone()).await;
            let (a, reg) = autoscaler_against(&url, cloud_spec(true));
            let d = reg.get("demo").unwrap();
            let b = ready_backend("sb-1");
            d.set_backends(vec![b.clone()]);

            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind().as_deref(), Some("bind0"));
            assert_eq!(daemon.posts.load(Ordering::Relaxed), 1);
        }

        /// A spec that no longer asks for a cloud URL withdraws every bind,
        /// and a spec that never did asks the daemon for nothing.
        #[tokio::test]
        async fn withdraws_binds_when_the_spec_stops_asking() {
            let daemon = FakeDaemon::default();
            daemon.binds.lock().unwrap().push(json!({
                "sandbox_id": "sb-1", "subdomain": "old", "port": 8080, "is_public": true,
                "deployment": {"namespace": "default", "id": "demo"},
            }));
            let url = serve(daemon.clone()).await;
            let (a, reg) = autoscaler_against(&url, spec());
            let d = reg.get("demo").unwrap();
            let b = ready_backend("sb-1");
            b.set_bind(Some("old".into()));
            d.set_backends(vec![b.clone()]);

            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind(), None);
            assert!(daemon.binds.lock().unwrap().is_empty());
            assert_eq!(daemon.posts.load(Ordering::Relaxed), 0);
        }

        /// A daemon that cannot be reached costs nothing but a retry: the
        /// replica keeps serving the proxy's own routes.
        #[tokio::test]
        async fn a_failed_bind_is_retried_next_tick_not_fatal() {
            let (a, reg) = autoscaler_against("http://127.0.0.1:1", cloud_spec(true));
            let d = reg.get("demo").unwrap();
            let b = ready_backend("sb-1");
            d.set_backends(vec![b.clone()]);

            a.reconcile_ingress(&d).await;
            assert_eq!(b.bind(), None);
            assert!(d.backends().iter().any(|x| x.sandbox_id == "sb-1"), "still in the pool");
        }
    }

    /// The record of a suspended sandbox is the *only* record: mvm-ctrl drops a
    /// stopped sandbox from `GET /sandboxes`, so anything lost here is a VM
    /// still holding a disk that nothing will ever resume or reap.
    mod suspended_bookkeeping {
        use super::*;

        #[test]
        fn remembering_is_idempotent() {
            let (a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();

            a.remember_suspended(&d, vec!["sb-1".into(), "sb-2".into()]);
            a.remember_suspended(&d, vec!["sb-2".into(), "sb-3".into()]);

            assert_eq!(d.state().suspended, vec!["sb-1", "sb-2", "sb-3"]);
        }

        /// Claimed before the resume is attempted, so two concurrent scale-ups
        /// cannot both try to start the same VM.
        #[test]
        fn taking_removes_it_oldest_first() {
            let (a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();
            a.remember_suspended(&d, vec!["sb-1".into(), "sb-2".into()]);

            assert_eq!(a.take_suspended(&d).as_deref(), Some("sb-1"));
            assert_eq!(d.state().suspended, vec!["sb-2"]);
            assert_eq!(a.take_suspended(&d).as_deref(), Some("sb-2"));
            assert_eq!(a.take_suspended(&d), None, "an empty record yields nothing");
        }

        #[test]
        fn forgetting_removes_only_the_named_one() {
            let (a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();
            a.remember_suspended(&d, vec!["sb-1".into(), "sb-2".into()]);

            a.forget_suspended(&d, "sb-1");
            assert_eq!(d.state().suspended, vec!["sb-2"]);
            a.forget_suspended(&d, "never-there"); // not an error
            assert_eq!(d.state().suspended, vec!["sb-2"]);
        }

        /// The record survives a restart, or the VM is stranded.
        #[test]
        fn the_record_is_persisted_as_it_changes() {
            let (a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();
            a.remember_suspended(&d, vec!["sb-1".into()]);

            let reloaded = Registry::new(reg.state_dir().parent().unwrap().join("state.json"));
            assert_eq!(reloaded.load().unwrap(), 1);
            assert_eq!(reloaded.get("demo").unwrap().state().suspended, vec!["sb-1"]);
        }

        /// Startup adoption must leave suspended VMs alone.
        ///
        /// This is the bug that would have destroyed every `retain` sandbox on
        /// every restart: a stopped **KVM** sandbox *is* in the daemon's fleet
        /// list (mvm-ctrl reloads persisted KVM sandboxes on every `list`), it
        /// is not routable, and `adopt_existing` kills whatever it cannot adopt.
        #[test]
        fn a_suspended_vm_is_neither_adopted_nor_orphaned() {
            let (_a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();
            d.set_state(crate::deployment::DeploymentState {
                suspended: vec!["sb-1".into()],
                ..Default::default()
            });

            // What the fleet list looks like for a stopped KVM sandbox of ours.
            let mut stopped = info(heyo_sdk::SandboxStatus::Stopped, None);
            stopped.id = "sb-1".into();
            stopped.name = "applb-demo-000000000001".into();

            assert_eq!(vm::owner_of(&stopped.name), Some("demo"), "it is ours");
            assert!(
                vm::routable_addr(&stopped, 8080).is_err(),
                "and not routable, so adoption would otherwise treat it as an orphan",
            );
            assert!(
                d.state().suspended.contains(&stopped.id),
                "the suspended record is what has to save it",
            );
        }

        /// Deregistering must not leave a stopped VM behind. Teardown is the
        /// last moment anything knows the sandbox exists.
        #[tokio::test]
        async fn teardown_clears_the_record() {
            let (a, reg) = autoscaler();
            let d = reg.get("demo").unwrap();
            a.remember_suspended(&d, vec!["sb-1".into()]);

            // The kill calls fail against a dead daemon; teardown logs and
            // carries on, which is what must not leave the record behind.
            a.teardown(&d).await;
            assert!(d.state().suspended.is_empty());
        }
    }

    /// A stopped VM this LB has lost track of is worth more than the disk it
    /// holds: destroying it means the next scale-up mints a *new* sandbox id,
    /// with a new directory under the daemon's data dir, while the old one's
    /// disks stay on the host forever. See `sweep_suspended`.
    mod reclaiming_stopped_vms {
        use super::*;

        fn deployment(reg: &Arc<Registry>, idle: IdleAction, max: u32) -> Arc<Deployment> {
            let mut s = spec();
            s.scaling.idle_action = idle;
            s.scaling.max_replicas = max;
            reg.upsert(s);
            reg.get("demo").unwrap()
        }

        #[test]
        fn the_budget_counts_every_vm_the_deployment_already_holds() {
            let (a, reg) = autoscaler();
            let d = deployment(&reg, IdleAction::Retain, 4);
            assert_eq!(reclaim_budget(&d), 4, "an empty deployment may take its max");

            d.set_backends(vec![Arc::new(VmBackend::new(
                "sb-live".into(),
                "10.0.0.1:80".parse().unwrap(),
            ))]);
            d.set_pending(vec![pending("sb-booting")]);
            a.remember_suspended(&d, vec!["sb-kept".into()]);

            assert_eq!(reclaim_budget(&d), 1, "running, booting and suspended all count");
        }

        /// The cap is what keeps this from becoming the leak it closes: a host
        /// carrying a hundred stale sandboxes must not hand all hundred to one
        /// deployment that would then never destroy any of them.
        #[test]
        fn a_deployment_at_its_ceiling_reclaims_nothing() {
            let (_a, reg) = autoscaler();
            let d = deployment(&reg, IdleAction::Retain, 1);
            d.set_backends(vec![Arc::new(VmBackend::new(
                "sb-live".into(),
                "10.0.0.1:80".parse().unwrap(),
            ))]);

            assert_eq!(reclaim_budget(&d), 0);
        }

        #[test]
        fn the_budget_never_goes_negative() {
            let (a, reg) = autoscaler();
            let d = deployment(&reg, IdleAction::Retain, 1);
            a.remember_suspended(&d, vec!["a".into(), "b".into(), "c".into()]);
            assert_eq!(reclaim_budget(&d), 0);
        }

        /// Reclaiming is limited to `retain` on purpose: under `destroy` a
        /// stopped sandbox of ours is one this LB already decided it did not
        /// want, and taking it back would quietly convert every deployment to
        /// `retain`.
        #[test]
        fn only_retain_deployments_are_reclaim_candidates() {
            let (_a, reg) = autoscaler();
            let d = deployment(&reg, IdleAction::Destroy, 4);
            assert!(d.spec.is_managed());
            assert_ne!(d.spec.scaling.idle_action, IdleAction::Retain);

            let d = deployment(&reg, IdleAction::Retain, 4);
            assert_eq!(d.spec.scaling.idle_action, IdleAction::Retain);
        }

        /// A reclaimed sandbox has to land in the same record `scale_up` reads,
        /// or the resume path never sees it and the churn continues.
        #[test]
        fn a_reclaimed_sandbox_is_what_the_next_scale_up_resumes() {
            let (a, reg) = autoscaler();
            let d = deployment(&reg, IdleAction::Retain, 4);

            a.remember_suspended(&d, vec!["sb-recovered".into()]);
            assert_eq!(a.take_suspended(&d).as_deref(), Some("sb-recovered"));
        }
    }

    #[tokio::test]
    async fn graceful_eviction_marks_the_backend_draining() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        let b = Arc::new(VmBackend::new("sb-1".into(), "10.0.0.1:80".parse().unwrap()));
        d.set_backends(vec![b.clone()]);

        let out = a.evict(&d, "sb-1", false).await;
        assert!(matches!(out, EvictOutcome::Draining), "got {out:?}");
        assert!(b.is_draining(), "eviction must stop new traffic to the VM");
        // The backend is still in the pool (the autoscaler reaps it later), but
        // is no longer selectable.
        assert!(d.select(&[]).is_none());
    }

    #[tokio::test]
    async fn evicting_an_unknown_vm_is_not_found() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        d.set_backends(vec![Arc::new(VmBackend::new(
            "sb-1".into(),
            "10.0.0.1:80".parse().unwrap(),
        ))]);

        let out = a.evict(&d, "sb-does-not-exist", false).await;
        assert!(matches!(out, EvictOutcome::NotFound), "got {out:?}");
    }

    fn pending(id: &str) -> PendingVm {
        PendingVm::new(id.into())
    }

    #[test]
    fn a_deployment_is_live_only_while_the_registry_holds_that_object() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        assert!(a.is_live(&d));

        // A rebuild installs a different object; the old handle is stale even
        // though the id is still registered.
        let fresh = reg.upsert(spec());
        assert!(!a.is_live(&d));
        assert!(a.is_live(&fresh));

        reg.remove("demo");
        assert!(!a.is_live(&fresh));
    }

    /// The leak this guards: a VM created while an admin request deregisters the
    /// deployment lands in a pool nobody reconciles, and runs until its TTL.
    #[test]
    fn vms_created_for_a_deregistered_deployment_are_unclaimed() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        let created = vec!["sb-1".to_string()];

        assert!(
            a.unclaimed(&d, &created).is_empty(),
            "while it is live, the autoscaler owns what it created",
        );

        reg.remove("demo");
        assert_eq!(a.unclaimed(&d, &created), created);
    }

    /// A rebuild (`POST`, or a `PUT` that changes the VM template) starts from an
    /// empty pool, so nothing it left behind is inherited.
    #[test]
    fn a_rebuild_inherits_nothing() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        d.set_pending(vec![pending("sb-1")]);

        reg.upsert(spec());
        assert_eq!(a.unclaimed(&d, &["sb-1".to_string()]), vec!["sb-1".to_string()]);
    }

    /// …but a pool-preserving edit carries the pool over, so those VMs are still
    /// tracked and must *not* be killed.
    #[test]
    fn a_pool_preserving_edit_keeps_the_vms_it_inherited() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        d.set_pending(vec![pending("sb-inherited")]);
        d.set_backends(vec![Arc::new(VmBackend::new(
            "sb-running".into(),
            "10.0.0.1:80".parse().unwrap(),
        ))]);

        // A scaling-only edit: `Registry::update` copies both lists onto the new
        // object, which now owns those VMs.
        let mut edited = spec();
        edited.scaling.max_replicas = 9;
        let new = reg.update(edited).unwrap();
        assert!(!Arc::ptr_eq(&new, &d), "the edit installs a new object");

        assert!(
            a.unclaimed(&d, &["sb-inherited".into(), "sb-running".into()]).is_empty(),
            "the replacement inherited these; killing them would drop live capacity",
        );
        // One created *after* the copy is in neither list, so it is abandoned.
        assert_eq!(
            a.unclaimed(&d, &["sb-too-late".to_string()]),
            vec!["sb-too-late".to_string()],
        );
    }

    #[test]
    fn nothing_created_means_nothing_to_reap() {
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        reg.remove("demo");
        // Stale, but there is nothing to check — and no registry lookup to make.
        assert!(a.unclaimed(&d, &[]).is_empty());
    }

    fn info(status: heyo_sdk::SandboxStatus, guest_ip: Option<&str>) -> SandboxInfo {
        SandboxInfo {
            id: "sb-1".into(),
            name: "applb-demo-000000000001".into(),
            status,
            image: "artifacts".into(),
            region: None,
            start_command: None,
            working_directory: None,
            size_class: None,
            // Added to `SandboxInfo` after 0.1.6; unset for the same
            // reason the rest of these are — nothing here reads it.
            disk_size_gb: None,
            env_vars: None,
            setup_hooks: None,
            uptime_secs: 0,
            ttl_seconds: None,
            is_deployed: true,
            error_message: None,
            status_changed_at: String::new(),
            urls: vec![],
            guest_ip: guest_ip.map(Into::into),
            metadata: None,
            account_id: None,
            created_at: None,
            cpus: None,
            memory: None,
            backend_type: None,
        }
    }

    /// `at_rest` decides whether a deployment is skipped for the tick, so every
    /// false positive is a deployment that silently stops being reconciled.
    /// These cases are the ones that would produce one.
    mod at_rest {
        use super::*;

        /// One healthy VM at the desired size, TTL fresh: the shape of an idle
        /// agent sandbox, and the case the fast path exists for.
        fn settled() -> (Arc<Deployment>, HashMap<String, SandboxInfo>) {
            let mut s = spec();
            s.scaling.min_replicas = 1;
            s.scaling.max_replicas = 1;
            let d = Arc::new(Deployment::new(s));
            d.set_backends(vec![Arc::new(VmBackend::new(
                "sb-1".into(),
                "10.0.0.1:8080".parse().unwrap(),
            ))]);
            let mut fleet = HashMap::new();
            fleet.insert("sb-1".to_string(), info(heyo_sdk::SandboxStatus::Running, Some("10.0.0.1")));
            (d, fleet)
        }

        /// The common case: the daemon runs exactly what the pool tracks.
        fn no_extras() -> HashMap<&'static str, usize> {
            HashMap::new()
        }

        /// The rule that stops a single replica slot from buying VMs forever.
        ///
        /// Before this, a pending VM absent from one fleet listing was dropped
        /// on the spot. That freed the slot, `live` fell below `desired`, and
        /// the next tick created a replacement — every 2s, each one holding a
        /// `disk_size_gb` data disk nothing tracked. Ten sandboxes and ten disks
        /// for one replica is what that looked like in production.
        ///
        /// So the first absence must *hold*, and holding must be bounded.
        #[test]
        fn a_missing_pending_vm_holds_its_slot_then_gives_up() {
            let t = 1_000_000u64;

            // First sighting: start the clock and keep the slot.
            assert_eq!(hold_missing(None, t), Some(t), "a fresh absence holds");

            // Still inside the window: keep holding, and keep the *original*
            // timestamp — re-stamping it each tick would hold forever.
            assert_eq!(hold_missing(Some(t), t + 1), Some(t));
            assert_eq!(hold_missing(Some(t), t + MISSING_GRACE - 1), Some(t));

            // Boundary and beyond: give up, so the VM is killed and reclaimed
            // rather than silently forgotten.
            assert_eq!(hold_missing(Some(t), t + MISSING_GRACE), None);
            assert_eq!(hold_missing(Some(t), t + MISSING_GRACE * 10), None);

            // Clock skew must not read as an elapsed grace: `saturating_sub`
            // floors at zero, so a timestamp from the future still holds.
            assert_eq!(hold_missing(Some(t + 5), t), Some(t + 5));
        }

        #[test]
        fn an_idle_pool_at_its_desired_size_is_at_rest() {
            let (d, fleet) = settled();
            assert!(at_rest(&d, &fleet, &no_extras()));
        }

        /// The fast path must not hide a VM that exists but is in no pool.
        ///
        /// This is the at-rest half of the duplicate-VM leak: a create that the
        /// client gave up on while the daemon went on to build the sandbox
        /// leaves a replica nothing tracks. If the pool is otherwise at its
        /// desired size, every condition above says "nothing to do" and the VM
        /// runs unreferenced until its TTL — a day here, holding its data disk
        /// the whole time. Counting owned sandboxes is what routes this
        /// deployment to `reconcile_one`, where `adopt_untracked` takes it back.
        #[test]
        fn a_running_vm_the_pool_does_not_track_is_work() {
            let (d, fleet) = settled();
            let owned = HashMap::from([("demo", 2)]);
            assert_eq!(d.backends().len(), 1, "one tracked backend");
            assert!(
                !at_rest(&d, &fleet, &owned),
                "the daemon runs two replicas for a pool that tracks one",
            );
            // Equal counts are the normal case and must stay on the fast path.
            assert!(at_rest(&d, &fleet, &HashMap::from([("demo", 1)])));
            // Fewer is not this check's business: a backend missing from the
            // fleet is already caught below.
            assert!(at_rest(&d, &fleet, &HashMap::from([("demo", 0)])));
        }

        #[test]
        fn a_booting_vm_is_work() {
            let (d, fleet) = settled();
            d.set_pending(vec![PendingVm::new("sb-2".into())]);
            assert!(!at_rest(&d, &fleet, &no_extras()));
        }

        #[test]
        fn a_draining_vm_is_work() {
            let (d, fleet) = settled();
            d.backends()[0].set_draining(true);
            assert!(!at_rest(&d, &fleet, &no_extras()));
        }

        #[test]
        fn being_below_the_desired_size_is_work() {
            let (d, fleet) = settled();
            d.set_backends(vec![]);
            assert!(!at_rest(&d, &fleet, &no_extras()));
        }

        /// Half the TTL gone means a renewal call is due, and that is an await.
        #[test]
        fn a_ttl_past_its_halfway_mark_is_work() {
            let (d, mut fleet) = settled();
            let entry = fleet.get_mut("sb-1").unwrap();
            entry.ttl_seconds = Some(3600);
            entry.uptime_secs = 1800;
            assert!(!at_rest(&d, &fleet, &no_extras()));
        }

        /// A backend the daemon no longer reports has just disappeared. Reading
        /// that as "nothing to do" would leave a dead VM in the routing pool.
        #[test]
        fn a_backend_missing_from_the_fleet_is_work() {
            let (d, _) = settled();
            assert!(!at_rest(&d, &HashMap::new(), &no_extras()));
        }
    }

    /// The message is the deliverable here: "it hangs on VM creation" has two
    /// completely different causes, and only one of them is worth waiting out.
    #[test]
    fn a_stalled_boot_says_whether_the_daemon_or_the_guest_is_the_problem() {
        let check = crate::config::HealthCheck {
            expected_header: None,
            path: Some("/healthz".into()),
            port: None,
            timeout_secs: 2,
        };

        // Daemon side: nothing to do but wait.
        let waiting = boot_stall(&info(heyo_sdk::SandboxStatus::Provisioning, None), &check, 8080);
        assert!(waiting.contains("daemon"), "{waiting}");
        assert!(!waiting.contains("guest"), "{waiting}");

        // Guest side — the artifacts case: the VM is up, the server inside is
        // not, and no amount of waiting will change that. The probe target has to
        // be named, because that is what somebody goes and checks.
        let stalled = boot_stall(&info(heyo_sdk::SandboxStatus::Running, Some("172.16.0.2")), &check, 8080);
        assert!(stalled.contains("guest is up"), "{stalled}");
        assert!(stalled.contains("/healthz"), "{stalled}");
        // The address actually dialled, so it can be tried by hand from the host.
        assert!(stalled.contains("172.16.0.2:8080"), "{stalled}");

        // A daemon that has an explanation gets to give it.
        let mut failing = info(heyo_sdk::SandboxStatus::Provisioning, None);
        failing.error_message = Some("no space left on device".into());
        assert!(
            boot_stall(&failing, &check, 8080).contains("no space left on device"),
            "the daemon's own reason must survive",
        );

        // A TCP-only check names no path, so it must not claim to have requested one.
        let tcp = crate::config::HealthCheck { expected_header: None, path: None, port: Some(9000), timeout_secs: 2 };
        let msg = boot_stall(&info(heyo_sdk::SandboxStatus::Running, Some("172.16.0.2")), &tcp, 8080);
        assert!(msg.contains("TCP") && msg.contains("9000"), "{msg}");
    }

    /// A pending VM per 2s tick per line would bury the log this is meant to make
    /// readable; a pending VM with *no* line is the bug being fixed. So: first
    /// sighting, every transition, and a heartbeat.
    #[test]
    fn boot_progress_is_logged_on_change_and_on_a_heartbeat_but_not_every_tick() {
        use heyo_sdk::SandboxStatus;
        let (a, reg) = autoscaler();
        let d = reg.get("demo").unwrap();
        let p = pending("sb-1");

        // First sighting: nothing has named this sandbox id yet, so it reports.
        let first = a.note_boot_progress(&d, &p, &info(SandboxStatus::Provisioning, None), 2);
        assert_eq!(first.status, Some(SandboxStatus::Provisioning));
        assert_eq!(first.reported_at_secs, 2);

        // Same status a tick later: quiet.
        let quiet = a.note_boot_progress(&d, &first, &info(SandboxStatus::Provisioning, None), 4);
        assert_eq!(quiet.reported_at_secs, 2, "should not have reported again");

        // Transition to Running: reports immediately, without waiting out the
        // heartbeat — this is the moment the diagnosis changes from "the daemon is
        // slow" to "the guest is not answering".
        let moved = a.note_boot_progress(&d, &quiet, &info(SandboxStatus::Running, Some("172.16.0.2")), 6);
        assert_eq!(moved.reported_at_secs, 6);
        assert_eq!(moved.status, Some(SandboxStatus::Running));

        // Unchanged, but the heartbeat is due.
        let beat = a.note_boot_progress(
            &d,
            &moved,
            &info(SandboxStatus::Running, Some("172.16.0.2")),
            6 + BOOT_HEARTBEAT,
        );
        assert_eq!(beat.reported_at_secs, 6 + BOOT_HEARTBEAT);

        // The identity that makes any of this safe: nothing but the bookkeeping
        // changes, so the VM keeps its id and its birthday across every tick.
        assert_eq!(beat.sandbox_id, p.sandbox_id);
        assert_eq!(beat.created_at, p.created_at);
    }

    #[tokio::test]
    async fn tearing_down_a_static_deployment_just_clears_routing() {
        let (a, reg) = autoscaler();
        reg.upsert(static_spec());
        let d = reg.get("proxy").unwrap();
        // Prepopulated from the spec's upstreams.
        assert_eq!(d.backends().len(), 1);

        // Static backends are not sandboxes, so teardown must not dial the
        // daemon (the test VmManager points at a dead port); it just drops them.
        a.teardown(&d).await;
        assert!(d.backends().is_empty());
    }

    #[tokio::test]
    async fn unhealthy_ready_managed_backend_recovers_only_after_health_succeeds() {
        use heyo_sdk::SandboxStatus;
        use std::sync::atomic::AtomicBool;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let healthy = Arc::new(AtomicBool::new(false));
        let serving = healthy.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let ok = serving.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut request = [0; 256];
                    let _ = stream.read(&mut request).await;
                    let status = if ok { "200 OK" } else { "503 Service Unavailable" };
                    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });

        let mut deployment_spec = spec();
        deployment_spec.health.port = Some(addr.port());
        let (a, reg) = autoscaler_against("http://127.0.0.1:1", deployment_spec);
        let d = reg.get("demo").unwrap();
        let backend = Arc::new(VmBackend::new("sb-1".into(), addr));
        backend.set_healthy(false);
        d.set_backends(vec![backend.clone()]);
        let fleet = HashMap::from([(
            "sb-1".into(),
            info(SandboxStatus::Running, Some("127.0.0.1")),
        )]);

        a.reprobe_unhealthy_managed(&d, &fleet).await;
        assert!(!backend.is_healthy(), "a 503 must remain unroutable");

        healthy.store(true, Ordering::Relaxed);
        a.reprobe_unhealthy_managed(&d, &fleet).await;
        assert!(backend.is_healthy(), "a successful re-probe restores routing");
        assert_eq!(d.backends()[0].sandbox_id, "sb-1", "recovery does not replace the VM");
    }

    #[tokio::test]
    async fn reserved_rollout_recovers_source_without_adoption_scaling_or_persistence() {
        use heyo_sdk::SandboxStatus;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024]; socket.read(&mut request).await.unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            }
        });
        let mut spec = spec();
        spec.health.port = Some(addr.port());
        spec.scaling.min_replicas = 4; spec.scaling.max_replicas = 4;
        let (scaler, registry) = autoscaler_against("http://127.0.0.1:1", spec);
        let d = registry.get("demo").unwrap();
        let source = Arc::new(VmBackend::new("source".into(), addr));
        let draining = Arc::new(VmBackend::new("draining".into(), addr));
        draining.set_draining(true);
        d.set_backends(vec![source.clone(), draining.clone()]);
        let mut candidate = info(SandboxStatus::Running, Some("127.0.0.1"));
        candidate.id = "candidate".into(); candidate.name = "applb-demo-candidate".into();
        let fleet = HashMap::from([
            ("source".into(), info(SandboxStatus::Running, Some("127.0.0.1"))),
            ("candidate".into(), candidate),
        ]);
        for status in ["running", "reconciliation_required"] {
            let operation = serde_json::from_value(serde_json::json!({
                "operation_id":"reserved", "deployment":"demo", "source_revision":"before",
                "target_spec_sha256":"hash", "status":status, "phase":"preparing",
                "readiness_verified":false, "previous_stopped":false, "error":null,
                "spec":d.spec, "prepared":null, "prefix":"applb-demo-candidate",
                "allocations":[], "previous":["source"], "stopped":[], "deadline":0, "drain_deadline":null
            })).unwrap();
            d.mutate_state(|s| s.rollouts = vec![operation]);
            registry.persist_one("demo").unwrap();
            let state = d.state();
            let persisted = std::fs::read(registry.state_dir().join("demo.json")).unwrap();
            source.set_healthy(false);
            scaler.reconcile_one(&d, &fleet, &HashMap::new()).await;
            assert!(source.is_healthy(), "source recovery must work while {status}");
            assert!(draining.is_draining(), "recovery cannot reopen admission on a retiring VM");
            assert_eq!(d.backends().len(), 2, "candidate must not be adopted and source must not be pruned");
            assert!(Arc::ptr_eq(&d.backends()[0], &source));
            assert!(d.pending().is_empty(), "reserved deployment cannot scale");
            assert_eq!(*d.state(), *state, "no lifecycle state mutation");
            assert_eq!(std::fs::read(registry.state_dir().join("demo.json")).unwrap(), persisted);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn workspace_recovery_admission_waits_for_creates_and_blocks_new_placement() {
        let mut spec = spec();
        spec.vm.as_mut().unwrap().workspace = Some(serde_json::from_value(serde_json::json!({"store":"/unused"})).unwrap());
        let (scaler, registry) = autoscaler_against("http://127.0.0.1:1", spec);
        let d = registry.get("demo").unwrap();
        let in_progress = scaler.creates.acquire().await.unwrap();
        let guard = scaler.workspace_recovery_guard(); tokio::pin!(guard);
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut guard).await.is_err());
        drop(in_progress);
        let admission = guard.await;
        scaler.workspaces.begin_replacement("demo", 1).unwrap();
        let create = scaler.scale_up(&d, 1); tokio::pin!(create);
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut create).await.is_err());
        drop(admission);
        create.await;
        assert!(d.pending().is_empty());
        assert!(scaler.workspaces.blocked(&d).is_some());
    }

    mod scheduled_snapshots {
        use super::*;

        fn b(id: &str, up: u64) -> Arc<VmBackend> {
            Arc::new(VmBackend::ready_secs_ago(id, up))
        }

        #[test]
        fn nothing_without_an_interval() {
            assert_eq!(snapshot_candidate(None, &[b("sb-1", 10 * 86_400)]), None);
        }

        #[test]
        fn a_replica_up_longer_than_the_interval_is_recycled() {
            assert_eq!(snapshot_candidate(Some(3600), &[b("sb-1", 3599)]), None);
            assert_eq!(
                snapshot_candidate(Some(3600), &[b("sb-1", 3600)]),
                Some("sb-1".to_string())
            );
        }

        #[test]
        fn nothing_while_a_replica_is_already_draining() {
            let draining = b("sb-1", 7200);
            draining.set_draining(true);
            assert_eq!(snapshot_candidate(Some(3600), &[draining]), None);
        }

        #[test]
        fn a_due_deployment_is_not_at_rest() {
            let mut s = spec();
            s.scaling.min_replicas = 1;
            s.scaling.max_replicas = 1;
            s.vm.as_mut().unwrap().workspace = Some(crate::config::WorkspaceSpec {
                path: None,
                store: "/srv/art".into(),
                artifact_ref: None,
                auth: None,
                snapshot_interval_secs: Some(3600),
            });
            let (_scaler, registry) = autoscaler_against("http://127.0.0.1:1", s);
            let d = registry.get("demo").unwrap();
            let fleet = |up: u64| {
                let info: SandboxInfo = serde_json::from_value(serde_json::json!({
                    "id": "sb-1", "name": "applb-demo-000000000001", "status": "running",
                    "image": "demo", "uptime_secs": up, "is_deployed": true,
                    "status_changed_at": "", "urls": [], "ttl_seconds": 86_400
                }))
                .unwrap();
                HashMap::from([("sb-1".to_string(), info)])
            };
            d.set_backends(vec![b("sb-1", 60)]);
            assert!(at_rest(&d, &fleet(60), &HashMap::new()), "a fresh replica is at rest");
            d.set_backends(vec![b("sb-1", 3700)]);
            assert!(!at_rest(&d, &fleet(3700), &HashMap::new()), "a due one needs reconcile_one");
        }
    }

    /// Sandboxes named for a deployment this LB does not have. The 2026-09-29
    /// incident: a second app-lb with an empty state file destroyed every
    /// sandbox the live one served, disks and uncaptured workspaces included.
    mod unowned_sandboxes {
        use super::*;
        use axum::{Json, Router, extract::{Path, State}, routing::{delete, get, post}};
        use std::sync::Mutex;

        #[derive(Default)]
        struct Daemon {
            stopped: Mutex<Vec<String>>,
            deleted: Mutex<Vec<String>>,
        }

        fn row(id: &str, name: &str, status: &str) -> serde_json::Value {
            serde_json::json!({
                "id": id, "name": name, "status": status,
                "image": "fastcar", "uptime_secs": 0, "is_deployed": true,
                "status_changed_at": "", "urls": [], "guest_ip": "127.0.0.1"
            })
        }

        /// A daemon running one sandbox owned by `ghost` — a deployment no
        /// test registers — and holding one stopped `ghost` sandbox.
        async fn daemon() -> (String, Arc<Daemon>, tokio::task::JoinHandle<()>) {
            let d = Arc::new(Daemon::default());
            let app = Router::new()
                .route("/deployed-sandboxes", get(|| async {
                    Json(vec![row("sb-running", "applb-ghost-000000000001", "running")])
                }))
                .route("/sandboxes/inactive", get(|| async {
                    Json(serde_json::json!({
                        "sandboxes": [row("sb-stopped", "applb-ghost-000000000002", "stopped")],
                        "next_cursor": null
                    }))
                }))
                .route("/deployed-sandboxes/:id", delete(|State(d): State<Arc<Daemon>>, Path(id): Path<String>| async move {
                    d.deleted.lock().unwrap().push(id);
                    Json(serde_json::json!({}))
                }))
                .route("/sandbox/:id/stop", post(|State(d): State<Arc<Daemon>>, Path(id): Path<String>| async move {
                    d.stopped.lock().unwrap().push(id);
                    Json(serde_json::json!({}))
                }))
                .with_state(d.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (url, d, server)
        }

        #[tokio::test]
        async fn an_lb_with_no_deployments_touches_nothing() {
            let (url, daemon, server) = daemon().await;
            let (scaler, registry) = autoscaler_against(&url, spec());
            registry.remove("demo");
            assert!(registry.deployments().is_empty());
            scaler.adopt_existing().await;
            scaler.sweep_suspended().await;
            assert!(daemon.deleted.lock().unwrap().is_empty(), "nothing destroyed");
            assert!(daemon.stopped.lock().unwrap().is_empty(), "nothing stopped either");
            server.abort();
        }

        #[tokio::test]
        async fn a_sandbox_of_an_unknown_deployment_is_stopped_never_destroyed() {
            let (url, daemon, server) = daemon().await;
            let (scaler, _registry) = autoscaler_against(&url, spec());
            scaler.adopt_existing().await;
            assert_eq!(*daemon.stopped.lock().unwrap(), vec!["sb-running".to_string()]);
            assert!(daemon.deleted.lock().unwrap().is_empty(), "its disk is kept");
            server.abort();
        }

        #[tokio::test]
        async fn the_suspended_sweep_leaves_unknown_stopped_sandboxes_to_the_disk_ttl() {
            let (url, daemon, server) = daemon().await;
            let (scaler, _registry) = autoscaler_against(&url, spec());
            scaler.sweep_suspended().await;
            assert!(daemon.deleted.lock().unwrap().is_empty());
            server.abort();
        }
    }

    #[tokio::test]
    async fn record_only_inventory_detects_untracked_and_inactive_resources() {
        use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
        use std::sync::atomic::AtomicUsize;
        let mode = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/deployed-sandboxes", get(|State(mode): State<Arc<AtomicUsize>>| async move {
                let owned = serde_json::json!({
                    "id": "sb-1", "name": "applb-demo-000000000001", "status": "running",
                    "image": "artifacts", "uptime_secs": 0, "is_deployed": true,
                    "status_changed_at": "", "urls": [], "guest_ip": "127.0.0.1"
                });
                Json(if mode.load(Ordering::SeqCst) == 2 { vec![owned] } else { vec![] })
            }))
            .route("/sandboxes/inactive", get(|State(mode): State<Arc<AtomicUsize>>| async move {
                if mode.load(Ordering::SeqCst) == 3 { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
                let owned = serde_json::json!({
                    "id": "sb-1", "name": "applb-demo-000000000001", "status": "stopped",
                    "image": "artifacts", "uptime_secs": 0, "is_deployed": true,
                    "status_changed_at": "", "urls": []
                });
                let rows = if mode.load(Ordering::SeqCst) == 1 { vec![owned] } else { vec![] };
                Json(serde_json::json!({"sandboxes": rows, "next_cursor": null})).into_response()
            })).with_state(mode.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (scaler, registry) = autoscaler_against(&url, spec());
        assert!(registry.get("demo").unwrap().backends().is_empty());
        assert!(!scaler.has_owned_resources("demo").await.unwrap());
        for state in [1, 2] {
            mode.store(state, Ordering::SeqCst);
            assert!(scaler.has_owned_resources("demo").await.unwrap());
            assert!(!scaler.has_owned_resources("another-deployment").await.unwrap());
        }
        mode.store(3, Ordering::SeqCst);
        assert!(scaler.has_owned_resources("demo").await.is_err(), "unavailable inventory is not empty");
        server.abort();
    }
}
