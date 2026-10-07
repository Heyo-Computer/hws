//! Live deployment state: the VM pool, in-flight accounting, and selection.

use crate::config::{DeploymentSpec, StaticUpstream};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A single routable backend — a ready VM, or a static proxy_pass upstream.
///
/// `in_flight` is the one number that matters: it picks the upstream *and*
/// drives the autoscaler, which is why we track it ourselves instead of using
/// pingora-load-balancing (whose selection algorithms cannot see it).
///
/// `peer` is the address handed to pingora (`HttpPeer`) and the identity used
/// for retry-exclusion and display. It is a `host:port` *string* rather than a
/// resolved `SocketAddr` so a static upstream can be a hostname that pingora
/// re-resolves per connection.
#[derive(Debug)]
pub struct VmBackend {
    pub sandbox_id: String,
    pub peer: String,
    /// Resolvable connection address, separated from `peer` because an HTTPS
    /// upstream keeps its URL as the stable identity shown to operators.
    pub address: String,
    pub tls: bool,
    pub sni: String,
    /// Makes checking admission and reserving an in-flight slot atomic with an
    /// operator drain. Selection itself is intentionally lock-free and may be
    /// stale; [`try_acquire`](Self::try_acquire) is the authoritative gate.
    admission: Mutex<()>,
    in_flight: AtomicUsize,
    draining: AtomicBool,
    healthy: AtomicBool,
    last_active: AtomicU64,
    /// When this VM joined the pool (LB clock). Serving uptime, as opposed to
    /// the daemon's `uptime_secs` which counts provisioning too; this is what
    /// the LB actually watched the VM serve for.
    ready_at: u64,
    /// Latest CPU/memory sample from the daemon's `/system/usage`, refreshed by
    /// the autoscaler each tick. CPU is stored as f64 bits (percent of a core);
    /// `has_usage` distinguishes "no sample yet" from a genuine zero.
    cpu_percent_bits: AtomicU64,
    mem_bytes: AtomicU64,
    has_usage: AtomicBool,
    /// The daemon-side proxy bind of this VM's port, when the deployment has
    /// `ingress.cloud`: the subdomain the daemon minted, which is what the
    /// cloud routes the deployment's URL to. `None` until bound, and again
    /// once unbound on drain. See [`crate::config::IngressSpec`].
    bind: Mutex<Option<String>>,
}

impl VmBackend {
    /// A backend for a managed VM, addressed by its resolved guest `SocketAddr`.
    pub fn new(sandbox_id: String, addr: SocketAddr) -> Self {
        let address = addr.to_string();
        Self::with_peer(sandbox_id, address.clone(), address, false, String::new())
    }

    /// A backend for a static proxy_pass upstream, addressed by a `host:port`
    /// string (which pingora resolves per connection). The address doubles as the
    /// backend's display id, since there is no sandbox.
    pub fn for_upstream(address: String) -> Self {
        let target = StaticUpstream::parse(&address)
            .expect("deployment specs validate static upstreams before construction");
        Self::with_peer(
            address.clone(),
            address,
            target.address,
            target.tls,
            target.sni,
        )
    }

    fn with_peer(sandbox_id: String, peer: String, address: String, tls: bool, sni: String) -> Self {
        Self {
            sandbox_id,
            peer,
            address,
            tls,
            sni,
            admission: Mutex::new(()),
            in_flight: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
            healthy: AtomicBool::new(true),
            last_active: AtomicU64::new(now_secs()),
            ready_at: now_secs(),
            cpu_percent_bits: AtomicU64::new(0),
            mem_bytes: AtomicU64::new(0),
            has_usage: AtomicBool::new(false),
            bind: Mutex::new(None),
        }
    }

    /// A backend that became ready `secs` ago, for tests of uptime rules.
    #[cfg(test)]
    pub fn ready_secs_ago(sandbox_id: &str, secs: u64) -> Self {
        let mut b = Self::new(sandbox_id.to_string(), "127.0.0.1:9".parse().unwrap());
        b.ready_at = now_secs().saturating_sub(secs);
        b
    }

    /// The daemon-side bind of this VM's port, if it has one.
    pub fn bind(&self) -> Option<String> {
        self.bind.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Record (or forget) the daemon-side bind.
    pub fn set_bind(&self, subdomain: Option<String>) {
        *self.bind.lock().unwrap_or_else(|e| e.into_inner()) = subdomain;
    }

    /// Seconds this VM has been in the pool.
    pub fn uptime_secs(&self) -> u64 {
        now_secs().saturating_sub(self.ready_at)
    }

    /// Record the latest resource sample for this VM.
    pub fn set_usage(&self, cpu_percent: f64, mem_bytes: u64) {
        self.cpu_percent_bits
            .store(cpu_percent.to_bits(), Ordering::Relaxed);
        self.mem_bytes.store(mem_bytes, Ordering::Relaxed);
        self.has_usage.store(true, Ordering::Relaxed);
    }

    /// Latest `(cpu_percent, mem_bytes)`, or `None` if the daemon has not yet
    /// reported usage for this VM (freshly promoted, or usage unavailable).
    pub fn usage(&self) -> Option<(f64, u64)> {
        self.has_usage.load(Ordering::Relaxed).then(|| {
            (
                f64::from_bits(self.cpu_percent_bits.load(Ordering::Relaxed)),
                self.mem_bytes.load(Ordering::Relaxed),
            )
        })
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Eligible to receive a *new* request. A draining VM keeps serving what it
    /// already has, but takes nothing new.
    pub fn is_available(&self) -> bool {
        self.is_healthy() && !self.is_draining()
    }

    pub fn set_draining(&self, draining: bool) {
        let _guard = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.draining.store(draining, Ordering::Relaxed);
    }

    pub fn set_healthy(&self, healthy: bool) {
        let _guard = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn last_active(&self) -> u64 {
        self.last_active.load(Ordering::Relaxed)
    }

    pub fn acquire(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.last_active.store(now_secs(), Ordering::Relaxed);
    }

    /// Reserve this backend for a new request if it is still accepting traffic.
    ///
    /// The admission mutex closes the selection-to-acquire race: after
    /// `set_draining(true)` returns, either a request is already reflected in
    /// `in_flight`, or it cannot acquire a slot.
    pub fn try_acquire(&self) -> bool {
        let _guard = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if !self.is_available() {
            return false;
        }
        self.acquire();
        true
    }

    /// Saturating so a double-release can never wrap to `usize::MAX` and pin the
    /// deployment at max replicas forever.
    pub fn release(&self) {
        let _ = self
            .in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
        self.last_active.store(now_secs(), Ordering::Relaxed);
    }
}

/// Holds an in-flight slot on a backend for as long as it lives.
///
/// The proxy releases its slot by hand (`Ctx::release`, which has to be
/// idempotent across several exit paths). A shell session cannot: it lives for
/// minutes or hours across an arbitrary number of failure modes, and a leaked
/// slot pins the deployment at max replicas forever.
///
/// Holding a slot is also what keeps a session's VM alive. An unrouted sandbox
/// serves no requests, so nothing else moves `last_active` — without this, a
/// deployment with `scale_to_zero_after_secs` set would reap the VM out from
/// under an open shell.
pub struct BackendSlot {
    backend: Arc<VmBackend>,
}

impl BackendSlot {
    pub fn sandbox_id(&self) -> &str {
        &self.backend.sandbox_id
    }
}

impl Drop for BackendSlot {
    fn drop(&mut self) {
        self.backend.release();
    }
}

impl VmBackend {
    /// Try to take an in-flight slot, released when the returned guard drops.
    pub fn try_hold(self: &Arc<Self>) -> Option<BackendSlot> {
        self.try_acquire().then(|| BackendSlot {
            backend: self.clone(),
        })
    }
}

/// Where a pending VM came from, and therefore what may be deleted if its boot
/// never finishes.
///
/// The whole point of the distinction is disk reclamation. A boot that fails
/// leaves per-sandbox disks behind, and whether they are disposable is not a
/// property of the failure — it is a property of where the sandbox came from.
/// Guessing wrong in one direction leaks gigabytes; guessing wrong in the other
/// destroys a deployment's retained state, so the origin is recorded at the
/// moment it is known rather than inferred later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOrigin {
    /// `VmManager::create` made this sandbox for this boot. Nothing has ever
    /// served from it and no earlier replica is hiding inside it: its
    /// `/workspace` holds only whatever the guest managed to write on the way
    /// to failing. Disks are disposable.
    Created,
    /// A suspended replica the pool resumed. Its `/workspace` *is* the
    /// deployment's retained state — the reason `take_suspended` prefers it
    /// over a fresh boot — so a failed resume must leave every disk alone and
    /// let the sweep or an operator decide.
    Resumed,
}

/// A VM that has been created but is not yet serving.
///
/// The two progress fields exist because a boot that never finishes is otherwise
/// completely silent: the autoscaler simply re-queues the VM every tick, forever,
/// with nothing logged and nothing on the dashboard but a `pending` count. They
/// are plain values rather than atomics because `promote_pending` rebuilds this
/// vec on every tick and is the only writer — it carries the previous tick's
/// values forward, so there is nothing to share.
#[derive(Debug, Clone)]
pub struct PendingVm {
    pub sandbox_id: String,
    pub created_at: u64,
    /// The same instant in milliseconds, for the boot timings in the
    /// "VM ready" line; `0` when unknown (a VM adopted after a restart).
    pub created_ms: u64,
    /// The daemon's last reported status, `None` before the first observation.
    /// Kept so a *transition* (Provisioning → Running, or → Stopped) can be
    /// logged the moment it happens instead of at the next heartbeat.
    pub status: Option<heyo_sdk::SandboxStatus>,
    /// Age in seconds at which this VM's progress was last logged. Bounds the
    /// heartbeat: a pool of stuck VMs must not write a line per VM per 2s tick.
    pub reported_at_secs: u64,
    /// Fresh boot or resumed replica. See [`BootOrigin`]; read only by the
    /// autoscaler's give-up path, to decide whether the disks may be reclaimed.
    pub origin: BootOrigin,
    /// When this VM first went missing from the daemon's fleet listing, if it
    /// currently is. `None` means it was in the most recent listing.
    ///
    /// A created sandbox is this deployment's responsibility until something
    /// explicitly kills it, and absence from one listing is not proof it is
    /// gone — a sandbox still provisioning (copying a multi-gigabyte rootfs, on
    /// a loaded host) may simply not be listed yet. Dropping it on the first
    /// miss did two harmful things at once: it leaked the sandbox, *and* it
    /// freed the replica slot, so the next tick created a duplicate — every 2s,
    /// unboundedly, for as long as the condition lasted.
    pub missing_since: Option<u64>,
}

impl PendingVm {
    /// A freshly created sandbox. The common case, and the one whose disks a
    /// failed boot may reclaim.
    pub fn new(sandbox_id: String) -> Self {
        Self {
            sandbox_id,
            created_at: now_secs(),
            created_ms: crate::obs::now_millis().max(0) as u64,
            status: None,
            reported_at_secs: 0,
            origin: BootOrigin::Created,
            missing_since: None,
        }
    }

    /// A suspended replica being woken up, whose data disk carries state from
    /// before it was suspended and must outlive a failed resume.
    pub fn resumed(sandbox_id: String) -> Self {
        Self {
            origin: BootOrigin::Resumed,
            ..Self::new(sandbox_id)
        }
    }

    /// When this VM was created, in milliseconds. `created_ms` only when it
    /// agrees with `created_at`: a VM adopted after a restart has its
    /// `created_at` dated from the daemon's uptime, and its `created_ms` is
    /// then just when the record was made.
    pub fn created_at_ms(&self) -> u64 {
        if self.created_ms != 0 && self.created_ms / 1000 == self.created_at {
            self.created_ms
        } else {
            self.created_at.saturating_mul(1000)
        }
    }

    /// How long this VM has been booting.
    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.created_at)
    }
}

/// Per-deployment runtime state that has to outlive a restart.
///
/// Distinct from the spec: the spec is what the operator wrote, this is what the
/// LB learned. It is persisted alongside the spec because losing it leaks real
/// resources — a suspended sandbox that app-lb forgets is invisible to the
/// daemon's running-VM list and so is never reaped by anything.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UpstreamDrain {
    /// The exact `host:port` entry from `DeploymentSpec::upstreams`.
    pub upstream: String,
    /// Operator context for the drain. Informational; never used for routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// LB-clock Unix timestamp at which new traffic was stopped.
    pub started_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct DeploymentState {
    /// Irreversible controller freeze; neither reload nor ordinary updates clear it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<crate::retirement::Operation>,
    /// Write-ahead evidence for ordinary allocation attempts. Unknown outcomes
    /// remain here across restart and prevent a retirement success receipt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_attempts: Vec<crate::retirement::CreateAttempt>,
    /// False for old records, any legacy create dispatch, unjournaled adoption
    /// or arbitrary host worker. Success on /sandbox-deploy cannot prove an
    /// exactly-once allocation because its queue delivery may be replayed.
    /// No API or timeout can promote this bit back to true.
    #[serde(default)]
    pub allocation_history_complete: bool,
    #[serde(default = "crate::rollout::revision")]
    pub rollout_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rollouts: Vec<crate::rollout::Operation>,
    /// Sandboxes this deployment stopped rather than destroyed, under
    /// `scaling.idle_action: retain`. They hold their `/workspace` data disk and
    /// are candidates for resume in preference to a cold create.
    ///
    /// Tracked here because a stopped sandbox is **absent** from the daemon's
    /// `GET /sandboxes` (mvm-ctrl drops it from the in-memory map on stop), so
    /// the fleet list cannot be asked what we suspended.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspended: Vec<String>,
    /// Static upstreams administratively removed from new-request selection.
    ///
    /// Separate from health: a failed probe may recover by itself; an operator
    /// drain stays in force across health changes and process restarts until it
    /// is explicitly removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_drains: Vec<UpstreamDrain>,
    /// Highest Orchestrator endpoint-set version applied to this deployment.
    /// Persisting it prevents an app-lb restart from accepting a snapshot older
    /// than the last upstream membership it routed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_version: Option<u64>,
    /// Source that actually supplied the durable discovery version, not just
    /// the current environment setting. Prevents falsely attesting a new source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_source_url: Option<String>,
    /// Durable public-selector transition. A committed record makes restart
    /// fail closed on the regional spec until fresh discovery is observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_handoff: Option<crate::registry::RouteHandoffRecord>,
}

#[derive(Debug)]
pub struct Deployment {
    pub spec: DeploymentSpec,
    pub regional: Option<Arc<crate::regional::Router>>,
    /// Runtime state, persisted with the spec. Copy-on-write like the pools.
    state: ArcSwap<DeploymentState>,
    /// Ready, routable VMs. Copy-on-write: the autoscaler is the only writer.
    backends: ArcSwap<Vec<Arc<VmBackend>>>,
    /// Booting VMs, not yet routable.
    pending: ArcSwap<Vec<PendingVm>>,
    /// Requests blocked waiting for a VM to boot.
    ///
    /// This is real demand that `in_flight` cannot see: a waiting request has no
    /// backend to hold a slot on. Without counting it, a scaled-to-zero
    /// deployment looks idle *while a request is waiting on it*, so the
    /// autoscaler leaves it at zero and the request blocks until it times out.
    waiters: AtomicUsize,
    /// Wakes cold-start waiters when a VM becomes ready, and nudges the
    /// autoscaler when a request arrives with nowhere to go.
    pub ready_signal: Notify,
    pub scale_signal: Notify,
    /// Keeps independent runtime-state writers from losing each other's fields.
    /// In particular, suspended-VM bookkeeping must not erase an upstream drain.
    state_change_lock: Mutex<()>,
    /// Consecutive VM boot failures — timeouts and terminal statuses alike.
    ///
    /// Runtime-only, like the pools: a restart (or a spec update, which builds a
    /// new `Deployment`) starts the count over, which is right — both are
    /// exactly the moments a broken image may have been fixed.
    boot_failures: AtomicU64,
    /// Epoch seconds before which the autoscaler must not create VMs for this
    /// deployment. See [`boot_backoff_secs`].
    boot_backoff_until: AtomicU64,
}

impl Deployment {
    pub fn new(spec: DeploymentSpec) -> Self {
        // A static (proxy_pass) deployment has a fixed set of backends known at
        // registration; populate them now so it is routable immediately and the
        // autoscaler never has to (indeed, it skips static deployments entirely).
        let backends: Vec<Arc<VmBackend>> = spec
            .upstreams
            .iter()
            .map(|addr| Arc::new(VmBackend::for_upstream(addr.clone())))
            .collect();
        Self {
            regional: spec.discovery.as_ref().and_then(|d| d.regional.as_ref()).map(|_| Arc::new(crate::regional::Router::new())),
            spec,
            state: ArcSwap::from_pointee(DeploymentState { allocation_history_complete:true, rollout_revision: crate::rollout::revision(), ..Default::default() }),
            backends: ArcSwap::from_pointee(backends),
            pending: ArcSwap::from_pointee(Vec::new()),
            waiters: AtomicUsize::new(0),
            ready_signal: Notify::new(),
            scale_signal: Notify::new(),
            state_change_lock: Mutex::new(()),
            boot_failures: AtomicU64::new(0),
            boot_backoff_until: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> Arc<DeploymentState> {
        self.state.load_full()
    }

    pub fn set_state(&self, state: DeploymentState) {
        let _guard = self
            .state_change_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.apply_state(state);
    }

    fn apply_state(&self, state: DeploymentState) {
        if self.spec.is_static() {
            for backend in self.backends().iter() {
                backend.set_draining(
                    state
                        .upstream_drains
                        .iter()
                        .any(|drain| drain.upstream == backend.peer),
                );
            }
        }
        self.state.store(Arc::new(state));
    }

    /// The durable operator drain for one static upstream, if any.
    pub fn upstream_drain(&self, upstream: &str) -> Option<UpstreamDrain> {
        self.state()
            .upstream_drains
            .iter()
            .find(|drain| drain.upstream == upstream)
            .cloned()
    }

    /// Read-modify-write the runtime state, returning whether it changed.
    ///
    /// The return value is what tells a caller whether the change is worth a
    /// disk write; these paths run every tick and usually change nothing.
    pub fn mutate_state(&self, f: impl FnOnce(&mut DeploymentState)) -> bool {
        let _guard = self
            .state_change_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = self.state();
        let mut next = (*before).clone();
        f(&mut next);
        if next == *before {
            return false;
        }
        self.apply_state(next);
        true
    }

    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Relaxed)
    }

    /// Register a cold-start waiter for as long as the guard lives.
    pub fn track_waiter(self: &Arc<Self>) -> WaiterGuard {
        self.waiters.fetch_add(1, Ordering::Relaxed);
        WaiterGuard {
            deployment: self.clone(),
        }
    }

    pub fn backends(&self) -> Arc<Vec<Arc<VmBackend>>> {
        self.backends.load_full()
    }

    pub fn set_backends(&self, backends: Vec<Arc<VmBackend>>) {
        let _guard = self
            .state_change_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.spec.is_static() {
            let state = self.state();
            for backend in &backends {
                backend.set_draining(
                    state
                        .upstream_drains
                        .iter()
                        .any(|drain| drain.upstream == backend.peer),
                );
            }
        }
        self.backends.store(Arc::new(backends));
    }

    pub fn pending(&self) -> Arc<Vec<PendingVm>> {
        self.pending.load_full()
    }

    pub fn set_pending(&self, pending: Vec<PendingVm>) {
        self.pending.store(Arc::new(pending));
    }

    /// Total in-flight across the pool, including draining VMs — they still
    /// represent real load.
    pub fn total_in_flight(&self) -> usize {
        self.backends().iter().map(|b| b.in_flight()).sum()
    }

    /// Least-in-flight pick, skipping backends already tried on this request.
    ///
    /// `exclude` is what makes retry work: on `fail_to_connect` we re-enter
    /// `upstream_peer` and must not hand back the backend that just failed. The
    /// exclusion key is the peer address string (see [`VmBackend::peer`]).
    pub fn select(&self, exclude: &[String]) -> Option<Arc<VmBackend>> {
        self.backends()
            .iter()
            .filter(|b| b.is_available() && !exclude.contains(&b.peer))
            .min_by_key(|b| b.in_flight())
            .cloned()
    }

    /// Whether the autoscaler could still add capacity, i.e. whether a request
    /// arriving now is worth holding for a cold start.
    ///
    /// Always false for anything without a VM pool: a static deployment's
    /// upstream set is fixed and a site has no backends at all, so a request
    /// that finds nothing available must fail fast rather than hold for a boot
    /// that will never come.
    pub fn can_grow(&self) -> bool {
        if !self.spec.is_managed() {
            return false;
        }
        let live = self.backends().len() + self.pending().len();
        (live as u32) < self.spec.scaling.max_replicas
    }

    /// Total demand: requests being served plus requests waiting for a VM.
    ///
    /// Waiters must be included or a scaled-to-zero deployment can never wake
    /// up: the request that would justify a VM is precisely the one with no VM
    /// to be counted against.
    pub fn demand(&self) -> usize {
        self.total_in_flight() + self.waiters()
    }

    /// Desired ready-replica count.
    ///
    /// Load term: enough VMs to keep each at `target_concurrency`. The warm pool
    /// is *additive* — spare capacity above current load — then the whole thing
    /// is clamped to [min, max].
    ///
    /// Scale-to-zero requires `warm_pool == 0`: a warm pool exists precisely to
    /// absorb cold starts, so honouring both would be contradictory. It would
    /// also be unreachable in practice — an empty pool reports maximal idleness,
    /// so a warm pool that ever emptied could never refill itself.
    pub fn desired_replicas(&self) -> u32 {
        let policy = &self.spec.scaling;
        let demand = self.demand();

        let needed = demand.div_ceil(policy.target_concurrency.max(1) as usize) as u32;
        let mut desired = needed.saturating_add(policy.warm_pool);

        let may_scale_to_zero = policy.min_replicas == 0 && policy.warm_pool == 0;
        if may_scale_to_zero && demand == 0 && self.idle_for() >= policy.scale_to_zero_after_secs {
            desired = 0;
        }

        desired.clamp(policy.min_replicas, policy.max_replicas)
    }

    /// Seconds since the pool last saw activity. An empty pool is treated as
    /// maximally idle so a scaled-to-zero deployment stays there.
    pub fn idle_for(&self) -> u64 {
        let backends = self.backends();
        if backends.is_empty() {
            return u64::MAX;
        }
        let last = backends.iter().map(|b| b.last_active()).max().unwrap_or(0);
        now_secs().saturating_sub(last)
    }

    // -- boot-failure backoff ------------------------------------------------

    /// Record one failed boot and push the create embargo out.
    ///
    /// Returns the streak length and the delay it produced, so the caller can
    /// log one line that says both.
    pub fn note_boot_failure(&self, now: u64) -> (u64, u64) {
        let failures = self.boot_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let delay = boot_backoff_secs(failures);
        self.boot_backoff_until
            .store(now.saturating_add(delay), Ordering::Relaxed);
        (failures, delay)
    }

    /// A VM booted and passed its health check: the image works, so the streak
    /// and any embargo end. Returns whether there was a streak to clear, so the
    /// recovery is logged once rather than on every routine promotion.
    pub fn note_boot_success(&self) -> bool {
        self.boot_backoff_until.store(0, Ordering::Relaxed);
        self.boot_failures.swap(0, Ordering::Relaxed) != 0
    }

    /// Seconds until the autoscaler may create VMs again, or `None` when it may
    /// do so now.
    pub fn boot_backoff_remaining(&self, now: u64) -> Option<u64> {
        let until = self.boot_backoff_until.load(Ordering::Relaxed);
        (until > now).then(|| until - now)
    }

    /// Failed boots in a row since the last VM that passed its health check.
    /// What [`boot_backoff_secs`] grows from; reset by a healthy boot, and —
    /// because every spec write builds a fresh `Deployment` — by any edit.
    pub fn boot_failure_streak(&self) -> u64 {
        self.boot_failures.load(Ordering::Relaxed)
    }
}

/// First backoff after a failed boot. Small on purpose: one flaky boot must not
/// add real latency to a request already waiting on a cold start.
const BOOT_BACKOFF_BASE_SECS: u64 = 30;

/// The ceiling. A deployment that has failed this many times in a row is down
/// either way; retrying hourly keeps it visible without feeding the churn.
const BOOT_BACKOFF_MAX_SECS: u64 = 3600;

/// How long to wait before replacing a failed boot, by streak length.
///
/// Doubles from thirty seconds to an hour. This exists because the reconcile
/// loop otherwise replaces a doomed VM on its next 2-second tick, forever: a
/// deployment whose guest exits immediately used to churn a sandbox every few
/// seconds — and one whose guest merely never answered health checks, one every
/// `boot_timeout_secs` — each cycle a fresh sandbox id and a fresh set of disk
/// directories, with no error state anywhere that stopped it.
pub fn boot_backoff_secs(failures: u64) -> u64 {
    if failures == 0 {
        return 0;
    }
    BOOT_BACKOFF_BASE_SECS
        .saturating_mul(1 << (failures - 1).min(63))
        .min(BOOT_BACKOFF_MAX_SECS)
}

/// Keeps a deployment's waiter count accurate for the life of a cold-start wait.
///
/// RAII because the wait has several exits (VM arrives, timeout, request
/// cancelled); a leaked waiter would keep the deployment scaled up forever.
pub struct WaiterGuard {
    deployment: Arc<Deployment>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let _ = self
            .deployment
            .waiters
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCheck, RouteRule, ScalingPolicy, VmSpec};
    use crate::config::Driver;

    fn backend(addr: &str) -> Arc<VmBackend> {
        Arc::new(VmBackend::new(format!("sb-{addr}"), addr.parse().unwrap()))
    }

    fn deployment(scaling: ScalingPolicy) -> Deployment {
        Deployment::new(DeploymentSpec {
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
            scaling,
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
        })
    }

    /// A static (proxy_pass) deployment with the given upstreams.
    fn static_deployment(upstreams: &[&str]) -> Deployment {
        Deployment::new(DeploymentSpec {
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
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            discovery: None,
            gateway: None,
            build: None,
            artifact: None,
            site: None,
            update: None,
            auth: None,
        })
    }

    #[test]
    fn selects_least_in_flight() {
        let d = deployment(ScalingPolicy::default());
        let a = backend("10.0.0.1:80");
        let b = backend("10.0.0.2:80");
        a.acquire();
        a.acquire();
        b.acquire();
        d.set_backends(vec![a, b.clone()]);
        assert_eq!(d.select(&[]).unwrap().peer, b.peer);
    }

    #[test]
    fn select_skips_excluded_draining_and_unhealthy() {
        let d = deployment(ScalingPolicy::default());
        let a = backend("10.0.0.1:80");
        let b = backend("10.0.0.2:80");
        let c = backend("10.0.0.3:80");
        d.set_backends(vec![a.clone(), b.clone(), c.clone()]);

        // Excluding the first (e.g. it just failed to connect) moves on.
        assert_eq!(d.select(std::slice::from_ref(&a.peer)).unwrap().peer, b.peer);

        b.set_draining(true);
        c.set_healthy(false);
        assert!(d.select(std::slice::from_ref(&a.peer)).is_none());
        assert_eq!(d.select(&[]).unwrap().peer, a.peer);
    }

    #[test]
    fn https_upstream_keeps_identity_and_separates_tls_connection_details() {
        let backend = VmBackend::for_upstream("https://ci.eu1.heyo.work:443".into());
        assert_eq!(backend.peer, "https://ci.eu1.heyo.work:443");
        assert_eq!(backend.address, "ci.eu1.heyo.work:443");
        assert!(backend.tls);
        assert_eq!(backend.sni, "ci.eu1.heyo.work");

        let plaintext = VmBackend::for_upstream("ci.eu1.heyo.work:443".into());
        assert!(!plaintext.tls);
        assert!(plaintext.sni.is_empty());
    }

    #[test]
    fn a_durable_static_drain_stops_new_traffic_but_not_in_flight_work() {
        let d = static_deployment(&["eu1.example:443", "us1.example:443"]);
        let eu1 = d.backends()[0].clone();
        eu1.acquire();

        d.set_state(DeploymentState {
            upstream_drains: vec![UpstreamDrain {
                upstream: eu1.peer.clone(),
                reason: Some("regional maintenance".into()),
                started_at: 123,
            }],
            ..Default::default()
        });

        assert!(eu1.is_draining());
        assert_eq!(eu1.in_flight(), 1, "the existing request remains accounted for");
        assert_eq!(d.select(&[]).unwrap().peer, "us1.example:443");
        eu1.release();
        assert_eq!(eu1.in_flight(), 0);
        assert!(eu1.is_draining(), "drain intent remains after work reaches zero");
    }

    #[test]
    fn removing_a_static_drain_makes_a_healthy_upstream_available_again() {
        let d = static_deployment(&["eu1.example:443", "us1.example:443"]);
        let eu1 = d.backends()[0].clone();
        d.set_state(DeploymentState {
            upstream_drains: vec![UpstreamDrain {
                upstream: eu1.peer.clone(),
                reason: None,
                started_at: 123,
            }],
            ..Default::default()
        });
        assert!(eu1.is_draining());

        d.set_state(DeploymentState::default());
        assert!(eu1.is_available());
    }

    #[test]
    fn cordon_is_atomic_with_new_request_admission() {
        let backend = Arc::new(VmBackend::for_upstream("eu1.example:443".into()));
        assert!(backend.try_acquire());
        assert_eq!(backend.in_flight(), 1);

        backend.set_draining(true);
        assert!(
            !backend.try_acquire(),
            "no slot may appear after set_draining returns",
        );
        assert_eq!(backend.in_flight(), 1, "the admitted request remains visible");

        backend.release();
        assert_eq!(backend.in_flight(), 0);
        backend.set_draining(false);
        assert!(backend.try_acquire(), "uncordon reopens admission when healthy");
        backend.release();
    }

    #[test]
    fn static_deployment_is_routable_immediately_and_cannot_grow() {
        let d = static_deployment(&["10.0.0.9:8080", "backend.internal:8080"]);
        // Backends are populated from the spec at construction, no autoscaler.
        assert_eq!(d.backends().len(), 2);
        assert!(d.spec.is_static());
        // Never holds a request for a cold start.
        assert!(!d.can_grow());
        // Load-balances least-in-flight across the fixed upstreams.
        let first = d.select(&[]).unwrap();
        first.acquire();
        let second = d.select(&[]).unwrap();
        assert_ne!(first.peer, second.peer, "second request picks the idle upstream");
    }

    #[test]
    fn select_on_empty_pool_is_none_not_panic() {
        let d = deployment(ScalingPolicy::default());
        assert!(d.select(&[]).is_none());
    }

    #[test]
    fn release_saturates_at_zero() {
        let b = backend("10.0.0.1:80");
        b.release();
        b.release();
        assert_eq!(b.in_flight(), 0);
        b.acquire();
        assert_eq!(b.in_flight(), 1);
    }

    #[test]
    fn acquire_release_round_trips() {
        let b = backend("10.0.0.1:80");
        for _ in 0..5 {
            b.acquire();
        }
        assert_eq!(b.in_flight(), 5);
        for _ in 0..5 {
            b.release();
        }
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn desired_scales_with_load() {
        let d = deployment(ScalingPolicy {
            min_replicas: 1,
            max_replicas: 10,
            target_concurrency: 10,
            ..Default::default()
        });
        let a = backend("10.0.0.1:80");
        d.set_backends(vec![a.clone()]);

        // 25 in-flight / target 10 -> ceil = 3.
        for _ in 0..25 {
            a.acquire();
        }
        assert_eq!(d.desired_replicas(), 3);
    }

    #[test]
    fn desired_is_clamped_to_min_and_max() {
        let d = deployment(ScalingPolicy {
            min_replicas: 2,
            max_replicas: 4,
            target_concurrency: 1,
            ..Default::default()
        });
        let a = backend("10.0.0.1:80");
        d.set_backends(vec![a.clone()]);
        // Idle, but min_replicas holds the floor.
        assert_eq!(d.desired_replicas(), 2);

        // Far past max, but the ceiling holds.
        for _ in 0..100 {
            a.acquire();
        }
        assert_eq!(d.desired_replicas(), 4);
    }

    #[test]
    fn warm_pool_adds_headroom_above_load() {
        let d = deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 10,
            warm_pool: 2,
            target_concurrency: 10,
            scale_to_zero_after_secs: 0,
            ..Default::default()
        });
        let a = backend("10.0.0.1:80");
        d.set_backends(vec![a.clone()]);

        // Idle: just the warm pool. Scale-to-zero must not eat it, even though
        // min_replicas is 0 and the pool is idle.
        assert_eq!(d.desired_replicas(), 2);

        // 10 in-flight needs 1, plus 2 warm spares.
        for _ in 0..10 {
            a.acquire();
        }
        assert_eq!(d.desired_replicas(), 3);
    }

    /// Regression: an empty pool reports `idle_for() == u64::MAX`, so a warm
    /// pool starting from zero used to be zeroed out by scale-to-zero and could
    /// never boot its first VM.
    #[test]
    fn warm_pool_bootstraps_from_an_empty_pool() {
        let d = deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 3,
            warm_pool: 1,
            target_concurrency: 2,
            scale_to_zero_after_secs: 300,
            ..Default::default()
        });
        assert_eq!(d.desired_replicas(), 1);
    }

    #[test]
    fn scales_to_zero_only_when_idle_and_min_is_zero() {
        let d = deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 4,
            warm_pool: 0,
            target_concurrency: 10,
            scale_to_zero_after_secs: 0, // idle immediately
            ..Default::default()
        });
        let a = backend("10.0.0.1:80");
        d.set_backends(vec![a.clone()]);
        assert_eq!(d.desired_replicas(), 0);

        // In-flight work blocks scale-to-zero even when "idle" by time.
        a.acquire();
        assert_eq!(d.desired_replicas(), 1);
    }

    #[test]
    fn empty_pool_stays_at_zero_when_allowed() {
        let d = deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 4,
            scale_to_zero_after_secs: 300,
            ..Default::default()
        });
        // No backends => idle_for is MAX => desired 0, and no panic on max().
        assert_eq!(d.desired_replicas(), 0);
    }

    #[test]
    fn zero_ceiling_prevents_wake_despite_in_flight_requests_and_waiters() {
        let d = Arc::new(deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 0,
            warm_pool: 0,
            ..Default::default()
        }));
        let a = backend("10.0.0.1:80");
        a.acquire();
        d.set_backends(vec![a]);
        let _waiter = d.track_waiter();
        assert_eq!(d.demand(), 2);
        assert_eq!(d.desired_replicas(), 0);
        assert!(!d.can_grow());
        d.set_backends(vec![]);
        assert_eq!(d.demand(), 1);
        assert_eq!(d.desired_replicas(), 0);
        assert!(!d.can_grow(), "a request cannot wake the paused pool");
    }

    /// Regression: a request waiting on a scaled-to-zero deployment holds no
    /// in-flight slot, so the pool looked idle and stayed at zero — the waiting
    /// request then blocked until its cold-start timeout and 500'd.
    #[test]
    fn a_cold_start_waiter_is_demand_and_forces_scale_up() {
        let d = Arc::new(deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 3,
            warm_pool: 0,
            target_concurrency: 2,
            scale_to_zero_after_secs: 0, // maximally eager to scale to zero
            ..Default::default()
        }));
        assert_eq!(d.desired_replicas(), 0);

        let guard = d.track_waiter();
        assert_eq!(d.demand(), 1);
        assert_eq!(
            d.desired_replicas(),
            1,
            "a waiting request must justify booting a VM",
        );

        drop(guard);
        assert_eq!(d.demand(), 0);
        assert_eq!(d.desired_replicas(), 0, "waiter must not leak after drop");
    }

    #[test]
    fn waiters_and_in_flight_both_count_toward_demand() {
        let d = Arc::new(deployment(ScalingPolicy {
            min_replicas: 0,
            max_replicas: 10,
            target_concurrency: 2,
            scale_to_zero_after_secs: 0,
            ..Default::default()
        }));
        let a = backend("10.0.0.1:80");
        d.set_backends(vec![a.clone()]);
        for _ in 0..4 {
            a.acquire();
        }
        let _g1 = d.track_waiter();
        let _g2 = d.track_waiter();
        // 4 in-flight + 2 waiting = 6, over target 2 => 3 replicas.
        assert_eq!(d.demand(), 6);
        assert_eq!(d.desired_replicas(), 3);
    }

    #[test]
    fn concurrent_waiters_are_tracked_independently() {
        let d = Arc::new(deployment(ScalingPolicy::default()));
        let guards: Vec<_> = (0..5).map(|_| d.track_waiter()).collect();
        assert_eq!(d.waiters(), 5);
        drop(guards);
        assert_eq!(d.waiters(), 0);
    }

    #[test]
    fn can_grow_counts_pending_against_max() {
        let d = deployment(ScalingPolicy {
            max_replicas: 2,
            ..Default::default()
        });
        assert!(d.can_grow());
        d.set_backends(vec![backend("10.0.0.1:80")]);
        assert!(d.can_grow());
        // A booting VM already counts, so we don't over-provision.
        d.set_pending(vec![PendingVm::new("sb-2".into())]);
        assert!(!d.can_grow());
    }

    /// The schedule that keeps a deployment whose guest never boots from
    /// churning a fresh sandbox every reconcile tick.
    #[test]
    fn boot_backoff_doubles_from_thirty_seconds_to_an_hour() {
        assert_eq!(boot_backoff_secs(0), 0, "no failures, no embargo");
        assert_eq!(boot_backoff_secs(1), 30);
        assert_eq!(boot_backoff_secs(2), 60);
        assert_eq!(boot_backoff_secs(3), 120);
        assert_eq!(boot_backoff_secs(7), 1920);
        assert_eq!(boot_backoff_secs(8), 3600, "capped, not 3840");
        // A streak long enough to overflow the shift must still cap cleanly.
        assert_eq!(boot_backoff_secs(1000), 3600);
    }

    /// The origin is what stands between a failed resume and the deletion of a
    /// deployment's retained `/workspace`, so it is asserted at the constructors
    /// rather than trusted: `new` is the disposable case and `resumed` is not,
    /// and a default that silently drifted to `Created` would be invisible until
    /// it took somebody's data disk.
    #[test]
    fn a_pending_vm_records_whether_its_disks_are_disposable() {
        assert_eq!(
            PendingVm::new("sb-1".into()).origin,
            BootOrigin::Created,
            "a fresh create has nothing worth keeping",
        );
        assert_eq!(
            PendingVm::resumed("sb-1".into()).origin,
            BootOrigin::Resumed,
            "a resumed replica's data disk is the state it was suspended to keep",
        );
        // `resumed` builds on `new`, so guard the rest of the fields against a
        // future edit to either constructor.
        let r = PendingVm::resumed("sb-1".into());
        assert_eq!(r.sandbox_id, "sb-1");
        assert_eq!(r.status, None);
        assert_eq!(r.reported_at_secs, 0);
    }

    #[test]
    fn boot_failures_embargo_creates_and_a_success_clears_it() {
        let d = deployment(ScalingPolicy::default());
        let now = 1000;
        assert_eq!(d.boot_backoff_remaining(now), None, "starts clear");

        let (streak, delay) = d.note_boot_failure(now);
        assert_eq!((streak, delay), (1, 30));
        assert_eq!(d.boot_backoff_remaining(now), Some(30));
        assert_eq!(d.boot_backoff_remaining(now + 30), None, "expires on time");

        // A second failure doubles the wait and restarts it from *its* now.
        let (streak, delay) = d.note_boot_failure(now + 30);
        assert_eq!((streak, delay), (2, 60));
        assert_eq!(d.boot_backoff_remaining(now + 31), Some(59));

        // One good boot ends the streak — and says so exactly once.
        assert!(d.note_boot_success(), "there was a streak to clear");
        assert_eq!(d.boot_backoff_remaining(now + 31), None);
        assert!(!d.note_boot_success(), "routine promotions stay quiet");
        assert_eq!(d.note_boot_failure(now).0, 1, "the count restarted");
    }
}
