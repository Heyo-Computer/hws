//! Where a `spread` deployment's replicas run (`docs/design/fleet-shared-state.md`
//! § 4): the placement controller, and each host's view of its decisions.
//!
//! **Every host**, once a second:
//! - reports `(in_flight, waiters, ready, booting, idle)` for each `spread`
//!   deployment it runs into `host_demand`, only when the numbers change;
//! - reads every host's reports and every placement target into a [`View`].
//!   The data plane reads the view, never the database.
//!
//! **The controller**, whichever host holds the `placement` lease, every 2 s:
//! - computes each `spread` deployment's fleet-wide replica count with the
//!   same formula a single host uses ([`crate::deployment::desired_for`]),
//!   from the fleet's summed demand, so `min_replicas` and `warm_pool` count
//!   once for the fleet;
//! - splits it over the live, active hosts the deployment may run on,
//!   preferring hosts with demand, then hosts already running replicas;
//! - gives a draining host nothing, but lets it keep the replicas it has
//!   ready until the active hosts have theirs (make before break);
//! - writes `placement_targets`, fenced by the lease's epoch.
//!
//! It never creates a VM. Each host's autoscaler reconciles its own daemon to
//! its own target ([`target`]). Without a controller, a host keeps its last
//! target. One exception covers scale-from-zero: a request waits on a host
//! only when no peer has replicas ready or is asked to run any (or it arrived
//! by hop), so a host holding a waiter with a target of zero boots one
//! replica on its own authority. The controller absorbs it on its next tick,
//! since that host now reports the demand.

use crate::config::{DeploymentSpec, PlacementMode, ScalingPolicy};
use crate::fleet_pg::{Capacity, DemandReport, HostRow};
use crate::fleet_sync::{Fleet, Lease};
use crate::registry::Registry;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const LEASE_PLACEMENT: &str = "placement";
/// A host's lifecycle states (`fleet.hosts.state`, design § 7).
pub const ACTIVE: &str = "active";
pub const DRAINING: &str = "draining";
pub const MAINTENANCE: &str = "maintenance";
/// How long a draining host must see no direct client request for a
/// `spread` deployment, with none of their replicas left, before it is in
/// maintenance: DNS TTL plus the health check's detection time plus margin.
pub const DEFAULT_DRAIN_QUIET: Duration = Duration::from_secs(360);
const SYNC_EVERY: Duration = Duration::from_secs(1);
const PLAN_EVERY: Duration = Duration::from_secs(2);
/// The controller rewrites an unchanged plan this often, so a target lost
/// to a failed write never stays lost.
const REWRITE_EVERY: Duration = Duration::from_secs(30);

/// This process's placer, in fleet mode. Global because every `Deployment`
/// asks it for its target and deployments are rebuilt on every spec write.
static PLACER: OnceLock<Arc<Placer>> = OnceLock::new();

/// A host is full for this long after its daemon refuses a create for
/// capacity, so the controller stops sending it new replicas.
const FULL_AFTER_REFUSAL: Duration = Duration::from_secs(300);
/// A host with less memory than this available takes no new replicas.
const FULL_BELOW_FREE_MB: u64 = 1024;
/// Capacity is rewritten at least this often, so its report never goes
/// stale ([`crate::fleet_pg::CAPACITY_STALE_SECS`]) while the host is up.
const CAPACITY_EVERY: Duration = Duration::from_secs(30);

/// The latest host sample from this daemon's `/system/usage`, fed by the
/// autoscaler's usage poll: `(cpus, memory total, memory available)` in bytes.
static HOST_USAGE: Mutex<Option<(u32, u64, u64)>> = Mutex::new(None);
/// When this host's daemon last refused a create for capacity.
static CAPACITY_REFUSED: Mutex<Option<Instant>> = Mutex::new(None);

/// Record this host's latest usage sample. Cheap, and harmless outside a
/// fleet: nothing reads it there.
pub fn note_host_usage(cpus: u32, memory_total_bytes: u64, memory_available_bytes: u64) {
    *HOST_USAGE.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((cpus, memory_total_bytes, memory_available_bytes));
}

/// Whether a refused create's error says the daemon is out of capacity, as
/// heyvmd's memory admission does ("host memory capacity unavailable").
pub fn is_capacity_refusal(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("capacity unavailable")
        || m.contains("insufficient memory")
        || m.contains("out of memory")
}

/// Record that this host's daemon just refused a create for capacity.
pub fn note_capacity_refusal() {
    *CAPACITY_REFUSED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
}

/// This host's capacity from the latest sample, or `None` before the first.
fn local_capacity() -> Option<Capacity> {
    let (cpus, total, available) = (*HOST_USAGE.lock().unwrap_or_else(|e| e.into_inner()))?;
    if total == 0 {
        return None;
    }
    let refused = CAPACITY_REFUSED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some_and(|t| t.elapsed() < FULL_AFTER_REFUSAL);
    let mb = |b: u64| b / (1024 * 1024);
    Some(Capacity {
        cpus,
        mem_total_mb: mb(total),
        mem_free_mb: mb(available),
        full: refused || mb(available) < FULL_BELOW_FREE_MB,
    })
}

/// Whether two capacity reports differ enough to be worth a write: `full`
/// changed, or free memory moved by more than 5% of the total.
fn capacity_moved(a: &Capacity, b: &Capacity) -> bool {
    a.full != b.full
        || a.cpus != b.cpus
        || a.mem_total_mb != b.mem_total_mb
        || a.mem_free_mb.abs_diff(b.mem_free_mb) * 20 > a.mem_total_mb.max(1)
}

/// Whether new pinned deployments that name no home go to the fleet host
/// with the most free memory (`APP_LB_FLEET_PLACE_BY_CAPACITY=1`). Off by
/// default: a deployment then runs on the host that took the request.
pub fn place_by_capacity() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("APP_LB_FLEET_PLACE_BY_CAPACITY")
            .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"))
    })
}

/// Whether a new deployment may be homed on another host than the one that
/// took the request. Only a plain VM pool qualifies: anything the receiving
/// host would prepare locally at registration (a build, a site, mounts it
/// pulls, a local artifact or workspace store, an update script, a tunnel,
/// discovery or gateways, static upstreams) stays where it was registered.
pub fn capacity_placeable(spec: &DeploymentSpec) -> bool {
    let Some(vm) = spec.vm.as_ref() else {
        return false;
    };
    spec.build.is_none()
        && spec.site.is_none()
        && spec.update.is_none()
        && spec.tunnel.is_none()
        && spec.discovery.is_none()
        && spec.gateway.is_none()
        && spec.upstreams.is_empty()
        && vm.mounts.is_empty()
        && spec.artifact.as_ref().is_none_or(|a| a.is_remote())
        && vm.workspace.as_ref().is_none_or(|w| {
            !matches!(
                w.backend(),
                Some(crate::config::WorkspaceStore::Local(_)) | None
            )
        })
}

/// [`choose_home`] over the installed placer's live members; `None` outside a
/// fleet or before the member list is readable.
pub fn choose_home_now() -> Option<String> {
    choose_home(&placer()?.fleet.live_members())
}

/// The home for a new pinned deployment, chosen by free memory among the
/// live, active members that reported capacity and are not full. `None`
/// when no member has a usable report: the caller keeps today's rule (the
/// host that took the request).
pub fn choose_home(members: &[HostRow]) -> Option<String> {
    members
        .iter()
        .filter(|m| m.state == ACTIVE)
        .filter_map(|m| m.capacity.filter(|c| !c.full).map(|c| (m, c)))
        // Most free memory; ties go to the first host by name, for a stable
        // answer.
        .max_by(|(ma, a), (mb, b)| {
            a.mem_free_mb
                .cmp(&b.mem_free_mb)
                .then_with(|| mb.host.cmp(&ma.host))
        })
        .map(|(m, _)| m.host.clone())
}

pub fn install(placer: Arc<Placer>) {
    let _ = PLACER.set(placer);
}

pub fn placer() -> Option<&'static Arc<Placer>> {
    PLACER.get()
}

pub(crate) fn spreads(spec: &DeploymentSpec) -> bool {
    spec.placement
        .as_ref()
        .is_some_and(|p| p.mode == PlacementMode::Spread)
}

/// How many replicas this host should run for `spec`, when the fleet decides
/// that rather than this host: `None` for anything but a `spread` deployment
/// in fleet mode.
pub fn target(spec: &DeploymentSpec, waiters: usize) -> Option<u32> {
    if !spreads(spec) {
        return None;
    }
    let placer = placer()?;
    let view = placer.view.load();
    // Before the first read, the host sizes itself: a restart must keep the
    // replicas it adopts, not drain them for an empty view.
    if !view.loaded {
        return None;
    }
    let mine = view
        .targets
        .get(&spec.id)
        .and_then(|(_, hosts)| hosts.get(&placer.host).copied())
        .unwrap_or(0);
    // A request waits here only when no peer could take it (or it arrived
    // by hop), so a waiter with no target here boots one replica here.
    let stranded = waiters > 0 && mine == 0;
    Some(if stranded { 1 } else { mine }.min(spec.scaling.max_replicas))
}

/// The cached state of the fleet's placement, as of the last sync.
#[derive(Debug, Default)]
pub struct View {
    /// Whether this was read from the fleet, not the empty start.
    loaded: bool,
    /// deployment → (generation, host → desired).
    targets: HashMap<String, (u64, HashMap<String, u32>)>,
    /// deployment → host → report.
    demand: HashMap<String, HashMap<String, DemandReport>>,
}

pub struct Placer {
    host: String,
    fleet: Arc<Fleet>,
    registry: Arc<Registry>,
    forwards: bool,
    lease: Arc<Lease>,
    view: ArcSwap<View>,
    /// What this host last reported, so unchanged numbers are not rewritten.
    reported: Mutex<Option<HashMap<String, DemandReport>>>,
    /// The capacity this host last wrote, and when.
    reported_capacity: Mutex<Option<(Capacity, Instant)>>,
    planned: Mutex<Option<Instant>>,
    last_write: Mutex<Option<Instant>>,
    /// The last request for a `spread` deployment that a client sent here
    /// directly, not by hop: what a drain waits to stop.
    last_direct: Mutex<Instant>,
    drain_quiet: Duration,
}

impl Placer {
    pub fn new(host: &str, fleet: Arc<Fleet>, registry: Arc<Registry>, forwards: bool) -> Self {
        let lease = fleet.lease(LEASE_PLACEMENT);
        Self {
            host: host.to_string(),
            fleet,
            registry,
            forwards,
            lease,
            view: ArcSwap::from_pointee(View::default()),
            reported: Mutex::new(None),
            reported_capacity: Mutex::new(None),
            planned: Mutex::new(None),
            last_write: Mutex::new(None),
            last_direct: Mutex::new(Instant::now()),
            drain_quiet: DEFAULT_DRAIN_QUIET,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn drain_quiet(&self) -> Duration {
        self.drain_quiet
    }

    pub fn with_drain_quiet(mut self, quiet: Duration) -> Self {
        self.drain_quiet = quiet;
        self
    }

    /// This host's lifecycle state, as last read; `active` before the first.
    pub fn state(&self) -> String {
        self.fleet
            .member(&self.host)
            .map_or_else(|| ACTIVE.to_string(), |m| m.state)
    }

    /// A client sent a request for a `spread` deployment straight here.
    pub fn note_direct(&self) {
        *self.last_direct.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    /// Seconds since the last direct request for a `spread` deployment.
    pub fn quiet_secs(&self) -> u64 {
        self.last_direct
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .elapsed()
            .as_secs()
    }

    /// Replicas of `spread` deployments this host still runs or boots.
    pub fn spread_replicas(&self) -> usize {
        self.registry
            .deployments()
            .values()
            .filter(|d| spreads(&d.spec))
            .map(|d| d.backends().len() + d.pending().len())
            .sum()
    }

    /// A draining host enters maintenance once clients have stopped coming
    /// (DNS has moved them) and its `spread` replicas are gone.
    async fn settle_drain(&self) {
        if self.state() != DRAINING
            || self.spread_replicas() > 0
            || self.quiet_secs() < self.drain_quiet.as_secs()
        {
            return;
        }
        match self.fleet.set_host_state(&self.host, MAINTENANCE).await {
            Ok(_) => tracing::info!(
                host = %self.host,
                quiet_secs = self.quiet_secs(),
                "drained: no spread replicas and no direct requests; this host is in maintenance"
            ),
            Err(e) => tracing::warn!(error = %e, "could not enter maintenance"),
        }
    }

    /// A live peer with ready replicas of `id`, least utilised first: where a
    /// request goes when this host has none ready.
    pub fn peer_ready(&self, id: &str) -> Option<String> {
        let view = self.view.load();
        // A peer the controller no longer asks to run any is about to drain
        // the ones it has, so it is passed over.
        let targets = view.targets.get(id).map(|(_, t)| t);
        view.demand
            .get(id)?
            .iter()
            .filter(|(h, r)| {
                r.ready > 0
                    && targets.is_none_or(|t| t.get(*h).is_some_and(|n| *n > 0))
                    && self.reachable(h)
            })
            // in_flight / ready, compared without division.
            .min_by(|(ha, a), (hb, b)| {
                (a.in_flight * b.ready)
                    .cmp(&(b.in_flight * a.ready))
                    .then_with(|| ha.cmp(hb))
            })
            .map(|(h, _)| h.clone())
    }

    /// A live peer the controller has asked to run `id`, the one asked for
    /// most first: where a request goes to wait for a cold start this host
    /// is not asked to make.
    pub fn peer_targeted(&self, id: &str) -> Option<String> {
        let view = self.view.load();
        let (_, hosts) = view.targets.get(id)?;
        hosts
            .iter()
            .filter(|(h, n)| **n > 0 && self.reachable(h))
            .max_by(|(ha, a), (hb, b)| a.cmp(b).then_with(|| hb.cmp(ha)))
            .map(|(h, _)| h.clone())
    }

    /// This host's target for `id`.
    pub fn mine(&self, id: &str) -> u32 {
        let view = self.view.load();
        view.targets
            .get(id)
            .and_then(|(_, hosts)| hosts.get(&self.host).copied())
            .unwrap_or(0)
    }

    fn reachable(&self, host: &str) -> bool {
        host != self.host
            && self
                .fleet
                .live_member(host)
                .is_some_and(|m| m.address.is_some())
    }

    /// Whether this host issues `spec`'s certificate. A `spread` deployment
    /// runs on several hosts and so is certified by one of them: the first by
    /// name among the live hosts that run it, or this host when it knows of
    /// no other.
    pub fn issues_certificate(&self, spec: &DeploymentSpec) -> bool {
        let Some(placement) = spec.placement.as_ref().filter(|_| spreads(spec)) else {
            return true;
        };
        // Active hosts first: a draining one may be about to restart.
        let mut hosts: Vec<(bool, String)> = self
            .fleet
            .live_members()
            .into_iter()
            .filter(|m| {
                m.state != MAINTENANCE && placement.includes(&m.host) && m.host != self.host
            })
            .map(|m| (m.state != ACTIVE, m.host))
            .collect();
        if placement.includes(&self.host) {
            hosts.push((self.state() != ACTIVE, self.host.clone()));
        }
        hosts
            .into_iter()
            .min()
            .is_none_or(|(_, first)| first == self.host)
    }

    /// Report, read, and — holding the lease — plan.
    async fn sync(&self) {
        self.report().await;
        self.report_capacity().await;
        let pg = self.fleet.pg();
        match (pg.demand().await, pg.targets().await) {
            (Ok(demand), Ok(targets)) => {
                let mut view = View {
                    loaded: true,
                    ..View::default()
                };
                for (host, id, report) in demand {
                    view.demand.entry(id).or_default().insert(host, report);
                }
                for (id, host, desired, generation) in targets {
                    let entry = view.targets.entry(id).or_default();
                    entry.0 = entry.0.max(generation);
                    entry.1.insert(host, desired);
                }
                self.view.store(Arc::new(view));
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(error = %e, "could not read the fleet's placement; keeping the last view")
            }
        }
        let due = self
            .planned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none_or(|t| t.elapsed() >= PLAN_EVERY);
        self.settle_drain().await;
        if due && let Some(epoch) = self.lease.held() {
            *self.planned.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            self.plan(epoch).await;
        }
    }

    /// Publish this host's numbers for the `spread` deployments it runs.
    async fn report(&self) {
        let now: HashMap<String, DemandReport> = self
            .registry
            .deployments()
            .values()
            .filter(|d| spreads(&d.spec))
            .map(|d| {
                (
                    d.spec.id.clone(),
                    DemandReport {
                        in_flight: d.total_in_flight() as u64,
                        waiters: d.waiters() as u64,
                        ready: d.backends().iter().filter(|b| !b.is_draining()).count() as u64,
                        booting: d.pending().len() as u64,
                        idle_secs: d.idle_for().min(u32::MAX as u64),
                    },
                )
            })
            .collect();
        let last = self
            .reported
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let clear = last.is_none();
        let last = last.unwrap_or_default();
        let rows: Vec<_> = now
            .iter()
            .filter(|(id, r)| last.get(*id) != Some(r))
            .map(|(id, r)| (id.clone(), *r))
            .collect();
        let gone: Vec<_> = last
            .keys()
            .filter(|id| !now.contains_key(*id))
            .cloned()
            .collect();
        if !clear && rows.is_empty() && gone.is_empty() {
            return;
        }
        match self
            .fleet
            .pg()
            .report_demand(&self.host, rows, gone, clear)
            .await
        {
            Ok(()) => *self.reported.lock().unwrap_or_else(|e| e.into_inner()) = Some(now),
            Err(e) => tracing::debug!(error = %e, "could not report this host's demand"),
        }
    }

    /// Publish this host's capacity when it moved, or at least every
    /// [`CAPACITY_EVERY`] so the report never goes stale.
    async fn report_capacity(&self) {
        let Some(now) = local_capacity() else { return };
        let due = self
            .reported_capacity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none_or(|(last, at)| capacity_moved(&last, &now) || at.elapsed() >= CAPACITY_EVERY);
        if !due {
            return;
        }
        match self.fleet.pg().report_capacity(&self.host, now).await {
            Ok(true) => {
                *self
                    .reported_capacity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some((now, Instant::now()))
            }
            Ok(false) => {
                tracing::debug!("no hosts row yet; capacity waits for the first heartbeat")
            }
            Err(e) => tracing::debug!(error = %e, "could not report this host's capacity"),
        }
    }

    /// The controller's tick.
    async fn plan(&self, epoch: u64) {
        let members: Vec<HostRow> = self.fleet.live_members();
        if members.is_empty() {
            // Not even this host: the member list is not readable yet.
            return;
        }
        let local = self.registry.deployments();
        let foreign = self.registry.foreign();
        let specs = local
            .values()
            .map(|d| &d.spec)
            .chain(foreign.values().map(|s| s.as_ref()))
            .filter(|s| spreads(s));
        let view = self.view.load();
        let capacity: HashMap<String, Capacity> = members
            .iter()
            .filter_map(|m| m.capacity.map(|c| (m.host.clone(), c)))
            .collect();
        let mut plan = Vec::new();
        let mut changed = false;
        for spec in specs {
            let placement = spec.placement.as_ref().expect("spread has a placement");
            let (mut eligible, mut draining) = (Vec::new(), Vec::new());
            for m in members.iter().filter(|m| placement.includes(&m.host)) {
                if m.state == ACTIVE {
                    &mut eligible
                } else {
                    &mut draining
                }
                .push(m.host.as_str());
            }
            // The last hosts are never drained to nothing.
            if eligible.is_empty() {
                eligible = std::mem::take(&mut draining);
            }
            let reports = view.demand.get(&spec.id);
            let assigned = assign(
                &spec.scaling,
                &eligible,
                &draining,
                reports,
                Some(&capacity),
            );
            let (generation, current) = view.targets.get(&spec.id).cloned().unwrap_or_default();
            let same = assigned.len() == current.len()
                && assigned.iter().all(|(h, n)| current.get(h) == Some(n));
            if !same {
                changed = true;
                tracing::info!(
                    deployment = %spec.id,
                    targets = ?assigned,
                    generation = generation + 1,
                    "placement changed"
                );
            }
            plan.push((
                spec.id.clone(),
                if same { generation } else { generation + 1 },
                assigned,
            ));
        }
        changed |= view
            .targets
            .keys()
            .any(|id| !plan.iter().any(|(p, _, _)| p == id));
        let rewrite = {
            let mut last = self.last_write.lock().unwrap_or_else(|e| e.into_inner());
            let due = changed || last.is_none_or(|t| t.elapsed() >= REWRITE_EVERY);
            if due {
                *last = Some(Instant::now());
            }
            due
        };
        if !rewrite {
            return;
        }
        match self
            .fleet
            .pg()
            .write_targets(LEASE_PLACEMENT, epoch, plan)
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::warn!(epoch, "placement lease lost; the plan was not written"),
            Err(e) => tracing::warn!(error = %e, "could not write the placement plan"),
        }
    }
}

/// Split `spec`'s fleet-wide replica count over `eligible` hosts. Every
/// eligible and every `draining` host gets a row, zero included, so a host
/// that should run nothing is told so. A draining host's requests count
/// toward the fleet's demand, and it keeps its ready replicas only while an
/// eligible host is short of its share.
///
/// **Capacity.** When every eligible host reported its capacity, the split is
/// weighted by each host's memory instead of even: a host with twice the
/// memory gets twice the share. A host that is `full` gets no new share: it
/// keeps at most the replicas it has ready, and the rest go to the others.
/// When any eligible host reported nothing (an older binary, a stale report),
/// the split is the even one it has always been.
pub fn assign(
    policy: &ScalingPolicy,
    eligible: &[&str],
    draining: &[&str],
    reports: Option<&HashMap<String, DemandReport>>,
    capacity: Option<&HashMap<String, Capacity>>,
) -> Vec<(String, u32)> {
    let report = |h: &str| reports.and_then(|r| r.get(h)).copied().unwrap_or_default();
    let counted: Vec<DemandReport> = eligible.iter().chain(draining).map(|h| report(h)).collect();
    let demand: u64 = counted.iter().map(|r| r.in_flight + r.waiters).sum();
    let idle = counted
        .iter()
        .filter(|r| r.ready + r.booting > 0)
        .map(|r| r.idle_secs)
        .min()
        .unwrap_or(u64::MAX);
    let desired = crate::deployment::desired_for(policy, demand as usize, idle);

    // Demand first (a replica where the requests are), then replicas already
    // running (no churn), then name (stable).
    let mut order: Vec<&str> = eligible.to_vec();
    order.sort_by(|a, b| {
        let (ra, rb) = (report(a), report(b));
        (rb.in_flight + rb.waiters)
            .cmp(&(ra.in_flight + ra.waiters))
            .then((rb.ready + rb.booting).cmp(&(ra.ready + ra.booting)))
            .then(a.cmp(b))
    });
    let ready = |h: &str| report(h).ready.min(u64::from(u32::MAX)) as u32;
    let caps: Option<Vec<Capacity>> =
        capacity.and_then(|c| order.iter().map(|h| c.get(*h).copied()).collect());
    let counts: Vec<u32> = match caps {
        // Every host reported: weight by memory, and keep the full ones to
        // what they already run.
        Some(caps) if !order.is_empty() => {
            let weights: Vec<u64> = caps.iter().map(|c| c.mem_total_mb.max(1)).collect();
            let open: Vec<bool> = caps.iter().map(|c| !c.full).collect();
            if open.iter().any(|o| *o) {
                let all = apportion(desired, &weights);
                let mut counts: Vec<u32> = order
                    .iter()
                    .zip(&all)
                    .zip(&open)
                    .map(|((h, share), open)| if *open { 0 } else { (*share).min(ready(h)) })
                    .collect();
                let kept: u32 = counts.iter().sum();
                let open_weights: Vec<u64> = weights
                    .iter()
                    .zip(&open)
                    .map(|(w, o)| if *o { *w } else { 0 })
                    .collect();
                for (i, n) in apportion(desired.saturating_sub(kept), &open_weights)
                    .into_iter()
                    .enumerate()
                {
                    if open[i] {
                        counts[i] = n;
                    }
                }
                counts
            } else {
                // Every host is full: someone still has to try.
                apportion(desired, &weights)
            }
        }
        // Today's even split: identical to weighting every host the same.
        _ => apportion(desired, &vec![1; order.len()]),
    };
    let shares: Vec<(&str, u32)> = order.iter().copied().zip(counts).collect();
    // Make before break: while any host is short of its share, no host is
    // asked to give up a replica it has ready, so moving one never dips
    // serving capacity. Once the new ones are ready the shares apply, and
    // the old host drains its extra.
    let hold = shares
        .iter()
        .any(|(h, share)| u64::from(*share) > report(h).ready);
    shares
        .into_iter()
        .map(|(h, share)| {
            (
                h.to_string(),
                if hold { share.max(ready(h)) } else { share },
            )
        })
        .chain(
            draining
                .iter()
                .map(|h| (h.to_string(), if hold { ready(h) } else { 0 })),
        )
        .collect()
}

/// Split `total` over items in proportion to `weights` (largest remainder),
/// in the items' order: a tie goes to the earlier item. Equal weights give
/// `total / n` each, plus one for the first `total % n`, exactly as the even
/// split always did. A zero weight gets nothing unless every weight is zero,
/// when the split is even.
fn apportion(total: u32, weights: &[u64]) -> Vec<u32> {
    if weights.is_empty() {
        return Vec::new();
    }
    let sum: u128 = weights.iter().map(|w| u128::from(*w)).sum();
    if sum == 0 {
        return apportion(total, &vec![1; weights.len()]);
    }
    let t = u128::from(total);
    let mut out: Vec<u32> = weights
        .iter()
        .map(|w| (t * u128::from(*w) / sum) as u32)
        .collect();
    let given: u32 = out.iter().sum();
    // Rank by remainder, largest first, then by position.
    let mut rank: Vec<usize> = (0..weights.len()).filter(|i| weights[*i] > 0).collect();
    rank.sort_by(|a, b| {
        let ra = t * u128::from(weights[*a]) % sum;
        let rb = t * u128::from(weights[*b]) % sum;
        rb.cmp(&ra).then(a.cmp(b))
    });
    for i in rank.into_iter().take((total - given) as usize) {
        out[i] += 1;
    }
    out
}

/// The placer as a pingora service.
pub struct Service(pub Arc<Placer>);

#[async_trait]
impl BackgroundService for Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let placer = &self.0;
        tracing::info!(host = %placer.host, forwards = placer.forwards, "fleet placement running");
        let mut ticker = tokio::time::interval(SYNC_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => placer.sync().await,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(min: u32, max: u32, warm: u32, tc: u32) -> ScalingPolicy {
        ScalingPolicy {
            min_replicas: min,
            max_replicas: max,
            warm_pool: warm,
            target_concurrency: tc,
            scale_to_zero_after_secs: 300,
            ..Default::default()
        }
    }

    fn reports(rows: &[(&str, u64, u64, u64)]) -> HashMap<String, DemandReport> {
        rows.iter()
            .map(|(h, in_flight, waiters, ready)| {
                (
                    h.to_string(),
                    DemandReport {
                        in_flight: *in_flight,
                        waiters: *waiters,
                        ready: *ready,
                        booting: 0,
                        idle_secs: 0,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn min_replicas_count_once_for_the_fleet() {
        let a = assign(&policy(2, 5, 0, 10), &["us4", "us5"], &[], None, None);
        assert_eq!(a, vec![("us4".into(), 1), ("us5".into(), 1)]);
        let a = assign(&policy(3, 5, 0, 10), &["us4", "us5"], &[], None, None);
        assert_eq!(a.iter().map(|(_, n)| n).sum::<u32>(), 3);
    }

    #[test]
    fn a_lone_replica_goes_where_the_demand_is() {
        let r = reports(&[("us5", 0, 1, 0)]);
        let a = assign(&policy(0, 5, 0, 10), &["us4", "us5"], &[], Some(&r), None);
        assert_eq!(a, vec![("us5".into(), 1), ("us4".into(), 0)]);
    }

    #[test]
    fn demand_is_summed_across_hosts() {
        // 12 + 9 in flight at 10 per replica: 3 replicas for the fleet,
        // where one host alone would have asked for 2 and the other for 1.
        let r = reports(&[("us4", 12, 0, 2), ("us5", 9, 0, 1)]);
        let a = assign(&policy(0, 10, 0, 10), &["us4", "us5"], &[], Some(&r), None);
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 1)]);
    }

    #[test]
    fn with_no_demand_running_replicas_stay_put() {
        let r = reports(&[("us5", 0, 0, 1)]);
        let a = assign(&policy(1, 5, 0, 10), &["us4", "us5"], &[], Some(&r), None);
        assert_eq!(a, vec![("us5".into(), 1), ("us4".into(), 0)]);
    }

    #[test]
    fn a_moved_replica_is_made_before_the_old_one_is_broken() {
        // Both of min 2 on us4; us5 joins. us5 is asked for one while us4
        // keeps both until us5's is ready, then gives one up.
        let joining = reports(&[("us4", 0, 0, 2)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4", "us5"],
            &[],
            Some(&joining),
            None,
        );
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 1)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4", "us5"],
            &[],
            Some(&reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 0)])),
            None,
        );
        assert_eq!(
            a,
            vec![("us4".into(), 2), ("us5".into(), 1)],
            "still booting"
        );
        let ready = reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 1)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4", "us5"],
            &[],
            Some(&ready),
            None,
        );
        assert_eq!(a, vec![("us4".into(), 1), ("us5".into(), 1)]);
    }

    #[test]
    fn a_draining_host_keeps_its_replicas_until_the_active_ones_are_ready() {
        // min 2, one on each; us5 drains. us4 is asked for both, and us5
        // keeps its one until us4 has two ready.
        let before = reports(&[("us4", 0, 0, 1), ("us5", 3, 0, 1)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4"],
            &["us5"],
            Some(&before),
            None,
        );
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 1)]);
        let after = reports(&[("us4", 0, 0, 2), ("us5", 3, 0, 1)]);
        let a = assign(&policy(2, 5, 0, 10), &["us4"], &["us5"], Some(&after), None);
        assert_eq!(a, vec![("us4".into(), 2), ("us5".into(), 0)]);
        // A draining host's requests still count: scale-from-zero demand
        // that arrives there is the fleet's.
        let waiting = reports(&[("us5", 0, 2, 0)]);
        let a = assign(
            &policy(0, 5, 0, 10),
            &["us4"],
            &["us5"],
            Some(&waiting),
            None,
        );
        assert_eq!(a, vec![("us4".into(), 1), ("us5".into(), 0)]);
    }

    #[test]
    fn max_replicas_caps_the_fleet() {
        let r = reports(&[("us4", 100, 0, 1), ("us5", 100, 0, 1)]);
        let a = assign(&policy(0, 3, 0, 10), &["us4", "us5"], &[], Some(&r), None);
        assert_eq!(a.iter().map(|(_, n)| n).sum::<u32>(), 3);
    }

    fn caps(rows: &[(&str, u64, bool)]) -> HashMap<String, Capacity> {
        rows.iter()
            .map(|(h, total, full)| {
                (
                    h.to_string(),
                    Capacity {
                        cpus: 8,
                        mem_total_mb: *total,
                        mem_free_mb: total / 2,
                        full: *full,
                    },
                )
            })
            .collect()
    }

    fn by_host(a: &[(String, u32)]) -> HashMap<String, u32> {
        a.iter().map(|(h, n)| (h.clone(), *n)).collect()
    }

    #[test]
    fn apportion_with_equal_weights_is_the_even_split() {
        for n in 1..6usize {
            for total in 0..20u32 {
                let even: Vec<u32> = (0..n as u32)
                    .map(|i| total / n as u32 + u32::from(i < total % n as u32))
                    .collect();
                assert_eq!(apportion(total, &vec![7; n]), even, "{total} over {n}");
            }
        }
        assert_eq!(
            apportion(5, &[0, 0]),
            vec![3, 2],
            "all-zero weights split evenly"
        );
        assert_eq!(
            apportion(4, &[1, 0, 1]),
            vec![2, 0, 2],
            "a zero weight gets nothing"
        );
    }

    #[test]
    fn without_capacity_from_every_host_the_split_is_unchanged() {
        let r = reports(&[("us4", 3, 0, 1), ("us5", 9, 0, 1)]);
        for p in [
            policy(2, 5, 0, 10),
            policy(0, 10, 0, 1),
            policy(3, 3, 1, 10),
        ] {
            let old = assign(&p, &["us4", "us5"], &[], Some(&r), None);
            // Only one host reported: the even split, exactly as before.
            let partial = caps(&[("us5", 128_000, false)]);
            assert_eq!(
                assign(&p, &["us4", "us5"], &[], Some(&r), Some(&partial)),
                old
            );
            // Equal capacity everywhere weighs every host the same.
            let equal = caps(&[("us4", 64_000, false), ("us5", 64_000, false)]);
            assert_eq!(
                assign(&p, &["us4", "us5"], &[], Some(&r), Some(&equal)),
                old
            );
        }
    }

    #[test]
    fn capacity_weights_the_split_by_memory() {
        // us1 62 GB, us4 91 GB, us5 125 GB; seven replicas.
        let c = caps(&[
            ("us1", 62_000, false),
            ("us4", 91_000, false),
            ("us5", 125_000, false),
        ]);
        let a = assign(
            &policy(7, 10, 0, 10),
            &["us1", "us4", "us5"],
            &[],
            None,
            Some(&c),
        );
        let a = by_host(&a);
        assert_eq!(a.values().sum::<u32>(), 7);
        assert!(a["us5"] >= a["us4"] && a["us4"] >= a["us1"], "{a:?}");
        assert_eq!((a["us1"], a["us4"], a["us5"]), (2, 2, 3));
        // Twice the memory, twice the share.
        let c = caps(&[("big", 200_000, false), ("small", 100_000, false)]);
        let a = by_host(&assign(
            &policy(6, 10, 0, 10),
            &["big", "small"],
            &[],
            None,
            Some(&c),
        ));
        assert_eq!((a["big"], a["small"]), (4, 2));
    }

    #[test]
    fn a_full_host_gets_no_new_share_but_keeps_what_it_runs() {
        let c = caps(&[("us1", 62_000, true), ("us5", 125_000, false)]);
        // Nothing running on the full host: it is given nothing.
        let a = by_host(&assign(
            &policy(4, 10, 0, 10),
            &["us1", "us5"],
            &[],
            None,
            Some(&c),
        ));
        assert_eq!((a["us1"], a["us5"]), (0, 4));
        // One ready there already: it keeps it and gets no more.
        let r = reports(&[("us1", 0, 0, 1), ("us5", 0, 0, 3)]);
        let a = by_host(&assign(
            &policy(4, 10, 0, 10),
            &["us1", "us5"],
            &[],
            Some(&r),
            Some(&c),
        ));
        assert_eq!((a["us1"], a["us5"]), (1, 3));
        // Every host full: someone still has to try, by weight.
        let all = caps(&[("us1", 62_000, true), ("us5", 124_000, true)]);
        let a = by_host(&assign(
            &policy(3, 10, 0, 10),
            &["us1", "us5"],
            &[],
            None,
            Some(&all),
        ));
        assert_eq!(a.values().sum::<u32>(), 3);
        assert_eq!((a["us1"], a["us5"]), (1, 2));
    }

    #[test]
    fn capacity_keeps_draining_and_make_before_break_as_they_were() {
        let c = caps(&[("us4", 91_000, false), ("us5", 125_000, false)]);
        // A draining host is held at what it has ready while the eligible one
        // is short, then given nothing.
        let before = reports(&[("us4", 0, 0, 0), ("us5", 0, 0, 2)]);
        let a = assign(
            &policy(2, 5, 0, 10),
            &["us4"],
            &["us5"],
            Some(&before),
            Some(&c),
        );
        assert_eq!(
            by_host(&a),
            by_host(&assign(
                &policy(2, 5, 0, 10),
                &["us4"],
                &["us5"],
                Some(&before),
                None
            ))
        );
        let after = reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 2)]);
        let a = by_host(&assign(
            &policy(2, 5, 0, 10),
            &["us4"],
            &["us5"],
            Some(&after),
            Some(&c),
        ));
        assert_eq!((a["us4"], a["us5"]), (2, 0));
        // Moving a share to a bigger host never drops a ready replica first.
        let r = reports(&[("us4", 0, 0, 2), ("us5", 0, 0, 0)]);
        let big = caps(&[("us4", 10_000, false), ("us5", 190_000, false)]);
        let a = by_host(&assign(
            &policy(2, 5, 0, 10),
            &["us4", "us5"],
            &[],
            Some(&r),
            Some(&big),
        ));
        assert_eq!(
            a["us4"], 2,
            "us4 keeps its ready replicas while us5 is short"
        );
        assert_eq!(a["us5"], 2);
    }

    #[test]
    fn the_home_is_the_active_host_with_the_most_free_memory() {
        let row = |host: &str, state: &str, cap: Option<(u64, bool)>| HostRow {
            capacity: cap.map(|(free, full)| Capacity {
                cpus: 8,
                mem_total_mb: 128_000,
                mem_free_mb: free,
                full,
            }),
            state: state.into(),
            ..member(host)
        };
        assert_eq!(
            choose_home(&[row("us4", ACTIVE, None), row("us5", ACTIVE, None)]),
            None,
            "no reports: keep today's rule"
        );
        let members = [
            row("us1", ACTIVE, Some((40_000, false))),
            row("us4", ACTIVE, Some((20_000, false))),
            row("us5", ACTIVE, Some((90_000, true))),
            row("us6", DRAINING, Some((99_000, false))),
            row("us7", ACTIVE, None),
        ];
        assert_eq!(
            choose_home(&members).as_deref(),
            Some("us1"),
            "full, draining and silent hosts are passed over"
        );
        let tie = [
            row("us5", ACTIVE, Some((10, false))),
            row("us4", ACTIVE, Some((10, false))),
        ];
        assert_eq!(
            choose_home(&tie).as_deref(),
            Some("us4"),
            "a tie goes to the first by name"
        );
    }

    #[test]
    fn only_a_plain_vm_pool_may_be_homed_elsewhere() {
        let vm: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [], "vm": {"driver": "firecracker", "image": "img", "port": 8080}
        }))
        .unwrap();
        assert!(capacity_placeable(&vm));
        let mut built = vm.clone();
        built.build =
            serde_json::from_value(serde_json::json!({"repo": "https://example.com/r.git"}))
                .unwrap();
        assert!(
            !capacity_placeable(&built),
            "a build runs on the host that took it"
        );
        let mut static_pool = vm.clone();
        static_pool.vm = None;
        static_pool.upstreams = vec!["127.0.0.1:1".into()];
        assert!(!capacity_placeable(&static_pool));
        let mut local_store = vm.clone();
        local_store.artifact =
            serde_json::from_value(serde_json::json!({"store": "/srv/art", "ref": "x"})).unwrap();
        assert!(
            !capacity_placeable(&local_store),
            "a local artifact store is this host's"
        );
        let mut remote_store = vm.clone();
        remote_store.artifact = serde_json::from_value(
            serde_json::json!({"store": "https://hub.heyo.work", "ref": "heyo/x:1"}),
        )
        .unwrap();
        assert!(capacity_placeable(&remote_store));
    }

    #[test]
    fn capacity_refusals_and_moves_are_recognised() {
        assert!(is_capacity_refusal(
            "api error (409): host memory capacity unavailable"
        ));
        assert!(!is_capacity_refusal("image not found"));
        let a = Capacity {
            cpus: 8,
            mem_total_mb: 100_000,
            mem_free_mb: 50_000,
            full: false,
        };
        assert!(
            !capacity_moved(
                &a,
                &Capacity {
                    mem_free_mb: 52_000,
                    ..a
                }
            ),
            "2% is noise"
        );
        assert!(capacity_moved(
            &a,
            &Capacity {
                mem_free_mb: 60_000,
                ..a
            }
        ));
        assert!(capacity_moved(&a, &Capacity { full: true, ..a }));
    }

    fn member(host: &str) -> HostRow {
        HostRow {
            host: host.into(),
            address: Some(format!("{host}.example")),
            state: "active".into(),
            boot_id: "b".into(),
            age_secs: 0.0,
            capacity: None,
        }
    }

    /// The installed placer, as `Deployment`, the request path and ACME see
    /// it. One test, since there is one per process.
    #[test]
    fn the_installed_placer_steers_targets_peers_and_certificates() {
        let pg = crate::fleet_pg::PgStore::open_in(
            "postgres://u@127.0.0.1:9/x",
            "us4",
            Duration::from_secs(1),
            "fleet",
        )
        .unwrap();
        let fleet = Fleet::new(pg, "/nonexistent/m.json", vec![0; 32]);
        let placer = Arc::new(Placer::new(
            "us4",
            fleet.clone(),
            Arc::new(Registry::new("/dev/null")),
            true,
        ));
        install(placer.clone());

        let mut spec: DeploymentSpec = serde_json::from_value(serde_json::json!({
            "id": "web", "routes": [{"host": "web.example"}],
            "vm": {"image": "i", "port": 8080, "driver": "firecracker"},
            "scaling": {"max_replicas": 4},
            "placement": {"mode": "spread"}
        }))
        .unwrap();
        // Before the first read the host sizes itself.
        assert_eq!(target(&spec, 1), None);
        placer.view.store(Arc::new(View {
            loaded: true,
            ..View::default()
        }));
        // Read, with no targets yet: nothing, unless a request is waiting here.
        assert_eq!(target(&spec, 0), Some(0));
        assert_eq!(
            target(&spec, 1),
            Some(1),
            "a stranded waiter boots one here"
        );

        let mut view = View {
            loaded: true,
            ..View::default()
        };
        view.targets.insert(
            "web".into(),
            (
                3,
                HashMap::from([("us4".into(), 0), ("us5".into(), 2), ("us6".into(), 1)]),
            ),
        );
        view.demand.insert(
            "web".into(),
            HashMap::from([
                (
                    "us5".to_string(),
                    DemandReport {
                        in_flight: 9,
                        ready: 2,
                        ..Default::default()
                    },
                ),
                (
                    "us6".to_string(),
                    DemandReport {
                        in_flight: 2,
                        ready: 1,
                        ..Default::default()
                    },
                ),
            ]),
        );
        placer.view.store(Arc::new(view));
        assert_eq!(target(&spec, 0), Some(0));

        // Peers count only while they are live members with an address.
        assert_eq!(placer.peer_ready("web"), None);
        fleet.set_members(vec![member("us4"), member("us5"), member("us6")]);
        assert_eq!(
            placer.peer_ready("web").as_deref(),
            Some("us6"),
            "2/1 beats 9/2"
        );
        assert_eq!(placer.peer_targeted("web").as_deref(), Some("us5"));
        fleet.set_members(vec![member("us4"), member("us5")]);
        assert_eq!(placer.peer_ready("web").as_deref(), Some("us5"));
        // A ready peer whose target went to zero is about to drain.
        let mut view = View {
            loaded: true,
            ..View::default()
        };
        view.targets.insert(
            "web".into(),
            (4, HashMap::from([("us4".into(), 1), ("us5".into(), 0)])),
        );
        view.demand.insert(
            "web".into(),
            HashMap::from([(
                "us5".to_string(),
                DemandReport {
                    ready: 1,
                    ..Default::default()
                },
            )]),
        );
        placer.view.store(Arc::new(view));
        assert_eq!(placer.peer_ready("web"), None);
        assert_eq!(
            placer.peer_targeted("web"),
            None,
            "and nobody else is asked"
        );

        // The first live host by name certifies a spread deployment.
        assert!(placer.issues_certificate(&spec), "us4 < us5");
        spec.placement.as_mut().unwrap().hosts = vec!["us5".into(), "us6".into()];
        assert!(!placer.issues_certificate(&spec), "us4 does not run it");
        fleet.set_members(vec![member("us3"), member("us4")]);
        spec.placement.as_mut().unwrap().hosts = vec![];
        assert!(!placer.issues_certificate(&spec), "us3 < us4");
        // An active host issues before a draining one, and a host in
        // maintenance never.
        let mut draining = member("us3");
        draining.state = DRAINING.into();
        fleet.set_members(vec![draining, member("us4")]);
        assert!(placer.issues_certificate(&spec), "us3 is draining");
        let mut down = member("us3");
        down.state = MAINTENANCE.into();
        let mut us4 = member("us4");
        us4.state = DRAINING.into();
        fleet.set_members(vec![down, us4]);
        assert!(
            placer.issues_certificate(&spec),
            "the draining us4 is all there is"
        );
        assert_eq!(placer.state(), DRAINING);

        // Anything not spread is not the placer's.
        spec.placement = None;
        assert_eq!(target(&spec, 5), None);
        assert!(placer.issues_certificate(&spec));
    }

    #[test]
    fn no_eligible_host_gets_nothing() {
        assert!(assign(&policy(2, 5, 0, 10), &[], &[], None, None).is_empty());
    }
}
