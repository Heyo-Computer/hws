//! In-process metrics.
//!
//! app-lb's whole vantage point is the request path and the reconcile loop, so
//! that is what it can honestly measure: how long requests take, how long a
//! cold VM takes to become servable, how often the autoscaler grows and shrinks
//! a pool, and how loaded each VM is. The daemon exposes no CPU/memory
//! telemetry for a guest (`SandboxInfo` carries status, uptime, and TTL, nothing
//! more), and exec-ing into a live microVM to read `/proc` destabilises it — so
//! "resource usage" here means concurrency and pool utilisation, the load
//! signals the LB already owns, never fabricated guest counters.
//!
//! Everything on the hot path is a relaxed atomic. Counters and histogram
//! buckets are additive, so no lock is ever taken to record; the only lock-shy
//! structure is the per-deployment map, which mirrors the registry's
//! copy-on-write `ArcSwap` (a deployment is inserted at most once, then only
//! read). Reads are for the dashboard poll and can tolerate a torn-across-fields
//! snapshot — it is a monitoring view, not an invariant.

use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Latency bucket upper bounds in milliseconds. The last, implicit bucket is
/// everything above the final bound. Chosen to straddle the range a tap-network
/// proxy hop actually spans: sub-ms upstreams up to cold-start-shaped seconds.
pub const LATENCY_BOUNDS_MS: &[u64] = &[1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/// Cold-start bucket upper bounds in seconds. `promote_pending` measures boot
/// time in whole seconds, and a Firecracker VM is typically serving in ~1–2s,
/// so the low end is dense; the tail runs out to the default cold-start budget.
pub const COLD_START_BOUNDS_S: &[u64] = &[1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 120];

/// A fixed-bucket cumulative histogram over `u64` samples in some base unit.
///
/// Buckets are `bounds.len() + 1` wide — one per upper bound plus an overflow
/// bucket for samples past the last bound. `record` is a couple of relaxed
/// adds; percentiles are derived at snapshot time from the bucket counts.
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [u64],
    buckets: Box<[AtomicU64]>,
    count: AtomicU64,
    sum: AtomicU64,
}

impl Histogram {
    pub fn new(bounds: &'static [u64]) -> Self {
        Self {
            bounds,
            buckets: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
        }
    }

    pub fn record(&self, value: u64) {
        // First bucket whose bound the sample fits under; the overflow bucket
        // (index == bounds.len()) catches everything larger.
        let idx = self
            .bounds
            .iter()
            .position(|&b| value <= b)
            .unwrap_or(self.bounds.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HistogramSnapshot {
        let counts: Vec<u64> = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect();
        HistogramSnapshot::from_parts(
            self.bounds,
            counts,
            self.count.load(Ordering::Relaxed),
            self.sum.load(Ordering::Relaxed),
        )
    }
}

/// One `le` (less-than-or-equal) bucket. `le: None` is the overflow bucket —
/// samples above the last finite bound.
#[derive(Debug, Clone, Serialize)]
pub struct Bucket {
    pub le: Option<u64>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum: u64,
    pub mean: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub buckets: Vec<Bucket>,
    /// Carried so snapshots can be merged (global = sum of per-deployment).
    #[serde(skip)]
    bounds: &'static [u64],
}

impl HistogramSnapshot {
    fn from_parts(bounds: &'static [u64], counts: Vec<u64>, count: u64, sum: u64) -> Self {
        let mean = if count == 0 { 0.0 } else { sum as f64 / count as f64 };
        let buckets = bounds
            .iter()
            .map(|&b| Some(b))
            .chain(std::iter::once(None))
            .zip(counts.iter().copied())
            .map(|(le, count)| Bucket { le, count })
            .collect::<Vec<_>>();
        Self {
            count,
            sum,
            mean,
            p50: percentile(bounds, &counts, count, 0.50),
            p90: percentile(bounds, &counts, count, 0.90),
            p99: percentile(bounds, &counts, count, 0.99),
            buckets,
            bounds,
        }
    }

    pub fn empty(bounds: &'static [u64]) -> Self {
        Self::from_parts(bounds, vec![0; bounds.len() + 1], 0, 0)
    }

    /// Fold another histogram over the same bounds into this one. Buckets are
    /// additive across deployments, so the global view is an exact merge, not an
    /// average of percentiles.
    pub fn merge(&mut self, other: &HistogramSnapshot) {
        debug_assert_eq!(self.bounds, other.bounds, "cannot merge unlike histograms");
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .zip(&other.buckets)
            .map(|(a, b)| a.count + b.count)
            .collect();
        *self = Self::from_parts(self.bounds, counts, self.count + other.count, self.sum + other.sum);
    }
}

/// Rank-based percentile over cumulative buckets, linearly interpolated within
/// the containing bucket. Approximate by construction — the sample's exact value
/// is gone, only its bucket survives — which is the accepted trade for O(1)
/// recording. A sample landing in the overflow bucket reports the last finite
/// bound as a floor rather than an unbounded number.
fn percentile(bounds: &[u64], counts: &[u64], total: u64, q: f64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let target = q * total as f64;
    let mut cumulative = 0u64;
    let mut lower = 0f64;
    for (i, &c) in counts.iter().enumerate() {
        let prev_cumulative = cumulative;
        cumulative += c;
        if (cumulative as f64) >= target && c > 0 {
            let upper = bounds.get(i).map(|&b| b as f64).unwrap_or(lower);
            if upper <= lower {
                return upper;
            }
            // How far into this bucket the target rank falls.
            let into = (target - prev_cumulative as f64) / c as f64;
            return lower + into * (upper - lower);
        }
        lower = bounds.get(i).map(|&b| b as f64).unwrap_or(lower);
    }
    lower
}

/// Per-response-class tallies, kept alongside every latency histogram.
#[derive(Debug, Default)]
struct StatusCounts {
    total: AtomicU64,
    c2xx: AtomicU64,
    c3xx: AtomicU64,
    c4xx: AtomicU64,
    c5xx: AtomicU64,
    /// No response written at all — upstream never produced one (all retries
    /// failed, cold start timed out). Distinct from a 5xx the guest returned.
    errors: AtomicU64,
}

impl StatusCounts {
    fn record(&self, status: Option<u16>) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let bucket = match status {
            Some(s) if (200..300).contains(&s) => &self.c2xx,
            Some(s) if (300..400).contains(&s) => &self.c3xx,
            Some(s) if (400..500).contains(&s) => &self.c4xx,
            Some(s) if (500..600).contains(&s) => &self.c5xx,
            Some(_) => &self.c5xx, // out-of-range status; treat as server error
            None => &self.errors,
        };
        bucket.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> StatusSnapshot {
        StatusSnapshot {
            total: self.total.load(Ordering::Relaxed),
            c2xx: self.c2xx.load(Ordering::Relaxed),
            c3xx: self.c3xx.load(Ordering::Relaxed),
            c4xx: self.c4xx.load(Ordering::Relaxed),
            c5xx: self.c5xx.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusSnapshot {
    pub total: u64,
    pub c2xx: u64,
    pub c3xx: u64,
    pub c4xx: u64,
    pub c5xx: u64,
    pub errors: u64,
}

impl StatusSnapshot {
    fn merge(&mut self, o: &StatusSnapshot) {
        self.total += o.total;
        self.c2xx += o.c2xx;
        self.c3xx += o.c3xx;
        self.c4xx += o.c4xx;
        self.c5xx += o.c5xx;
        self.errors += o.errors;
    }
}

/// Autoscaler activity, all monotonic since process start. Rates (per-second)
/// are the dashboard's job to derive by diffing successive polls.
#[derive(Debug, Default)]
struct AutoscaleCounts {
    /// VMs the autoscaler asked the daemon to create.
    vms_created: AtomicU64,
    /// Ready VMs marked draining by a scale-down decision.
    vms_drained: AtomicU64,
    /// VMs actually killed once drained (or past the drain deadline).
    vms_reaped: AtomicU64,
    /// Reconcile ticks that grew the pool / shrank it. Event counts, not VM
    /// counts: one event can move several VMs.
    scale_up_events: AtomicU64,
    scale_down_events: AtomicU64,
    /// Requests that hit an empty/at-capacity pool and waited for a boot.
    cold_start_waits: AtomicU64,
    /// …of those, the ones a VM eventually served vs. the ones that timed out.
    cold_start_hits: AtomicU64,
    cold_start_timeouts: AtomicU64,
    /// VMs killed for never passing their health check inside
    /// `scaling.boot_timeout_secs`. Distinct from `vms_reaped`, which counts
    /// deliberate retirements: a boot failure is the pool trying and failing to
    /// reach its own `min_replicas`, and a deployment that only ever produces
    /// these is one whose guest never starts.
    boot_timeouts: AtomicU64,
    /// Creates the daemon refused — the pool asked for a VM and did not get an
    /// id back.
    ///
    /// This existed nowhere before, and its absence was a genuine hole rather
    /// than a missing nicety. `record_scale_up` returns early on zero, so a
    /// deployment whose every create is rejected increments *nothing*:
    /// `vms_created`, `scale_up_events` and `boot_timeouts` all sit at 0, which
    /// is indistinguishable from a deployment nobody has asked anything of. The
    /// only trace was a log line. A pool stuck at `ready: 0` with a `desired` of
    /// 1 and three zeroes next to it is the single most confusing state this
    /// system produces, and it is exactly the state a host with no room for a
    /// `disk_size_gb` allocation lands in.
    create_failures: AtomicU64,
    /// Rolling replacements that hit their progress deadline and paused.
    rollout_stalls: AtomicU64,
    /// What the daemon said the last time it refused. The counter says a pool is
    /// stuck; this says why, which is the half that ends the investigation —
    /// "No space left on device" and "image not found" produce identical
    /// counters and want opposite fixes. Only the most recent is kept: a
    /// deployment failing every 2s would otherwise be an unbounded log.
    last_create_error: Mutex<Option<String>>,
}

impl AutoscaleCounts {
    fn snapshot(&self) -> AutoscaleSnapshot {
        AutoscaleSnapshot {
            vms_created: self.vms_created.load(Ordering::Relaxed),
            vms_drained: self.vms_drained.load(Ordering::Relaxed),
            vms_reaped: self.vms_reaped.load(Ordering::Relaxed),
            scale_up_events: self.scale_up_events.load(Ordering::Relaxed),
            scale_down_events: self.scale_down_events.load(Ordering::Relaxed),
            cold_start_waits: self.cold_start_waits.load(Ordering::Relaxed),
            cold_start_hits: self.cold_start_hits.load(Ordering::Relaxed),
            cold_start_timeouts: self.cold_start_timeouts.load(Ordering::Relaxed),
            boot_timeouts: self.boot_timeouts.load(Ordering::Relaxed),
            create_failures: self.create_failures.load(Ordering::Relaxed),
            rollout_stalls: self.rollout_stalls.load(Ordering::Relaxed),
            last_create_error: self
                .last_create_error
                .lock()
                .ok()
                .and_then(|e| e.clone()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AutoscaleSnapshot {
    pub vms_created: u64,
    pub vms_drained: u64,
    pub vms_reaped: u64,
    pub scale_up_events: u64,
    pub scale_down_events: u64,
    pub cold_start_waits: u64,
    pub cold_start_hits: u64,
    pub cold_start_timeouts: u64,
    pub boot_timeouts: u64,
    pub create_failures: u64,
    /// Omitted while zero, so the payload is unchanged for a fleet that has
    /// never had a rollout stall.
    #[serde(skip_serializing_if = "is_zero")]
    pub rollout_stalls: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_create_error: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl AutoscaleSnapshot {
    fn merge(&mut self, o: &AutoscaleSnapshot) {
        self.vms_created += o.vms_created;
        self.vms_drained += o.vms_drained;
        self.vms_reaped += o.vms_reaped;
        self.scale_up_events += o.scale_up_events;
        self.scale_down_events += o.scale_down_events;
        self.cold_start_waits += o.cold_start_waits;
        self.cold_start_hits += o.cold_start_hits;
        self.cold_start_timeouts += o.cold_start_timeouts;
        self.boot_timeouts += o.boot_timeouts;
        self.create_failures += o.create_failures;
        self.rollout_stalls += o.rollout_stalls;
        if self.last_create_error.is_none() {
            self.last_create_error = o.last_create_error.clone();
        }
    }
}

/// Everything measured for a single deployment. All storage lives here; the
/// global view is these merged, so a counter is never double-recorded.
#[derive(Debug)]
pub struct DeploymentMetrics {
    latency: Histogram,
    status: StatusCounts,
    cold_start: Histogram,
    autoscale: AutoscaleCounts,
}

impl Default for DeploymentMetrics {
    fn default() -> Self {
        Self {
            latency: Histogram::new(LATENCY_BOUNDS_MS),
            status: StatusCounts::default(),
            cold_start: Histogram::new(COLD_START_BOUNDS_S),
            autoscale: AutoscaleCounts::default(),
        }
    }
}

impl DeploymentMetrics {
    fn snapshot(&self) -> DeploymentMetricsSnapshot {
        DeploymentMetricsSnapshot {
            requests: self.status.snapshot(),
            latency_ms: self.latency.snapshot(),
            cold_start_s: self.cold_start.snapshot(),
            autoscale: self.autoscale.snapshot(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentMetricsSnapshot {
    pub requests: StatusSnapshot,
    pub latency_ms: HistogramSnapshot,
    pub cold_start_s: HistogramSnapshot,
    pub autoscale: AutoscaleSnapshot,
}

impl DeploymentMetricsSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            requests: StatusSnapshot::default(),
            latency_ms: HistogramSnapshot::empty(LATENCY_BOUNDS_MS),
            cold_start_s: HistogramSnapshot::empty(COLD_START_BOUNDS_S),
            autoscale: AutoscaleSnapshot::default(),
        }
    }

    pub(crate) fn merge(&mut self, o: &DeploymentMetricsSnapshot) {
        self.requests.merge(&o.requests);
        self.latency_ms.merge(&o.latency_ms);
        self.cold_start_s.merge(&o.cold_start_s);
        self.autoscale.merge(&o.autoscale);
    }
}

/// Whole-host resource usage from the daemon, refreshed each reconcile tick.
/// A single gauge (not per-deployment), so a plain set of atomics; CPU% is
/// stored as f64 bits.
#[derive(Debug, Default)]
struct HostGauge {
    available: std::sync::atomic::AtomicBool,
    cpu_count: AtomicU64,
    cpu_percent_bits: AtomicU64,
    memory_total_bytes: AtomicU64,
    memory_used_bytes: AtomicU64,
    sampled_at_ms: AtomicU64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct HostUsageSnapshot {
    /// False until the daemon's poller has produced a sample.
    pub available: bool,
    pub cpu_count: u64,
    pub cpu_percent: f64,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub sampled_at_ms: u64,
}

/// The metrics registry: one `DeploymentMetrics` per deployment, the derived
/// global rollup, and the host usage gauge. Shared as `Arc<Metrics>` by the
/// proxy, the autoscaler, and the admin API.
#[derive(Debug)]
pub struct Metrics {
    per_deployment: ArcSwap<HashMap<String, Arc<DeploymentMetrics>>>,
    /// Counters folded in from deployments that have been deregistered.
    ///
    /// The global rollup has always included history from deployments that are
    /// gone, and it should: traffic that happened, happened. Keeping their whole
    /// `DeploymentMetrics` alive to achieve that was fine for a few dozen
    /// long-lived services and a leak for a fleet of sandboxes, where ids churn
    /// constantly and every one ever seen was retained. Retiring folds the
    /// numbers in here and drops the entry.
    retired: Mutex<DeploymentMetricsSnapshot>,
    host: HostGauge,
    /// Whether the last attempt to list the daemon's sandboxes succeeded, and
    /// what it said if not.
    ///
    /// Fleet-wide rather than per-deployment because the consequence is
    /// fleet-wide: `Autoscaler::reconcile` returns the moment `vms.list()`
    /// fails, so *every* managed deployment stops reconciling at once. Nothing
    /// scales, nothing boots, and no per-deployment counter moves — including
    /// `create_failures`, because `scale_up` is never reached. Without this the
    /// whole control plane can be down and every number on the dashboard reads
    /// like a quiet afternoon.
    daemon: DaemonGauge,
    /// The unowned sandboxes on the host as of the last successful listing,
    /// whole-vector swapped so a reader never sees a half-written tick.
    host_sandboxes: ArcSwap<Vec<HostSandboxView>>,
    /// Billable traffic per deployment and owner, for `GET /usage`. Separate
    /// from the counters above: those are a monitoring view that retires with
    /// the deployment, these are series a billing collector reads by id.
    usage: crate::usage::UsageMeter,
}

#[derive(Debug, Default)]
struct DaemonGauge {
    /// Starts `false` and is set by the first listing attempt either way, so
    /// "never tried" and "tried and failed" are not conflated: `last_error` is
    /// `None` in the first case and populated in the second.
    reachable: std::sync::atomic::AtomicBool,
    last_error: Mutex<Option<String>>,
}

/// One sandbox on the daemon's host that no deployment owns.
///
/// app-lb only ever *manages* the sandboxes it named (`applb-<deployment>-…`,
/// see [`crate::vm::owner_of`]); everything else on the host — created through
/// the heyvm CLI, the cloud API, the desktop — was invisible to it, and so to
/// the dashboard and to app-obs, which take app-lb's word for what exists. But
/// the host is one machine: those VMs share its CPU and memory with every
/// pool, and an operator reading a loaded host off a half-empty pool table
/// has been misled. So the reconcile tick, which lists the daemon anyway,
/// publishes them here. Reported, never acted on: no drain, no kill, no adopt.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostSandboxView {
    pub sandbox_id: String,
    pub name: String,
    pub status: heyo_sdk::SandboxStatus,
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_ip: Option<String>,
    pub uptime_secs: u64,
    /// Latest per-VM sample from the daemon, `None` if not yet reported.
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    /// The heyo account the sandbox is billed to, when the daemon knows.
    /// This is also what a namespace-scoped caller's view is narrowed by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// RFC 3339, when the daemon reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DaemonSnapshot {
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            per_deployment: ArcSwap::from_pointee(HashMap::new()),
            retired: Mutex::new(DeploymentMetricsSnapshot::empty()),
            host: HostGauge::default(),
            daemon: DaemonGauge::default(),
            host_sandboxes: ArcSwap::from_pointee(Vec::new()),
            usage: crate::usage::UsageMeter::default(),
        }
    }

    /// Billable traffic counters (see [`crate::usage`]).
    pub fn usage(&self) -> &crate::usage::UsageMeter {
        &self.usage
    }

    /// Overwrite the host usage gauge with the daemon's latest sample.
    pub fn record_host_usage(
        &self,
        available: bool,
        cpu_count: u32,
        cpu_percent: f64,
        memory_total_bytes: u64,
        memory_used_bytes: u64,
        sampled_at_ms: u64,
    ) {
        self.host.available.store(available, Ordering::Relaxed);
        self.host.cpu_count.store(cpu_count as u64, Ordering::Relaxed);
        self.host
            .cpu_percent_bits
            .store(cpu_percent.to_bits(), Ordering::Relaxed);
        self.host
            .memory_total_bytes
            .store(memory_total_bytes, Ordering::Relaxed);
        self.host
            .memory_used_bytes
            .store(memory_used_bytes, Ordering::Relaxed);
        self.host.sampled_at_ms.store(sampled_at_ms, Ordering::Relaxed);
    }

    pub fn host_snapshot(&self) -> HostUsageSnapshot {
        HostUsageSnapshot {
            available: self.host.available.load(Ordering::Relaxed),
            cpu_count: self.host.cpu_count.load(Ordering::Relaxed),
            cpu_percent: f64::from_bits(self.host.cpu_percent_bits.load(Ordering::Relaxed)),
            memory_total_bytes: self.host.memory_total_bytes.load(Ordering::Relaxed),
            memory_used_bytes: self.host.memory_used_bytes.load(Ordering::Relaxed),
            sampled_at_ms: self.host.sampled_at_ms.load(Ordering::Relaxed),
        }
    }

    /// The daemon answered a sandbox listing.
    pub fn record_daemon_reachable(&self) {
        self.daemon.reachable.store(true, Ordering::Relaxed);
        if let Ok(mut last) = self.daemon.last_error.lock() {
            *last = None;
        }
    }

    /// The daemon did not answer, and what it said.
    ///
    /// The error is kept because the two shapes want different fixes and are
    /// indistinguishable from a boolean: a connection refused means the daemon
    /// is not listening where app-lb is looking — `APP_LB_DAEMON_URL` against a
    /// daemon in API mode, which binds `--port` rather than the TUI's 34099 —
    /// while a timeout or a 5xx means it is there and unwell.
    pub fn record_daemon_unreachable(&self, error: &str) {
        self.daemon.reachable.store(false, Ordering::Relaxed);
        if let Ok(mut last) = self.daemon.last_error.lock() {
            *last = Some(error.to_string());
        }
    }

    /// Replace the unowned-sandbox inventory with this tick's listing.
    ///
    /// Only ever called with a *successful* listing: when the daemon is
    /// unreachable the previous inventory stands, exactly as every pool's
    /// numbers do, and `daemon.reachable` is what says so.
    pub fn record_host_sandboxes(&self, sandboxes: Vec<HostSandboxView>) {
        self.host_sandboxes.store(Arc::new(sandboxes));
    }

    pub fn host_sandboxes(&self) -> Arc<Vec<HostSandboxView>> {
        self.host_sandboxes.load_full()
    }

    pub fn daemon_snapshot(&self) -> DaemonSnapshot {
        DaemonSnapshot {
            reachable: self.daemon.reachable.load(Ordering::Relaxed),
            last_error: self.daemon.last_error.lock().ok().and_then(|e| e.clone()),
        }
    }

    /// Get, or insert-then-get, the metrics for a deployment.
    ///
    /// The fast path is a lock-free `ArcSwap` load and a hash lookup — the state
    /// every request and every reconcile hits. The slow path (copy-on-write
    /// insert) runs at most once per deployment id ever seen, so the clone is a
    /// non-issue. Racing inserts are resolved by re-checking under the rebuilt
    /// map so two callers can't install divergent counters.
    pub fn deployment(&self, id: &str) -> Arc<DeploymentMetrics> {
        if let Some(m) = self.per_deployment.load().get(id) {
            return m.clone();
        }
        let created = Arc::new(DeploymentMetrics::default());
        let mut installed = created.clone();
        self.per_deployment.rcu(|current| {
            let mut next = (**current).clone();
            // Another caller may have won the race between the load above and
            // here; if so, adopt theirs so everyone shares one counter set.
            installed = next.entry(id.to_string()).or_insert(created.clone()).clone();
            next
        });
        installed
    }

    /// Fold a deregistered deployment's counters into the retired total and
    /// drop its entry.
    ///
    /// Called when a deployment goes away. Without it the map grows for the life
    /// of the process — one entry per id ever seen — which is invisible for a
    /// few dozen services and unbounded for a sandbox fleet whose ids are
    /// created and destroyed all day. The numbers are not lost: they move to
    /// `retired`, so the global rollup still counts traffic that happened.
    pub fn retire(&self, id: &str) {
        let mut removed = None;
        self.per_deployment.rcu(|current| {
            let mut next = (**current).clone();
            removed = next.remove(id);
            next
        });
        if let Some(m) = removed
            && let Ok(mut retired) = self.retired.lock()
        {
            retired.merge(&m.snapshot());
        }
    }

    // --- Recording (hot paths) -------------------------------------------

    /// A completed request: its final status (None = no response written) and
    /// wall-clock time from routing to teardown.
    pub fn record_request(&self, deployment: &str, status: Option<u16>, latency: Duration) {
        let m = self.deployment(deployment);
        m.status.record(status);
        // Saturate rather than truncate: a multi-hour hang is still "very slow",
        // and u128->u64 could otherwise wrap it small.
        m.latency.record(latency.as_millis().min(u64::MAX as u128) as u64);
    }

    /// A VM went from created to servable in `secs` (LB-observed boot time).
    pub fn record_cold_start(&self, deployment: &str, secs: u64) {
        self.deployment(deployment).cold_start.record(secs);
    }

    /// A reconcile tick created `n` VMs for this deployment.
    pub fn record_scale_up(&self, deployment: &str, n: u64) {
        if n == 0 {
            return;
        }
        let m = self.deployment(deployment);
        m.autoscale.vms_created.fetch_add(n, Ordering::Relaxed);
        m.autoscale.scale_up_events.fetch_add(1, Ordering::Relaxed);
    }

    /// A reconcile tick marked `n` VMs draining.
    pub fn record_scale_down(&self, deployment: &str, n: u64) {
        if n == 0 {
            return;
        }
        let m = self.deployment(deployment);
        m.autoscale.vms_drained.fetch_add(n, Ordering::Relaxed);
        m.autoscale.scale_down_events.fetch_add(1, Ordering::Relaxed);
    }

    /// A rolling replacement passed its progress deadline and paused.
    pub fn record_rollout_stall(&self, deployment: &str) {
        self.deployment(deployment).autoscale.rollout_stalls.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reaped(&self, deployment: &str, n: u64) {
        if n == 0 {
            return;
        }
        self.deployment(deployment).autoscale.vms_reaped.fetch_add(n, Ordering::Relaxed);
    }

    /// A request began waiting on a cold start.
    pub fn record_cold_start_wait(&self, deployment: &str) {
        self.deployment(deployment).autoscale.cold_start_waits.fetch_add(1, Ordering::Relaxed);
    }

    /// A cold-start wait ended with a VM serving the request.
    pub fn record_cold_start_hit(&self, deployment: &str) {
        self.deployment(deployment).autoscale.cold_start_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// A cold-start wait ended in timeout with no VM.
    pub fn record_cold_start_timeout(&self, deployment: &str) {
        self.deployment(deployment).autoscale.cold_start_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// A booting VM was given up on for never passing its health check.
    pub fn record_boot_timeout(&self, deployment: &str) {
        self.deployment(deployment).autoscale.boot_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// The daemon refused to create a VM, and what it said.
    ///
    /// The counterpart to `record_scale_up`, which deliberately records nothing
    /// when zero VMs were created — so without this a pool whose every create is
    /// rejected reports all zeroes and looks idle rather than broken.
    pub fn record_create_failure(&self, deployment: &str, error: &str) {
        let m = self.deployment(deployment);
        m.autoscale.create_failures.fetch_add(1, Ordering::Relaxed);
        // A poisoned lock loses the message, never the count: the counter is
        // what a dashboard alerts on, and it is an atomic that cannot be lost.
        if let Ok(mut last) = m.autoscale.last_create_error.lock() {
            *last = Some(error.to_string());
        }
    }

    // --- Reading (dashboard poll) ----------------------------------------

    /// The snapshot for one deployment, or an all-zero snapshot if it has never
    /// recorded anything (so a freshly-registered deployment still renders).
    pub fn deployment_snapshot(&self, id: &str) -> DeploymentMetricsSnapshot {
        self.per_deployment
            .load()
            .get(id)
            .map(|m| m.snapshot())
            .unwrap_or_else(DeploymentMetricsSnapshot::empty)
    }

    /// Global rollup: every live deployment's snapshot merged, plus the totals
    /// carried over from deregistered ones. Exact, because the underlying
    /// buckets and counters are additive.
    pub fn global_snapshot(&self) -> DeploymentMetricsSnapshot {
        let mut global = match self.retired.lock() {
            Ok(retired) => retired.clone(),
            Err(_) => DeploymentMetricsSnapshot::empty(),
        };
        for m in self.per_deployment.load().values() {
            global.merge(&m.snapshot());
        }
        global
    }

    /// How many deployments currently hold their own counters. The number that
    /// used to grow without bound.
    pub fn tracked_deployments(&self) -> usize {
        self.per_deployment.load().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Retiring a deployment must free its entry — the map used to grow by one
    /// per id ever seen, which a sandbox fleet turns into an unbounded leak —
    /// without losing the traffic it served from the global rollup.
    #[test]
    fn retiring_a_deployment_frees_its_entry_but_keeps_its_totals() {
        let m = Metrics::new();
        m.record_request("gone", Some(200), Duration::from_millis(7));
        m.record_request("stays", Some(500), Duration::from_millis(3));
        assert_eq!(m.tracked_deployments(), 2);

        m.retire("gone");

        assert_eq!(m.tracked_deployments(), 1, "the entry is dropped");
        assert_eq!(
            m.deployment_snapshot("gone").requests.total,
            0,
            "and it no longer reports as a live deployment",
        );
        let global = m.global_snapshot();
        assert_eq!(global.requests.total, 2, "but its requests still count");
        assert_eq!(global.requests.c2xx, 1);
        assert_eq!(global.latency_ms.count, 2);
    }

    /// Retiring the same id twice must not double-count it into the rollup.
    #[test]
    fn retiring_twice_counts_once() {
        let m = Metrics::new();
        m.record_request("gone", Some(200), Duration::from_millis(1));
        m.retire("gone");
        m.retire("gone");
        assert_eq!(m.global_snapshot().requests.total, 1);
    }

    #[test]
    fn histogram_buckets_and_overflow() {
        let h = Histogram::new(LATENCY_BOUNDS_MS);
        h.record(0); // <= 1
        h.record(1); // <= 1
        h.record(3); // <= 5
        h.record(999_999); // overflow
        let s = h.snapshot();
        assert_eq!(s.count, 4);
        assert_eq!(s.buckets[0].count, 2, "0 and 1 fall in the <=1 bucket");
        assert_eq!(s.buckets[0].le, Some(1));
        assert_eq!(s.buckets.last().unwrap().le, None, "final bucket is overflow");
        assert_eq!(s.buckets.last().unwrap().count, 1);
    }

    #[test]
    fn percentiles_are_monotonic_and_bounded() {
        let h = Histogram::new(LATENCY_BOUNDS_MS);
        for v in [1, 2, 5, 10, 25, 50, 100] {
            for _ in 0..10 {
                h.record(v);
            }
        }
        let s = h.snapshot();
        assert!(s.p50 <= s.p90, "p50 {} !<= p90 {}", s.p50, s.p90);
        assert!(s.p90 <= s.p99, "p90 {} !<= p99 {}", s.p90, s.p99);
        assert!(s.p99 <= 100.0, "p99 {} exceeds max sample", s.p99);
    }

    #[test]
    fn empty_histogram_reports_zeroes() {
        let s = Histogram::new(COLD_START_BOUNDS_S).snapshot();
        assert_eq!(s.count, 0);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.p50, 0.0);
    }

    #[test]
    fn status_classes_are_partitioned() {
        let c = StatusCounts::default();
        c.record(Some(200));
        c.record(Some(204));
        c.record(Some(301));
        c.record(Some(404));
        c.record(Some(503));
        c.record(None);
        let s = c.snapshot();
        assert_eq!(s.total, 6);
        assert_eq!(s.c2xx, 2);
        assert_eq!(s.c3xx, 1);
        assert_eq!(s.c4xx, 1);
        assert_eq!(s.c5xx, 1);
        assert_eq!(s.errors, 1);
    }

    #[test]
    fn deployment_metrics_are_shared_not_duplicated() {
        let m = Metrics::new();
        let a = m.deployment("demo");
        let b = m.deployment("demo");
        assert!(Arc::ptr_eq(&a, &b), "same id must return the same counters");
        m.record_request("demo", Some(200), Duration::from_millis(5));
        assert_eq!(m.deployment_snapshot("demo").requests.total, 1);
    }

    #[test]
    fn global_is_the_merge_of_all_deployments() {
        let m = Metrics::new();
        m.record_request("a", Some(200), Duration::from_millis(3));
        m.record_request("b", Some(500), Duration::from_millis(7));
        m.record_cold_start("a", 2);
        m.record_scale_up("b", 3);

        let g = m.global_snapshot();
        assert_eq!(g.requests.total, 2);
        assert_eq!(g.requests.c2xx, 1);
        assert_eq!(g.requests.c5xx, 1);
        assert_eq!(g.latency_ms.count, 2);
        assert_eq!(g.cold_start_s.count, 1);
        assert_eq!(g.autoscale.vms_created, 3);
        assert_eq!(g.autoscale.scale_up_events, 1);
    }

    #[test]
    fn unknown_deployment_snapshot_is_empty_not_missing() {
        let m = Metrics::new();
        let s = m.deployment_snapshot("never-seen");
        assert_eq!(s.requests.total, 0);
        assert_eq!(s.latency_ms.buckets.len(), LATENCY_BOUNDS_MS.len() + 1);
    }

    #[test]
    fn cold_start_outcomes_are_counted() {
        let m = Metrics::new();
        m.record_cold_start_wait("demo");
        m.record_cold_start_wait("demo");
        m.record_cold_start_hit("demo");
        m.record_cold_start_timeout("demo");
        let a = m.deployment_snapshot("demo").autoscale;
        assert_eq!(a.cold_start_waits, 2);
        assert_eq!(a.cold_start_hits, 1);
        assert_eq!(a.cold_start_timeouts, 1);
    }
}
