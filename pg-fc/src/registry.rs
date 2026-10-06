//! Schema -> VM registry. One entry per schema, created once and reused.
//! A background reaper stops VMs that go idle (no connections) for too long.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use deadpool_postgres::Pool;
use heyo_sdk::{HeyoError, P2pTunnel, Sandbox};
use futures::StreamExt;
use tokio::sync::{Mutex, OnceCell, OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use crate::config::{Config, PressureConfig};
use crate::dedicated::{Credential, Credentials};
use crate::dumpsrv::DumpServer;
use crate::reclaim::{POST_STOP_RECLAIM_DELAY, RECLAIM_FIRST_DELAY, Reclaimer};
use crate::spares::SparePool;
use crate::store::{Bringup, BringupKind, Store, StoreRecord, Tier};
use crate::vm;
use crate::vm::RestoreSource;

/// Bound on the pre-stop CHECKPOINT the reaper issues before killing an idle
/// VM. An immediate checkpoint flushes at most shared_buffers of dirty pages
/// to virtio-SSD storage — seconds on any size class — so a longer wait means
/// something is wedged and the stop should proceed.
const PRE_STOP_CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a supervised background loop (reaper, eviction sweep) logs an
/// info-level "still alive" heartbeat when nothing else is happening. Every pass
/// also logs at debug; this throttles the visible-at-info line so a healthy,
/// idle loop proves liveness roughly this often without spamming the log.
const SUPERVISOR_HEARTBEAT: Duration = Duration::from_secs(900);

/// How often the offload pacer wakes to consider one unit of housekeeping.
/// Short on purpose: the tick is not how fast work happens (one job can take
/// minutes), it is how quickly the pacer notices the host went quiet — a
/// second after the last client bring-up drains, the next cold schema starts
/// moving. A tick with nothing to do costs a couple of atomic loads.
const OFFLOAD_TICK: Duration = Duration::from_secs(1);

/// Grace before the pacer's first job, so a restart's reconnect storm and the
/// warm pool's first fill happen against an otherwise idle host.
const OFFLOAD_FIRST_DELAY: Duration = Duration::from_secs(60);

/// Bounds on how long the pacer waits after a scan that found no work, taken
/// from the configured `*_SWEEP_SECS` (see [`SchemaRegistry::offload_idle_rescan`]).
const OFFLOAD_IDLE_RESCAN_MIN: Duration = Duration::from_secs(5);
const OFFLOAD_IDLE_RESCAN_MAX: Duration = Duration::from_secs(60);

/// Delay before the orphan-disk sweep's first pass after startup — long enough
/// to let the pooler finish coming up and reattach warm VMs (so their disks are
/// held open and never misread as orphans), short enough that frequent
/// redeploys can't starve the sweep (see [`supervise`]).
const ORPHAN_FIRST_DELAY: Duration = Duration::from_secs(180);

/// A disk directory must be at least this old (by mtime) to be an orphan
/// candidate. A VM mid-create/mid-boot has a brand-new `sb-<id>/` that the
/// daemon may not report yet (`get` 404s during provisioning) and whose disk
/// isn't open yet — deleting it would be catastrophic. A genuine orphan is
/// stale by definition (its schema was offloaded long ago), so an age floor
/// costs nothing and closes the create race outright.
const ORPHAN_MIN_AGE: Duration = Duration::from_secs(1800);

/// Cap on directory deletions per orphan sweep. Bounds the blast radius of any
/// misclassification to a batch, and keeps a first run over a large backlog
/// from doing hundreds of `remove_dir_all`s (and daemon round-trips) in one
/// pass; the rest drain over subsequent sweeps.
const ORPHAN_MAX_DELETES_PER_SWEEP: usize = 100;

/// Cap on leftover boot artefacts pruned per sweep (see the rootfs prune in
/// [`SchemaRegistry::sweep_orphans`]). Higher than the directory cap: removing
/// one file from a stopped VM's directory is cheap and completely reversible —
/// the daemon rebuilds it from the base image on the next boot — where
/// deleting a directory is not.
const ORPHAN_MAX_ROOTFS_PRUNES_PER_SWEEP: usize = 250;

/// Name of the per-VM rootfs copy heyvmd clones into `run/<id>/` at boot and
/// removes again on a clean stop. One that outlives its VM is pure waste
/// (~200MB each on the pg image); see the prune in
/// [`SchemaRegistry::sweep_orphans`].
const VM_ROOTFS_FILE: &str = "rootfs.ext4";

/// Abort an orphan sweep after this many consecutive daemon errors while
/// checking sandbox liveness: a flaking/restarting heyvmd must never let a
/// "gone?" ambiguity turn into a deletion, so we stop and try again next sweep.
///
/// "Consecutive" means *since the last probe the daemon answered* — `Present`
/// and `Gone` alike; [`daemon_error_run`] owns that rule so no match arm can
/// drift from it. Clearing the run on `Gone` alone (as this once did) quietly
/// redefines the breaker as "errors since the last orphan", which on a host
/// whose forgotten dirs sort late in readdir order never clears at all: the
/// `Present`-heavy prefix accumulates strays until five of them abort the pass
/// before it has reached a single deletable dir. Measured on a pooler host
/// before the fix — 38 of 40 passes aborted, 11 dirs reclaimed in 7 hours
/// against a 2.5k backlog, while the sweep looked healthy in every log line.
const ORPHAN_MAX_DAEMON_ERRORS: usize = 5;

/// Drain mode: when a sweep's per-pass caps left candidates behind, re-run
/// after this long instead of waiting the whole configured interval — but
/// only if no client bring-up is queued at that moment. Turns the per-pass
/// cap from a throughput ceiling (100 per interval) into a blast-radius
/// bound (100 per ~20s while a backlog exists and the host is quiet).
const ORPHAN_DRAIN_REARM: Duration = Duration::from_secs(20);

/// Cadence of the pending-bring-up janitor (see [`SchemaRegistry::spawn_pending_janitor`]).
/// Frequent is fine: a pass over an empty ledger is a HashMap read.
const PENDING_JANITOR_TICK: Duration = Duration::from_secs(300);
const PENDING_JANITOR_FIRST_DELAY: Duration = Duration::from_secs(240);

/// First-failure backoff for offloads (archive/freeze) of one schema.
/// Doubles per consecutive failure, capped at [`OFFLOAD_BACKOFF_CAP`].
const OFFLOAD_BACKOFF_BASE: Duration = Duration::from_secs(30 * 60);
/// Ceiling on the offload backoff: even a permanently sick schema is retried
/// this often, so a fixed environment heals without operator action.
const OFFLOAD_BACKOFF_CAP: Duration = Duration::from_secs(24 * 3600);

/// Circuit breaker for one eviction sweep: after this many *consecutive*
/// archive failures the pass aborts instead of grinding on. Each failed archive
/// can cost a full ready-timeout (~5 min of a wedged bring-up), and a run of
/// them means the environment is sick — daemon flaking, host disk full,
/// Postgres unable to start — not that these particular schemas are odd.
/// Sweeping on multiplies a systemic outage by the candidate count; stopping
/// costs nothing, since every remaining candidate is retried next sweep.
const SWEEP_MAX_CONSECUTIVE_FAILURES: usize = 3;

/// A ready, warm VM for one schema. `target` is where client bytes are spliced
/// — either the VM's guest IP directly (same-host, no tunnel) or the local end
/// of an iroh tunnel. Holding `tunnel` (when present) keeps that forward alive;
/// holding `pool` keeps a bootstrap/health connection warm.
pub struct SchemaEntry {
    pub sandbox: Sandbox,
    /// Splice destination for this schema's Postgres.
    pub target: SocketAddr,
    /// Some in tunnel mode (kept alive for the entry's lifetime); None when
    /// dialing the guest IP directly.
    #[allow(dead_code)]
    pub tunnel: Option<P2pTunnel>,
    #[allow(dead_code)]
    pub pool: Pool,
    /// Exempt from idle reaping (a permanent keep-alive schema).
    pub keepalive: bool,
    /// Admission control for the VM's Postgres. The pooler splices client
    /// connections 1:1, so without a bound here the guest's `max_connections`
    /// is enforced by *Postgres*, as a `FATAL: sorry, too many clients
    /// already` on the (N+1)th client. That FATAL is what an application sees
    /// as a hard connection error mid-import, and the usual reaction — tear
    /// the pool down and retry — strands every transaction already in flight.
    ///
    /// Holding a permit for each spliced connection converts that rejection
    /// into a wait: over-eager clients queue at the pooler instead of being
    /// refused by the database. This bounds the guest; it does not multiplex
    /// (see `checkout`).
    slots: Arc<Semaphore>,
    /// What `slots` started with, for reporting (a `Semaphore` only exposes
    /// what's currently free).
    slot_limit: usize,
    /// Number of client connections currently spliced through this entry.
    active: AtomicUsize,
    /// Last time a connection started or ended. `active == 0` plus a stale
    /// `last_active` is what marks the VM idle. Refreshed at checkout so an
    /// entry handed out but not yet counted in `active` isn't reaped mid-race.
    last_active: StdMutex<Instant>,
    /// What this entry's own bring-up cost, measured from the moment it
    /// cleared the admission queue to the moment Postgres was serving (see
    /// `vm::ensure_vm`). The queue wait is excluded on purpose: it is a
    /// function of how many other clients arrived at once, not of what this
    /// VM costs to bring back.
    ///
    /// This is the price of *not* keeping the VM warm, so it is what the
    /// reaper prices the idle timeout off — see [`Self::idle_budget`].
    bringup_took: Duration,
    /// What that bring-up was — a create, a spare claim, a reattach or a
    /// restore. `None` for an entry that didn't come from a client bring-up
    /// (a fenced handoff reattach), which is never recorded.
    bringup_kind: Option<BringupKind>,
}

impl SchemaEntry {
    pub fn new(
        sandbox: Sandbox,
        target: SocketAddr,
        tunnel: Option<P2pTunnel>,
        pool: Pool,
        keepalive: bool,
        slots: usize,
        bringup_took: Duration,
        bringup_kind: Option<BringupKind>,
    ) -> Self {
        Self {
            sandbox,
            target,
            tunnel,
            pool,
            keepalive,
            slots: Arc::new(Semaphore::new(slots)),
            slot_limit: slots,
            active: AtomicUsize::new(0),
            last_active: StdMutex::new(Instant::now()),
            bringup_took,
            bringup_kind,
        }
    }

    /// This entry's own bring-up, as the registry row records it.
    pub fn bringup(&self) -> Option<Bringup> {
        self.bringup_kind.map(|kind| Bringup {
            kind,
            took_ms: u64::try_from(self.bringup_took.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Free client slots right now (0 = the next client will queue).
    pub fn free_slots(&self) -> usize {
        self.slots.available_permits()
    }

    /// Total client slots this VM's Postgres was measured to allow.
    pub fn slot_limit(&self) -> usize {
        self.slot_limit
    }

    fn touch(&self) {
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// Live client connections currently spliced through this entry. Read-only
    /// view of the private `active` counter for the dashboard; the proxy path
    /// mutates it only through `ConnGuard`.
    pub fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// How long since the last connect/disconnect on this entry.
    pub fn idle_for(&self) -> Duration {
        self.last_active.lock().unwrap().elapsed()
    }

    /// The sandbox id of the VM backing this entry.
    pub fn sandbox_id(&self) -> String {
        self.sandbox.sandbox_id().to_string()
    }

    /// True when reached over an iroh tunnel rather than a direct guest IP.
    pub fn is_tunneled(&self) -> bool {
        self.tunnel.is_some()
    }

    /// Idle = not keep-alive, no live connections, and quiet for `>= timeout`.
    fn is_idle(&self, timeout: Duration) -> bool {
        !self.keepalive
            && self.active.load(Ordering::SeqCst) == 0
            && self.last_active.lock().unwrap().elapsed() >= timeout
    }

    /// How long this particular VM may sit idle before the reaper stops it —
    /// see [`idle_budget`], which this hands its measured bring-up cost to.
    fn idle_budget(
        &self,
        normal: Duration,
        fast: Option<Duration>,
        fast_bringup: Duration,
    ) -> Duration {
        idle_budget(self.bringup_took, normal, fast, fast_bringup)
    }
}

/// Which idle timeout applies to a VM whose own bring-up took `bringup_took`.
///
/// The warm hold exists to spare the next client the bring-up, so it is priced
/// off what that bring-up actually cost: a VM that came back in under
/// `fast_bringup` — the daemon `start()` of a VM still on disk — gets `fast`,
/// and everything else (a create, a spare claim that still had to `initdb`,
/// any thaw) keeps the full `normal` budget. `fast` of `None` disables the
/// two-speed behavior entirely.
///
/// Measured rather than inferred from whether the VM already existed, because
/// the number that matters is what the *host* can do right now. When heyvmd is
/// saturated a restart that is normally 200ms takes seconds — and that is
/// exactly when a short timeout does damage, feeding stop/start work to a
/// daemon already behind. Those bring-ups fail this test on their own and fall
/// back to `normal`, so the reaper eases off under load with no extra knob and
/// no load signal to calibrate.
///
/// Free-standing so the policy can be tested without building a `SchemaEntry`
/// (which needs a live sandbox, tunnel and pool).
fn idle_budget(
    bringup_took: Duration,
    normal: Duration,
    fast: Option<Duration>,
    fast_bringup: Duration,
) -> Duration {
    match fast {
        Some(fast) if bringup_took <= fast_bringup => fast,
        _ => normal,
    }
}

/// Hard ceiling on one pass's stop allowance, above whatever the drain window
/// asks for. This is daemon protection rather than smoothing — 24 stops, 8 at
/// a time, is about as much as one heyvmd should be asked to absorb in a tick
/// while it is also serving bring-ups. On a fleet big enough for the window to
/// ask for more, this binds and the fleet simply drains over longer than the
/// window, which is the safe direction to err.
const IDLE_MAX_STOPS_PER_PASS: usize = 24;

/// How many idle-stops run concurrently within one reaper pass.
///
/// A stop is almost entirely waiting — a guest `df`, a CHECKPOINT, the
/// daemon's stop call — so serializing them made a pass cost the sum of every
/// victim's worst case (tens of seconds each) and let one slow VM push the
/// whole fleet past its idle deadline. Bounded rather than unleashed because
/// the far end is one heyvmd, whose sandbox manager goes lock-contended before
/// anything else does: a mass expiry must not become a burst of stop calls
/// against the same daemon the clients are queued on. Eight finishes a full
/// capped pass in three rounds even if every stop hits its worst case, and
/// stays well under what a bring-up burst already asks of the daemon.
const IDLE_STOP_CONCURRENCY: usize = 8;

/// Floor on one pass's stop allowance, whatever the drain window works out to.
///
/// Without it a small fleet computes a fractional allowance and the reaper
/// would take many passes to stop a handful of VMs — smoothing something that
/// was never going to be a swing. Four per pass clears a small backlog in
/// seconds and is far below any rate that shows up on a chart.
const IDLE_MIN_STOPS_PER_PASS: usize = 4;

/// Bound on the daemon's stop call for one idle-stopped VM.
///
/// The reaper used to await `Sandbox::stop()` with no timeout at all, so a
/// single VM whose stop never returned (a lock-contended or wedged heyvmd —
/// the exact condition under which the pooler most needs to be shedding VMs)
/// parked the pass, and with it every other stop, indefinitely. Matches the
/// untracked reaper's bound, which always had one.
const IDLE_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The same bound for the untracked reaper's stops, which always had one.
const UNTRACKED_STOP_TIMEOUT: Duration = IDLE_STOP_TIMEOUT;

/// How often the urgent device-grow watcher samples a warm schema that is not
/// filling. A guest query per warm VM every few seconds is not survivable, so
/// the bulk of the warm set is looked at once a minute. See
/// [`SchemaRegistry::spawn_disk_grower`].
const URGENT_GROW_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// How often the urgent grower re-samples a schema that is filling, sits near
/// the threshold, or has been sampled only once — and so how often its loop
/// ticks. A minute is too slow for a bulk load: at 15–30 MB/s the last 5% of a
/// 2GiB device goes in seconds, and a migration's copy ran straight past the
/// urgent threshold into `No space left on device` between two samples. Only
/// the schemas that earn it pay for this cadence.
const URGENT_GROW_FAST_INTERVAL: Duration = Duration::from_secs(10);

/// Fill rate, between two samples, that puts a schema on the fast cadence.
/// Well above what WAL churn and ordinary writes produce; a bulk load clears
/// it by an order of magnitude.
const URGENT_GROW_FILLING_BYTES_PER_SEC: f64 = 1024.0 * 1024.0;

/// A schema within this many points of the urgent threshold is sampled on the
/// fast cadence whatever its measured rate: one burst between two slow
/// samples would otherwise carry it over.
const URGENT_GROW_WATCH_MARGIN_PCT: f64 = 15.0;

/// Added to the projection horizon for the stop itself: once a grow is
/// decided, the guest keeps writing through the checkpoint and the daemon's
/// stop.
const URGENT_GROW_STOP_MARGIN: Duration = Duration::from_secs(10);

/// Cap on devices the urgent grower resizes **offline** in one pass. Each
/// offline grow drops a schema's live sessions, so a pass that needs many
/// trickles instead of restarting the whole warm set at once. Online grows
/// drop nothing and are not capped.
const URGENT_GROW_MAX_PER_PASS: usize = 4;

/// How [`SchemaRegistry::grow_device_now`] grew a device, or that it didn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrgentGrow {
    /// Grown under the running VM; no session was dropped.
    Online,
    /// Stopped and grown offline; the next connect boots it.
    Offline,
    /// Not this pass's to grow after all. Not a failure.
    Skipped,
}

/// How many warm schemas the urgent grower samples at once. Each sample uses
/// its own schema's housekeeping pool, so this bounds pooler-side concurrency
/// only — it never puts two queries on one VM.
const URGENT_GROW_SAMPLE_CONCURRENCY: usize = 8;

/// Per-schema idle-timeout jitter: a deterministic factor in [0.85, 1.15)
/// derived from the schema name. Clients that arrive (and go quiet) together
/// would otherwise expire together and stop as one wave; spreading each
/// schema's effective timeout ±15% breaks the cohort up permanently without
/// any state. Deterministic so a schema's effective timeout is stable across
/// passes and restarts.
fn jittered_timeout(schema: &str, timeout: Duration) -> Duration {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    schema.hash(&mut h);
    let unit = (h.finish() % 1000) as f64 / 1000.0;
    timeout.mul_f64(0.85 + 0.30 * unit)
}

/// How many VMs one reaper pass may stop, given the live-tier fleet size.
///
/// This is the whole answer to the sawtooth. Idle reaping is deadline-driven,
/// so a burst workload goes idle in a burst: with a 60s budget the ±15%
/// per-schema jitter spreads a cohort's deadlines over about eighteen seconds,
/// and every VM in it is due at once. What the reaper does with that backlog
/// decides whether the fleet ramps down or falls off a cliff — and a flat
/// per-pass cap does not decide it, because a cohort larger than the cap keeps
/// the reaper saturated at cap-per-tick regardless of how the deadlines
/// spread. Widening the jitter cannot fix that; only bounding the rate can.
///
/// So the allowance is `live × tick / window`: at most one window's worth of
/// the fleet per window, i.e. a straight line of known gradient however
/// synchronized the expiry. `live` is the live-tier schema count rather than
/// the warm/running count on purpose — stopping a VM does not change its tier,
/// so the divisor holds still for the length of a drain and the slope stays
/// constant. Sizing off the running count instead makes the allowance shrink
/// as the drain proceeds, which decays into a long tail: the last VMs of a
/// 600-VM cohort would wait half an hour past a 60s budget.
///
/// Clamped both ways. [`IDLE_MIN_STOPS_PER_PASS`] keeps a small fleet from
/// smoothing something that was never a swing; [`IDLE_MAX_STOPS_PER_PASS`] is
/// the daemon's protection and binds on a fleet big enough to ask for more,
/// which just means the drain takes longer than the window.
///
/// `window` of `None` disables the rate limit (the flat ceiling, as before).
fn drain_allowance(live: usize, tick: Duration, window: Option<Duration>) -> usize {
    let Some(window) = window.filter(|w| !w.is_zero()) else {
        return IDLE_MAX_STOPS_PER_PASS;
    };
    // Rounded up so the allowance is never zero while any window is set.
    let per_pass = (live as u128 * tick.as_millis()).div_ceil(window.as_millis().max(1)) as usize;
    per_pass.clamp(IDLE_MIN_STOPS_PER_PASS, IDLE_MAX_STOPS_PER_PASS)
}

/// RAII marker for one in-flight client connection. Bumps the entry's active
/// count for its lifetime and refreshes activity on both ends, so the reaper
/// never stops a VM with (or that just had) a live connection.
///
/// Also owns the entry's admission permit, so the guest's connection budget is
/// released on exactly the same event that ends the splice — including an
/// error or a panic on the proxy path. A permit leak here would silently
/// shrink the VM's usable connection count until a restart, so it must not be
/// released anywhere but `Drop`.
pub struct ConnGuard(Arc<SchemaEntry>, #[allow(dead_code)] OwnedSemaphorePermit);

impl ConnGuard {
    /// Take an admission permit, then mark the entry active. Waits up to
    /// `timeout` for a free slot; `None` means every slot is busy and the
    /// caller should fail this client rather than queue forever.
    async fn acquire(entry: Arc<SchemaEntry>, timeout: Duration) -> Option<Self> {
        let permit = match entry.slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // Queueing is the whole point, but it is also the moment the
                // client stops getting what it asked for — say so. Silent
                // backpressure reads as "the pooler is slow"; this names it.
                let waited = Instant::now();
                warn!(
                    "all {} client slots busy on this VM; client is queueing \
                     (up to {timeout:?}) instead of being refused by Postgres",
                    entry.slot_limit()
                );
                let p = tokio::time::timeout(timeout, entry.slots.clone().acquire_owned())
                    .await
                    .ok()?
                    .ok()?;
                info!("client admitted after queueing {:?}", waited.elapsed());
                p
            }
        };
        entry.active.fetch_add(1, Ordering::SeqCst);
        entry.touch();
        Some(Self(entry, permit))
    }

    pub fn entry(&self) -> &SchemaEntry {
        &self.0
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

/// Bound on the dashboard's per-VM stat queries (DB and guest-OS stats) so a
/// wedged VM can't hang a detail-page render.
const STATS_TIMEOUT: Duration = Duration::from_secs(3);

/// Live database usage for a warm entry, read over its warm pool.
pub struct DbStats {
    pub db_size_bytes: i64,
    pub backends: i32,
}

/// Live guest-OS stats for a warm, pooler-managed VM, read over the same warm
/// PG pool as [`DbStats`] — never the guest console. `/proc` reads use
/// `pg_read_file` (needs superuser or `pg_read_server_files`; the default
/// `postgres` user qualifies); disk usage runs `df` as an ordinary fork under
/// the Postgres backend via `COPY FROM PROGRAM` (`pg_execute_server_program`).
/// Each piece degrades to `None` independently, so a locked-down role still
/// shows whatever it can.
pub struct GuestStats {
    /// Guest RAM (total, available) in bytes, from `/proc/meminfo`.
    pub mem: Option<(u64, u64)>,
    /// 1/5/15-minute load averages, from `/proc/loadavg`.
    pub load: Option<(f64, f64, f64)>,
    /// Filesystem holding the Postgres data directory: (total, used,
    /// available) bytes, from `df -kP` on `current_setting('data_directory')`.
    pub disk: Option<(u64, u64, u64)>,
}

/// A plain, owned point-in-time view of one warm schema entry — no `Sandbox`,
/// `Pool`, or lock handles — safe to hand to the dashboard's render layer.
pub struct EntrySnapshot {
    pub schema: String,
    pub sandbox_id: String,
    pub target: SocketAddr,
    pub active: usize,
    /// Client slots free / total on this VM's Postgres. `free == 0` means new
    /// clients are queueing at the pooler.
    pub free_slots: usize,
    pub slot_limit: usize,
    pub idle_secs: u64,
    /// The idle timeout that actually applies to this entry, which with
    /// two-speed reaping is per-VM rather than the one configured number —
    /// see [`idle_budget`]. `None` when idle reaping is off.
    pub idle_budget_secs: Option<u64>,
    /// What this entry's own bring-up cost, the input that chose that budget.
    /// Surfaced so "why did this VM stop after a minute" is answerable from
    /// the dashboard instead of the log.
    pub bringup_ms: u128,
    pub keepalive: bool,
    pub tunneled: bool,
}

pub struct SchemaRegistry {
    cfg: Config,
    // Outer Mutex guards the map only; the per-schema OnceCell serializes the
    // (slow) first VM bring-up without blocking other schemas. A failed init
    // leaves the cell empty so the next client retries.
    entries: Mutex<HashMap<String, Arc<OnceCell<Arc<SchemaEntry>>>>>,
    // Persistent schema → sandbox-id map. Outlives entry eviction and process
    // restarts, so a reconnect after a stop/reap/restart reattaches to the same
    // VM (by id) rather than creating a duplicate with a fresh, empty data disk.
    store: Store,
    // Schemas whose VM is mid-offload (dump/compact + kill in flight). A
    // checkout for a schema in this set waits until it clears, then
    // cold-starts — which restores from S3. Guards against a client bringing a
    // VM back up while the offload is dumping and killing it. Held for the
    // whole operation (per-schema, via ArchivingGuard); the dispatcher also
    // consults it at pick time so concurrent workers, the pressure pass, and
    // dashboard buttons never pick each other's schemas.
    archiving: StdMutex<HashSet<String>>,
    // True while an eviction sweep is running. Single-flights the sweep so the
    // periodic timer and a manual "sweep now" can't stack overlapping passes over
    // the same candidates.
    sweeping: AtomicBool,
    // True while an orphan-disk sweep is running. Its own single-flight (not
    // shared with `sweeping`) because it touches no VMs or checkouts — it only
    // deletes directories the daemon confirms gone — so it may run alongside an
    // eviction sweep; this just stops two orphan passes from racing.
    orphan_sweeping: AtomicBool,
    // Offline-trims stopped VMs' data disks (Firecracker has no discard
    // passthrough, so freed guest blocks never return to the host on their
    // own). `Some` when PG_VM_POOL_RECLAIM_CMD is configured.
    reclaimer: Option<Arc<Reclaimer>>,
    // Warm-spare pool: pre-booted empty VMs a cold bring-up claims instead of
    // paying create + boot + initdb. `Some` when PG_VM_POOL_WARM_SPARES > 0.
    spares: Option<Arc<SparePool>>,
    // Local dump store + token registry for the frozen tier. `Some` when
    // PG_VM_POOL_FREEZE_AFTER_SECS is configured.
    dumps: Option<Arc<DumpServer>>,
    // Per-schema failure memory so the sweeps skip recently-failed offloads
    // instead of burning a ready-timeout on the same sick schemas every pass.
    offload_backoff: OffloadBackoff,
    // Per-schema failure memory for the *urgent* device-grow path, kept
    // separate from `offload_backoff` on purpose: a schema whose grow keeps
    // failing must not thereby become un-offloadable, and vice versa. Also
    // doubles as the rate limiter for the "at the cap, cannot help" complaint,
    // which would otherwise repeat every pass forever.
    grow_backoff: OffloadBackoff,
    // The urgent grower's last disk sample per warm schema: what turns two
    // samples into a fill rate and decides how soon to look again. Pruned to
    // the warm set every pass; a grow forgets the schema, whose next bring-up
    // starts a fresh baseline on the resized device.
    urgent_samples: StdMutex<HashMap<String, GrowSample>>,
    /// Per-schema bring-up circuit breaker — see [`BringupBreaker`].
    bringup_breaker: BringupBreaker,
    // Single-flights the dashboard's purge action.
    purging: AtomicBool,
    // Provisioned dedicated databases: `database → (role, password)`. Consulted
    // on the auth path (which password to challenge for, and whether this
    // client may route here at all) and on every bring-up (so the owning role
    // exists inside the VM). Empty unless an operator has provisioned one.
    dedicated: Arc<Credentials>,
    // Trusted peer nodes: how to reach another pooler's admin API, and the
    // address a guest on this host dials to reach its pooler. Empty unless an
    // operator has recorded one.
    peers: Arc<crate::peers::PeerStore>,
    // When each pairing's slot was first seen with no subscriber attached, and
    // whether that has already been reported. Edge-triggered like the
    // dashboard's webhook alerts: an inactive slot is a standing condition, so
    // warning every tick would bury the journal instead of informing it.
    repl_inactive: StdMutex<HashMap<String, (Instant, bool)>>,
    // Last replication status sample per database, refreshed by
    // `spawn_replication_monitor`. The dashboard renders from this rather than
    // querying a VM, so a page load never disturbs what it is showing and a
    // wedged VM cannot hang a render.
    repl_status: StdMutex<HashMap<String, crate::replication::wire::StatusJson>>,
    // Replication pairings, `database → (role, peer, state)`. Loaded even when
    // the feature is disabled, because this is what holds the pin that keeps a
    // replicating VM off the idle reaper and the offload ladder — see
    // [`Self::pinned`].
    replication: Arc<crate::replication::ReplStore>,
    physical: Arc<crate::replication::PhysicalStore>,
    physical_sources: Arc<crate::replication::PhysicalSourceStore>,
    // Loaded before any recovery workers are started.  An incomplete record is
    // therefore an admission fence from the first observable instant of boot.
    database_maintenance: Arc<crate::database_maintenance::Store>,
    replication_ops: StdMutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    binding_ops: StdMutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>,
    // The knobs `PUT /api/config` may change while the pooler runs. The loops
    // that use them read here on every pass rather than off `cfg`.
    runtime: Arc<crate::runtime_config::RuntimeConfig>,
}

impl SchemaRegistry {
    pub fn new(cfg: Config) -> Result<Self> {
        // Per-disk reclaim locks live under the run dir. Publish it once here:
        // the boot path is a free function with no access to the config.
        crate::reclaim::set_run_dir(cfg.run_dir.clone());
        let store = Store::load(cfg.state_file.clone());
        let reclaimer = cfg
            .reclaim
            .as_ref()
            .map(|r| Arc::new(Reclaimer::new(r.cmd.clone(), cfg.run_dir.clone())));
        let runtime = Arc::new(crate::runtime_config::RuntimeConfig::load(&cfg));
        let spares = (cfg.warm_spares > 0).then(|| {
            // A persisted override outranks the env's count from the first pass.
            let target = runtime.warm_spares().unwrap_or(cfg.warm_spares);
            Arc::new(SparePool::new(target, cfg.chilled_vehicles))
        });
        // The dump server has two consumers: the frozen tier (freeze + thaw)
        // and the S3 archive tier, whose dumps *stream* through it so they
        // never touch the guest's data disk. Either one enables it.
        let dumps = (cfg.freeze.is_some() || cfg.archive.is_some())
            .then(|| Arc::new(DumpServer::new(cfg.dump_net.dump_dir.clone())));
        let dedicated = Arc::new(Credentials::load(cfg.dedicated_file.clone()));
        let peers = Arc::new(crate::peers::PeerStore::load(cfg.peers_file.clone()));
        let replication = Arc::new(crate::replication::ReplStore::load(
            cfg.replication_file.clone(),
        ));
        let physical = Arc::new(crate::replication::PhysicalStore::load(
            cfg.replication_file.with_extension("physical.json"),
        )?);
        let physical_sources = Arc::new(crate::replication::PhysicalSourceStore::load(
            cfg.replication_file.with_extension("physical-sources.json"),
        )?);
        let database_maintenance = Arc::new(crate::database_maintenance::Store::load(
            cfg.replication_file
                .with_extension("database-maintenance.json"),
        )?);
        Ok(Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
            store,
            archiving: StdMutex::new(HashSet::new()),
            sweeping: AtomicBool::new(false),
            orphan_sweeping: AtomicBool::new(false),
            reclaimer,
            spares,
            dumps,
            offload_backoff: OffloadBackoff::new(),
            grow_backoff: OffloadBackoff::new(),
            urgent_samples: StdMutex::new(HashMap::new()),
            bringup_breaker: BringupBreaker::default(),
            purging: AtomicBool::new(false),
            dedicated,
            peers,
            replication,
            physical,
            physical_sources,
            database_maintenance,
            replication_ops: StdMutex::new(HashMap::new()),
            binding_ops: StdMutex::new(HashMap::new()),
            repl_status: StdMutex::new(HashMap::new()),
            repl_inactive: StdMutex::new(HashMap::new()),
            runtime,
        })
    }

    /// The runtime-mutable knobs and where each came from.
    pub fn runtime(&self) -> &Arc<crate::runtime_config::RuntimeConfig> {
        &self.runtime
    }

    /// Apply a `PUT /api/config` patch and push the parts that live outside
    /// the knob store (the spare pool's target) to where they are read.
    pub fn apply_runtime(&self, patch: pg_fc_api::RuntimeKnobs) -> Result<pg_fc_api::RuntimeKnobs, String> {
        let eff = self.runtime.apply(patch)?;
        if let (Some(pool), Some(n)) = (&self.spares, eff.warm_spares) {
            pool.set_target(n);
        }
        Ok(eff)
    }

    /// The trusted peer nodes — what the replication API and dashboard mutate.
    pub fn peers(&self) -> &Arc<crate::peers::PeerStore> {
        &self.peers
    }

    /// The replication pairings this node is part of.
    pub fn replication(&self) -> &Arc<crate::replication::ReplStore> {
        &self.replication
    }

    pub fn physical(&self) -> &Arc<crate::replication::PhysicalStore> {
        &self.physical
    }
    pub fn physical_sources(&self) -> &Arc<crate::replication::PhysicalSourceStore> {
        &self.physical_sources
    }
    pub fn database_maintenance(&self) -> &crate::database_maintenance::Store {
        &self.database_maintenance
    }
    pub fn bound_vm_id(&self, database: &str) -> Option<String> {
        self.store.record(database).map(|r| r.sandbox_id)
    }

    pub fn physical_admission_ready(&self, database: &str) -> bool {
        let bound = self.bound_vm_id(database);
        if bound.is_none() && (self.physical.get(database).is_some() || self.physical_sources.get(database).is_some()) { return false; }
        !bound.as_deref().is_some_and(|id| self.physical_sources.has_grant_for_source_vm(database, id))
            && !self.physical_source_fenced(database)
            && self.physical.get(database).is_none_or(|r| {
                if r.phase == crate::replication::PhysicalPhase::StandbyBinding {
                    false
                } else if r.phase == crate::replication::PhysicalPhase::Standby {
                    r.candidate_id == bound
                } else if r.handoff_started() {
                    r.phase == crate::replication::PhysicalPhase::Activated && r.candidate_id == bound
                } else { r.previous_vm_id == bound }
            })
    }

    pub fn physical_source_fenced(&self, database: &str) -> bool {
        self.physical_sources.get(database).is_some_and(|r| r.fence.is_some()
            && self.bound_vm_id(database).as_deref() == Some(r.source_vm_id.as_str()))
    }

    pub fn physical_reconnect_allowed(&self, database: &str, role: &str) -> bool {
        let Some(source) = self.physical_sources.get(database) else { return false };
        (source.handoff.is_some() || source.fence.is_some())
            && (source.repl.as_ref().is_some_and(|login| login.role == role)
                || self.replication.by_repl_role(role).is_some_and(|r| r.database == database && r.repl_role == role))
            && self.bound_vm_id(database).as_deref() == Some(source.source_vm_id.as_str())
    }

    pub async fn commit_physical_binding(self: &Arc<Self>, database: &str, expected: &str, candidate: &str) -> Result<()> {
        let _binding = self.binding_lock(database).write_owned().await;
        let reg = self.clone();
        let (db, old, new) = (database.to_owned(), expected.to_owned(), candidate.to_owned());
        tokio::task::spawn_blocking(move || reg.store.commit_handoff_binding(&db, &old, &new)).await??;
        self.entries.lock().await.remove(database);
        Ok(())
    }

    fn binding_lock(&self, database: &str) -> Arc<tokio::sync::RwLock<()>> {
        self.binding_ops.lock().unwrap().entry(database.into())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(()))).clone()
    }

    /// Checkout an already-owned physical VM by exact ID.  This deliberately
    /// bypasses ordinary name-based bring-up and is safe while the caller owns
    /// `replication_operation`; it cannot publish a stale `pg-{database}` VM.
    pub async fn checkout_physical_exact(&self, database: &str, candidate: &str) -> Result<ConnGuard> {
        if self.bound_vm_id(database).as_deref() != Some(candidate) { bail!("exact physical binding changed"); }
        let cell = self.entries.lock().await.entry(database.to_string()).or_insert_with(|| Arc::new(OnceCell::new())).clone();
        let entry = cell.get_or_try_init(|| vm::ensure_fenced_vm(&self.cfg, database, candidate)).await?;
        if entry.sandbox_id() != candidate { bail!("warm entry does not match exact physical binding"); }
        ConnGuard::acquire(entry.clone(), self.cfg.admit_timeout).await.context("physical standby connection slots exhausted")
    }

    pub async fn exec_bound(&self, database: &str, expected_id: &str, command: &str, env: HashMap<String, String>) -> Result<()> {
        let guard = self.checkout(database).await?;
        if guard.entry().sandbox_id() != expected_id { bail!("database binding changed during physical preparation"); }
        let result = vm::physical_exec(&self.cfg, &guard.entry().sandbox, command, env, "physical source setup").await?;
        if result.exit_code != 0 { bail!("physical source guest setup failed (exit {})", result.exit_code); }
        Ok(())
    }

    pub(crate) async fn raw_replication_operation(
        &self,
        database: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .replication_ops
            .lock()
            .unwrap()
            .entry(database.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    pub async fn replication_operation(
        &self,
        database: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>> {
        let guard = self.raw_replication_operation(database).await;
        // Check after acquisition: begin_database_maintenance takes this same
        // lock before publishing its journal record, so crossing operations
        // have a total order and a waiter cannot proceed on a stale precheck.
        self.database_maintenance.check(database)?;
        Ok(guard)
    }

    /// Durably close ordinary admission for a retirement/rename.  Both names'
    /// operation and binding locks are acquired in lexical order so all earlier
    /// cold publications drain before the gate becomes visible.
    pub async fn begin_database_maintenance(
        &self,
        operation: crate::database_maintenance::Operation,
    ) -> Result<()> {
        let mut names = vec![operation.database.clone()];
        if let Some(destination) = &operation.destination {
            names.push(destination.clone());
        }
        names.sort();
        names.dedup();
        let mut operation_guards = Vec::new();
        let mut binding_guards = Vec::new();
        for name in &names {
            operation_guards.push(self.raw_replication_operation(name).await);
        }
        for name in &names {
            binding_guards.push(self.binding_lock(name).write_owned().await);
        }

        if let Some(existing) = self.database_maintenance.get(&operation.id) {
            // Store::begin performs the complete identity comparison and makes
            // retries of the exact operation harmless.
            self.database_maintenance.begin(operation.clone())?;
            if existing.database != operation.database {
                bail!("maintenance retry changed database");
            }
        } else {
            if self.bound_vm_id(&operation.database).as_deref() != Some(operation.bound_vm.as_str())
            {
                bail!("maintenance source is not bound to the exact requested VM");
            }
            if self.dedicated.by_database(&operation.database).is_none()
                || self
                    .schema_record(&operation.database)
                    .is_none_or(|r| r.tier != Tier::Live)
                || self
                    .physical_sources
                    .get(&operation.database)
                    .is_some_and(|r| {
                        r.fence.is_some() || r.handoff.is_some() || r.handoff_candidate.is_some()
                    })
                || self.physical.get(&operation.database).is_some_and(|r| {
                    !matches!(
                        r.phase,
                        crate::replication::PhysicalPhase::Verified
                            | crate::replication::PhysicalPhase::Standby
                    )
                })
            {
                bail!(
                    "maintenance requires a dedicated live database with no active handoff or preparation"
                );
            }
            if let Some(destination) = &operation.destination {
                if self.bound_vm_id(destination).is_some()
                    || self.dedicated.by_database(destination).is_some()
                    || self.replication.get(destination).is_some()
                    || self.physical.reserves_database(destination)
                    || self.physical_sources.get(destination).is_some()
                {
                    bail!("maintenance destination is already in use");
                }
            }
            self.database_maintenance.begin(operation.clone())?;
        }
        // Persistence precedes invalidation: once a warm connection can no
        // longer be found, every replacement path already observes the fence.
        let mut entries = self.entries.lock().await;
        for name in names {
            entries.remove(&name);
        }
        Ok(())
    }

    /// Reconnect the exact maintenance-owned VM through database `postgres`.
    /// This cannot create or require the retired tenant database after rename.
    pub async fn checkout_database_maintenance_exact(
        &self,
        operation_id: &str,
    ) -> Result<ConnGuard> {
        let operation = self
            .database_maintenance
            .get(operation_id)
            .context("unknown maintenance operation")?;
        let bound = self.bound_vm_id(&operation.database).or_else(|| {
            operation
                .destination
                .as_deref()
                .and_then(|db| self.bound_vm_id(db))
        });
        if bound.as_deref() != Some(operation.bound_vm.as_str()) {
            bail!("maintenance source binding changed");
        }
        let cell = self
            .entries
            .lock()
            .await
            .entry(operation.database.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let entry = cell
            .get_or_try_init(|| vm::ensure_fenced_vm(&self.cfg, "postgres", &operation.bound_vm))
            .await?;
        if entry.sandbox_id() != operation.bound_vm {
            bail!("maintenance VM identity changed");
        }
        ConnGuard::acquire(entry.clone(), self.cfg.admit_timeout)
            .await
            .context("maintenance connection slots exhausted")
    }

    pub async fn commit_database_maintenance(
        &self,
        operation: &crate::database_maintenance::Operation,
    ) -> Result<()> {
        // The operation executor owns raw_replication_operation. Ordinary
        // admission remains fenced across every individual durable write.
        let mut names = vec![operation.database.clone()];
        if let Some(new) = &operation.destination {
            names.push(new.clone());
        }
        names.sort();
        let mut locks = Vec::new();
        for name in &names {
            locks.push(self.binding_lock(name).write_owned().await);
        }
        if let Some(new) = &operation.destination {
            self.store.rename_database(&operation.database, new)?;
            self.dedicated.rename_database(&operation.database, new)?;
            self.replication.rename_database(&operation.database, new)?;
            self.physical.rename_database(&operation.database, new)?;
            self.physical_sources
                .rename_database(&operation.database, new)?;
        } else {
            self.store
                .retire_database(&operation.database, &operation.bound_vm)?;
            self.dedicated.remove(&operation.database)?;
        }
        let mut entries = self.entries.lock().await;
        for name in names {
            entries.remove(&name);
        }
        self.repl_status.lock().unwrap().remove(&operation.database);
        Ok(())
    }

    /// Whether replication is enabled on this node (`PG_VM_POOL_REPLICATION`).
    /// Gates the routes and new pairings only — existing records still pin.
    pub fn replication_cfg(&self) -> Option<&crate::config::ReplicationConfig> {
        self.cfg.replication.as_ref()
    }

    /// True when nothing may stop, compact, freeze, archive or purge this
    /// schema's VM.
    ///
    /// The union of the operator's static `PG_VM_POOL_KEEPALIVE_SCHEMAS` pin
    /// and the *dynamic* replication pin, and it replaces every bare
    /// `cfg.is_keepalive` call on a lifecycle path. Stopping a replicated VM
    /// costs more than the usual cold start: on a primary it drops the
    /// walsender and leaves an inactive slot pinning WAL (which, unbounded,
    /// fills the data disk — a cluster-wide PANIC), and on a replica it stops
    /// consuming so the primary's slot backs up instead. Both are recoverable
    /// only by a full re-seed, which is why this outranks every storage tier
    /// including emergency disk-pressure eviction.
    pub fn pinned(&self, schema: &str) -> bool {
        self.cfg.is_keepalive(schema)
            || self.replication.is_pinned(schema)
            || self.physical.reserves_database(schema)
            || self.physical_sources.get(schema).is_some()
            || self.database_maintenance.check(schema).is_err()
    }

    /// [`Self::pin_reason`] for whichever schema currently binds VM `id`, so a
    /// dashboard action keyed on a sandbox id can refuse without the caller
    /// having to resolve the schema itself. `None` when the VM backs nothing
    /// pinned.
    pub fn pin_reason_for_vm(&self, id: &str) -> Option<String> {
        if self.physical.owns_vm(id) || self.physical_sources.owns_vm(id)
            || !self.physical.list().is_empty() {
            // Also covers a create accepted by the daemon before its ID can be
            // durably recorded. No manual unbound-VM cleanup during preparation.
            return Some(format!("VM cleanup is reserved by physical replica preparation ({id})"));
        }
        self.store_records()
            .into_iter()
            .find(|(_, r)| r.sandbox_id == id && r.tier == Tier::Live)
            .and_then(|(schema, _)| self.pin_reason(&schema))
    }

    /// Why `schema` is pinned, for a dashboard refusal that tells the operator
    /// what to do about it. `None` when it isn't.
    pub fn pin_reason(&self, schema: &str) -> Option<String> {
        if self.database_maintenance.check(schema).is_err() {
            return Some(format!("{schema} is reserved by database maintenance"));
        }
        if self.physical.reserves_database(schema) || self.physical_sources.get(schema).is_some() {
            return Some(format!("{schema} is reserved by physical replication; ordinary lifecycle changes are disabled"));
        }
        if self.replication.is_fenced(schema) {
            return Some(format!("{schema} is fenced for a planned switchover; explicitly unfence it first"));
        }
        if let Some(rec) = self.replication.get(schema).filter(|r| r.state.pins()) {
            return Some(format!(
                "{schema} is replicating ({} with peer {}); detach or promote it first",
                rec.role.as_str(),
                rec.peer
            ));
        }
        self.cfg
            .is_keepalive(schema)
            .then(|| format!("{schema} is in PG_VM_POOL_KEEPALIVE_SCHEMAS"))
    }

    /// The provisioned dedicated-database credentials — the auth path's lookup
    /// table and what the admin API/dashboard mutate.
    pub fn dedicated(&self) -> &Arc<Credentials> {
        &self.dedicated
    }

    /// The owning credential for `schema`, if it is a dedicated database. Every
    /// bring-up passes this to [`vm::ensure_vm`] so the role exists (and owns
    /// its database) inside whatever VM ends up serving it.
    fn owner_of(&self, schema: &str) -> Option<Credential> {
        self.dedicated.by_database(schema)
    }

    /// Provision a dedicated database: a fixed database name with its own login
    /// role and password, whose credential can never be used to create another
    /// VM (see [`crate::dedicated`]).
    ///
    /// Refuses a name the pooler has *already* backed as an ordinary schema —
    /// that VM holds someone else's data, and provisioning over it would hand
    /// that data to a brand-new credential. Recording the credential is all
    /// this does; the VM is built by the first checkout, exactly like any other
    /// schema (callers that want it warm up front can follow with
    /// [`Self::spawn_provision`]).
    /// Assemble everything a bring-up needs to know about `schema` that
    /// [`Config`] cannot answer: the pin, the owning role, and the schema's
    /// replication role and login.
    ///
    /// One place, so a new per-schema fact never has to be threaded through
    /// `ensure_vm`'s callers again.
    fn bring_up_for<'a>(
        &self,
        schema: &str,
        owner: Option<&'a Credential>,
        repl_login: Option<&'a Credential>,
    ) -> vm::BringUp<'a> {
        vm::BringUp {
            pinned: self.pinned(schema),
            owner,
            replication: self
                .replication
                .get(schema)
                // Failed replication still owns PostgreSQL objects. In
                // particular, even an invalidated logical slot prevents a
                // primary from starting with minimal WAL. Releasing the VM
                // pin must not erase its durable role or downgrade settings.
                .filter(|r| r.state.pins() || r.state == crate::replication::State::Failed)
                .map(|r| r.role),
            repl_login,
            // Maintenance bring-ups wait as long as it takes; only a client
            // checkout arms a deadline (see `checkout`).
            admission_deadline: None,
        }
    }

    /// The `REPLICATION` login that must exist inside `schema`'s VM, as a
    /// [`Credential`] so it reuses `vm::ensure_role`'s create/align path.
    ///
    /// Only a **primary** has one: it is the credential a replica
    /// authenticates *with*, so on the replica's own VM there is nothing for
    /// it to log into. Returned owned; the caller holds it for the borrow that
    /// [`Self::bring_up_for`] takes.
    fn repl_login_for(&self, schema: &str) -> Option<Credential> {
        self.replication
            .get(schema)
            .filter(|r| r.state.pins() && r.role == crate::replication::Role::Primary)
            .map(|r| Credential {
                database: r.database.clone(),
                role: r.repl_role.clone(),
                password: r.repl_password.clone(),
                created_at: r.created_at,
            })
    }

    pub fn create_dedicated(
        &self,
        database: &str,
        role: &str,
        password: &str,
    ) -> Result<Credential> {
        self.database_maintenance.check(database)?;
        if self.store.record(database).is_some() && !self.dedicated.is_dedicated(database) {
            bail!(
                "{database:?} is already an existing pooler schema with its own VM and data; \
                 pick a different name (or drop that schema first)"
            );
        }
        self.dedicated.create(database, role, password)
    }

    /// Bring `schema`'s VM up in the background and let go of it immediately.
    ///
    /// Used right after provisioning so the tenant's first real connection
    /// doesn't pay a cold start. Runs through the ordinary checkout path, so it
    /// shares the bring-up gate, the pending-bring-up ledger and the
    /// failed-bring-up cleanup with every other client — a failure here is
    /// logged and left for the next connect to retry, never fatal to the
    /// provisioning that triggered it.
    pub fn spawn_provision(self: &Arc<Self>, schema: &str) {
        let registry = self.clone();
        let schema = schema.to_string();
        tokio::spawn(async move {
            match registry.checkout(&schema).await {
                // Dropping the guard leaves the VM warm; the idle reaper takes
                // it from here like any other unused schema.
                Ok(_guard) => info!("schema {schema}: pre-provisioned VM is ready"),
                Err(e) => warn!("schema {schema}: pre-provisioning failed (will retry on the first client connect): {e:#}"),
            }
        });
    }

    /// The pooler's configuration, for the replication flows that have to
    /// build guest commands and per-database connections themselves.
    pub fn cfg(&self) -> &Config {
        &self.cfg
    }

    /// Whether this node terminates client TLS. A primary refuses to hand a
    /// replica a credential it would then send in cleartext.
    pub fn tls_enabled(&self) -> bool {
        self.cfg.tls_cert.is_some()
    }

    /// A superuser connection to `schema`'s **own** database, bringing its VM
    /// up first if it isn't warm.
    ///
    /// The returned [`ConnGuard`] must be held for the length of the
    /// operation: it is what keeps the idle reaper off the VM while the
    /// caller is talking to it. `SchemaEntry::pool` cannot be used directly
    /// for this — it is pinned to `postgres` — and publications,
    /// subscriptions, grants and the replication status views are all
    /// per-database objects.
    pub async fn db_client(
        self: &Arc<Self>,
        schema: &str,
    ) -> Result<(ConnGuard, deadpool_postgres::Object)> {
        let guard = self.checkout(schema).await?;
        let client = vm::db_client(&self.cfg, &guard.entry().target, schema)
            .await
            .with_context(|| format!("connecting to database {schema}"))?;
        Ok((guard, client))
    }

    /// Connect to this VM's `postgres` maintenance database. This path is not
    /// publicly routable by database name and remains usable while the tenant
    /// database has `ALLOW_CONNECTIONS false`.
    pub async fn maintenance_client(
        &self,
        schema: &str,
    ) -> Result<(ConnGuard, deadpool_postgres::Object)> {
        let expected_vm = self.physical_sources.get(schema).filter(|r| r.fence.is_some()
            && self.bound_vm_id(schema).as_deref() == Some(r.source_vm_id.as_str())).map(|r| r.source_vm_id)
            .or_else(|| self.replication.get(schema).and_then(|r| r.fence).map(|f| f.vm_id))
            .with_context(|| format!("refusing maintenance bypass for unfenced database {schema}"))?;
        let record = self.store.record(schema)
            .with_context(|| format!("fenced database {schema} has no durable VM binding"))?;
        if record.tier != Tier::Live { bail!("fenced database {schema} is not on a live VM"); }
        if !expected_vm.is_empty() && expected_vm != record.sandbox_id {
            bail!("fenced database {schema} VM identity changed");
        }
        let cell = self.entries.lock().await.entry(schema.to_string())
            .or_insert_with(|| Arc::new(OnceCell::new())).clone();
        if let Some(entry) = cell.get() && entry.sandbox_id() != record.sandbox_id {
            bail!("warm VM identity differs from the durable fenced VM binding");
        }
        let entry = cell.get_or_try_init(|| vm::ensure_fenced_vm(&self.cfg, schema, &record.sandbox_id)).await?;
        let guard = ConnGuard::acquire(entry.clone(), self.cfg.admit_timeout).await
            .with_context(|| format!("maintenance connection slots exhausted for {schema}"))?;
        let client = guard
            .entry()
            .pool
            .get()
            .await
            .with_context(|| format!("connecting to maintenance database for {schema}"))?;
        Ok((guard, client))
    }

    /// Make `schema`'s running VM match the replication role now recorded for
    /// it — planting the durable marker and, when the WAL level has to change,
    /// restarting Postgres inside the guest.
    ///
    /// The bring-up path already does this ([`vm::ensure_vm`] calls
    /// `ensure_replication_mode`), but that only runs on a *cold* start. A
    /// pairing is set up against a database that is normally already warm, so
    /// without this the primary would keep serving at `wal_level = minimal`
    /// until something happened to evict it — and `CREATE PUBLICATION` would
    /// succeed while nothing could ever stream from it.
    ///
    /// Implemented as evict-then-checkout rather than a bespoke path, so the
    /// mode is applied by exactly the same code a cold start uses. The
    /// `archiving` claim is held throughout for the reason every other
    /// multi-step VM operation holds it: it is what stops the offload pacer,
    /// the pressure pass and the dashboard's buttons from picking this schema
    /// out from under a half-finished restart.
    pub async fn apply_replication_mode(self: &Arc<Self>, schema: &str) -> Result<()> {
        let claim = ArchivingGuard::claim(&self.archiving, schema)
            .with_context(|| format!("schema {schema} is busy with another offload or restart"))?;
        // Drop the warm entry so the next checkout re-runs the full bring-up
        // (which reattaches to the same VM by id — nothing is stopped here).
        let cell = self.entries.lock().await.get(schema).cloned();
        if let Some(cell) = cell {
            self.evict(schema, &cell).await;
        }
        let _guard = self
            .checkout_inner(schema, Some(&claim))
            .await
            .with_context(|| format!("bringing schema {schema} up in its new replication mode"))?;
        Ok(())
    }

    /// The last status sample for `database`, or `None` if it has not been
    /// sampled yet.
    pub fn replication_status_cached(
        &self,
        database: &str,
    ) -> Option<crate::replication::wire::StatusJson> {
        self.repl_status.lock().unwrap().get(database).cloned()
    }

    /// Sample one pairing now: this node's own side over its VM, plus the
    /// peer's side over its admin API.
    ///
    /// Neither half is allowed to fail the whole sample. A primary whose peer
    /// is unreachable still reports its own slot — which is precisely the
    /// situation where the slot's retained WAL is the number that matters.
    pub async fn sample_replication(
        self: &Arc<Self>,
        rec: &crate::replication::ReplRecord,
    ) -> crate::replication::wire::StatusJson {
        let mut out = crate::replication::wire::StatusJson {
            record: rec.into(),
            primary: None,
            replica: None,
            peer_error: None,
        };
        match crate::replication::orchestrate::local_status(self, rec).await {
            Ok((p, r)) => {
                out.primary = p;
                out.replica = r;
            }
            Err(e) => out.peer_error = Some(format!("local: {e:#}")),
        }
        // The peer's half, best-effort and timeout-bounded.
        if let (Some(peer), Some(cfg)) = (self.peers.get(&rec.peer), self.cfg.replication.as_ref())
            && let Ok(client) =
                crate::replication::peer::PeerClient::new(peer, cfg.peer_timeout)
        {
            match client.status(&rec.database).await {
                Ok(remote) => {
                    // Fill in whichever side we are not.
                    if out.primary.is_none() {
                        out.primary = remote.primary;
                    }
                    if out.replica.is_none() {
                        out.replica = remote.replica;
                    }
                }
                Err(e) => out.peer_error = Some(format!("peer {}: {e:#}", rec.peer)),
            }
        }
        self.repl_status
            .lock()
            .unwrap()
            .insert(rec.database.clone(), out.clone());
        out
    }

    /// Background sampler for every live pairing.
    ///
    /// Besides feeding the dashboard, this is the thing that shouts before a
    /// replication slot becomes a disk-full PANIC. An inactive slot pins WAL
    /// on the primary's data disk indefinitely; the guest's
    /// `max_slot_wal_keep_size` is the hard backstop (it invalidates the slot
    /// instead of filling the disk), and this is the warning that arrives
    /// first, while the pairing is still savable.
    ///
    /// No-op when nothing is replicating or `PG_VM_POOL_REPL_MONITOR_SECS=0`.
    pub fn spawn_replication_monitor(self: &Arc<Self>) {
        let Some(interval) = self.cfg.replication.as_ref().and_then(|c| c.monitor_interval) else {
            return;
        };
        let registry = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                registry.replication_pass().await;
            }
        });
    }

    async fn replication_pass(self: &Arc<Self>) {
        let Some(cfg) = self.cfg.replication.as_ref() else {
            return;
        };
        for rec in self.replication.list() {
            if !rec.state.pins() {
                continue;
            }
            let s = self.sample_replication(&rec).await;

            // Promote Syncing -> Active once the initial copy has finished.
            if let Some(r) = s.replica.as_ref()
                && rec.state == crate::replication::State::Syncing
                && r.worker_running
                && (r.tables_total == 0 || r.tables_ready == r.tables_total)
            {
                let _ = self.replication.set_state(
                    &rec.database,
                    crate::replication::State::Active,
                    "streaming",
                );
            }

            let Some(p) = s.primary.as_ref() else { continue };
            // `wal_status` leaving `reserved` means WAL the subscriber still
            // needs is at risk; `lost` means it is already gone and the
            // replica has to be rebuilt from scratch.
            if let Some(w) = p.wal_status.as_deref()
                && w != "reserved"
            {
                let msg = format!(
                    "{}: replication slot {} is {w} — {}",
                    rec.database,
                    rec.slot,
                    if w == "lost" {
                        "WAL the replica needed has been removed; it must be re-seeded"
                    } else {
                        "the slot is retaining WAL past max_wal_size"
                    }
                );
                warn!("{msg}");
                crate::events::journal_error("replication", msg);
                if w == "lost" {
                    let _ = self.replication.set_state(
                        &rec.database,
                        crate::replication::State::Failed,
                        "the replication slot was invalidated (wal_status=lost)",
                    );
                }
            }
            self.note_slot_activity(&rec, p, cfg);
        }
    }

    /// Track how long a slot has had no subscriber, and say so once when that
    /// becomes worth acting on.
    ///
    /// This is the warning that arrives *before* the guest's
    /// `max_slot_wal_keep_size` fires. Two independent triggers, because they
    /// catch different failures: a slot pinning a lot of WAL is the one about
    /// to fill the data disk, while a slot that has simply been unattached for
    /// a long time is a replica that has quietly gone away and will pin WAL
    /// eventually. Edge-triggered — reported once per outage and re-armed when
    /// a subscriber comes back — so a standing condition informs the journal
    /// rather than burying it.
    fn note_slot_activity(
        &self,
        rec: &crate::replication::ReplRecord,
        p: &crate::replication::wire::PrimaryStatus,
        cfg: &crate::config::ReplicationConfig,
    ) {
        let mut seen = self.repl_inactive.lock().unwrap();
        if p.slot_active {
            if seen.remove(&rec.database).is_some() {
                info!("{}: a subscriber is attached to slot {} again", rec.database, rec.slot);
            }
            return;
        }
        let now = Instant::now();
        let (since, warned) = seen
            .entry(rec.database.clone())
            .or_insert_with(|| (now, false));
        if *warned {
            return;
        }
        let idle = now.duration_since(*since);
        let behind = p.behind_bytes.unwrap_or(0).max(0) as u64;
        let reason = if behind >= cfg.lag_warn_bytes {
            format!("it is pinning {} of WAL", crate::orphans::human_iec(behind))
        } else if idle >= cfg.slot_stale {
            format!("it has had none for {} minutes", idle.as_secs() / 60)
        } else {
            return;
        };
        *warned = true;
        drop(seen);
        let msg = format!(
            "{}: no subscriber is attached to replication slot {} and {reason}. An inactive \
             slot retains WAL on this VM's data disk indefinitely, and a full data disk is a \
             cluster-wide PANIC — max_slot_wal_keep_size will invalidate the slot (forcing a \
             re-seed) before that happens. Detach the pairing if the replica is gone for good.",
            rec.database, rec.slot
        );
        warn!("{msg}");
        crate::events::journal_error("replication", msg);
    }

    /// Warm every VM a replication pairing depends on, once, at startup.
    ///
    /// Two things need this. The obvious one: a pairing only replicates while
    /// both VMs are up, and after a pooler restart nothing has checked them
    /// out. The subtler one: `reap_untracked` classifies a running VM with no
    /// warm entry as untracked and stops it, so until a pinned schema is in
    /// the entry map it is a stop waiting to happen — the pin there is a
    /// guard, this is what makes it unnecessary.
    ///
    /// Each is an ordinary background checkout through the same gates as a
    /// client's, so this cannot storm the daemon; a failure is logged and left
    /// for the next attempt, exactly like [`Self::spawn_provision`].
    pub fn spawn_replication_pinner(self: &Arc<Self>) {
        let pinned = self.replication.pinned_databases();
        if pinned.is_empty() {
            return;
        }
        info!(
            "replication: warming {} pinned VM(s): {}",
            pinned.len(),
            pinned.join(", ")
        );
        for schema in pinned {
            self.spawn_provision(&schema);
        }
    }

    /// Sandbox ids currently bound to a schema — the exclusion set that keeps
    /// the spare pool from handing out a VM some schema already owns (a spare
    /// keeps its `spare-pg-*` name after being claimed, so the name alone
    /// can't tell).
    fn bound_ids(&self) -> std::sync::Arc<HashSet<String>> {
        self.store.bound_ids()
    }

    /// Which password this client must prove, decided from its **role**
    /// alone — the property [`Credentials::challenge_password`] exists to
    /// preserve, extended to cover replication logins.
    ///
    /// Order: a replication login is challenged with its own password, then a
    /// dedicated one with its own, then everyone else with the shared
    /// `PG_VM_POOL_PASSWORD` (`None` = no gate). Keeping the requested
    /// database out of this step is what makes the handshake look identical
    /// whatever was asked for, so a prober cannot enumerate provisioned names
    /// by watching which connections get challenged.
    pub fn challenge_password_for(&self, role: &str) -> Option<String> {
        if let Some(source) = self.physical_sources.by_repl_role(role) {
            return source.repl.map(|login| login.password);
        }
        challenge_password_in(
            &self.replication,
            &self.dedicated,
            self.cfg.pg_password.as_deref(),
            role,
        )
    }

    /// Resolve an *authenticated* client's VM, rejecting unauthorized routes.
    ///
    /// A replication login is pinned to its own database exactly as a
    /// dedicated one is — and it has to be resolved **first**, because
    /// `Credentials::authorize` would otherwise reject it under the "this
    /// database is dedicated, only its own role may open it" rule, which is
    /// precisely the database it is trying to reach.
    pub fn authorize_route(&self, role: &str, database: &str, physical: bool) -> Result<String, String> {
        if physical && let Some(source) = self.physical_sources.by_repl_role(role) {
            let rename = self.database_maintenance.rename_for(&source.database);
            if rename.is_none() {
                self.database_maintenance
                    .check(&source.database)
                    .map_err(|e| e.to_string())?;
            }
            if self.bound_vm_id(&source.database).as_deref() != Some(source.source_vm_id.as_str()) {
                if !rename.as_ref().is_some_and(|op| {
                    op.bound_vm == source.source_vm_id
                        && op
                            .destination
                            .as_deref()
                            .and_then(|db| self.bound_vm_id(db))
                            .as_deref()
                            == Some(source.source_vm_id.as_str())
                }) {
                return Err("physical source no longer owns the serving binding".into());
            }
            }
            return Ok(source.database);
        }
        self.database_maintenance
            .check(database)
            .map_err(|e| e.to_string())?;
        authorize_route_in(&self.replication, &self.dedicated, role, database, physical)
    }

    /// The configured idle-reaping timeout (`None` when reaping is disabled), so
    /// a dashboard can label how close a warm VM is to being stopped.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.runtime.idle_timeout()
    }

    /// Whether the S3 eviction tier is configured — gates the dashboard's manual
    /// "reap to S3" control.
    pub fn archive_enabled(&self) -> bool {
        self.cfg.archive.is_some()
    }

    /// Whether any offload tier is configured — local compaction or S3. That
    /// is all the manual TTL sweep needs, so it gates that dashboard control:
    /// a compaction-only host still gets a way to drain its backlog on demand.
    pub fn offload_enabled(&self) -> bool {
        self.cfg.archive.is_some() || self.cfg.compact.is_some()
    }

    /// Point `schema` back at its S3 archive: set its tier to `Archived` so the
    /// next checkout takes the restore path instead of reattaching to a dead
    /// binding — or, when the bound VM is gone, creating a fresh empty VM and
    /// serving an empty database while a good archive sits unread in S3.
    ///
    /// The re-probe is not a formality. The dashboard page an operator acts
    /// from may be minutes old, and marking a schema archived when no archive
    /// is actually there converts a recoverable problem into an unservable
    /// one: the checkout would fail outright instead of quietly serving
    /// nothing. Refusing here costs one HEAD.
    ///
    /// Only the tier is written. The VM the row currently binds is left alone
    /// — once the tier is `Archived` the checkout path forces `known_id` to
    /// `None`, so that VM is unreferenced and the orphan sweep reclaims it.
    /// Killing it here would add a daemon round-trip, and a failure mode, to
    /// an action whose whole value is that it writes one field.
    pub async fn adopt_archive(&self, schema: &str) -> Result<String> {
        if !crate::is_valid_schema(schema) {
            bail!("{schema:?} is not a valid schema name");
        }
        let Some(a) = self.cfg.archive.as_ref() else {
            bail!("the S3 archive tier is not configured");
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .context("building the S3 HTTP client")?;
        // Probe before writing anything. Marking a schema archived when no
        // archive is actually there converts "serves an empty database" into
        // "cannot be served at all" — the checkout would fail outright. One
        // HEAD buys the difference.
        let Some(probe) = crate::imgarchive::probe_archive(&a.s3, &http, schema).await else {
            bail!(
                "schema {schema}: no usable archive in S3 (checked both the dump and image keys) \
                 — refusing to mark it archived"
            );
        };
        let prev = self.store.adopt_archived(schema).await;
        let what = format!(
            "{} archive ({})",
            probe.kind_str(),
            crate::orphans::human_iec(probe.bytes)
        );
        let (verb, detail) = match &prev {
            None => (
                "adopted",
                "this server had no record of it at all".to_string(),
            ),
            Some(r) if r.tier == Tier::Archived => (
                "re-confirmed",
                format!("it was already archived, bound to {}", r.sandbox_id),
            ),
            Some(r) => (
                "repaired",
                format!(
                    "its tier was `{}`, bound to VM {} — that VM is now unreferenced and the \
                     disk sweep will reclaim it",
                    r.tier.as_str(),
                    r.sandbox_id
                ),
            ),
        };
        let msg = format!("schema {schema} {verb}: restores from its {what} ({detail})");
        crate::events::journal_info("archive-fix", msg.clone());
        Ok(msg)
    }

    /// One schema's durable registry row, or `None` when this server has no
    /// record of it — the state that makes a workbook with an archive in S3
    /// unrecoverable through an ordinary connect.
    pub fn schema_record(&self, schema: &str) -> Option<StoreRecord> {
        self.store.record(schema)
    }

    /// The S3 archive tier's client config, for the dashboard's archive
    /// reconciliation page. `None` when the tier isn't configured.
    pub fn archive_s3(&self) -> Option<crate::s3::S3Config> {
        self.cfg.archive.as_ref().map(|a| a.s3.clone())
    }

    /// Whether the image-level archive is configured — gates the dashboard's
    /// per-VM "archive as image" control.
    pub fn image_archive_enabled(&self) -> bool {
        self.cfg.image_archive.is_some()
    }

    /// Whether automatic disk reclamation is configured — gates the dashboard's
    /// manual "reclaim disk slack" control.
    pub fn reclaim_enabled(&self) -> bool {
        self.reclaimer.is_some()
    }

    /// The port clients dial the pooler on, for rendering an example connection
    /// string. Only the port: the host a client should use is whatever already
    /// reaches this pooler, which a bind address like `0.0.0.0` can't tell us.
    pub fn listen_port(&self) -> u16 {
        self.cfg.listen_addr.port()
    }

    /// The configured heyvmd run dir, if any (`PG_VM_POOL_RUN_DIR`).
    pub fn run_dir(&self) -> Option<PathBuf> {
        self.cfg.run_dir.clone()
    }

    /// Point-in-time view of every *warm* schema entry (VMs the pooler currently
    /// holds). Takes the same map lock the reaper/checkout use, but holds it only
    /// for a fast, await-free read — no meaningful contention. Stopped/reaped
    /// schemas aren't warm; pair with [`Self::store_records`] for those.
    pub async fn snapshot(&self) -> Vec<EntrySnapshot> {
        let map = self.entries.lock().await;
        map.iter()
            .filter_map(|(schema, cell)| {
                cell.get().map(|e| EntrySnapshot {
                    schema: schema.clone(),
                    sandbox_id: e.sandbox_id(),
                    target: e.target,
                    active: e.active_count(),
                    free_slots: e.free_slots(),
                    slot_limit: e.slot_limit(),
                    idle_secs: e.idle_for().as_secs(),
                    idle_budget_secs: self.runtime.idle_timeout().map(|t| {
                        e.idle_budget(t, self.runtime.idle_timeout_fast(), self.cfg.fast_bringup)
                            .as_secs()
                    }),
                    bringup_ms: e.bringup_took.as_millis(),
                    keepalive: e.keepalive,
                    tunneled: e.is_tunneled(),
                })
            })
            .collect()
    }

    /// The durable per-schema records the pooler has ever backed, surviving
    /// eviction and restarts — used to recover the schema name for a VM that's
    /// currently stopped (not warm) and to surface archived (killed) schemas
    /// that no longer appear in the daemon's inventory at all.
    pub fn store_records(&self) -> Vec<(String, StoreRecord)> {
        self.store.records()
    }

    /// The durable record for one schema — which VM last backed it and which
    /// storage tier its data is on. `None` when the pooler has never brought it
    /// up (a just-provisioned dedicated database, before its first checkout).
    pub fn store_record(&self, schema: &str) -> Option<StoreRecord> {
        self.store.record(schema)
    }

    /// Inspect the existing guest without waking or provisioning a database.
    /// Never expose query text: it may contain credentials or application data.
    pub async fn database_sessions(&self, schema: &str) -> Result<serde_json::Value> {
        let _binding = self.binding_lock(schema).read_owned().await;
        let id = self.bound_vm_id(schema).context("database has no VM binding")?;
        let entry = self.warm_entry(&id).await.context("database is not warm; session state is unknown")?;
        let query = async {
            let client = entry.pool.get().await?;
            let rows = client
                .query(
                "SELECT pid, datname, usename, application_name, client_addr::text, \
                 state, backend_type, backend_start::text \
                 FROM pg_stat_activity WHERE pid <> pg_backend_pid() ORDER BY pid",
                &[],
                )
                .await?;
            let sessions: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                "pid": r.get::<_, i32>(0),
                "database": r.get::<_, Option<String>>(1),
                "username": r.get::<_, Option<String>>(2),
                "application_name": r.get::<_, Option<String>>(3),
                "client_address": r.get::<_, Option<String>>(4),
                "state": r.get::<_, Option<String>>(5),
                "backend_type": r.get::<_, Option<String>>(6),
                "backend_start": r.get::<_, Option<String>>(7),
                    })
                })
                .collect();
            Ok::<_, anyhow::Error>(serde_json::json!({
                "database": schema, "sandbox_id": id, "sessions": sessions,
            }))
        };
        tokio::time::timeout(STATS_TIMEOUT, query).await.context("session inspection timed out")?
    }

    /// Live database stats for a warm, pooler-managed VM, read over the pooler's
    /// own warm Postgres pool — the *same* safe TCP path the liveness probe uses,
    /// **not** a guest console exec, so it never disturbs the VM. `None` when the
    /// VM isn't warm or the query fails/times out.
    pub async fn db_stats(&self, sandbox_id: &str, schema: &str) -> Option<DbStats> {
        let entry = self.warm_entry(sandbox_id).await?;
        let query = async {
            let client = entry.pool.get().await.ok()?;
            let row = client
                .query_opt(
                    "SELECT pg_database_size(datname), numbackends \
                     FROM pg_stat_database WHERE datname = $1",
                    &[&schema],
                )
                .await
                .ok()??;
            Some(DbStats {
                db_size_bytes: row.get(0),
                backends: row.get(1),
            })
        };
        tokio::time::timeout(STATS_TIMEOUT, query).await.ok()?
    }

    /// Live guest-OS memory/load/disk for a warm, pooler-managed VM (see
    /// [`GuestStats`] for how each piece is read and degrades). `None` when
    /// the VM isn't warm or nothing could be read within [`STATS_TIMEOUT`].
    pub async fn guest_stats(&self, sandbox_id: &str) -> Option<GuestStats> {
        let entry = self.warm_entry(sandbox_id).await?;
        let query = async {
            let mut client = entry.pool.get().await.ok()?;
            // /proc reads: no fork, just the backend reading two pseudo-files.
            // The explicit (offset, length) form is required — /proc files
            // stat as 0 bytes, so the whole-file form reads nothing.
            let mem_load = client
                .query_opt(
                    "SELECT pg_read_file('/proc/meminfo', 0, 8192), \
                            pg_read_file('/proc/loadavg', 0, 256)",
                    &[],
                )
                .await
                .ok()
                .flatten();
            let (mem, load) = mem_load
                .map(|row| (parse_meminfo(row.get(0)), parse_loadavg(row.get(1))))
                .unwrap_or((None, None));
            let disk = df_data_dir(&mut client).await;
            (mem.is_some() || load.is_some() || disk.is_some()).then_some(GuestStats {
                mem,
                load,
                disk,
            })
        };
        tokio::time::timeout(STATS_TIMEOUT, query).await.ok()?
    }

    /// The warm entry backing `sandbox_id`, if any (brief map-lock read).
    async fn warm_entry(&self, sandbox_id: &str) -> Option<Arc<SchemaEntry>> {
        let map = self.entries.lock().await;
        map.values().find_map(|cell| {
            let e = cell.get()?;
            (e.sandbox_id() == sandbox_id).then(|| e.clone())
        })
    }

    /// Check out the entry for `schema`, bringing the VM up on first request.
    /// The returned guard keeps the VM off the reaper's radar until dropped.
    /// Concurrent callers for the same schema share one bring-up.
    pub async fn checkout(&self, schema: &str) -> Result<ConnGuard> {
        // A cold checkout can publish its VM binding. Finish that publication
        // before a replacement CAS, never after it. Independent of the
        // replication-operation mutex, whose callers also use checkout.
        let _binding = self.binding_lock(schema).read_owned().await;
        // Recheck under the binding lock.  begin_database_maintenance cannot
        // return until every checkout which passed an earlier check has left
        // this publication-critical section.
        self.database_maintenance.check(schema)?;
        if self
            .physical
            .get(schema)
            .is_some_and(|r| r.phase == crate::replication::PhysicalPhase::StandbyBinding)
        {
            bail!("standby binding is in progress; retry after completion");
        }
        // An outgoing grant/fence takes precedence over the older activation
        // that originally made this same VM a writer.
        if self.physical_source_fenced(schema) {
            return self.maintenance_client(schema).await.map(|(guard, _)| guard);
        }
        if self.bound_vm_id(schema).as_deref().is_some_and(|id| self.physical_sources.has_grant_for_source_vm(schema, id)) {
            if self.replication.is_fenced(schema) {
                return self.maintenance_client(schema).await.map(|(guard, _)| guard);
            }
            bail!("physical source grant lost its fence; refusing ordinary checkout");
        }
        if let Some(rec) = self.physical.get(schema).filter(|r| r.phase == crate::replication::PhysicalPhase::Standby) {
            let candidate = rec.candidate_id.context("standby lost candidate identity")?;
            return self.checkout_physical_exact(schema, &candidate).await;
        }
        if let Some(rec) = self.physical.get(schema).filter(|r| r.handoff_started()) {
            if rec.phase != crate::replication::PhysicalPhase::Activated {
                bail!("physical handoff for {schema} is incomplete; admission remains closed");
            }
            let candidate = rec.candidate_id.context("activated handoff lost candidate identity")?;
            if self.bound_vm_id(schema).as_deref() != Some(candidate.as_str()) {
                bail!("activated physical handoff binding mismatch");
            }
            let cell = self.entries.lock().await.entry(schema.to_string()).or_insert_with(|| Arc::new(OnceCell::new())).clone();
            let entry = cell.get_or_try_init(|| vm::ensure_fenced_vm(&self.cfg, schema, &candidate)).await?;
            if entry.sandbox_id() != candidate { bail!("warm physical handoff binding mismatch"); }
            return ConnGuard::acquire(entry.clone(), self.cfg.admit_timeout).await
                .context("physical handoff connection slots exhausted");
        }
        if self.replication.is_fenced(schema) {
            // Status polling and startup warming must not take the normal
            // restore/grant path for a fenced database either.
            return self.maintenance_client(schema).await.map(|(guard, _)| guard);
        }
        if !self.physical_admission_ready(schema) { bail!("physical preparation binding mismatch; refusing ordinary checkout"); }
        self.checkout_inner(schema, None).await
    }

    /// Check out while this caller owns this schema's maintenance claim. The
    /// borrowed claim is both the authority to pass the archiving wait and the
    /// lifetime proof that exclusion remains held through the checkout.
    async fn checkout_inner(
        &self,
        schema: &str,
        claim: Option<&ArchivingGuard<'_>>,
    ) -> Result<ConnGuard> {
        // Refresh durable activity up front so the S3 eviction sweep sees this
        // schema as recently used even long after its VM leaves the warm map
        // (the in-memory `SchemaEntry::last_active` doesn't survive that).
        self.store.touch(schema);
        let mut offload_waited: Option<Instant> = None;
        loop {
            // If this schema is mid-archive (dump + kill in flight), don't race
            // the archiver by bringing the VM back up. Wait for it to clear; the
            // subsequent cold start restores from S3. This wait used to be
            // completely silent — a client parked here for a whole offload
            // read as unexplained connect latency — so name it, once, and
            // account for it when it ends.
            if self.is_archiving(schema)
                && !claim.is_some_and(|c| c.owns(&self.archiving, schema))
            {
                if offload_waited.is_none() {
                    offload_waited = Some(Instant::now());
                    info!(
                        "schema {schema}: client waiting for an in-flight offload of this \
                         schema to finish before (re)connecting"
                    );
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            if let Some(t) = offload_waited.take() {
                info!("schema {schema}: offload cleared after {:?}; proceeding", t.elapsed());
            }

            // Warm path: claim the entry under the map lock, which the reaper
            // also takes — so it can't evict this entry between its idle-check
            // and our claim. `touch()` is what does the claiming: it makes the
            // entry non-idle for a full idle_timeout, which covers the window
            // between dropping the lock and `active` actually being
            // incremented. The permit is deliberately NOT taken here — it can
            // block for `admit_timeout`, and holding the map lock across that
            // would stall checkouts for every *other* schema behind this one.
            let (cell, warm) = {
                let mut map = self.entries.lock().await;
                let cell = map
                    .entry(schema.to_string())
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .clone();
                let warm = cell.get().inspect(|e| e.touch()).cloned();
                (cell, warm)
            };

            if let Some(entry) = warm {
                let Some(guard) = ConnGuard::acquire(entry, self.cfg.admit_timeout).await else {
                    bail!(
                        "schema {schema}: all client connection slots busy after {:?}; \
                         the VM's Postgres is at its connection limit",
                        self.cfg.admit_timeout
                    );
                };
                // A VM stopped out-of-band (manual stop) or a tunnel dropped by a
                // network change leaves a cached entry whose local tunnel still
                // accepts but never reaches Postgres — splicing to it would hang.
                // Probe first; reuse only if it actually answers, else evict and
                // fall through to re-init (which restarts the VM).
                if self.entry_alive(guard.entry()).await {
                    return Ok(guard);
                }
                warn!("schema {schema}: cached VM unreachable, restarting it");
                drop(guard);
                self.evict(schema, &cell).await;
                continue;
            }

            // Cold path: bring the VM up without holding the map lock. Concurrent
            // first-connects share one bring-up via the OnceCell (one runs
            // ensure_vm, the rest await it here). Log entry/exit with timing so a
            // slow or stuck bring-up is visible — otherwise a client just parks
            // here silently until ready_timeout, which reads as a hang in the log.
            let started = Instant::now();
            // Circuit breaker: a schema whose last bring-ups failed is held
            // off with a fast, explicit error instead of re-running (and
            // re-failing) a bring-up that can cost 30+ minutes of S3 download
            // and a VM apiece — a client that reconnects on every failure
            // otherwise keeps a restore storm running indefinitely.
            if let Some((failures, retry_in)) = self.bringup_breaker.holding(schema) {
                bail!(
                    "schema {schema}: {failures} consecutive bring-up failure(s); holding \
                     off new attempts for another {retry_in:?} (last error is on the \
                     events page)"
                );
            }
            info!("schema {schema}: cold start, bringing up VM (or awaiting in-progress bring-up)");
            // Reattach to the VM we last used for this schema (survives eviction
            // and process restarts), else find-or-create by name. If the schema
            // was archived to S3 (VM killed), bring up a fresh VM and restore the
            // dump into it before serving — the stored id is dead so we don't
            // reattach.
            let record = self.store.record(schema);
            let known_id = record.as_ref().map(|r| r.sandbox_id.clone());
            let restore = match record.as_ref().map(|r| r.tier) {
                Some(Tier::Archived) => match self.cfg.archive.as_ref() {
                    // "Archived" covers both archive formats — which S3 key
                    // actually holds data decides the restore strategy (a HEAD
                    // or two on the cold path; transport trouble defaults to
                    // the dump path, exactly the pre-image behavior).
                    //
                    // The config that comes back is addressed at the prefix
                    // holding the archive — the legacy one when this host's
                    // own prefix is known to hold nothing for the schema.
                    Some(a) => Some({
                        let (kind, s3) = crate::imgarchive::pick_restore(&a.s3, schema).await;
                        if s3.prefix != a.s3.prefix {
                            info!(
                                "schema {schema}: nothing under s3://{}/{}; restoring from the \
                                 legacy prefix {}",
                                a.s3.bucket, a.s3.prefix, s3.prefix
                            );
                        }
                        match kind {
                            crate::imgarchive::RestoreKind::Dump => RestoreSource::S3(s3),
                            crate::imgarchive::RestoreKind::Image => {
                                info!("schema {schema}: restoring from its disk-image archive");
                                RestoreSource::S3Image(s3)
                            }
                        }
                    }),
                    None => bail!(
                        "schema {schema} is archived to S3, but the eviction tier is not \
                         configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*) — \
                         cannot restore it"
                    ),
                },
                Some(Tier::Frozen) => match (&self.dumps, &self.cfg.freeze) {
                    (Some(srv), Some(f)) => Some(RestoreSource::Local {
                        srv: srv.clone(),
                        port: f.listen.port(),
                    }),
                    _ => bail!(
                        "schema {schema} is frozen to a local dump, but the frozen tier is \
                         not configured (set PG_VM_POOL_FREEZE_AFTER_SECS) — cannot restore it"
                    ),
                },
                Some(Tier::Compacted) => match &self.cfg.compact {
                    Some(c) => Some(RestoreSource::LocalImage(c.compact_path(schema))),
                    None => bail!(
                        "schema {schema} is compacted to a local image, but the compacted \
                         tier is not configured (set PG_VM_POOL_COMPACT_AFTER_SECS + \
                         PG_VM_POOL_RUN_DIR) — cannot thaw it"
                    ),
                },
                _ => None,
            };
            let bound = self.spares.as_ref().map(|_| self.bound_ids()).unwrap_or_default();
            // A dedicated database's owning role has to exist inside whatever
            // VM serves it — including one a restore has just rebuilt from
            // scratch, which carries the data but no roles.
            let owner = self.owner_of(schema);
            let repl_login = self.repl_login_for(schema);
            let mut up = self.bring_up_for(schema, owner.as_ref(), repl_login.as_ref());
            // A client waits only so long in the admission queue (see
            // `vm::DEFAULT_ADMISSION_WAIT`), counted from when this cold start
            // began — so time spent behind another client's attempt at the
            // same schema counts against it too.
            up.admission_deadline = vm::admission_deadline_from(started);
            match cell
                .get_or_try_init(|| {
                    vm::ensure_vm(
                        &self.cfg,
                        schema,
                        known_id.as_deref(),
                        restore.as_ref(),
                        // How big this schema's data device was when it was
                        // last seen. Only a restore that has to build the VM
                        // reads it, and only there does it matter.
                        record.as_ref().map(|r| r.disk_gb).filter(|gb| *gb > 0),
                        self.spares.as_deref().map(|p| (p, &*bound)),
                        &up,
                    )
                })
                .await
            {
                Ok(entry) => {
                    // Remember which VM now backs this schema so a later restart
                    // reattaches to it instead of creating a duplicate. `put`
                    // also clears any `archived` flag (this is a fresh VM id), so
                    // a just-restored schema is durably marked live again.
                    self.store.put(schema, entry.sandbox.sandbox_id());
                    // Per-VM create/restore time, written lazily by the flush
                    // loop. Every client that shared this bring-up lands here
                    // with the same entry; only the first marks it dirty.
                    if let Some(bringup) = entry.bringup() {
                        self.store.set_bringup(schema, bringup);
                    }
                    // The bring-up resolved: the id is durably bound, so the
                    // pending ledger's claim on it is settled.
                    crate::pending::clear(schema).await;
                    // Whatever the offload sweeps last concluded about this
                    // schema described the data before it came back up; a
                    // client can write to it now. Forget it, so a schema
                    // settled as empty (backed off for the full cap) is
                    // compacted and archived on the normal schedule again.
                    if restore.is_some() {
                        self.offload_backoff.clear(schema);
                    }
                    // A thawed schema's local offload artifact is now dead
                    // weight: the row is durably live, the data lives on the
                    // VM's disk, and the next freeze/compact rewrites the file
                    // from scratch. Left in place it pins those bytes per
                    // thawed schema forever (they are only otherwise deleted
                    // on S3 promotion).
                    let thawed_file = match &restore {
                        Some(RestoreSource::Local { .. }) => {
                            self.dumps.as_ref().map(|srv| srv.dump_path(schema))
                        }
                        Some(RestoreSource::LocalImage(path)) => Some(path.clone()),
                        _ => None,
                    };
                    if let Some(file) = thawed_file {
                        // The emptiness marker describes the image, not the
                        // schema: it goes with it.
                        let _ =
                            tokio::fs::remove_file(crate::imgarchive::empty_marker(&file)).await;
                        match tokio::fs::remove_file(&file).await {
                            Ok(()) => {
                                info!("schema {schema}: thawed; removed {}", file.display());
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => warn!(
                                "schema {schema}: thawed but removing {} failed: {e}",
                                file.display()
                            ),
                        }
                    }
                    info!("schema {schema}: VM ready in {:?}", started.elapsed());
                    self.bringup_breaker.clear(schema);
                    let Some(guard) =
                        ConnGuard::acquire(entry.clone(), self.cfg.admit_timeout).await
                    else {
                        bail!(
                            "schema {schema}: all client connection slots busy after {:?}; \
                             the VM's Postgres is at its connection limit",
                            self.cfg.admit_timeout
                        );
                    };
                    return Ok(guard);
                }
                Err(e) if vm::is_shed(&e) => {
                    // Load, not a broken schema: nothing was built, so there
                    // is no VM to stop, and the circuit breaker stays out of
                    // it — the next client gets a fresh place in the queue,
                    // not a hold-off.
                    warn!("{e:#}");
                    return Err(e);
                }
                Err(e) => {
                    warn!(
                        "schema {schema}: bring-up failed after {:?}: {e:#}",
                        started.elapsed()
                    );
                    crate::events::journal_error(
                        "bring-up",
                        format!(
                            "schema {schema}: bring-up failed after {:?}: {e:#}",
                            started.elapsed()
                        ),
                    );
                    // Same leak guard as the archive/freeze bring-ups: a
                    // ready-timeout leaves a running VM `ensure_vm` never
                    // returned a handle to. Without this it has no owner —
                    // no registry row, not spare-named, daemon still knows
                    // it — so no reaper, purge, or sweep ever reclaims its
                    // RAM or disk.
                    vm::stop_after_failed_bringup(schema, known_id.as_deref()).await;
                    let (n, hold) = self.bringup_breaker.record_failure(schema);
                    if n > 1 {
                        warn!(
                            "schema {schema}: {n} consecutive bring-up failures — holding off \
                             new attempts for {hold:?}"
                        );
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Remove `cell` from the map iff it's still the current cell for `schema`,
    /// so a concurrent re-init that already installed a fresh cell isn't lost.
    async fn evict(&self, schema: &str, cell: &Arc<OnceCell<Arc<SchemaEntry>>>) {
        let mut map = self.entries.lock().await;
        if matches!(map.get(schema), Some(cur) if Arc::ptr_eq(cur, cell)) {
            map.remove(schema);
        }
    }

    /// Liveness probe on the warm path: is anything still listening for this
    /// entry? Catches a VM stopped out-of-band and a dead tunnel forward.
    /// Cheap on a healthy VM (a local round-trip), so it's safe per checkout.
    ///
    /// Only a *refusal* counts as dead. This used to require a successful
    /// `SELECT 1` within 3s and treat everything else — a slow answer, a
    /// server error, connection saturation — as a dead VM, which then evicted
    /// the entry and dropped into a re-init that power-cycles it. Every one of
    /// those is survivable on its own; the reboot isn't, since the pooler stops
    /// VMs with an unclean kill and takes any in-flight ingest with it. A
    /// stalled probe in particular is the *expected* reading of a VM under a
    /// heavy load, so the old check reliably killed VMs for being busy.
    async fn entry_alive(&self, entry: &SchemaEntry) -> bool {
        !matches!(
            crate::vm::probe_pg(&entry.pool).await,
            crate::vm::PgProbe::Unreachable(_)
        )
    }

    /// Spawn the registry-store flush loop: activity bumps (`touch`/`put` on
    /// unchanged mappings) only mark the store dirty, and this loop persists
    /// them at most once per [`crate::store::FLUSH_INTERVAL`] — one O(rows)
    /// serialize per interval however many schemas a storm touches, instead of
    /// one per schema. Mapping *changes* still flush immediately inside the
    /// store, so this loop is durability-relevant only for idle clocks.
    pub fn spawn_store_flusher(self: &Arc<Self>) {
        let registry = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(crate::store::FLUSH_INTERVAL).await;
                registry.store.flush_dirty();
            }
        });
    }

    /// Spawn the untracked-VM reconciler alongside the idle reaper.
    ///
    /// The idle reaper only ever sees `self.entries` — VMs this pooler
    /// process brought up and still tracks. A running VM with **no warm
    /// entry and no bring-up in flight** is unused by definition (every
    /// client path runs through a warm entry), yet nothing stops it: VMs
    /// left running across a pooler restart, VMs whose idle-stop failed
    /// (a failed stop is logged, not retried), VMs the daemon booted on its
    /// own. Worse, the offload ladder cannot pass them: compaction refuses a
    /// disk a running VM holds open and backs off (30m→24h), and while
    /// compaction is *eligible* the picker never falls through to the dump
    /// archive. The visible symptom is "many running VMs, no sessions,
    /// nothing offboarding".
    ///
    /// This loop lists the daemon's running VMs and stops every one that is
    /// bound to a live schema but tracked by nothing — only after seeing the
    /// same VM untracked on **two consecutive passes**, so a bring-up that
    /// lands between the listing and the map check is never stopped
    /// mid-flight. Unbound running VMs (no live registry row) are left
    /// alone: the purge owns offloaded-tier leftovers and anything else is
    /// not the pooler's to stop. Same cadence as the idle reaper, and the same
    /// [`drain_allowance`] rate limit — this pass needs it even more than the
    /// idle reaper does, because after a pooler restart its population is the
    /// *entire running fleet* at once (the warm map starts empty, so every
    /// running VM is untracked by definition). Uncapped, that made every
    /// deploy stop the whole fleet about two passes later.
    pub fn spawn_untracked_reaper(self: &Arc<Self>) {
        let Some(timeout) = self.cfg.idle_timeout else {
            return; // idle reaping off ⇒ the operator wants VMs left running
        };
        let tick = (timeout / 4).max(Duration::from_secs(5));
        let registry = self.clone();
        let suspects: Arc<tokio::sync::Mutex<HashSet<String>>> = Arc::default();
        tokio::spawn(supervise("untracked-reaper", tick, tick, move || {
            let registry = registry.clone();
            let suspects = suspects.clone();
            async move {
                let mut suspects = suspects.lock().await;
                registry.reap_untracked(&mut suspects, tick).await
            }
        }));
    }

    /// One reconciler pass — see [`Self::spawn_untracked_reaper`]. Returns
    /// how many VMs were stopped.
    async fn reap_untracked(&self, suspects: &mut HashSet<String>, tick: Duration) -> usize {
        let infos = match vm::list_with_retry().await {
            Ok(l) => l,
            Err(e) => {
                warn!("untracked-reaper: listing sandboxes failed; skipping pass: {e:#}");
                return 0;
            }
        };
        // id → schema for every live row.
        let live_by_id: HashMap<String, String> = self
            .store_records()
            .into_iter()
            .filter(|(_, r)| r.tier == Tier::Live)
            .map(|(schema, r)| (r.sandbox_id, schema))
            .collect();
        let spare_claimed = self
            .spares
            .as_ref()
            .map(|p| p.claimed_ids())
            .unwrap_or_default();
        let mut seen_now: HashSet<String> = HashSet::new();
        let mut stopped = 0usize;
        let mut superseded_seen = 0usize;
        // `(id, schema, superseded)` for every VM confirmed untracked on two
        // consecutive passes — collected first, then rate-limited and stopped
        // below rather than stopped inline, which is what made this pass a
        // fleet-wide cliff.
        let mut confirmed: Vec<(String, String, bool)> = Vec::new();
        let allowance = drain_allowance(self.store.live_count(), tick, self.cfg.idle_drain_window);
        for info in infos
            .iter()
            .filter(|i| i.status == heyo_sdk::SandboxStatus::Running)
        {
            if info.name.starts_with(crate::spares::SPARE_PREFIX)
                || spare_claimed.contains(&info.id)
            {
                continue; // the spare pool owns these
            }
            if self.physical.owns_vm(&info.id) || self.physical_sources.owns_vm(&info.id) {
                continue; // physical journals own even superseded pg-* VMs
            }
            // Bound to a live schema, or a SUPERSEDED DUPLICATE: a running
            // `pg-<schema>` VM that is not that schema's current binding (a
            // retrying bring-up created it and moved on; nothing references
            // it, so neither the idle reaper, the ladder nor the purge will
            // ever touch it). Duplicates are stopped, never deleted — if the
            // rebind was wrong, the superseded disk may hold the real data.
            let (schema, superseded) = match live_by_id.get(&info.id) {
                Some(schema) => (schema.clone(), false),
                None => {
                    let Some(schema) = info.name.strip_prefix("pg-") else {
                        continue; // not a pooler-shaped VM: not ours to stop
                    };
                    match self.store.record(schema) {
                        Some(rec) if rec.sandbox_id != info.id => (schema.to_string(), true),
                        _ => continue, // no row, or this IS the binding (live_by_id miss = non-live tier; purge owns it)
                    }
                }
            };
            let schema = schema.as_str();
            // Tracked = a cell exists, warm OR initializing (bring-up in flight).
            if self.entries.lock().await.contains_key(schema) && !superseded {
                continue;
            }
            if self.is_archiving(schema) || crate::pending::get(schema).as_deref() == Some(&info.id) {
                continue;
            }
            // A pinned schema's VM must stay up even when nothing has checked
            // it out yet. This is the exclusion that actually bites: after a
            // pooler restart the warm-entry map is empty until the first
            // client connects, so a replicating VM looks "untracked" and would
            // be stopped here — breaking the pairing on every restart, with
            // only a routine idle-stop line in the log to explain it.
            // `spawn_replication_pinner` warms these at startup so this is a
            // belt-and-braces guard, not the only one.
            if !superseded && self.pinned(schema) {
                continue;
            }
            if superseded {
                superseded_seen += 1;
            }
            // Every current suspect is recorded, including any this pass will
            // not get to: that is what keeps a deferred VM *confirmed* rather
            // than restarting its two-pass clock every time the allowance
            // runs out.
            seen_now.insert(info.id.clone());
            if !suspects.contains(&info.id) {
                continue; // first sighting: confirm next pass
            }
            confirmed.push((info.id.clone(), schema.to_string(), superseded));
        }
        // Rate-limited exactly like the idle reaper, for a sharper version of
        // the same reason. This pass's whole population appears at once after a
        // pooler restart — the warm map starts empty, so every running VM is
        // untracked by definition — and stopping all of them was a fleet-wide
        // cliff two passes (~2.5 min) after every deploy. Oldest-first has no
        // meaning here, so the daemon's own listing order decides; the excess
        // stays confirmed and goes next pass.
        let deferred = confirmed.len().saturating_sub(allowance);
        confirmed.truncate(allowance);
        if deferred > 0 {
            info!(
                "untracked-reaper: stopping {} untracked VM(s) this pass, deferring \
                 {deferred} to keep the fleet ramping down instead of falling off a cliff \
                 (PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS)",
                confirmed.len()
            );
        }
        let mut stops = futures::stream::iter(confirmed.into_iter().map(
            |(id, schema, superseded)| async move {
                if self.physical.owns_vm(&id) || self.physical_sources.owns_vm(&id) {
                    return false; // ownership may have been persisted after inventory
                }
                info!(
                    "untracked-reaper: VM {id} (schema {schema}{}) is running with no warm \
                     entry and no bring-up in flight on two consecutive passes — stopping it \
                     so the idle/offload ladder can reclaim it",
                    if superseded { ", superseded duplicate" } else { "" }
                );
                match heyo_sdk::Sandbox::connect(id.clone(), vm::local_opts()) {
                    Ok(sb) => match tokio::time::timeout(UNTRACKED_STOP_TIMEOUT, sb.stop()).await {
                            Ok(Ok(())) => {
                                crate::events::journal_info(
                                    "untracked",
                                format!("schema {schema}: stopped untracked running VM {id}"),
                                );
                                return true;
                            }
                            Ok(Err(e)) => {
                                warn!("untracked-reaper: stopping {id} failed: {e:#}")
                            }
                            Err(_) => warn!("untracked-reaper: stopping {id} timed out"),
                    },
                    Err(e) => warn!("untracked-reaper: connecting to {id} failed: {e:#}"),
                }
                false
            },
        ))
        // Serially these cost up to UNTRACKED_STOP_TIMEOUT each, so a full
        // allowance could outlast several ticks and pile passes up behind it.
        .buffer_unordered(IDLE_STOP_CONCURRENCY);
        while let Some(ok) = stops.next().await {
            stopped += usize::from(ok);
        }
        if !seen_now.is_empty() && stopped == 0 {
            info!(
                "untracked-reaper: {} running VM(s) tracked by nothing ({superseded_seen} \
                 superseded duplicate(s)) — confirming next pass",
                seen_now.len()
            );
        }
        *suspects = seen_now;
        if stopped > 0
            && let Some(reclaimer) = &self.reclaimer
        {
            reclaimer.spawn_soon(POST_STOP_RECLAIM_DELAY);
        }
        stopped
    }

    /// Spawn the background idle-reaper if an idle timeout is configured.
    pub fn spawn_reaper(self: &Arc<Self>) {
        let Some(timeout) = self.cfg.idle_timeout else {
            info!("idle reaping disabled (PG_VM_POOL_IDLE_TIMEOUT_SECS=0)");
            return;
        };
        match self.cfg.idle_timeout_fast {
            Some(fast) => info!(
                "idle reaper: stopping VMs after {timeout:?} without connections, or {fast:?} \
                 for a VM whose own bring-up took <= {:?} (a restart of a VM still on disk — \
                 keeping one of those warm buys the next client almost nothing)",
                self.cfg.fast_bringup
            ),
            None => info!(
                "idle reaper: stopping VMs after {timeout:?} without connections \
                 (PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS=0: no short timeout for \
                 cheap-to-restart VMs)"
            ),
        }
        match self.cfg.disk_grow {
            Some(g) => info!(
                "disk growth: at idle-stop, devices spanned by a >= {:.0}%-full data fs \
                 are doubled offline (cap {}GiB, via the daemon's workspace resize)",
                g.pct, g.max_gb
            ),
            None => info!("disk growth disabled (PG_VM_POOL_DISK_GROW_PCT unset)"),
        }
        let registry = self.clone();
        // Check a few times per timeout window so shutdown lands close to the
        // deadline, but not so often it busies the daemon. Paced off the
        // SHORTEST budget in play: with a 60s fast timeout under a 900s normal
        // one, a 225s tick would let every cheap VM overshoot its deadline by
        // more than the deadline itself.
        let shortest = self.cfg.idle_timeout_fast.unwrap_or(timeout).min(timeout);
        let tick = (shortest / 4).max(Duration::from_secs(5));
        match self.cfg.idle_drain_window {
            Some(w) => info!(
                "idle reaper: draining at most the whole live fleet per {w:?} \
                 ({IDLE_MIN_STOPS_PER_PASS}–{IDLE_MAX_STOPS_PER_PASS} VMs per {tick:?} pass) — \
                 a synchronized expiry ramps down instead of falling off a cliff \
                 (PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS)"
            ),
            None => info!(
                "idle reaper: drain rate limit disabled — up to \
                 {IDLE_MAX_STOPS_PER_PASS} VMs stop per {tick:?} pass \
                 (PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS=0)"
            ),
        }
        // Reaper `tick` is already short, so first pass and steady state match.
        // The timeouts are re-read every pass so `PUT /api/config` takes
        // effect without a restart; the tick stays as paced at boot.
        tokio::spawn(supervise("idle-reaper", tick, tick, move || {
            let registry = registry.clone();
            async move {
                let timeout = registry.runtime.idle_timeout().unwrap_or(timeout);
                registry.reap_idle(timeout, tick).await
            }
        }));
    }

    /// Evict and stop idle VMs — at most [`drain_allowance`] of them per pass,
    /// oldest-idle first. Eviction (removing the map cell) happens under the
    /// lock so a concurrent `checkout` either sees the entry before eviction
    /// (and bumps `active`, sparing it) or misses it and brings up a fresh VM.
    /// The actual stop happens after the lock is released.
    ///
    /// Each entry is judged against its own budget — see [`idle_budget`] — so
    /// a VM that is cheap to restart expires on the short timeout while one
    /// that cost a create or a thaw keeps the full warm hold.
    ///
    /// The per-pass allowance is what keeps a *synchronized* expiry from
    /// becoming a cliff. Clients arrive in bursts and go idle in bursts, and
    /// the per-schema jitter (see [`jittered_timeout`]) only spreads a
    /// cohort's deadlines by ±15% — eighteen seconds on a 60s budget. Stopping
    /// all of them as fast as the daemon will take them reads as "the fleet
    /// fell off a cliff" on the dashboard, hands the post-stop reclaim trigger
    /// hundreds of disks at once, and converts into a synchronized cold-start
    /// (and spare-claim) storm when those schemas come back. The allowance
    /// turns it into a ramp of known gradient; the excess waits a tick and is
    /// picked up oldest-first, so nothing is forgotten, only paced.
    ///
    /// Returns how many VMs were stopped, for the supervisor's heartbeat.
    async fn reap_idle(self: &Arc<Self>, timeout: Duration, tick: Duration) -> usize {
        let fast = self.runtime.idle_timeout_fast();
        let fast_bringup = self.cfg.fast_bringup;
        // Sized from the durable live-tier count, not the warm map: see
        // [`drain_allowance`] for why the divisor must not shrink mid-drain.
        let allowance = drain_allowance(self.store.live_count(), tick, self.cfg.idle_drain_window);
        let mut victims: Vec<(String, Arc<SchemaEntry>)> = Vec::new();
        let deferred;
        {
            let mut map = self.entries.lock().await;
            // Collect every expired entry with its idle age, then take only
            // the oldest-idle CAP of them out of the map. Each entry is judged
            // against its OWN budget (see `SchemaEntry::idle_budget`), so a
            // cheap-to-restart VM expires on the short timeout while one that
            // cost a create or a thaw keeps the full warm hold.
            let mut expired: Vec<(String, Duration)> = map
                .iter()
                .filter_map(|(schema, cell)| {
                    let entry = cell.get()?;
                    let budget = entry.idle_budget(timeout, fast, fast_bringup);
                    entry
                        .is_idle(jittered_timeout(schema, budget))
                        .then(|| (schema.clone(), entry.idle_for()))
                })
                .collect();
            expired.sort_by_key(|(_, idle)| std::cmp::Reverse(*idle));
            deferred = expired.len().saturating_sub(allowance);
            for (schema, _) in expired.into_iter().take(allowance) {
                if let Some(entry) = map.get(&schema).and_then(|cell| cell.get()).cloned() {
                    map.remove(&schema);
                    victims.push((schema, entry));
                }
            }
        }
        if deferred > 0 {
            info!(
                "idle reaper: stopping {} oldest-idle VM(s) this pass, deferring {deferred} \
                 — draining a synchronized expiry at {allowance}/pass so the fleet ramps \
                 down instead of falling off a cliff (PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS)",
                victims.len()
            );
        }
        let stopped = victims.len();
        // Device-growth candidates discovered while stopping: (schema, id,
        // target GiB). Sampled over the still-warm pool BEFORE the stop tears
        // it down — after the stop there's no cheap way to ask the guest, and
        // the resize is cheapest exactly then (the daemon's resize is offline;
        // on an already-stopped VM it costs no client disruption at all).
        let mut grow: Vec<(String, String, u64)> = Vec::new();
        // Victims stop concurrently, bounded by IDLE_STOP_CONCURRENCY. Each
        // stop is a sequence of waits on things outside this process — a guest
        // `df`, a CHECKPOINT on a micro VM, then the daemon's stop — so one at
        // a time a pass costs the SUM of them, tens of seconds apiece, which
        // on a busy host runs longer than the tick that scheduled it. No cap
        // can fix that; the work is per-VM-independent and the only reason it
        // was serial is that it was written as a loop.
        let mut stops = futures::stream::iter(victims.into_iter().map(|(schema, entry)| {
            let registry = self.clone();
            async move {
                info!(
                    "idle-stopping VM for schema {schema} (no connections for >= {:?}; \
                     its bring-up took {:?})",
                    entry.idle_budget(timeout, fast, fast_bringup),
                    entry.bringup_took,
                );
                let mut grow = None;
                if let Some(gc) = registry.cfg.disk_grow
                    && let Some((fs, dev)) = sample_disk(&entry).await
                {
                    // Note the device size while the VM is still up to answer
                    // the question. Once the offload ladder deletes that VM,
                    // the registry row is the only thing left that knows how
                    // big a restore has to build its replacement (see
                    // `Store::set_disk_gb`), and a stale value corrects itself
                    // here on the next idle-stop.
                    registry.store.set_disk_gb(&schema, device_gb(dev));
                    if let GrowVerdict::Grow(target) = grow_verdict(fs, dev, gc.pct, gc.max_gb) {
                        info!(
                            "schema {schema}: data fs is >= {:.0}% full and spans its device — \
                             queueing offline device grow to {target}GiB",
                            gc.pct
                        );
                        grow = Some((schema.clone(), entry.sandbox_id(), target));
                    }
                }
                checkpoint_and_stop(&entry, &schema).await;
                // Dropping the last Arc here tears down the tunnel + pool. Data
                // on the VM's /dev/vdb persists; a later connect restarts it.
                grow
            }
        }))
        .buffer_unordered(IDLE_STOP_CONCURRENCY);
        while let Some(queued) = stops.next().await {
            grow.extend(queued);
        }
        // The disks just released are prime reclaim candidates — without a trim
        // each keeps its full high-water allocation on the host. Trigger a run
        // once the Firecracker processes have fully exited (the script skips
        // any disk still held open, so an early fire is safe, just less useful).
        if stopped > 0
            && let Some(reclaimer) = &self.reclaimer
        {
            reclaimer.spawn_soon(POST_STOP_RECLAIM_DELAY);
        }
        // Run queued device grows in the background, strictly sequential (the
        // daemon single-flights resizes anyway) and each under the boot
        // permit: the daemon's resize fscks and cold-boots the stopped disk,
        // which must never interleave with a reclaim pass fsck'ing the same
        // file (see reclaim::BOOT_GATE).
        if !grow.is_empty() {
            let registry = self.clone();
            tokio::spawn(async move {
                for (schema, id, target) in grow {
                    let _permit = crate::reclaim::boot_permit(&id).await;
                    match vm::resize_disk(&id, target).await {
                        Ok(()) => {
                            info!("schema {schema}: data device grown to {target}GiB");
                            // The new size, recorded the moment it is real: a
                            // schema archived before its next idle-stop would
                            // otherwise be restored into the pre-grow device.
                            registry.store.set_disk_gb(&schema, target as u32);
                            crate::events::journal_info(
                                "disk-grow",
                                format!("schema {schema}: device grown to {target}GiB ({id})"),
                            );
                        }
                        Err(e) => {
                            warn!("schema {schema}: device grow to {target}GiB failed: {e:#}");
                            crate::events::journal_error(
                                "disk-grow",
                                format!("schema {schema}: grow of {id} to {target}GiB failed: {e:#}"),
                            );
                        }
                    }
                }
            });
        }
        stopped
    }

    // ---- disk-slack reclamation ---------------------------------------------

    /// Spawn the periodic disk-reclaim loop if `PG_VM_POOL_RECLAIM_CMD` is
    /// configured. Complements the post-reap trigger in [`Self::reap_idle`]:
    /// that one returns a just-stopped VM's slack promptly; this one is the
    /// backstop for VMs stopped out-of-band (dashboard, heyvm CLI, crashes).
    pub fn spawn_reclaimer(self: &Arc<Self>) {
        let Some(rc) = self.cfg.reclaim.clone() else {
            info!("automatic disk reclaim disabled (PG_VM_POOL_RECLAIM_CMD unset)");
            return;
        };
        // `reclaimer` is always Some when the config is.
        let Some(reclaimer) = self.reclaimer.clone() else {
            return;
        };
        info!(
            "disk reclaim: running `{}` every {:?} (and after idle reaps)",
            rc.cmd, rc.interval
        );
        let first = RECLAIM_FIRST_DELAY.min(rc.interval);
        tokio::spawn(supervise("disk-reclaim", first, rc.interval, move || {
            let reclaimer = reclaimer.clone();
            async move { reclaimer.run_once().await }
        }));
    }

    /// Kick off one disk-reclaim run now, in the background — the dashboard's
    /// "reclaim disk slack" control. Errors if reclamation isn't configured or
    /// a run is already in progress.
    pub fn spawn_reclaim_now(&self) -> Result<()> {
        let Some(reclaimer) = &self.reclaimer else {
            bail!("automatic disk reclaim is not configured (set PG_VM_POOL_RECLAIM_CMD)");
        };
        reclaimer.spawn_now()
    }

    // ---- offload tiers (compact / freeze / S3) ------------------------------

    /// Spawn the **offload pacer**: one task that trickles cold schemas down
    /// the storage ladder — compact, freeze, promote-to-S3, archive-to-S3 — one
    /// schema at a time, whenever the host has nothing better to do.
    ///
    /// This replaces the three periodic batch sweeps (S3 eviction, freeze,
    /// compact). Batching was the wrong shape for the work. A sweep woke on its
    /// own timer regardless of what the host was doing, then ran every
    /// candidate it found back to back — each one a VM boot plus a `pg_dump`
    /// plus an upload, minutes apiece, holding a bring-up slot and the shared
    /// sweep lock throughout. On a fleet with a real backlog that is a
    /// multi-hour block of self-inflicted load that lands, by construction, at
    /// an arbitrary moment: exactly when clients are reconnecting, or when the
    /// warm pool is trying to rebuild, is as likely as any other time.
    ///
    /// The pacer inverts it. It wakes every [`OFFLOAD_TICK`], and before
    /// dispatching *each* job it re-asks whether the host is quiet (see
    /// [`Self::dispatch_backpressure`]): no client is queued for a bring-up
    /// and no reclaim pass is running. Up to `PG_VM_POOL_OFFLOAD_WORKERS`
    /// jobs run concurrently (default 1 — the classic one-at-a-time pacing),
    /// with three brakes on the extra concurrency:
    ///
    ///   - the FIRST job is always allowed, but every additional one is
    ///     dispatched only while normalized host load (load1/cores, which on
    ///     Linux includes tasks blocked on disk I/O) is below
    ///     `PG_VM_POOL_OFFLOAD_LOAD_MAX` — aggressive with headroom, single
    ///     file without;
    ///   - at most ONE in-flight job may boot a VM (archive/freeze), because
    ///     boots share the FIFO bring-up gate with waiting clients;
    ///   - backpressure pauses NEW dispatch only — in-flight jobs always run
    ///     to completion (they hold per-schema claims, not host-wide locks).
    ///
    /// With one bound on the yielding, because "wait for quiet" is not the
    /// same promise as "eventually run". A host whose bring-up queue is never
    /// empty for a whole tick starves the pacer completely, and the work does
    /// not go away: it piles up until the host goes quiet (or the disk-pressure
    /// watchdog fires) and then lands as the single burst this design exists to
    /// avoid, against a disk already near the high-water mark. So after
    /// `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` of continuous *client*
    /// backpressure the pacer dispatches anyway — one job at a time, no-boot
    /// kinds only, and only that gate overridden (see [`Backpressure`]). It
    /// keeps trickling for as long as the host stays busy, so the same total
    /// work is spread across the busy hours instead of stacking up for them.
    ///
    /// Each dispatch re-picks against a fresh view of the host, excluding
    /// schemas already in flight here or claimed elsewhere (dashboard buttons,
    /// the pressure pass). The total work done is the same; it is spread thin
    /// and yields to anything a user is waiting on.
    ///
    /// Scanning is cheap because it only happens when the pacer is actually
    /// about to act: a tick during a busy host is an atomic load. When a scan
    /// finds nothing (with no jobs in flight), the next one is deferred by the
    /// configured sweep interval (the `*_SWEEP_SECS` vars keep that meaning),
    /// so an idle fleet costs a scan a minute rather than one a second.
    ///
    /// If this dispatcher task were ever dropped, its JoinSet would abort
    /// in-flight jobs mid-offload — safe for data (compaction/spool land via
    /// atomic rename; children are `kill_on_drop`) but it can leave a stale
    /// `.tmp` behind, so the loop body stays panic-free by construction.
    pub fn spawn_offloader(self: &Arc<Self>) {
        let mut tiers: Vec<String> = Vec::new();
        if let Some(c) = &self.cfg.compact {
            tiers.push(format!(
                "compact >= {:?} into {}",
                c.compact_after,
                c.compact_dir.display()
            ));
        }
        if let Some(f) = &self.cfg.freeze {
            tiers.push(format!(
                "freeze >= {:?} into {}",
                f.freeze_after,
                f.dump_dir.display()
            ));
        }
        if let Some(a) = &self.cfg.archive {
            tiers.push(format!(
                "S3 >= {:?} (s3://{}/{}{})",
                a.archive_after,
                a.s3.bucket,
                a.s3.prefix,
                a.s3.fallback_prefix()
                    .map(|p| format!("; restores fall back to {p}"))
                    .unwrap_or_default()
            ));
        }
        if tiers.is_empty() {
            info!(
                "offload pacer disabled — no tier configured (PG_VM_POOL_COMPACT_AFTER_SECS / \
                 FREEZE_AFTER_SECS / ARCHIVE_AFTER_SECS all unset)"
            );
            return;
        }
        let idle_rescan = self.offload_idle_rescan();
        let workers = self.cfg.offload_workers;
        let load_max = self.cfg.offload_load_max;
        let max_holdoff = self.cfg.offload_max_holdoff;
        info!(
            "offload pacer: {} — up to {workers} concurrent job(s), at most one that boots a VM, \
             extras only while load/core < {load_max} (tick {OFFLOAD_TICK:?}, rescan \
             {idle_rescan:?} when there is nothing to do); {}",
            tiers.join(", "),
            match max_holdoff {
                Some(d) => format!(
                    "after {d:?} held off by queued clients or a reclaim pass it trickles one \
                     no-boot job at a time anyway"
                ),
                None => "it yields to queued clients and reclaim passes indefinitely \
                         (PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS=0)"
                    .to_string(),
            }
        );

        let registry = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(OFFLOAD_FIRST_DELAY).await;
            // When the last scan found nothing, don't scan again until this.
            let mut hold_until: Option<Instant> = None;
            let mut quiet_since: Option<Instant> = None;
            // When the current unbroken stretch of backpressure began. Cleared
            // only when the host actually goes quiet — deliberately NOT by a
            // forced dispatch, so a host that stays busy keeps getting one
            // no-boot job at a time instead of one per holdoff window.
            let mut held_since: Option<Instant> = None;
            // In-flight jobs, each in its own JoinSet task so a panic inside
            // one offload is contained — the pacer must outlive any single
            // schema. The side map keys by task id so a job's label survives
            // its panic (a JoinError only carries the id).
            let mut jobs: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
            let mut in_flight: HashMap<tokio::task::Id, (String, OffloadKind, Instant)> =
                HashMap::new();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(OFFLOAD_TICK) => {}
                    Some(res) = jobs.join_next_with_id(), if !jobs.is_empty() => {
                        match res {
                            Ok((task_id, ())) => {
                                if let Some((schema, kind, started)) = in_flight.remove(&task_id) {
                                    debug!(
                                        "offload pacer: {} {schema} finished in {:?} \
                                         ({} still in flight)",
                                        kind.as_str(),
                                        started.elapsed(),
                                        jobs.len()
                                    );
                                }
                            }
                            Err(e) => {
                                let label = in_flight
                                    .remove(&e.id())
                                    .map(|(s, k, _)| format!("{} {s}", k.as_str()))
                                    .unwrap_or_else(|| "?".into());
                                if e.is_panic() {
                                    error!(
                                        "offload pacer: {label} PANICKED: {}",
                                        panic_message(e.into_panic())
                                    );
                                } else {
                                    error!("offload pacer: {label} failed to run: {e}");
                                }
                            }
                        }
                        // A completion is not a dispatch opportunity; the next
                        // tick (≤1s away) re-evaluates the host fresh.
                        continue;
                    }
                }
                if hold_until.is_some_and(|t| Instant::now() < t) {
                    continue;
                }
                if jobs.len() >= workers {
                    continue;
                }
                // How long this dispatch has been owed and what was holding
                // it, when it is the starvation escape hatch rather than a
                // normal quiet-host one.
                let mut forced: Option<(Duration, Backpressure)> = None;
                match registry.dispatch_backpressure() {
                    None => {
                        held_since = None;
                        quiet_since.get_or_insert_with(Instant::now);
                    }
                    Some(bp) => {
                        let held = held_since.get_or_insert_with(Instant::now).elapsed();
                        if forced_dispatch(bp, held, jobs.is_empty(), max_holdoff) {
                            forced = Some((held, bp));
                        } else {
                            // Log the first deferral of each busy stretch only: this
                            // loop runs 86 400 times a day and a busy host would
                            // otherwise fill the log with it.
                            if quiet_since.take().is_some() {
                                debug!("offload pacer: holding off — {}", bp.reason());
                            }
                            continue;
                        }
                    }
                }
                if forced.is_none()
                    && !dispatch_allowance(jobs.len(), workers, normalized_load(), load_max)
                {
                    continue;
                }
                let mut policy = registry.offload_policy();
                // At most one boot-kind job in flight: those compete with
                // waiting clients for the FIFO bring-up gate — and a forced
                // job must boot nothing at all, since the clients it is
                // stepping in front of are queued for exactly that gate.
                policy.no_boot =
                    forced.is_some() || in_flight.values().any(|(_, kind, _)| kind.boots());
                let excluded: HashSet<String> =
                    in_flight.values().map(|(schema, ..)| schema.clone()).collect();
                let Some(job) = registry.next_offload_job(policy, &excluded).await else {
                    // Only arm the idle hold when nothing is running: with
                    // jobs in flight an empty pick usually means "everything
                    // eligible is already claimed", and holding would delay
                    // the dispatch that should follow their completion.
                    if jobs.is_empty() {
                        hold_until = Some(Instant::now() + idle_rescan);
                    }
                    continue;
                };
                hold_until = None;
                let r = registry.clone();
                let (schema, kind) = (job.schema.clone(), job.kind);
                match forced {
                    // Worth a line of its own at info: a pacer starved this
                    // long is invisible otherwise (the holdoff itself only
                    // logs at debug), and this is the log that explains why
                    // housekeeping is running during peak traffic.
                    Some((held, bp)) => info!(
                        "offload dispatch: {} {schema} single-file — held off {held:?} \
                         because {} (PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS)",
                        kind.as_str(),
                        bp.reason()
                    ),
                    None => info!(
                        "offload dispatch: {} {schema} ({}/{workers} in flight)",
                        kind.as_str(),
                        jobs.len() + 1
                    ),
                }
                let task_id = jobs
                    .spawn(async move {
                        let _ = r.run_offload_job(job).await;
                    })
                    .id();
                in_flight.insert(task_id, (schema, kind, Instant::now()));
            }
        });
    }

    /// Why the dispatcher should not start a NEW offload job this tick, if it
    /// shouldn't. (In-flight jobs are never interrupted — they hold per-schema
    /// claims, not host-wide locks.)
    ///
    /// Every condition here is "something a person is waiting on, or something
    /// that would fight us for the same resource". Offloading is pure
    /// housekeeping: it has no deadline, so it always loses. Concurrency
    /// between offloads themselves is the dispatcher's business (worker cap +
    /// load gate + pick-time exclusion), not this function's — dashboard and
    /// pressure-pass claims are excluded at pick time via `is_archiving`.
    ///
    /// The distinction between the variants is what the starvation escape
    /// hatch keys on: a deferral that only costs someone else time may be
    /// overridden after a long enough holdoff, one that would duplicate work
    /// already claimed never may. See [`Backpressure`].
    fn dispatch_backpressure(&self) -> Option<Backpressure> {
        if crate::vm::bringups_waiting() > 0 {
            return Some(Backpressure::ClientsQueued);
        }
        // A pass holds the boot gate; an offload that boots a VM to dump it
        // would make it yield and lose that pass's progress.
        if crate::reclaim::pass_running() {
            return Some(Backpressure::ReclaimPass);
        }
        // A manual batch sweep from the dashboard.
        if self.sweeping.load(Ordering::SeqCst) {
            return Some(Backpressure::Sweeping);
        }
        None
    }

    /// How long to wait before re-scanning after a scan that found nothing.
    /// Taken from the shortest configured `*_SWEEP_SECS` — those vars no
    /// longer pace the work itself, only how eagerly an idle pooler looks for
    /// new candidates — and clamped so neither a 1-second nor a 12-hour value
    /// makes the pacer useless.
    fn offload_idle_rescan(&self) -> Duration {
        [
            self.cfg.compact.as_ref().map(|c| c.sweep_interval),
            self.cfg.freeze.as_ref().map(|f| f.sweep_interval),
            self.cfg.archive.as_ref().map(|a| a.sweep_interval),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(OFFLOAD_IDLE_RESCAN_MAX)
        .clamp(OFFLOAD_IDLE_RESCAN_MIN, OFFLOAD_IDLE_RESCAN_MAX)
    }

    /// The single most valuable offload available right now, or `None` when
    /// nothing is eligible. Also keeps `last_active` honest for schemas that
    /// look durably stale but are actually warm, so they aren't re-evaluated
    /// as candidates on every scan.
    ///
    /// `in_flight` is the caller's own set of schemas it already has jobs
    /// running for (the dispatcher's accounting); on top of it, any schema
    /// whose [`ArchivingGuard`] is currently claimed — a dashboard button, the
    /// pressure pass, or another worker mid-claim — is skipped, so concurrent
    /// pickers never collide on the same schema.
    async fn next_offload_job(
        &self,
        policy: OffloadPolicy,
        in_flight: &HashSet<String>,
    ) -> Option<OffloadJob> {
        // Live cross-check: a schema warm with active connections, or whose
        // in-memory idle clock is younger than the threshold, is not cold even
        // if its durable `last_active` drifted (one long-lived connection with
        // no new checkouts).
        let live: HashMap<String, (usize, u64)> = self
            .snapshot()
            .await
            .into_iter()
            .map(|e| (e.schema, (e.active, e.idle_secs)))
            .collect();
        let records = self.store_records();
        let at = Instant::now();
        let (job, refresh) = pick_offload_job(
            &records,
            &live,
            policy,
            // `pinned`, not `is_keepalive`: a replicated schema must never be
            // offloaded, and this closure is what the routine pacer, the
            // emergency pressure pass and the dashboard's TTL sweep all pick
            // through.
            &|schema| self.pinned(schema),
            &|schema| {
                in_flight.contains(schema)
                    || self.is_archiving(schema)
                    || self.offload_backoff.active(schema, at).is_some()
            },
            now_unix(),
        );
        for schema in refresh {
            self.store.touch(&schema);
        }
        job
    }

    /// Routine housekeeping: the configured thresholds, cheapest job first.
    fn offload_policy(&self) -> OffloadPolicy {
        OffloadPolicy {
            // Runtime knobs: `None` exactly when the tier is not configured.
            compact_after: self.runtime.compact_after().map(|d| d.as_secs()),
            freeze_after: self.runtime.freeze_after().map(|d| d.as_secs()),
            archive_after: self.runtime.archive_after().map(|d| d.as_secs()),
            image_archive: self.image_archive_enabled(),
            no_boot: false,
            mode: OffloadMode::Routine,
        }
    }

    /// Emergency policy: every idle schema is a candidate whatever its age
    /// (threshold `0`), coldest first, and freezing is dropped entirely — it
    /// costs a boot and leaves the bytes on the host, which is the one thing
    /// that cannot help here. The tiers themselves must still be configured:
    /// pressure eviction overrides the *thresholds*, never the operator's
    /// choice of where data may go.
    fn pressure_policy(&self) -> OffloadPolicy {
        OffloadPolicy {
            compact_after: self.cfg.compact.as_ref().map(|_| 0),
            freeze_after: None,
            archive_after: self.cfg.archive.as_ref().map(|_| 0),
            image_archive: self.image_archive_enabled(),
            no_boot: false,
            mode: OffloadMode::Pressure,
        }
    }

    /// Perform one job. Each arm is the same per-schema entry point the
    /// dashboard's buttons use, so failures journal and enter the per-schema
    /// backoff exactly as they always have.
    async fn run_offload_job(&self, job: OffloadJob) -> Result<()> {
        let OffloadJob { schema, kind } = job;
        info!("offload: {} schema {schema}", kind.as_str());
        let res = match kind {
            // `archive_schema` dispatches on the schema's current tier, so a
            // frozen/compacted schema is promoted (a file upload, no VM) and a
            // live one is dumped and killed.
            OffloadKind::Promote | OffloadKind::Archive => self.archive_schema(&schema).await,
            OffloadKind::Compact => self.compact_schema(&schema).await,
            OffloadKind::ImageArchive => self.archive_schema_as_image(&schema, None).await,
            OffloadKind::Freeze => self.freeze_schema(&schema).await,
        };
        if let Err(e) = &res {
            if e.downcast_ref::<AlreadyOffloading>().is_some() {
                // Benign: another worker / the dashboard claimed it first.
                debug!("offload: {} schema {schema} skipped — already in flight", kind.as_str());
            } else if e.downcast_ref::<crate::imgarchive::EmptyCluster>().is_some() {
                // Not a failure — `archive_schema` journals it as "kept local".
                debug!("offload: {} schema {schema} kept local — no user data", kind.as_str());
            } else {
                warn!(
                    "offload: {} schema {schema} failed (backing off): {e:#}",
                    kind.as_str()
                );
            }
        }
        res
    }

    /// Spawn the warm-spare replenisher if `PG_VM_POOL_WARM_SPARES` > 0: keeps
    /// the pool of pre-booted claimable VMs topped up (see `spares`).
    pub fn spawn_spare_replenisher(self: &Arc<Self>) {
        let Some(pool) = self.spares.clone() else {
            info!("warm-spare pool disabled (PG_VM_POOL_WARM_SPARES unset/0)");
            return;
        };
        info!(
            "warm-spare pool: keeping {} pre-booted VM(s) ready for claiming",
            pool.target()
        );
        let registry = self.clone();
        // Claiming (or failure-killing) a spare pokes the wake handle, so the
        // deficit is rebuilt immediately rather than on the next tick.
        let wake = pool.replenish_wake();
        tokio::spawn(supervise_with_wake(
            "warm-spares",
            Duration::from_secs(15),
            Duration::from_secs(60),
            Some(wake),
            // Every claim wakes this loop, and a pass costs a full daemon
            // listing — floor the cadence so a claim storm coalesces into one
            // pass per floor instead of one listing per claim.
            Duration::from_secs(5),
            move || {
                let registry = registry.clone();
                let pool = pool.clone();
                async move {
                    let bound = registry.bound_ids();
                    pool.replenish(&registry.cfg, &bound).await
                }
            },
        ));
    }

    /// Spawn the disk-pressure watchdog if `PG_VM_POOL_PRESSURE_PATH` is
    /// configured: when the VM-disk filesystem crosses the high-water mark,
    /// emergency-archive the oldest-idle schemas — TTL ignored — until it
    /// drops below the low-water mark. The backstop against the disk-full
    /// outage where VM creates, Postgres, and the dumps themselves all fail.
    /// Spawn the urgent device-grow watcher — the only path that can grow a
    /// **warm** VM's data device.
    ///
    /// Why it has to exist. Growth has two halves and neither one covers a
    /// busy schema on its own. Inside the guest, `init.sh`'s watcher extends
    /// the *filesystem* online as it fills, and then retires
    /// (`filesystem spans $DATA_DEV; watcher done`) — from that moment the
    /// *device* is the binding constraint. Growing the device used to be
    /// offline-only (the daemon fscks and cold-boots the disk to do it), and
    /// its one trigger was the idle-stop path in [`Self::reap_idle`]. A schema under
    /// continuous write load never goes idle, so it never reaches that
    /// trigger: it fills its device, Postgres starts failing writes with
    /// `No space left on device`, and it stays that way until its traffic
    /// happens to pause for a whole idle timeout. The busiest schemas were
    /// precisely the ones that could not grow.
    ///
    /// So this loop grows warm devices itself. It tries the daemon's online
    /// resize first, which grows the device and filesystem under the running
    /// VM and drops nothing; only when that is unavailable (an older heyvmd,
    /// or a failure partway) does it stop the VM and resize offline, at most
    /// [`URGENT_GROW_MAX_PER_PASS`] per pass. The threshold
    /// ([`crate::config::DiskGrowConfig::urgent_pct`], default 95% vs. 85%)
    /// was set for that offline cost; once every host's heyvmd has the online
    /// route it can come down, since firing early then costs nothing.
    pub fn spawn_disk_grower(self: &Arc<Self>) {
        let Some(gc) = self.cfg.disk_grow else {
            // `spawn_reaper` already logs that growth is off entirely.
            return;
        };
        let Some(urgent) = gc.urgent_pct else {
            info!(
                "urgent device growth disabled (PG_VM_POOL_DISK_GROW_URGENT_PCT=0) — a schema \
                 whose write load never pauses for a full idle timeout cannot grow its device \
                 and will wedge on ENOSPC once its filesystem spans it"
            );
            return;
        };
        info!(
            "urgent device growth: a warm VM whose data fs is >= {urgent:.0}% full and spans \
             its device, or is filling fast enough to get there before its next check, is \
             grown (doubling, cap {}GiB) online under the running VM, falling back to stop, \
             resize and boot on the next connect when the daemon can't — checked every {:?}, \
             or every {:?} while filling or within {:.0} points of the threshold; at most {} \
             offline grows per pass",
            gc.max_gb,
            URGENT_GROW_CHECK_INTERVAL,
            URGENT_GROW_FAST_INTERVAL,
            URGENT_GROW_WATCH_MARGIN_PCT,
            URGENT_GROW_MAX_PER_PASS
        );
        let registry = self.clone();
        tokio::spawn(supervise(
            "disk-grow",
            URGENT_GROW_FAST_INTERVAL,
            URGENT_GROW_FAST_INTERVAL,
            move || {
                let registry = registry.clone();
                async move { registry.urgent_grow_pass().await }
            },
        ));
    }

    /// One pass of the urgent device-grow watcher: sample every warm schema's
    /// data filesystem and grow the devices that are at the wall. Returns how
    /// many were grown.
    async fn urgent_grow_pass(&self) -> usize {
        let Some(gc) = self.cfg.disk_grow else {
            return 0;
        };
        let Some(urgent) = gc.urgent_pct else {
            return 0;
        };

        // Warm, initialized entries that no offload has claimed and that are
        // not inside a grow-backoff window. Snapshotted under the lock and
        // then released: the sampling below talks to guests, which must never
        // happen with the map lock held.
        let now = Instant::now();
        let warm: Vec<(String, Arc<SchemaEntry>)> = {
            let map = self.entries.lock().await;
            map.iter()
                .filter_map(|(schema, cell)| cell.get().map(|e| (schema.clone(), e.clone())))
                .filter(|(schema, _)| !self.is_archiving(schema))
                .filter(|(schema, _)| self.grow_backoff.active(schema, now).is_none())
                .collect()
        };
        // Forget schemas that left the warm set, and sample only the ones due
        // this tick: new, filling or nearly-full schemas on the fast cadence,
        // everything else once a minute.
        let candidates: Vec<(String, Arc<SchemaEntry>)> = {
            let mut memory = self.urgent_samples.lock().unwrap();
            let names: HashSet<&str> = warm.iter().map(|(schema, _)| schema.as_str()).collect();
            memory.retain(|schema, _| names.contains(schema.as_str()));
            warm.iter()
                .filter(|(schema, _)| urgent_sample_due(memory.get(schema), now))
                .cloned()
                .collect()
        };
        if candidates.is_empty() {
            return 0;
        }

        // Sample concurrently. Each read goes over its own schema's
        // housekeeping pool, so schemas never contend with each other, and a
        // wedged VM costs one bounded `STATS_TIMEOUT` instead of stalling
        // every schema queued behind it. Each reading keeps its own
        // timestamp: a fill rate is only as good as the gap it divides by.
        let samples: Vec<(String, Option<DiskSample>, Instant)> =
            futures::stream::iter(candidates.into_iter().map(|(schema, entry)| async move {
                let sample = sample_disk(&entry).await;
                (schema, sample, Instant::now())
            }))
            .buffer_unordered(URGENT_GROW_SAMPLE_CONCURRENCY)
            .collect()
            .await;

        let mut grown = 0usize;
        let mut grown_offline = 0usize;
        for (schema, sample, at) in samples {
            let Some((fs, dev)) = sample else { continue };
            // The sample already answers the question `disk_gb` exists to
            // answer, so bank it here too rather than only at idle-stop: a
            // warm schema offloaded before it ever idles would otherwise be
            // restored into a stale — or entirely unknown — device size.
            self.store.set_disk_gb(&schema, device_gb(dev));
            let reading = {
                let mut memory = self.urgent_samples.lock().unwrap();
                let reading = next_grow_sample(memory.get(&schema), fs, at, urgent);
                memory.insert(schema.clone(), reading);
                reading
            };
            match urgent_verdict(fs, dev, &reading, urgent, gc.max_gb) {
                GrowVerdict::NotNeeded => {}
                GrowVerdict::AtCap { current_gb } => {
                    // Growth is the only lever this pooler has and it is
                    // spent. Say so at error level with the fix in the
                    // message — silence here reads as "the pooler is fine"
                    // while the database fails every write. Recorded as a
                    // failure purely to rate-limit the complaint.
                    error!(
                        "schema {schema}: data fs is >= {urgent:.0}% full and spans its \
                         {current_gb}GiB device, which is already at PG_VM_POOL_DISK_MAX_GB \
                         ({}GiB) — the pooler cannot grow it any further and Postgres will \
                         fail writes with `No space left on device`. Raise \
                         PG_VM_POOL_DISK_MAX_GB, or move this schema off the pool",
                        gc.max_gb
                    );
                    crate::events::journal_error(
                        "disk-grow",
                        format!(
                            "schema {schema}: device at the {}GiB cap and full — raise \
                             PG_VM_POOL_DISK_MAX_GB",
                            gc.max_gb
                        ),
                    );
                    self.grow_backoff.record_failure(&schema, Instant::now());
                }
                GrowVerdict::Grow(target) => {
                    // Bound the blast radius: an offline grow drops a schema's
                    // live sessions, so a pass that needs many of them trickles
                    // rather than restarting the whole warm set at once. Online
                    // grows drop nothing and are not counted.
                    let allow_offline = grown_offline < URGENT_GROW_MAX_PER_PASS;
                    // Say so when it is the projection that crossed, not the
                    // reading: the grow fires on a filesystem that still has
                    // room — just not for long.
                    if grow_verdict(fs, dev, urgent, gc.max_gb) == GrowVerdict::NotNeeded {
                        info!(
                            "schema {schema}: data fs is {:.0}% full and filling at {}/s — \
                             projected past {urgent:.0}% before its next check; growing it now",
                            used_pct(fs.1, fs.2).unwrap_or(0.0),
                            crate::orphans::human_iec(reading.rate.unwrap_or(0.0).max(0.0) as u64),
                        );
                    }
                    match self.grow_device_now(&schema, target, allow_offline).await {
                        Ok(kind @ (UrgentGrow::Online | UrgentGrow::Offline)) => {
                            grown += 1;
                            if kind == UrgentGrow::Offline {
                                grown_offline += 1;
                            }
                            self.grow_backoff.clear(&schema);
                            // A new device: the next bring-up starts a fresh
                            // baseline rather than dividing across the resize.
                            self.urgent_samples.lock().unwrap().remove(&schema);
                        }
                        // Lost a race to an offload, the schema went cold under
                        // us, or it needs an offline grow this pass has no
                        // budget left for. None is this schema's fault, so it
                        // keeps its clean backoff record.
                        Ok(UrgentGrow::Skipped) => {}
                        Err(e) => {
                            let (n, hold) =
                                self.grow_backoff.record_failure(&schema, Instant::now());
                            warn!(
                                "schema {schema}: urgent device grow to {target}GiB failed \
                                 ({n} consecutive); holding off for {hold:?}: {e:#}"
                            );
                            crate::events::journal_error(
                                "disk-grow",
                                format!(
                                    "schema {schema}: urgent grow to {target}GiB failed: {e:#}"
                                ),
                            );
                        }
                    }
                }
            }
        }
        grown
    }

    /// Grow one warm schema's data device now.
    ///
    /// Online first: the daemon grows the device and the guest filesystem
    /// under the running VM and verifies both, so nothing is claimed, stopped
    /// or dropped, and the entry keeps serving throughout. The daemon
    /// serializes it against any stop on the same VM, so an offload that
    /// races it either finds the device already grown or makes the online
    /// grow answer 409.
    ///
    /// When the online route can't do it — a daemon without it, a VM that is
    /// not running, a failure partway — and `allow_offline` is set, fall back
    /// to the offline grow: claim it, stop it, resize, and leave it for the
    /// next connect to boot. Without `allow_offline` the schema is skipped
    /// and retried next pass.
    ///
    /// Unlike every other exclusive operation in this file, the offline grow does
    /// **not** refuse when the entry has live sessions. A schema that never
    /// goes idle is exactly the one this path exists for, and by the time it
    /// qualifies its database is out of room or seconds from it — those
    /// sessions are failing, or about to. Breaking them costs a reconnect;
    /// leaving them costs the database.
    ///
    /// The VM is deliberately left stopped rather than restarted here. The
    /// clients are reconnecting anyway, and `checkout`'s cold path already
    /// knows how to reattach by id and boot it — routing through that one path
    /// keeps the bring-up gate, the pending ledger and the failure bookkeeping
    /// in charge of the boot instead of duplicating all three here.
    /// `Online`/`Offline` grew the device that way; `Skipped` means this
    /// schema was not this pass's to touch after all (an offload claimed it,
    /// it went cold between the sample and here, or it needs an offline grow
    /// and `allow_offline` is false) — not a failure, so the caller must not
    /// put it in a backoff window for it. `Err` is a real failure.
    async fn grow_device_now(
        &self,
        schema: &str,
        target: u64,
        allow_offline: bool,
    ) -> Result<UrgentGrow> {
        let warm_id = {
            let map = self.entries.lock().await;
            map.get(schema).and_then(|cell| cell.get()).map(|entry| entry.sandbox_id())
        };
        let Some(id) = warm_id else {
            debug!("schema {schema} is no longer warm; leaving its device to the next pass");
            return Ok(UrgentGrow::Skipped);
        };
        if self.is_archiving(schema) {
            debug!("schema {schema}: an offload claimed it first; skipping this grow");
            return Ok(UrgentGrow::Skipped);
        }
        let online = vm::resize_disk_online(&id, target).await.with_context(|| {
            format!("growing schema {schema}'s data device to {target}GiB online")
        })?;
        match online {
            vm::OnlineGrow::Grown => {
                // Recorded the moment it is real, as the offline path does.
                self.store.set_disk_gb(schema, target as u32);
                info!(
                    "schema {schema}: data device and filesystem grown to {target}GiB online \
                     ({id} kept running; no sessions dropped)"
                );
                crate::events::journal_info(
                    "disk-grow",
                    format!("schema {schema}: online device grow to {target}GiB ({id})"),
                );
                return Ok(UrgentGrow::Online);
            }
            vm::OnlineGrow::FallBack(why) if !allow_offline => {
                info!(
                    "schema {schema}: online grow to {target}GiB unavailable ({why}) and this \
                     pass's offline grows are spent; retrying next pass"
                );
                return Ok(UrgentGrow::Skipped);
            }
            vm::OnlineGrow::FallBack(why) => {
                warn!(
                    "schema {schema}: online grow to {target}GiB unavailable ({why}); falling \
                     back to the offline grow"
                );
            }
        }

        // The same claim an offload takes. `checkout` waits on this set, so a
        // client arriving mid-resize queues at the front door instead of
        // racing the stop/start — and no offload can pick this schema while
        // its VM is halfway through a resize.
        let Some(_guard) = ArchivingGuard::claim(&self.archiving, schema) else {
            debug!("schema {schema}: an offload claimed it first; skipping this grow");
            return Ok(UrgentGrow::Skipped);
        };

        // Take the entry out of the map, but only once it is actually
        // initialized: removing a cell whose bring-up is still in flight would
        // orphan that bring-up — it completes, hands back an entry, and
        // nothing is left holding it.
        let entry = {
            let mut map = self.entries.lock().await;
            let initialized = match map.get(schema) {
                Some(cell) => cell.get().cloned(),
                None => None,
            };
            match initialized {
                Some(entry) => {
                    map.remove(schema);
                    entry
                }
                None => {
                    debug!(
                        "schema {schema} is no longer warm (gone cold, or a bring-up is in \
                         flight); leaving its device to the next pass"
                    );
                    return Ok(UrgentGrow::Skipped);
                }
            }
        };

        let id = entry.sandbox_id();
        let sessions = entry.active_count();
        warn!(
            "schema {schema}: data filesystem is full, or about to be, and spans its device — \
             growing it to {target}GiB now rather than waiting for an idle stop a schema under \
             load never reaches. Stopping VM {id} and dropping {sessions} live session(s); the \
             next connect boots it with room"
        );

        checkpoint_and_stop(&entry, schema).await;
        // Drop the last handle before the resize: it owns the tunnel and the
        // housekeeping pool, both now pointed at a stopped VM.
        drop(entry);

        // Same interlock as the idle-stop grow: the daemon's resize fscks and
        // cold-boots the stopped disk, which must never interleave with a
        // reclaim pass fsck'ing the same file (see `reclaim::BOOT_GATE`).
        let _permit = crate::reclaim::boot_permit(&id).await;
        vm::resize_disk(&id, target)
            .await
            .with_context(|| format!("growing schema {schema}'s data device to {target}GiB"))?;
        // Recorded the moment it is real: a schema offloaded before its next
        // idle stop would otherwise be restored into the pre-grow device.
        self.store.set_disk_gb(schema, target as u32);
        info!(
            "schema {schema}: data device grown to {target}GiB; next connect boots {id} \
             ({sessions} session(s) were dropped to do it)"
        );
        crate::events::journal_info(
            "disk-grow",
            format!(
                "schema {schema}: urgent device grow to {target}GiB ({id}); \
                 {sessions} session(s) dropped"
            ),
        );
        Ok(UrgentGrow::Offline)
    }

    pub fn spawn_pressure_reaper(self: &Arc<Self>) {
        let Some(pressure) = self.cfg.archive.as_ref().and_then(|a| a.pressure.clone()) else {
            info!("disk-pressure eviction disabled (PG_VM_POOL_PRESSURE_PATH unset)");
            return;
        };
        info!(
            "disk-pressure eviction: watching {} — archiving oldest-idle schemas at \
             >= {:.0}% full until < {:.0}% (checked every {:?}; TTL is overridden \
             under pressure)",
            pressure.path.display(),
            pressure.high_pct,
            pressure.low_pct,
            pressure.check_interval
        );
        let registry = self.clone();
        let tick = pressure.check_interval;
        tokio::spawn(supervise("disk-pressure", tick, tick, move || {
            let registry = registry.clone();
            let pressure = pressure.clone();
            async move { registry.pressure_pass(&pressure).await }
        }));
    }

    /// One pressure check: no-op below the high-water mark; above it, run
    /// emergency offloads through the parallel drain loop (up to
    /// `offload_workers` concurrent jobs, no-boot kinds first, usage re-read
    /// between dispatches) until below the low-water mark or out of
    /// candidates. Claims the same single-flight flag as the periodic sweep,
    /// so the two never interleave over the same schemas. Returns how many
    /// schemas were offloaded.
    async fn pressure_pass(self: &Arc<Self>, p: &PressureConfig) -> usize {
        let Some(pct) = disk_used_pct(&p.path).await else {
            warn!(
                "disk-pressure: could not read filesystem usage of {}; skipping this check",
                p.path.display()
            );
            return 0;
        };
        if pct < p.high_pct {
            debug!("disk-pressure: {} at {pct:.1}% (< {:.1}%), ok", p.path.display(), p.high_pct);
            return 0;
        }
        if self.sweeping.swap(true, Ordering::SeqCst) {
            info!(
                "disk-pressure: {} at {pct:.1}% but an eviction sweep is already running; \
                 will re-check in {:?}",
                p.path.display(),
                p.check_interval
            );
            return 0;
        }
        let _sweeping = SweepGuard(&self.sweeping);
        warn!(
            "disk-pressure: {} is {pct:.1}% full (>= {:.1}%) — emergency-archiving \
             oldest-idle schemas until < {:.1}%",
            p.path.display(),
            p.high_pct,
            p.low_pct
        );
        crate::events::journal_error(
            "sweep.pressure",
            format!(
                "{} at {pct:.1}% (>= {:.1}%) — emergency archiving engaged",
                p.path.display(),
                p.high_pct
            ),
        );

        // The emergency ladder, re-picked from scratch before every job: take
        // whatever frees the most bytes for the least work right now — which,
        // on a nearly-full host, means never booting a VM while any no-boot
        // option remains (see `OffloadKind::rank`). Candidate selection is
        // shared with the routine pacer, so the guards that keep a busy or
        // recently-failed schema out of reach are the same ones.
        //
        // Why re-pick rather than walk a list: each job changes the tier of
        // the schema it touches, and a compaction that frees 180MB is worth
        // more than the promotion of an image that frees 7MB — so the right
        // next job is a function of what just happened, not of an ordering
        // computed before any of it did.
        let policy = self.pressure_policy();
        let archived = self
            .offload_drain_loop(policy, Some(p), "disk-pressure", "sweep.pressure")
            .await;
        if let Some(cur) = disk_used_pct(&p.path).await
            && cur >= p.low_pct
        {
            error!(
                "disk-pressure: exhausted every candidate schema with {} still at {cur:.1}% — \
                 the remaining usage is running/keepalive VMs or non-VM data; eviction alone \
                 cannot relieve this",
                p.path.display()
            );
            crate::events::journal_error(
                "sweep.pressure",
                format!(
                    "exhausted all candidates, disk still at {cur:.1}% — eviction alone \
                     cannot relieve this ({archived} archived)"
                ),
            );
        }
        archived
    }

    /// The parallel drain core shared by the emergency pressure pass and the
    /// dashboard's TTL sweep: run offload jobs through up to `offload_workers`
    /// concurrent slots — at most one of which may boot a VM (boot-kinds
    /// compete with clients for the FIFO bring-up gate) — until the stand-down
    /// condition is met, the backlog runs dry, or the failure circuit breaker
    /// trips.
    ///
    /// `stand_down = Some(p)` re-reads disk usage between dispatches and stops
    /// once below `p.low_pct` (the emergency pass); `None` runs the eligible
    /// backlog dry (the manual TTL sweep). `log_tag` / `journal_kind` name the
    /// caller in the pooler log and the events journal.
    ///
    /// The caller holds the `sweeping` single-flight guard for the duration
    /// (which also pauses the routine pacer's dispatches — see
    /// [`Self::dispatch_backpressure`]). Unlike the routine pacer there is no
    /// host-load gate: both callers are operator or emergency paths where
    /// freeing disk outranks background politeness. Job children still run
    /// nice-19 (see `imgarchive`), and per-schema claim exclusion keeps
    /// workers, the pacer, and dashboard buttons off each other's schemas.
    ///
    /// On stand-down or abort, in-flight jobs are left to finish (each only
    /// frees more disk) and still count toward the returned total.
    async fn offload_drain_loop(
        self: &Arc<Self>,
        mut policy: OffloadPolicy,
        stand_down: Option<&PressureConfig>,
        log_tag: &str,
        journal_kind: &str,
    ) -> usize {
        /// How often to re-read disk usage while every worker slot is busy.
        const FULL_RECHECK: Duration = Duration::from_secs(2);
        enum DrainEnd {
            StoodDown(f64),
            Dry,
            Aborted,
        }
        let workers = self.cfg.offload_workers.max(1);
        let mut jobs: tokio::task::JoinSet<JobOutcome> = tokio::task::JoinSet::new();
        let mut in_flight: HashMap<tokio::task::Id, (String, OffloadKind)> = HashMap::new();
        let mut archived = 0usize;
        let mut consecutive_failures = 0usize;
        let end = loop {
            // Stand down the moment usage is below the low-water mark.
            if let Some(p) = stand_down
                && let Some(cur) = disk_used_pct(&p.path).await
                && cur < p.low_pct
            {
                break DrainEnd::StoodDown(cur);
            }
            if consecutive_failures >= SWEEP_MAX_CONSECUTIVE_FAILURES {
                break DrainEnd::Aborted;
            }
            // Fill every free worker slot.
            while jobs.len() < workers {
                // At most one boot-kind job in flight (see the pacer).
                policy.no_boot = in_flight.values().any(|(_, kind)| kind.boots());
                let excluded: HashSet<String> =
                    in_flight.values().map(|(schema, _)| schema.clone()).collect();
                let Some(job) = self.next_offload_job(policy, &excluded).await else {
                    break;
                };
                let (schema, kind) = (job.schema.clone(), job.kind);
                info!(
                    "{log_tag}: dispatching {} {schema} ({}/{workers} in flight)",
                    kind.as_str(),
                    jobs.len() + 1
                );
                let reg = Arc::clone(self);
                let task_id = jobs
                    .spawn(async move {
                        match reg.run_offload_job(job).await {
                            Ok(()) => JobOutcome::Done,
                            // A benign claim race (a pacer worker or dashboard
                            // job holds the schema) says nothing about
                            // environment health.
                            Err(e) if e.downcast_ref::<AlreadyOffloading>().is_some() => {
                                JobOutcome::Skipped
                            }
                            // Already logged and journaled by the operation
                            // itself, and the schema is now in backoff — the
                            // next pick skips it rather than looping on it.
                            Err(_) => JobOutcome::Failed,
                        }
                    })
                    .id();
                in_flight.insert(task_id, (schema, kind));
            }
            if jobs.is_empty() {
                // Nothing runnable and nothing in flight: backlog drained.
                break DrainEnd::Dry;
            }
            // Wait for a completion; under a stand-down condition, wake at
            // least every FULL_RECHECK so a full set of slow jobs can't delay
            // noticing that usage already dropped below the low-water mark.
            let next = if stand_down.is_some() {
                tokio::select! {
                    r = jobs.join_next_with_id() => r,
                    _ = tokio::time::sleep(FULL_RECHECK) => continue,
                }
            } else {
                jobs.join_next_with_id().await
            };
            match next {
                Some(Ok((task_id, outcome))) => {
                    in_flight.remove(&task_id);
                    match outcome {
                        JobOutcome::Done => {
                            archived += 1;
                            consecutive_failures = 0;
                        }
                        JobOutcome::Skipped => {}
                        JobOutcome::Failed => consecutive_failures += 1,
                    }
                }
                Some(Err(e)) => {
                    let label = in_flight
                        .remove(&e.id())
                        .map(|(schema, kind)| format!("{} {schema}", kind.as_str()))
                        .unwrap_or_else(|| "?".into());
                    if e.is_panic() {
                        error!("{log_tag}: {label} PANICKED: {}", panic_message(e.into_panic()));
                    } else {
                        error!("{log_tag}: {label} failed to run: {e}");
                    }
                    consecutive_failures += 1;
                }
                None => {}
            }
        };
        // Let in-flight jobs finish — each only frees more disk — and count
        // them before reporting.
        if !jobs.is_empty() {
            info!(
                "{log_tag}: waiting for {} in-flight offload(s) to finish",
                jobs.len()
            );
        }
        while let Some(res) = jobs.join_next_with_id().await {
            match res {
                Ok((task_id, outcome)) => {
                    in_flight.remove(&task_id);
                    if matches!(outcome, JobOutcome::Done) {
                        archived += 1;
                    }
                }
                Err(e) => {
                    let label = in_flight
                        .remove(&e.id())
                        .map(|(schema, kind)| format!("{} {schema}", kind.as_str()))
                        .unwrap_or_else(|| "?".into());
                    error!("{log_tag}: {label} did not finish cleanly: {e}");
                }
            }
        }
        match end {
            DrainEnd::StoodDown(cur) => {
                // stand_down is always Some here (the only branch that breaks
                // with StoodDown read it), but stay total.
                let low = stand_down.map(|p| p.low_pct).unwrap_or_default();
                info!(
                    "{log_tag}: down to {cur:.1}% (< {low:.1}%) after {archived} offload(s); \
                     standing down"
                );
                crate::events::journal_info(
                    journal_kind,
                    format!("stood down at {cur:.1}% after {archived} emergency offload(s)"),
                );
            }
            DrainEnd::Aborted => {
                error!(
                    "{log_tag}: aborting after {consecutive_failures} consecutive failures — \
                     environment unhealthy"
                );
                crate::events::journal_error(
                    journal_kind,
                    format!(
                        "ABORTED after {consecutive_failures} consecutive failures \
                         ({archived} offloaded first)"
                    ),
                );
            }
            // The caller reports "dry" its own way (the pressure pass checks
            // whether the disk is still over the mark; the TTL sweep just
            // journals the total).
            DrainEnd::Dry => {}
        }
        archived
    }

    /// Offload every schema whose disk has been idle longer than `ttl_secs`,
    /// now, in the background — the dashboard's manual TTL sweep. Runs the
    /// same parallel drain loop as the emergency pressure pass (up to
    /// `offload_workers` concurrent jobs, pressure-mode ranking: no-boot
    /// kinds first, at most one boot-kind in flight) but ignores disk usage
    /// entirely: it runs the TTL backlog dry. Freezing is dropped for the
    /// same reason the pressure pass drops it — it costs a boot and leaves
    /// the bytes on the host.
    ///
    /// Returns as soon as the sweep is launched; progress lands in the pooler
    /// log and the events journal (`sweep.ttl`). Errors if no offload tier
    /// is configured or a sweep is already running.
    pub fn spawn_ttl_sweep_now(self: &Arc<Self>, ttl_secs: u64) -> Result<()> {
        anyhow::ensure!(
            self.offload_enabled(),
            "no offload tier is configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_* \
             and/or PG_VM_POOL_COMPACT_AFTER_SECS)"
        );
        if self.sweeping.load(Ordering::SeqCst) {
            bail!("an eviction sweep is already running");
        }
        let registry = self.clone();
        tokio::spawn(async move {
            if registry.sweeping.swap(true, Ordering::SeqCst) {
                info!("ttl-sweep: another eviction sweep started first; skipping");
                return;
            }
            let _sweeping = SweepGuard(&registry.sweeping);
            info!(
                "ttl-sweep: offloading every schema idle > {ttl_secs}s (operator request, \
                 up to {} concurrent job(s))",
                registry.cfg.offload_workers.max(1)
            );
            crate::events::journal_info(
                "sweep.ttl",
                format!("manual TTL sweep engaged: offloading every schema idle > {ttl_secs}s"),
            );
            let policy = OffloadPolicy {
                compact_after: registry.cfg.compact.as_ref().map(|_| ttl_secs),
                // Costs a boot and keeps the bytes local — useless for draining.
                freeze_after: None,
                archive_after: registry.cfg.archive.as_ref().map(|_| ttl_secs),
                image_archive: registry.image_archive_enabled(),
                no_boot: false,
                mode: OffloadMode::Pressure,
            };
            let n = registry
                .offload_drain_loop(policy, None, "ttl-sweep", "sweep.ttl")
                .await;
            info!("ttl-sweep: finished — {n} schema(s) offloaded");
            crate::events::journal_info(
                "sweep.ttl",
                format!("manual TTL sweep finished: {n} schema(s) offloaded"),
            );
        });
        Ok(())
    }

    /// Archive **every** eligible schema now, in the background — the
    /// dashboard's "sweep now" control, and the one place batch behaviour
    /// survives. The offload pacer moves one schema at a time and defers to
    /// client work; this is the operator override for "I want the disk back
    /// now", so it runs the whole candidate list back to back and the pacer
    /// stands down while it does (see [`Self::dispatch_backpressure`]).
    ///
    /// Returns as soon as the sweep is launched (it can take a long time for a
    /// big backlog); the outcome shows up in the pooler log and the VMs'
    /// "Archived (S3)" status. Errors if the eviction tier isn't configured,
    /// or if a sweep is already running (the sweep itself is single-flighted,
    /// so this only reports it).
    pub fn spawn_sweep_now(self: &Arc<Self>) -> Result<()> {
        let Some(archive) = self.cfg.archive.clone() else {
            bail!(
                "S3 eviction tier is not configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*)"
            );
        };
        if self.sweeping.load(Ordering::SeqCst) {
            bail!("an eviction sweep is already running");
        }
        let registry = self.clone();
        let after = self.runtime.archive_after().unwrap_or(archive.archive_after);
        tokio::spawn(async move {
            let n = registry.sweep_archive(after).await;
            info!("manual eviction sweep finished: archived {n} schema(s)");
        });
        Ok(())
    }

    /// One eviction pass: archive every non-keepalive schema untouched for at
    /// least `threshold`, skipping any that is currently warm-and-busy.
    ///
    /// The operator-triggered path only ([`Self::spawn_sweep_now`]) — routine
    /// eviction is the offload pacer's, one schema at a time. Returns how many
    /// schemas it archived.
    ///
    /// Single-flighted: if a sweep is already in progress this returns
    /// immediately having done nothing, so triggers can't stack overlapping
    /// passes racing over the same candidates.
    async fn sweep_archive(&self, threshold: Duration) -> usize {
        if self.sweeping.swap(true, Ordering::SeqCst) {
            info!("S3 eviction: a sweep is already running; skipping this one");
            return 0;
        }
        let _sweeping = SweepGuard(&self.sweeping);

        let now = now_unix();
        let threshold_secs = threshold.as_secs();

        // Live cross-check: a schema warm with active connections, or one whose
        // in-memory idle clock is younger than the threshold, is not really cold
        // even if its durable `last_active` drifted stale (one long-lived
        // connection with no new checkouts). Refresh those and skip them.
        let live: HashMap<String, (usize, u64)> = self
            .snapshot()
            .await
            .into_iter()
            .map(|e| (e.schema, (e.active, e.idle_secs)))
            .collect();

        let mut candidates: Vec<String> = Vec::new();
        // Frozen/compacted schemas past the archive threshold get promoted
        // local-file → S3 without any VM (the file already exists on the host).
        let mut frozen_candidates: Vec<String> = Vec::new();
        let mut compact_candidates: Vec<String> = Vec::new();
        let mut total = 0usize;
        let mut backing_off = 0usize;
        let mut empty = 0usize;
        let (mut refreshed, mut keepalive, mut already, mut not_idle) = (0usize, 0usize, 0usize, 0usize);
        for (schema, rec) in self.store_records() {
            total += 1;
            let ka = self.pinned(&schema);
            if rec.tier == Tier::Frozen || rec.tier == Tier::Compacted {
                if !ka && now.saturating_sub(rec.last_active) >= threshold_secs {
                    if rec.tier == Tier::Frozen {
                        frozen_candidates.push(schema);
                    } else if self.compacted_empty(&schema) {
                        empty += 1;
                    } else {
                        compact_candidates.push(schema);
                    }
                } else {
                    not_idle += 1;
                }
                continue;
            }
            match classify_candidate(&rec, ka, now, threshold_secs, live.get(&schema).copied()) {
                SweepAction::Skip => {
                    // classify_candidate skips for exactly these reasons; tally
                    // them so a sweep that archives nothing still says why.
                    if rec.offloaded() {
                        already += 1;
                    } else if ka {
                        keepalive += 1;
                    } else {
                        not_idle += 1;
                    }
                }
                // Warm-and-busy but durably stale: keep its clock honest so it
                // isn't re-flagged every sweep.
                SweepAction::Refresh => {
                    refreshed += 1;
                    self.store.touch(&schema);
                }
                // A candidate still in failure backoff is skipped: each retry
                // of a sick schema costs a full wedged bring-up, and three in
                // a row abort the pass for the healthy candidates behind them.
                SweepAction::Archive => {
                    if self.offload_backoff.active(&schema, Instant::now()).is_some() {
                        backing_off += 1;
                    } else {
                        candidates.push(schema);
                    }
                }
            }
        }

        // Always log the evaluation, so a sweep that archives nothing is
        // explained ("all skipped as not-idle") rather than silent — the manual
        // "sweep now" button and the periodic pass both surface here.
        info!(
            "S3 eviction sweep: evaluated {total} schema(s) — {} live candidate(s) + \
             {} frozen + {} compacted promotion(s), {refreshed} refreshed (warm), \
             {backing_off} in failure backoff, skipped {} ({keepalive} keepalive, \
             {already} already archived, {empty} compacted with no user data, \
             {not_idle} idle < {threshold_secs}s)",
            candidates.len(),
            frozen_candidates.len(),
            compact_candidates.len(),
            keepalive + already + empty + not_idle,
        );

        // Promote local files first: cheap (a file upload, no VM), and every
        // success frees local disk.
        let n_frozen = frozen_candidates.len() + compact_candidates.len();
        let mut archived_frozen = 0usize;
        for schema in frozen_candidates {
            match self.archive_frozen_schema(&schema).await {
                Ok(()) => archived_frozen += 1,
                Err(e) => {
                    warn!(
                        "promoting frozen schema {schema} to S3 failed (will retry next sweep): {e:#}"
                    );
                    crate::events::journal_error(
                        "archive",
                        format!("promoting frozen schema {schema} to S3 failed: {e:#}"),
                    );
                }
            }
        }
        for schema in compact_candidates {
            match self.archive_compacted_schema(&schema).await {
                Ok(()) => archived_frozen += 1,
                Err(e) => {
                    warn!(
                        "promoting compacted schema {schema} to S3 failed (will retry next \
                         sweep): {e:#}"
                    );
                    crate::events::journal_error(
                        "archive",
                        format!("promoting compacted schema {schema} to S3 failed: {e:#}"),
                    );
                }
            }
        }

        if candidates.is_empty() {
            // Journal only sweeps that had work; a quiet fleet's no-op passes
            // would drown the events page.
            if n_frozen > 0 {
                crate::events::journal_info(
                    "sweep.archive",
                    format!("promoted {archived_frozen}/{n_frozen} local file(s) to S3"),
                );
            }
            return archived_frozen;
        }
        let n_live = candidates.len();
        let mut archived = archived_frozen;
        let mut consecutive_failures = 0usize;
        let mut aborted = false;
        for schema in candidates {
            match self.archive_schema(&schema).await {
                Ok(()) => {
                    archived += 1;
                    consecutive_failures = 0;
                }
                Err(e) => {
                    warn!("archiving schema {schema} to S3 failed (will retry next sweep): {e:#}");
                    consecutive_failures += 1;
                    if consecutive_failures >= SWEEP_MAX_CONSECUTIVE_FAILURES {
                        error!(
                            "S3 eviction sweep: aborting after {consecutive_failures} consecutive \
                             archive failures — the environment looks unhealthy (daemon, host disk, \
                             or S3), and each failure burns minutes of wedged bring-up; remaining \
                             candidates will be retried next sweep"
                        );
                        aborted = true;
                        break;
                    }
                }
            }
        }
        crate::events::journal_info(
            "sweep.archive",
            format!(
                "archived {archived}/{} ({n_live} live + {n_frozen} frozen promotion(s)){}",
                n_live + n_frozen,
                if aborted {
                    " — ABORTED after 3 consecutive failures"
                } else {
                    ""
                }
            ),
        );
        archived
    }

    /// Offload one schema's database to S3 and kill its VM to reclaim the disk.
    /// Also the target of the dashboard's manual "reap" button. Refuses if the
    /// VM has live client sessions. Serializes against [`Self::checkout`] via the
    /// `archiving` set so a client can't bring the VM back up mid-operation.
    ///
    /// Every outcome is journaled for the dashboard's events page — this
    /// wrapper is the single choke point all archive callers (periodic sweep,
    /// pressure reaper, manual reap) go through.
    pub async fn archive_schema(&self, schema: &str) -> Result<()> {
        let res = self.archive_schema_inner(schema).await;
        match &res {
            Ok(()) => {
                self.offload_backoff.clear(schema);
                crate::events::journal_info("archive", format!("schema {schema} → archived (S3)"));
                crate::events::record(crate::events::Event::OffloadDone);
            }
            // Not a failure: the schema has nothing worth uploading, and the
            // pooler can rebuild an empty database for free. Backed off for
            // the full cap straight away: the answer only changes when a
            // client writes to it, and the restore that allows that clears
            // the backoff.
            Err(e)
                if e.downcast_ref::<crate::imgarchive::EmptyCluster>()
                    .is_some() =>
            {
                let delay = self.offload_backoff.record_settled(schema, Instant::now());
                crate::events::journal_info(
                    "archive",
                    format!(
                        "schema {schema} kept local — its database holds no user data \
                         (sweeps skip it for {})",
                        fmt_backoff(delay)
                    ),
                );
            }
            // Losing the claim race to another worker / the dashboard is
            // benign — no backoff, no error journal.
            Err(e) if e.downcast_ref::<AlreadyOffloading>().is_some() => {
                crate::events::journal_info(
                    "archive",
                    format!("schema {schema} skipped — another offload is in flight"),
                );
            }
            Err(e) => {
                let (n, delay) = self.offload_backoff.record_failure(schema, Instant::now());
                crate::events::journal_error(
                    "archive",
                    format!(
                        "schema {schema}: {e:#} (failure {n}; sweeps skip this schema for {})",
                        fmt_backoff(delay)
                    ),
                );
            }
        }
        res
    }

    async fn archive_schema_inner(&self, schema: &str) -> Result<()> {
        let Some(archive) = self.cfg.archive.clone() else {
            bail!("S3 eviction tier is not configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*)");
        };
        match self.store.record(schema).map(|r| r.tier) {
            Some(Tier::Archived) => bail!("schema {schema} is already archived to S3"),
            // Frozen: no VM to dump — promote the existing local dump file.
            Some(Tier::Frozen) => return self.archive_frozen_schema(schema).await,
            // Compacted: likewise — promote the existing local image file.
            Some(Tier::Compacted) => return self.archive_compacted_schema(schema).await,
            _ => {}
        }

        // Claim the archiving slot; a Drop guard clears it on every exit path so
        // checkouts stuck waiting are released even on error/panic.
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being archived")));
            }
        };

        // Evict the warm entry under the map lock, refusing if it has live
        // sessions. Because the `archiving` set was inserted *before* this lock,
        // a checkout that slips in either grabbed the entry first (active > 0 →
        // we refuse) or will see the set and wait.
        {
            let mut map = self.entries.lock().await;
            if let Some(entry) = map.get(schema).and_then(|c| c.get()) {
                let active = entry.active_count();
                if active > 0 {
                    bail!("schema {schema} has {active} live session(s); refusing to archive");
                }
            }
            map.remove(schema);
        }

        // Bring the VM up ready for pg_dump (starts it if idle-stopped, reattaches
        // by id if it's still the same VM), dump to S3, then mark archived and
        // kill. Mark before kill: if we crash between them the data is safely in
        // S3 and the store says "archived", so the next connect restores — the
        // reverse order could lose the mapping to a killed VM.
        let known_id = self.store.record(schema).map(|r| r.sandbox_id);
        // No spare pool here: this bring-up exists to dump an *existing* VM's
        // data — a fresh spare would have nothing to dump.
        let owner = self.owner_of(schema);
        let repl_login = self.repl_login_for(schema);
        let entry = match vm::ensure_vm(
            &self.cfg,
            schema,
            known_id.as_deref(),
            None,
            None,
            None,
            &self.bring_up_for(schema, owner.as_ref(), repl_login.as_ref()),
        )
        .await {
            Ok(entry) => entry,
            Err(e) => {
                // A bring-up that started the VM but never reached a ready
                // Postgres (ready-timeout on a sick disk) has no handle to
                // clean up through — the same leak class as a failed dump.
                vm::stop_after_failed_bringup(schema, known_id.as_deref()).await;
                // This is exactly the schema the image path exists for: its
                // Postgres won't boot, so no dump will ever succeed — but the
                // disk itself can still be archived. Only the *known* VM's
                // disk qualifies: a fresh VM the failed bring-up may have
                // created holds an empty cluster, and archiving that would
                // durably shadow the real data.
                let e = e.context(format!("bringing up VM for schema {schema} to archive it"));
                return self
                    .image_archive_fallback(schema, known_id.as_deref(), &archive, e)
                    .await;
            }
        };

        // Note the data device's size while the VM that has it is still up.
        // The dump routes delete that VM, and a dump carries no trace of the
        // device it came off — so this row is the only thing that later stops
        // the restore from rebuilding the schema into a default-size device
        // and filling it mid-`pg_restore` (see `Store::set_disk_gb`). Recorded
        // before `set_tier`, whose durable write is what carries it to disk
        // ahead of the kill.
        if let Some((_, dev)) = sample_disk(&entry).await {
            self.store.set_disk_gb(schema, device_gb(dev));
        }

        // On dump failure, stop the VM this attempt booted before propagating.
        // Without this every failed archive leaks a running VM — nothing else
        // owns it (the warm entry was evicted above, so the idle reaper never
        // sees it), it burns RAM, and it pins its disk open against reclaim.
        // A whole sweep of failures leaks a fleet of them at once. Stop, not
        // kill: the data on its disk is still the only copy.
        // The same refusal the image paths make offline, asked of the running
        // Postgres this path already has: a dump of a database with no user
        // relations restores as an empty workbook, and uploading it replaces
        // whatever the schema's key holds. Unreachable (None) is not empty.
        if vm::has_user_relations(&self.cfg, &entry.target, schema).await == Some(false) {
            checkpoint_and_stop(&entry, schema).await;
            return Err(crate::imgarchive::empty_cluster(format!(
                "schema {schema}: refusing to dump it to S3 — its database has no user \
                 relations, and the upload would replace whatever s3://{}/{} holds",
                archive.s3.bucket,
                archive.s3.object_key(schema),
            )));
        }

        let dumps = self
            .dumps
            .as_deref()
            .map(|srv| (srv, self.cfg.dump_net.listen.port()));
        if let Err(e) = vm::dump_to_s3(&self.cfg, &entry.sandbox, schema, &archive.s3, dumps).await {
            warn!("schema {schema}: dump failed; stopping the VM booted for this attempt");
            checkpoint_and_stop(&entry, schema).await;
            // The VM this attempt used is the one whose disk holds the data —
            // the same disk the dump just failed to read a database out of.
            // With the VM checkpointed and stopped, that disk is exactly what
            // the image path archives.
            let sb_id = entry.sandbox.sandbox_id().to_string();
            drop(entry);
            let e = e.context(format!("dumping schema {schema} to S3"));
            return self
                .image_archive_fallback(schema, Some(&sb_id), &archive, e)
                .await;
        }

        self.store.set_tier(schema, Tier::Archived).await;
        let accomplished = format!("dumped to s3://{}/{}", archive.s3.bucket, archive.s3.object_key(schema));

        // Kill and confirm the disk directory is actually gone — a kill the
        // daemon acks but doesn't act on strands the disk (see kill_and_reclaim).
        // The dump is safe in S3 and the store is marked archived, so a kill
        // *failure* only orphans a (stopped) VM + disk — undesirable, not data loss.
        if let Err(e) = vm::kill_and_reclaim(&self.cfg, &entry.sandbox, schema, &accomplished).await {
            warn!("schema {schema}: archived to S3 but killing the VM failed (orphaned): {e:#}");
        }
        // Dropping `entry` tears down its pool/tunnel.
        Ok(())
    }

    /// Promote a frozen schema's local dump file to S3 — no VM involved: the
    /// dump already exists on the host, so this is a pooler-side upload,
    /// verified with a HEAD, then tier flip and local-file cleanup.
    async fn archive_frozen_schema(&self, schema: &str) -> Result<()> {
        let Some(archive) = self.cfg.archive.clone() else {
            bail!("S3 eviction tier is not configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*)");
        };
        let Some(dumps) = self.dumps.clone() else {
            bail!("schema {schema} is frozen but the frozen tier is not configured");
        };
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being archived")));
            }
        };
        anyhow::ensure!(
            self.store.record(schema).map(|r| r.tier) == Some(Tier::Frozen),
            "schema {schema} is no longer frozen; not promoting"
        );

        let path = dumps.dump_path(schema);
        // Set by `freeze_schema`, which had a live Postgres to ask.
        if tokio::fs::metadata(crate::imgarchive::empty_marker(&path))
            .await
            .is_ok()
        {
            return Err(crate::imgarchive::empty_cluster(format!(
                "schema {schema}: refusing to promote {} to S3 — it dumps a database with no \
                 user relations, and the upload would replace whatever s3://{}/{} holds",
                path.display(),
                archive.s3.bucket,
                archive.s3.object_key(schema),
            )));
        }
        let meta = std::fs::metadata(&path)
            .with_context(|| format!("reading local dump {}", path.display()))?;
        let len = meta.len();
        anyhow::ensure!(
            len >= 512,
            "local dump {} is only {len} bytes — refusing to promote a failed dump",
            path.display()
        );
        let key = archive.s3.object_key(schema);
        let http = reqwest::Client::builder()
            .build()
            .context("building HTTP client for S3 upload")?;
        // HEAD first so a wrong-region bucket is discovered (and latched)
        // before anything is presigned.
        let _ = archive.s3.head_object(&http, &key, Duration::from_secs(10)).await;
        // Single PUT for small dumps, 64MB multipart above 100MB — memory is
        // bounded by the part size, so there is no pooler-side cap on how
        // large a frozen dump can be promoted (there used to be a 512MB one,
        // which silently pinned oversized dumps to the local disk forever).
        crate::imgarchive::upload_path(&archive.s3, &http, &key, &path, len)
            .await
            .with_context(|| format!("uploading {} to s3://{}/{key}", path.display(), archive.s3.bucket))?;
        // Verify: the object must exist with exactly the file's size.
        match archive.s3.head_object(&http, &key, Duration::from_secs(10)).await {
            Ok(Some(id)) if id.content_length == len => {}
            Ok(Some(id)) => bail!(
                "uploaded s3://{}/{key} reports {} bytes but the local dump is {len} — \
                 refusing to trust it",
                archive.s3.bucket,
                id.content_length
            ),
            Ok(None) => bail!("uploaded s3://{}/{key} but a HEAD finds nothing", archive.s3.bucket),
            Err(e) => return Err(e.context("verifying the uploaded archive")),
        }

        self.store.set_tier(schema, Tier::Archived).await;
        if let Err(e) = tokio::fs::remove_file(&path).await {
            warn!("schema {schema}: promoted to S3 but deleting {} failed: {e}", path.display());
        }
        info!(
            "schema {schema}: frozen dump promoted to s3://{}/{key} ({len} bytes), local file removed",
            archive.s3.bucket
        );
        Ok(())
    }

    /// Promote a compacted schema's local image file to S3 — no VM, no
    /// recompression: the file already IS the archive format the image tier
    /// stores (`{schema}.img.zst`), so this is an upload + verify + tier
    /// flip + local-file cleanup. The compacted twin of the frozen-dump
    /// promotion ([`Self::archive_frozen_schema`]).
    async fn archive_compacted_schema(&self, schema: &str) -> Result<()> {
        let Some(archive) = self.cfg.archive.clone() else {
            bail!("S3 eviction tier is not configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*)");
        };
        let Some(compact) = self.cfg.compact.clone() else {
            bail!("schema {schema} is compacted but the compacted tier is not configured");
        };
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being archived")));
            }
        };
        let path = compact.compact_path(schema);
        let len = crate::imgarchive::promote_compact(&archive.s3, schema, &path)
            .await
            .with_context(|| format!("promoting compacted schema {schema} to S3"))?;
        self.store.set_tier(schema, Tier::Archived).await;
        if let Err(e) = tokio::fs::remove_file(&path).await {
            warn!("schema {schema}: promoted to S3 but deleting {} failed: {e}", path.display());
        }
        info!(
            "schema {schema}: compacted image promoted to s3://{}/{} ({len} bytes), local \
             file removed",
            archive.s3.bucket,
            archive.s3.image_object_key(schema),
        );
        Ok(())
    }

    /// Try the image-level archive after a failed dump-based attempt.
    /// `Ok(())` means the schema is durably archived (as an image); otherwise
    /// the original dump error comes back — annotated with the image failure
    /// when an attempt was actually made. A missing sandbox id or a disabled
    /// image tier just propagates the original error untouched.
    async fn image_archive_fallback(
        &self,
        schema: &str,
        sandbox_id: Option<&str>,
        archive: &crate::config::ArchiveConfig,
        original: anyhow::Error,
    ) -> Result<()> {
        if self.cfg.image_archive.is_none() {
            return Err(original);
        }
        let Some(id) = sandbox_id else {
            return Err(original);
        };
        info!(
            "schema {schema}: dump-based archive failed; falling back to a \
             disk-image archive of {id}"
        );
        match self.image_archive_now(schema, id, archive).await {
            Ok(()) => Ok(()),
            Err(img_e) => Err(original.context(format!(
                "the disk-image fallback also failed: {img_e:#}"
            ))),
        }
    }

    /// The image-archive core: archive the disk, flip the tier, kill the VM,
    /// journal. The caller must hold the schema's `ArchivingGuard` and have
    /// stopped the VM (a still-running one fails the disk-release wait).
    async fn image_archive_now(
        &self,
        schema: &str,
        sandbox_id: &str,
        archive: &crate::config::ArchiveConfig,
    ) -> Result<()> {
        let done =
            crate::imgarchive::archive_disk(&self.cfg, &archive.s3, schema, sandbox_id).await?;
        // Mark before kill, mirroring the dump path: if we crash between them
        // the image is durable and the store says "archived", so the next
        // connect restores — the reverse order could lose the mapping to a
        // killed VM.
        //
        // An unbound VM (on the daemon but not in the registry — incident-era
        // strays) needs its row *created* first: `set_tier` on a missing row
        // is a silent no-op, and an archive the registry doesn't know about
        // is unreachable — the next connect would serve a fresh empty DB.
        // Crash windows stay safe: after `put` alone the schema is live and
        // its VM still exists (the kill hasn't run), so a connect just boots
        // it; the image in S3 is redundant, never load-bearing.
        if self.store.record(schema).is_none() {
            self.store.put(schema, sandbox_id);
        }
        self.store.set_tier(schema, Tier::Archived).await;
        if let Err(e) = kill_by_id(sandbox_id).await {
            warn!(
                "schema {schema}: image-archived but killing VM {sandbox_id} failed \
                 (orphaned): {e:#}"
            );
        } else if let Some(dir) = self.cfg.run_dir.as_ref().map(|d| d.join(sandbox_id)) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if dir.exists() {
                // Same immediate cleanup as `vm::kill_and_reclaim`: the image
                // is durably in S3 and the space is needed now — if the
                // daemon confirms the id is gone, remove the leftover dir
                // ourselves instead of waiting for a sweep pass.
                match tokio::time::timeout(Duration::from_secs(5), self.daemon_state(sandbox_id))
                .await
                .unwrap_or(DaemonState::Error)
                {
                    DaemonState::Gone => match tokio::fs::remove_dir_all(&dir).await {
                        Ok(()) => info!(
                            "schema {schema}: image-archived; the daemon left {} behind, \
                             removed it directly",
                            dir.display()
                        ),
                        Err(e) => warn!(
                            "schema {schema}: image-archived, but removing leftover {} \
                             failed ({e}) — the orphan sweep will reclaim it",
                            dir.display()
                        ),
                    },
                    _ => warn!(
                        "schema {schema}: image-archived and VM killed, but {} still \
                         exists and the daemon still answers for {sandbox_id} — the \
                         orphan sweep will reclaim it",
                        dir.display()
                    ),
                }
            }
        }
        // The pgdata version travels with an image (unlike a dump), so a
        // restore needs a matching-major rootfs — put the version on the
        // record now, not when a restore fails on it.
        crate::events::journal_info(
            "archive.image",
            format!(
                "schema {schema} → archived as disk image ({}, pgdata v{})",
                crate::orphans::human_iec(done.bytes),
                done.pg_version.as_deref().unwrap_or("unknown"),
            ),
        );
        Ok(())
    }

    /// Manually archive `schema` as a disk image — the dashboard's per-VM
    /// "archive as image" action. Unlike the sweep's fallback this doesn't
    /// wait for a failed dump: it stops the VM (checkpointing through the
    /// warm entry when there is one) and archives the disk directly. For a
    /// schema whose Postgres is known-unbootable, this skips the futile
    /// minutes of bring-up the dump path would burn first.
    ///
    /// `viewed_id` is the sandbox the dashboard button was pressed on. It
    /// lets a VM the registry has *no row for* (an incident-era stray: a
    /// rescued ghost, a duplicate from the data-loss race, a row lost while
    /// the disk was full) be archived and adopted — the row is created from
    /// the verified archive, so the schema restores like any other. When the
    /// registry *does* know the schema under a different id, this refuses
    /// and names both VMs: two disks claim the same schema and only a human
    /// knows which holds the truth.
    pub async fn archive_schema_as_image(&self, schema: &str, viewed_id: Option<&str>) -> Result<()> {
        let res = self.archive_schema_as_image_inner(schema, viewed_id).await;
        match &res {
            Ok(()) => {
                self.offload_backoff.clear(schema);
                crate::events::record(crate::events::Event::OffloadDone);
            }
            // Benign claim race — no error journal.
            Err(e) if e.downcast_ref::<AlreadyOffloading>().is_some() => {
                crate::events::journal_info(
                    "archive.image",
                    format!("schema {schema} skipped — another offload is in flight"),
                );
            }
            Err(e) => {
                crate::events::journal_error("archive.image", format!("schema {schema}: {e:#}"));
            }
        }
        res
    }

    async fn archive_schema_as_image_inner(&self, schema: &str, viewed_id: Option<&str>) -> Result<()> {
        let Some(archive) = self.cfg.archive.clone() else {
            bail!(
                "S3 eviction tier is not configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + \
                 PG_VM_POOL_S3_*)"
            );
        };
        anyhow::ensure!(
            self.cfg.image_archive.is_some(),
            "image archiving is not enabled (set PG_VM_POOL_IMAGE_ARCHIVE=1 + PG_VM_POOL_RUN_DIR)"
        );
        match self.store.record(schema).map(|r| r.tier) {
            Some(Tier::Archived) => bail!("schema {schema} is already archived to S3"),
            Some(Tier::Frozen) => bail!(
                "schema {schema} is frozen to a local dump — the archive sweep promotes that \
                 to S3; there is no VM disk to image"
            ),
            Some(Tier::Compacted) => bail!(
                "schema {schema} is already compacted to a local image — the archive sweep \
                 promotes that to S3; there is no VM disk to image"
            ),
            _ => {}
        }
        let recorded = self.store.record(schema).map(|r| r.sandbox_id);
        let (id, adopting) =
            resolve_image_target(schema, recorded.as_deref(), viewed_id)?;
        if adopting {
            info!(
                "schema {schema}: VM {id} is not in the registry — archiving its disk \
                 and adopting the schema from the verified image"
            );
        }
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being archived")));
            }
        };
        // Evict the warm entry under the map lock, refusing live sessions —
        // same serialization against checkout as the dump path.
        let warm = {
            let mut map = self.entries.lock().await;
            let warm = map.get(schema).and_then(|c| c.get()).cloned();
            if let Some(entry) = &warm {
                let active = entry.active_count();
                if active > 0 {
                    bail!("schema {schema} has {active} live session(s); refusing to archive");
                }
            }
            map.remove(schema);
            warm
        };
        match warm {
            // A warm entry means a live pool on a running VM: checkpoint
            // through it, then stop — the image should carry as little
            // unreplayed WAL as possible.
            Some(entry) => checkpoint_and_stop(&entry, schema).await,
            // No warm entry, but the VM may still be running (idle, or left
            // over from before a pooler restart): best-effort stop by id.
            None => {
                if let Ok(sb) = heyo_sdk::Sandbox::connect(id.clone(), vm::local_opts()) {
                    match tokio::time::timeout(Duration::from_secs(30), sb.stop()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => info!(
                            "schema {schema}: pre-image stop of {id}: {e:#} \
                             (it may already be stopped)"
                        ),
                        Err(_) => warn!("schema {schema}: pre-image stop of {id} timed out"),
                    }
                }
            }
        }
        self.image_archive_now(schema, &id, &archive).await
    }

    /// Kick off one purge pass now, in the background — the dashboard's
    /// double-opt-in "purge" button. Works from the durable registry plus
    /// per-id daemon probes, so it finds waste even right after a daemon
    /// restart empties the in-memory listing. Deletes sandboxes that are pure
    /// waste:
    ///
    /// - VMs still backing schemas whose tier is `frozen`/`archived` — the
    ///   tier flip is only ever written after a size-verified durable dump,
    ///   so these are leftovers of a failed post-offload kill;
    /// - unclaimed spares: spare-named sandboxes neither bound to a schema in
    ///   the registry nor mid-claim in this process (an empty initdb cluster
    ///   by construction). A spare being restored into when the pooler last
    ///   crashed can look unclaimed and get deleted — its source dump is
    ///   still durable, so the restore just retries; never data loss.
    ///
    /// Errors if a purge is already running.
    pub fn spawn_purge_now(self: &Arc<Self>) -> Result<()> {
        if self.purging.swap(true, Ordering::SeqCst) {
            bail!("a purge is already running");
        }
        let registry = self.clone();
        tokio::spawn(async move {
            let _guard = SweepGuard(&registry.purging);
            registry.purge_pass().await;
        });
        Ok(())
    }

    async fn purge_pass(&self) {
        if !self.physical.list().is_empty() {
            crate::events::journal_error("purge", "physical replica preparation is pending; refusing all purge cleanup");
            return;
        }
        let infos = match heyo_sdk::Sandbox::list(vm::local_opts()).await {
            Ok(l) => l,
            Err(e) => {
                crate::events::journal_error("purge", format!("listing sandboxes failed: {e:#}"));
                return;
            }
        };
        crate::inventory::absorb(&infos);
        let live_ids: HashSet<String> = infos.iter().map(|s| s.id.clone()).collect();
        let bound: HashSet<String> = self
            .store_records()
            .into_iter()
            .map(|(_, r)| r.sandbox_id)
            .collect();
        let claimed = self
            .spares
            .as_ref()
            .map(|p| p.claimed_ids())
            .unwrap_or_default();

        let (mut offloaded, mut spares, mut failed) = (0usize, 0usize, 0usize);
        // 1. Leftover VMs of durably offloaded schemas.
        //
        // The daemon's listing is IN-MEMORY only (running + touched since
        // daemon start) — after a daemon restart it is nearly empty while
        // thousands of stopped VMs sit in the persisted store, which is
        // exactly the population a purge exists to delete. So a record whose
        // id is missing from the listing is probed per-id (the per-id GET
        // falls back to the daemon's persisted store) rather than skipped;
        // only a confirmed-gone (or unreachable) id is passed over. On a big
        // backlog this is thousands of cheap local GETs — progress is logged
        // so a long pass reads as working, not hung.
        let mut probed = 0usize;
        for (schema, rec) in self.store_records() {
            if rec.tier == Tier::Live {
                continue;
            }
            // Defensive: a pinned schema is always `Live`, so the check above
            // already covers it — but this loop *deletes VMs*, and a record
            // that somehow carried an offloaded tier while a pairing still
            // depended on it would destroy the only copy of a primary.
            if self.pinned(&schema) {
                crate::events::journal_error(
                    "purge",
                    format!(
                        "schema {schema} is tiered {} but is pinned by a replication \
                         pairing or keepalive — refusing to delete its VM",
                        rec.tier.as_str()
                    ),
                );
                continue;
            }
            if !live_ids.contains(&rec.sandbox_id) {
                probed += 1;
                if probed % 500 == 0 {
                    info!(
                        "purge: probed {probed} persisted-only candidate(s),                          deleted {offloaded} so far"
                    );
                }
                // Bounded: a wedged per-id endpoint must not hang a
                // 13k-candidate pass — an unanswered probe is treated like
                // Error (skip this record, keep walking).
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    self.daemon_state(&rec.sandbox_id),
                )
                .await
                {
                    Ok(DaemonState::Present { .. }) => {}
                    Ok(DaemonState::Gone | DaemonState::Error) | Err(_) => continue,
                }
            }
            info!("purge: schema {schema} is {} but VM {} still exists — deleting",
                rec.tier.as_str(), rec.sandbox_id);
            match kill_by_id(&rec.sandbox_id).await {
                Ok(()) => {
                    offloaded += 1;
                    crate::events::record(crate::events::Event::VmDeleted);
                }
                Err(e) => {
                    failed += 1;
                    warn!("purge: deleting {} failed: {e:#}", rec.sandbox_id);
                }
            }
        }
        // 2. Unclaimed spares.
        //
        // `bound` / `claimed` above are snapshots from the START of the pass,
        // and step 1 can run for a long time (it probes every persisted-only
        // record). A spare claimed and bound to a schema DURING the pass is
        // invisible to those snapshots and would be killed under a live
        // schema — the VM is gone, the registry still says live, and the
        // client's next connect gets an empty database. So re-read both right
        // before each kill, and skip anything claimed since.
        for s in &infos {
            if !s.name.starts_with(crate::spares::SPARE_PREFIX)
                || bound.contains(&s.id)
                || claimed.contains(&s.id)
            {
                continue;
            }
            let bound_now = self.store.bound_ids();
            let claimed_now = self
                .spares
                .as_ref()
                .map(|p| p.claimed_ids())
                .unwrap_or_default();
            if bound_now.contains(&s.id) || claimed_now.contains(&s.id) {
                info!("purge: spare {} was claimed during this pass — keeping it", s.id);
                continue;
            }
            info!("purge: unclaimed spare {} — deleting", s.id);
            match kill_by_id(&s.id).await {
                Ok(()) => {
                    spares += 1;
                    crate::events::record(crate::events::Event::VmDeleted);
                }
                Err(e) => {
                    failed += 1;
                    warn!("purge: deleting spare {} failed: {e:#}", s.id);
                }
            }
        }
        let msg = format!(
            "deleted {offloaded} offloaded-schema VM(s) + {spares} unclaimed spare(s){}",
            if failed > 0 {
                format!(", {failed} failed")
            } else {
                String::new()
            }
        );
        info!("purge: {msg}");
        crate::events::journal_info("purge", msg);
    }

    // ---- local frozen tier --------------------------------------------------

    /// Start the local dump HTTP server. Serves guest uploads and downloads
    /// for the frozen tier AND the S3 archive tier's streamed dumps; without
    /// it, freezing, thawing, and streamed archiving are inert.
    pub fn spawn_dump_server(self: &Arc<Self>) {
        let Some(srv) = self.dumps.clone() else {
            return;
        };
        let listen = self.cfg.dump_net.listen;
        tokio::spawn(async move {
            if let Err(e) = srv.serve(listen).await {
                error!(
                    "local dump server exited: {e:#} — freezing, thawing, and streamed \
                     archive dumps are down"
                );
            }
        });
    }

    /// Dump one schema to the local dump store and delete its VM. The frozen
    /// twin of [`Self::archive_schema`], with the same guards: `archiving`
    /// claim (checkouts wait), live-session refusal, dump verified complete
    /// (size-checked by `dump_to_local`) *before* the durable tier flip, and
    /// the tier flip durable *before* the kill.
    ///
    /// Journaled like [`Self::archive_schema`], as the choke point for all
    /// freeze callers.
    pub async fn freeze_schema(&self, schema: &str) -> Result<()> {
        let res = self.freeze_schema_inner(schema).await;
        match &res {
            Ok(()) => {
                self.offload_backoff.clear(schema);
                crate::events::journal_info(
                    "freeze",
                    format!("schema {schema} → frozen (local dump)"),
                );
                crate::events::record(crate::events::Event::OffloadDone);
            }
            // Benign claim race — no backoff, no error journal.
            Err(e) if e.downcast_ref::<AlreadyOffloading>().is_some() => {
                crate::events::journal_info(
                    "freeze",
                    format!("schema {schema} skipped — another offload is in flight"),
                );
            }
            Err(e) => {
                let (n, delay) = self.offload_backoff.record_failure(schema, Instant::now());
                crate::events::journal_error(
                    "freeze",
                    format!(
                        "schema {schema}: {e:#} (failure {n}; sweeps skip this schema for {})",
                        fmt_backoff(delay)
                    ),
                );
            }
        }
        res
    }

    async fn freeze_schema_inner(&self, schema: &str) -> Result<()> {
        let (Some(freeze), Some(dumps)) = (self.cfg.freeze.clone(), self.dumps.clone()) else {
            bail!("local freeze tier is not configured (set PG_VM_POOL_FREEZE_AFTER_SECS)");
        };
        if self.store.record(schema).map(|r| r.offloaded()).unwrap_or(false) {
            bail!("schema {schema} is already frozen or archived");
        }
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being frozen/archived")));
            }
        };
        {
            let mut map = self.entries.lock().await;
            if let Some(entry) = map.get(schema).and_then(|c| c.get()) {
                let active = entry.active_count();
                if active > 0 {
                    bail!("schema {schema} has {active} live session(s); refusing to freeze");
                }
            }
            map.remove(schema);
        }

        let known_id = self.store.record(schema).map(|r| r.sandbox_id);
        let owner = self.owner_of(schema);
        let repl_login = self.repl_login_for(schema);
        let entry = match vm::ensure_vm(
            &self.cfg,
            schema,
            known_id.as_deref(),
            None,
            None,
            None,
            &self.bring_up_for(schema, owner.as_ref(), repl_login.as_ref()),
        )
        .await {
            Ok(entry) => entry,
            Err(e) => {
                // Same leak guard as archive_schema_inner's bring-up.
                vm::stop_after_failed_bringup(schema, known_id.as_deref()).await;
                return Err(e)
                    .with_context(|| format!("bringing up VM for schema {schema} to freeze it"));
            }
        };

        // Note the data device's size while the VM that has it is still up.
        // The dump routes delete that VM, and a dump carries no trace of the
        // device it came off — so this row is the only thing that later stops
        // the restore from rebuilding the schema into a default-size device
        // and filling it mid-`pg_restore` (see `Store::set_disk_gb`). Recorded
        // before `set_tier`, whose durable write is what carries it to disk
        // ahead of the kill.
        if let Some((_, dev)) = sample_disk(&entry).await {
            self.store.set_disk_gb(schema, device_gb(dev));
        }

        // Asked here, where a running Postgres can answer it, and recorded
        // beside the dump: the promotion to S3 has only the dump file, and
        // "how many relations does this dump hold" is not a question a dump
        // file answers cheaply. Freezing an empty database locally is fine —
        // uploading it is what must not happen.
        let empty = vm::has_user_relations(&self.cfg, &entry.target, schema).await == Some(false);

        // Same leak guard as archive_schema_inner: a failed dump must not
        // leave the VM it booted running and unowned.
        let bytes = match vm::dump_to_local(
            &self.cfg,
            &entry.sandbox,
            schema,
            &dumps,
            freeze.listen.port(),
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("schema {schema}: dump failed; stopping the VM booted for this attempt");
                checkpoint_and_stop(&entry, schema).await;
                return Err(e)
                    .with_context(|| format!("dumping schema {schema} to the local dump store"));
            }
        };

        let marker = crate::imgarchive::empty_marker(&dumps.dump_path(schema));
        if empty {
            info!(
                "schema {schema}: froze an empty database — keeping it local; it will not be \
                 promoted to S3"
            );
            if let Err(e) = tokio::fs::write(&marker, b"").await {
                warn!("schema {schema}: writing {} failed: {e}", marker.display());
            }
        } else {
            let _ = tokio::fs::remove_file(&marker).await;
        }

        self.store.set_tier(schema, Tier::Frozen).await;
        let accomplished = format!("frozen to a {bytes}-byte local dump");
        if let Err(e) = vm::kill_and_reclaim(&self.cfg, &entry.sandbox, schema, &accomplished).await {
            warn!("schema {schema}: frozen locally but killing the VM failed (orphaned): {e:#}");
        }
        Ok(())
    }

    // ---- compacted tier -----------------------------------------------------

    /// Compact one schema's stopped disk to a local image and delete its VM —
    /// the compacted twin of [`Self::freeze_schema`], with the same guards:
    /// `archiving` claim (checkouts wait), live-session refusal, image
    /// verified complete (zstd -t + ext4 magic, atomic rename) *before* the
    /// durable tier flip, and the tier flip durable *before* the kill.
    pub async fn compact_schema(&self, schema: &str) -> Result<()> {
        let res = self.compact_schema_inner(schema).await;
        match &res {
            Ok(()) => {
                self.offload_backoff.clear(schema);
                crate::events::journal_info(
                    "compact",
                    format!("schema {schema} → compacted (local image)"),
                );
                crate::events::record(crate::events::Event::OffloadDone);
            }
            // Benign claim race — no backoff, no error journal.
            Err(e) if e.downcast_ref::<AlreadyOffloading>().is_some() => {
                crate::events::journal_info(
                    "compact",
                    format!("schema {schema} skipped — another offload is in flight"),
                );
            }
            Err(e) => {
                let (n, delay) = self.offload_backoff.record_failure(schema, Instant::now());
                crate::events::journal_error(
                    "compact",
                    format!(
                        "schema {schema}: {e:#} (failure {n}; sweeps skip this schema for {})",
                        fmt_backoff(delay)
                    ),
                );
            }
        }
        res
    }

    async fn compact_schema_inner(&self, schema: &str) -> Result<()> {
        let Some(compact) = self.cfg.compact.clone() else {
            bail!("compacted tier is not configured (set PG_VM_POOL_COMPACT_AFTER_SECS)");
        };
        if self.store.record(schema).map(|r| r.offloaded()).unwrap_or(false) {
            bail!("schema {schema} is already compacted, frozen, or archived");
        }
        let _guard = match ArchivingGuard::claim(&self.archiving, schema) {
            Some(g) => g,
            None => {
                return Err(anyhow::Error::new(AlreadyOffloading)
                    .context(format!("schema {schema} is already being offloaded")));
            }
        };
        {
            let mut map = self.entries.lock().await;
            if let Some(entry) = map.get(schema).and_then(|c| c.get()) {
                // A warm entry appeared since candidate selection: the VM may
                // be running (disk open). Leave it to the idle reaper.
                let active = entry.active_count();
                bail!(
                    "schema {schema} has a warm VM ({active} session(s)); refusing to compact"
                );
            }
            map.remove(schema);
        }
        let Some(rec) = self.store.record(schema) else {
            bail!("schema {schema} has no registry row — nothing to compact");
        };

        // Image the stopped disk. compact_disk's fd-scan wait refuses a disk
        // anything still holds open, so a VM started out-of-band fails this
        // rather than being imaged mid-write.
        let bytes = crate::imgarchive::compact_disk(&self.cfg, &compact, schema, &rec.sandbox_id)
                .await
                .with_context(|| format!("compacting schema {schema}'s data disk"))?;

        // Tier flip durable before the kill (crash between them = data safely
        // in the compact file, row says compacted, next connect thaws it —
        // the VM/disk becomes purge/orphan fodder, not data loss).
        self.store.set_tier(schema, Tier::Compacted).await;
        let accomplished = format!(
            "compacted to a {}-byte local image",
            bytes
        );
        match Sandbox::connect(rec.sandbox_id.clone(), vm::local_opts()) {
            Ok(sb) => {
                if let Err(e) = vm::kill_and_reclaim(&self.cfg, &sb, schema, &accomplished).await {
                    warn!("schema {schema}: compacted but killing the VM failed (orphaned): {e:#}");
                }
            }
            Err(e) => warn!(
                "schema {schema}: compacted but connecting to VM {} to kill it failed \
                 (orphaned): {e:#}",
                rec.sandbox_id
            ),
        }
        Ok(())
    }

    // ---- orphan-disk reclamation --------------------------------------------

    /// Spawn the orphan-disk sweep if `PG_VM_POOL_ORPHAN_SWEEP_SECS` (and a run
    /// dir) are configured: periodically delete `sb-<id>/` directories heyvmd no
    /// longer knows about, reclaiming disks a kill acked but didn't remove.
    pub fn spawn_orphan_reaper(self: &Arc<Self>) {
        let Some(interval) = self.cfg.orphan_sweep else {
            info!("orphan-disk sweep disabled (PG_VM_POOL_ORPHAN_SWEEP_SECS unset/0)");
            return;
        };
        // config guarantees run_dir is Some whenever orphan_sweep is Some.
        let Some(run_dir) = self.cfg.run_dir.clone() else {
            return;
        };
        info!(
            "orphan-disk sweep: reclaiming forgotten sb-<id>/ dirs under {} every {:?} \
             (min age {:?}, ≤{} deletions/pass; re-arms after {ORPHAN_DRAIN_REARM:?} while \
             a backlog remains and no client is waiting)",
            run_dir.display(),
            interval,
            ORPHAN_MIN_AGE,
            ORPHAN_MAX_DELETES_PER_SWEEP,
        );
        let registry = self.clone();
        let first = ORPHAN_FIRST_DELAY.min(interval);
        // Drain mode: a pass that hit its per-pass cap left work behind. Wake
        // the supervisor again shortly instead of waiting a whole interval —
        // but only if no client bring-up is queued at that moment; clients
        // first. `Notify` stores the permit, so a wake landing mid-pass just
        // triggers the next one, and the sweep's own single-flight makes a
        // double wake harmless.
        let wake = Arc::new(tokio::sync::Notify::new());
        tokio::spawn(supervise_with_wake(
            "orphan-reaper",
            first,
            interval,
            Some(wake.clone()),
            // No floor: the drain-rearm wake is already delayed 20s.
            Duration::ZERO,
            move || {
                let registry = registry.clone();
                let wake = wake.clone();
                async move {
                    let (acted, deferred) = registry.sweep_orphans().await;
                    if deferred > 0 {
                        debug!(
                            "orphan-disk sweep: {deferred} candidate(s) deferred — \
                             re-checking in ~{ORPHAN_DRAIN_REARM:?}"
                        );
                        tokio::spawn(async move {
                            tokio::time::sleep(ORPHAN_DRAIN_REARM).await;
                            if crate::vm::bringups_waiting() == 0 {
                                wake.notify_one();
                            }
                        });
                    }
                    acted
                }
            },
        ));
    }

    /// Reap bring-ups that started (the daemon accepted a create and handed out
    /// an id — recorded in the pending ledger) but never resolved into a
    /// registry binding: pooler died mid-bring-up, or the failure-path kill
    /// couldn't reach the daemon. These VMs are the "stuck in `provisioning`,
    /// bound to nothing" records no other sweep can touch — purge needs a
    /// registry row or a spare name, the orphan-disk sweep needs the daemon to
    /// have forgotten the id. Always on: the ledger only has entries if
    /// bring-ups actually leaked.
    pub fn spawn_pending_janitor(self: &Arc<Self>) {
        let registry = self.clone();
        info!(
            "pending-bringup janitor: reaping unresolved bring-ups every {:?}",
            PENDING_JANITOR_TICK
        );
        tokio::spawn(supervise(
            "pending-janitor",
            PENDING_JANITOR_FIRST_DELAY,
            PENDING_JANITOR_TICK,
            move || {
                let registry = registry.clone();
                async move { registry.pending_pass().await }
            },
        ));
    }

    /// One janitor pass; returns the number of entries resolved. An entry is
    /// only acted on well after any legitimate bring-up would have finished,
    /// and deletion needs the daemon to positively confirm the record — the
    /// same ambiguity-never-deletes rule as the orphan-disk sweep.
    async fn pending_pass(&self) -> usize {
        if !self.physical.list().is_empty() {
            warn!("pending-bringup janitor: physical preparation pending; refusing cleanup");
            return 0;
        }
        // Twice the ready budget plus slack: a slow-but-alive bring-up (ready
        // wait + restore) must never race its own janitor.
        let min_age = self.cfg.ready_timeout * 2 + Duration::from_secs(300);
        let stale = crate::pending::stale(min_age);
        if stale.is_empty() {
            return 0;
        }
        let mut resolved = 0usize;
        for (schema, id) in stale {
            // Bound after all — the bring-up won and only the ledger clear was
            // lost (e.g. a crash between store.put and clear). Settled.
            if self
                .store
                .record(&schema)
                .is_some_and(|r| r.sandbox_id == id)
            {
                crate::pending::clear(&schema).await;
                resolved += 1;
                continue;
            }
            // A bring-up for this schema is in flight right now (cell present
            // but uninitialized) — it may be reattaching to this very VM by
            // name; hands off until it settles.
            {
                let map = self.entries.lock().await;
                if map.get(&schema).is_some_and(|cell| cell.get().is_none()) {
                    continue;
                }
            }
            match self.daemon_state(&id).await {
                DaemonState::Gone => {
                    // Deleted out-of-band (or our failure-path kill did land) —
                    // if a disk dir lingers, the orphan-disk sweep owns it now
                    // that the daemon reports the id gone.
                    crate::pending::clear(&schema).await;
                    resolved += 1;
                }
                DaemonState::Present { .. } => match kill_by_id(&id).await {
                    Ok(()) => {
                        let msg = format!(
                            "schema {schema}: deleted VM {id} stranded by a failed bring-up \
                             (never bound to the registry)"
                        );
                        info!("pending-bringup janitor: {msg}");
                        crate::events::journal_info("pending-janitor", msg);
                        crate::pending::clear(&schema).await;
                        resolved += 1;
                    }
                    Err(e) => warn!(
                        "pending-bringup janitor: deleting stranded VM {id} \
                         (schema {schema}) failed; retrying next pass: {e:#}"
                    ),
                },
                // Daemon down or flaking: ambiguity never deletes.
                DaemonState::Error => {}
            }
        }
        resolved
    }

    /// One orphan-disk pass. Returns `(acted, deferred)`: directories deleted
    /// plus rootfs copies pruned (for the supervisor heartbeat), and how many
    /// candidates the per-pass caps pushed to a later pass — a non-zero
    /// `deferred` is what makes the reaper re-arm early (drain mode) instead
    /// of waiting a whole interval. Failed deletions are NOT deferred work:
    /// retrying them seconds later just re-fails (root-owned files etc.).
    /// Single-flighted on its own flag.
    ///
    /// A directory is deleted only when **all** of these hold, checked in
    /// cheapest-first order so a live disk is ruled out before any daemon
    /// round-trip or destructive call:
    ///   1. it's older than [`ORPHAN_MIN_AGE`] (not a VM mid-create);
    ///   2. no process holds a file in it open (not a running VM — the
    ///      chroot-proof device:inode check in [`crate::orphans`]);
    ///   3. heyvmd's per-id endpoint returns 404 (the daemon truly forgot it —
    ///      the *list* is unreliable, so we never classify off it);
    ///   4. its schema is offloaded (`frozen`/`archived`, data safe elsewhere)
    ///      or the id is unreferenced by any registry entry (dead).
    ///
    /// A `live`-tier schema whose VM is gone is a data-loss orphan: its disk is
    /// the only copy, so it is reported at error level and never deleted.
    /// Conditions 2 and 3 are re-checked immediately before each `remove_dir_all`
    /// against a fresh snapshot, since classification does many awaits.
    ///
    /// The same pass also **prunes leftover boot artefacts** from directories
    /// it is keeping. heyvmd clones the base image into `<dir>/rootfs.ext4`
    /// on every boot and deletes it on a clean stop, so a copy sitting next to
    /// a *stopped* VM's data disk is the residue of an unclean one — a daemon
    /// restart, a watchdog kill, a host reboot. It is ~200MB per VM, nothing
    /// reads it (the next boot overwrites it), and on a large fleet it is the
    /// single biggest reclaimable item in the run dir. Deleting it needs the
    /// same in-use and age guards as a directory, plus the daemon reporting the
    /// VM not running; the cost of being wrong is one extra image clone.
    async fn sweep_orphans(&self) -> (usize, usize) {
        if !self.physical.list().is_empty() {
            warn!("orphan-disk sweep: physical preparation pending; refusing cleanup");
            return (0, 0);
        }
        let Some(run_dir) = self.cfg.run_dir.clone() else {
            return (0, 0);
        };
        if self.orphan_sweeping.swap(true, Ordering::SeqCst) {
            info!("orphan-disk sweep: a pass is already running; skipping");
            return (0, 0);
        }
        let _guard = SweepGuard(&self.orphan_sweeping);

        // The restore scratch dir is dot-named, so the sb-* scan below never
        // sees it — GC its crash leftovers here, on the sweep's cadence.
        crate::imgarchive::gc_restore_scratch(&run_dir);

        // Registry view: sandbox-id → (schema, tier). The authoritative map of
        // which disks a schema still depends on.
        let by_id: HashMap<String, (String, Tier)> = self
            .store_records()
            .into_iter()
            .map(|(schema, r)| (r.sandbox_id, (schema, r.tier)))
            .collect();

        // Enumerate old-enough sb-* dirs. Fresh dirs (a VM mid-create) are
        // skipped by the age floor.
        let entries = match std::fs::read_dir(&run_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("orphan-disk sweep: cannot read run dir {}: {e}", run_dir.display());
                return (0, 0);
            }
        };
        let now = SystemTime::now();
        let mut dirs: Vec<(PathBuf, String)> = Vec::new();
        let mut too_new = 0usize;
        for ent in entries.flatten() {
            let name = ent.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with("sb-") {
                continue;
            }
            let path = ent.path();
            if !path.is_dir() {
                continue;
            }
            if let Ok(md) = ent.metadata()
                && let Ok(mtime) = md.modified()
                && now
                    .duration_since(mtime)
                    .map(|age| age < ORPHAN_MIN_AGE)
                    .unwrap_or(true)
            {
                too_new += 1;
                continue;
            }
            dirs.push((path, name.to_string()));
        }
        if dirs.is_empty() {
            debug!("orphan-disk sweep: no candidate dirs ({too_new} too new)");
            return (0, 0);
        }

        let open = crate::orphans::open_inodes();

        // Classify. Held-open first (a local filesystem check), then the daemon
        // round-trip only for dirs that survive it.
        let mut deletable: Vec<(PathBuf, String, String)> = Vec::new(); // (path, id, why)
        let mut dataloss: Vec<(String, String)> = Vec::new(); // (schema, id)
        let mut stale_rootfs: Vec<(PathBuf, String)> = Vec::new(); // (rootfs path, id)
        let (mut alive, mut held, mut daemon_errs) = (0usize, 0usize, 0usize);
        let mut aborted = false;
        for (path, id) in dirs {
            if crate::orphans::dir_held_open(&path, &open) {
                held += 1;
                continue;
            }
            let state = self.daemon_state(&id).await;
            daemon_errs = daemon_error_run(daemon_errs, &state);
            match state {
                DaemonState::Present { running } => {
                    alive += 1;
                    // The VM is stopped (or the daemon says so while nothing
                    // holds its files open, which amounts to the same thing):
                    // any rootfs clone left in its directory is dead weight.
                    if !running {
                        let rootfs = path.join(VM_ROOTFS_FILE);
                        if file_older_than(&rootfs, ORPHAN_MIN_AGE) {
                            stale_rootfs.push((rootfs, id));
                        }
                    }
                }
                DaemonState::Error => {
                    if daemon_errs >= ORPHAN_MAX_DAEMON_ERRORS {
                        warn!(
                            "orphan-disk sweep: aborting after {daemon_errs} consecutive daemon \
                             errors — heyvmd looks unhealthy; a 'gone?' ambiguity must never \
                             become a deletion. Retrying next sweep"
                        );
                        aborted = true;
                        break;
                    }
                    continue;
                }
                DaemonState::Gone => match by_id.get(&id) {
                        Some((schema, Tier::Live)) => dataloss.push((schema.clone(), id.clone())),
                        Some((schema, _)) => {
                            deletable.push((path, id, format!("offloaded schema {schema}")))
                        }
                        None => deletable.push((path, id, "unreferenced by any schema".into())),
                },
            }
        }

        // Data-loss orphans: never delete — shout so an operator acts.
        for (schema, id) in &dataloss {
            error!(
                "orphan-disk sweep: schema {schema}'s VM {id} is gone from heyvmd but its tier \
                 is still `live` — its data disk {}/{id} is the ONLY copy and the next connect \
                 will serve an EMPTY database. NOT deleting. Restore it, or mark it \
                 archived/frozen if the data is durable elsewhere.",
                run_dir.display(),
            );
        }

        let backlog = deletable.len().saturating_sub(ORPHAN_MAX_DELETES_PER_SWEEP);
        deletable.truncate(ORPHAN_MAX_DELETES_PER_SWEEP);
        let rootfs_backlog = stale_rootfs
            .len()
            .saturating_sub(ORPHAN_MAX_ROOTFS_PRUNES_PER_SWEEP);
        stale_rootfs.truncate(ORPHAN_MAX_ROOTFS_PRUNES_PER_SWEEP);
        info!(
            "orphan-disk sweep: {} deletable, {} stale rootfs cop(ies), {alive} live, {held} in \
             use, {} data-loss orphan(s), {too_new} too new{}{}",
            deletable.len() + backlog,
            stale_rootfs.len() + rootfs_backlog,
            dataloss.len(),
            if backlog > 0 { format!(", {backlog} deferred to later passes") } else { String::new() },
            if aborted { " (classification aborted early — daemon unhealthy)" } else { "" },
        );

        // Fresh open-file snapshot for the destructive phase: classification did
        // many awaits, during which a VM could have grabbed one of these disks.
        let open = crate::orphans::open_inodes();
        let (mut removed, mut freed, mut failed) = (0usize, 0u64, 0usize);
        for (path, id, why) in deletable {
            // Re-confirm not-held and still-gone immediately before deleting.
            if crate::orphans::dir_held_open(&path, &open) {
                continue;
            }
            if !matches!(self.daemon_state(&id).await, DaemonState::Gone) {
                continue;
            }
            let bytes = crate::orphans::dir_allocated_bytes(path.clone()).await;
            match std::fs::remove_dir_all(&path) {
                Ok(()) => {
                    removed += 1;
                    crate::events::record(crate::events::Event::VmDeleted);
                    freed += bytes;
                    info!(
                        "orphan-disk sweep: reclaimed {} ({}) — {why}",
                        path.display(),
                        crate::orphans::human_iec(bytes),
                    );
                }
                Err(e) => {
                    failed += 1;
                    warn!(
                        "orphan-disk sweep: failed to remove {} ({why}): {e} — \
                         (jailer may have left root-owned files; the pooler needs \
                         delete permission on the run dir)",
                        path.display(),
                    );
                }
            }
        }
        if removed > 0 || failed > 0 {
            info!(
                "orphan-disk sweep: reclaimed {removed} disk(s), {} freed{}",
                crate::orphans::human_iec(freed),
                if failed > 0 { format!(", {failed} could not be removed") } else { String::new() },
            );
        }

        // Boot-artefact prune. Every guard re-confirmed per file: nothing in
        // the directory is open, the daemon still reports the VM not running,
        // and the file itself is still old. A VM that booted since
        // classification fails all three — the boot re-clones the rootfs, so
        // even the mtime alone gives it away.
        let (mut pruned, mut pruned_bytes) = (0usize, 0u64);
        for (rootfs, id) in stale_rootfs {
            let Some(dir) = rootfs.parent() else { continue };
            if crate::orphans::dir_held_open(dir, &open) {
                continue;
            }
            if !file_older_than(&rootfs, ORPHAN_MIN_AGE) {
                continue;
            }
            if !matches!(self.daemon_state(&id).await, DaemonState::Present { running: false }) {
                continue;
            }
            let bytes = crate::orphans::file_allocated_bytes(&rootfs);
            match std::fs::remove_file(&rootfs) {
                Ok(()) => {
                    pruned += 1;
                    pruned_bytes += bytes;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!(
                    "orphan-disk sweep: pruning stale rootfs {} failed: {e}",
                    rootfs.display()
                ),
            }
        }
        if pruned > 0 {
            info!(
                "orphan-disk sweep: pruned {pruned} stale rootfs cop(ies) of stopped VMs, {} \
                 freed (each is re-cloned from the base image on that VM's next boot)",
                crate::orphans::human_iec(pruned_bytes),
            );
        }
        (removed + pruned, backlog + rootfs_backlog)
    }

    /// What heyvmd's per-id endpoint says about sandbox `id`. Uses `get`
    /// (`GET /deployed-sandboxes/:id`), which resolves by id and reports even a
    /// stopped sandbox — unlike the list, which is unreliable. `Gone` is the
    /// only state that permits deletion; `Error` (daemon down/flaking) is
    /// deliberately distinct from `Gone` so ambiguity never deletes.
    async fn daemon_state(&self, id: &str) -> DaemonState {
        let sb = match Sandbox::connect(id.to_string(), vm::local_opts()) {
            Ok(sb) => sb,
            Err(e) => {
                debug!("orphan-disk sweep: cannot connect to check {id}: {e:#}");
                return DaemonState::Error;
            }
        };
        match sb.get().await {
            Ok(info) => DaemonState::Present {
                running: info.status == heyo_sdk::SandboxStatus::Running,
            },
            Err(HeyoError::NotFound(_)) => DaemonState::Gone,
            Err(e) => {
                debug!("orphan-disk sweep: daemon error checking {id}: {e:#}");
                DaemonState::Error
            }
        }
    }

    fn is_archiving(&self, schema: &str) -> bool {
        self.archiving.lock().unwrap().contains(schema)
    }

    /// Is `schema`'s compacted image marked as holding no user relations?
    /// Promotion refuses such an image (see `imgarchive::promote_compact`),
    /// and the answer can't change while it sits there: only a restore, which
    /// deletes the image and its marker together, gives the schema new data.
    /// The S3 eviction sweep (no backoff of its own) skips it outright; the
    /// offload pacer instead backs it off for the full cap — see
    /// `OffloadBackoff::record_settled`.
    fn compacted_empty(&self, schema: &str) -> bool {
        self.cfg
            .compact
            .as_ref()
            .is_some_and(|c| crate::imgarchive::empty_marker(&c.compact_path(schema)).exists())
    }

    /// Warm-spare pool depth `(ready, target)`; `None` when the pool is
    /// disabled. Zero ready is the single biggest cold-start signal: the next
    /// new-schema connect pays a full create + boot instead of a spare claim.
    pub fn spare_pool_depth(&self) -> Option<(usize, usize)> {
        self.spares.as_ref().map(|p| p.depth())
    }

    /// Chilled-vehicle depth `(chilled, target)`; `None` when the pool is
    /// disabled. Zero chilled is the image-restore equivalent of zero warm
    /// spares: the next thaw falls back to stopping a running spare and
    /// waiting out the disk release, which is several seconds a client feels.
    pub fn chilled_vehicle_depth(&self) -> Option<(usize, usize)> {
        self.spares.as_ref().map(|p| p.chilled_depth())
    }

    /// The schemas currently claimed by an offload, whatever started it
    /// (dispatcher workers, the pressure pass, dashboard buttons) — the
    /// dashboard's "offloads in flight" readout.
    pub fn archiving_schemas(&self) -> Vec<String> {
        let mut v: Vec<String> = self.archiving.lock().unwrap().iter().cloned().collect();
        v.sort();
        v
    }
}

/// Does `path` exist and has it been untouched for at least `age`? False for a
/// missing file, and false when the mtime can't be read or lies in the future —
/// the callers use this as a "safe to delete" gate, so unknown means no.
fn file_older_than(path: &std::path::Path, age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|md| md.modified())
        .ok()
        .and_then(|mtime| SystemTime::now().duration_since(mtime).ok())
        .is_some_and(|elapsed| elapsed >= age)
}

/// One GiB, for device-size math.
pub(crate) const GIB: u64 = 1024 * 1024 * 1024;

/// Per-schema failure memory for offloads, so the archive/freeze/pressure
/// sweeps stop re-trying the same sick schemas every pass. Each failed
/// attempt on a schema costs up to a full ready-timeout (~5 min of wedged
/// bring-up), and the sweeps' consecutive-failure breaker means a handful of
/// permanently sick schemas can abort pass after pass — starving every
/// healthy candidate behind them. With backoff, a failed schema is skipped by
/// the sweeps for an exponentially growing window (30m, 1h, 2h … capped at
/// 24h) and retried after; any success clears it. Deliberately NOT consulted
/// by the dashboard's manual per-schema reap — a human clicking the button is
/// an explicit retry (and its success resets the backoff).
///
/// In-memory only: a pooler restart retries everything once, which is the
/// behavior you want after deploying a fix.
struct OffloadBackoff {
    map: StdMutex<HashMap<String, (u32, Instant)>>,
}

impl OffloadBackoff {
    fn new() -> Self {
        Self {
            map: StdMutex::new(HashMap::new()),
        }
    }

    /// Record one failure at `now`; returns (consecutive failures, how long
    /// sweeps will now skip this schema).
    fn record_failure(&self, schema: &str, now: Instant) -> (u32, Duration) {
        let mut map = self.map.lock().unwrap();
        let entry = map.entry(schema.to_string()).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
        (entry.0, offload_backoff_delay(entry.0))
    }

    /// Skip `schema` for the full cap from `now`: for an outcome that isn't a
    /// failure and won't change on its own (an empty cluster), so doubling
    /// up from 30m would only re-ask the same question all day. A restore
    /// clears it like any other backoff.
    fn record_settled(&self, schema: &str, now: Instant) -> Duration {
        self.map
            .lock()
            .unwrap()
            .insert(schema.to_string(), (u32::MAX, now));
        offload_backoff_delay(u32::MAX)
    }

    /// A success (or a completed restore) forgets the schema's failures.
    fn clear(&self, schema: &str) {
        self.map.lock().unwrap().remove(schema);
    }

    /// Time remaining in `schema`'s backoff window at `now`, if any.
    fn active(&self, schema: &str, now: Instant) -> Option<Duration> {
        let map = self.map.lock().unwrap();
        let (failures, last) = map.get(schema)?;
        offload_backoff_delay(*failures).checked_sub(now.saturating_duration_since(*last))
            .filter(|d| !d.is_zero())
    }
}

/// 30m, 1h, 2h, 4h, … capped at [`OFFLOAD_BACKOFF_CAP`].
fn offload_backoff_delay(failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(6); // 2^6 * 30m > cap already
    OFFLOAD_BACKOFF_BASE
        .saturating_mul(1u32 << exp)
        .min(OFFLOAD_BACKOFF_CAP)
}

/// Compact duration for backoff messages: "30m", "2h".
fn fmt_backoff(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h", s.div_ceil(3600))
    } else {
        format!("{}m", s.div_ceil(60))
    }
}

/// Sample a warm VM's data filesystem (total, used, avail bytes via `df` over
/// the pool, like `guest_stats`) plus its backing *device* size (sysfs sector
/// count × 512 via `pg_read_file` — the same source the daemon's own resize
/// verification reads in-guest). `None` when either read fails within the
/// stats timeout; the caller just skips growth this cycle.
/// One [`sample_disk`] reading: the guest data filesystem's
/// `(total, used, avail)` in bytes, and the size of the device backing it.
type DiskSample = ((u64, u64, u64), u64);

async fn sample_disk(entry: &SchemaEntry) -> Option<DiskSample> {
    let query = async {
        let mut client = entry.pool.get().await.ok()?;
        // Explicit (offset, length): sysfs files stat as 0 bytes, so the
        // whole-file form of pg_read_file reads nothing (same as /proc).
        let sectors: String = client
            .query_one(
                "SELECT pg_read_file('/sys/class/block/vdb/size', 0, 64)",
                &[],
            )
            .await
            .ok()?
            .get(0);
        let device = sectors.trim().parse::<u64>().ok()?.checked_mul(512)?;
        let fs = df_data_dir(&mut client).await?;
        Some((fs, device))
    };
    tokio::time::timeout(STATS_TIMEOUT, query).await.ok()?
}

/// A data device's size in whole GiB, rounded up — the unit both the daemon's
/// create and its resize speak, and the unit the registry records. Never 0: a
/// device that exists is at least 1GiB to anything that has to rebuild it.
fn device_gb(device_bytes: u64) -> u32 {
    device_bytes.div_ceil(GIB).max(1).min(u32::MAX as u64) as u32
}

/// What should happen to a VM's data device, given how full its guest
/// filesystem is. See [`grow_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrowVerdict {
    /// Below the trigger, or the filesystem has room left inside its device.
    NotNeeded,
    /// Grow the device to this many GiB.
    Grow(u64),
    /// The filesystem is at the trigger and spans a device already at
    /// `max_gb`. Nothing the pooler can do — growth is the only lever it has,
    /// and it is spent. Distinguished from `NotNeeded` so the caller can say
    /// so out loud instead of silently declining to act on a schema that is
    /// about to fail every write.
    AtCap { current_gb: u64 },
}

/// Decide whether (and to what) a VM's data device should grow. `fs` is the
/// guest data filesystem's (total, used, avail), `device_bytes` its backing
/// device size, `pct` the used% trigger to judge against, and `max_gb` the
/// ceiling.
///
/// Grows only when BOTH hold:
/// - used% (df semantics: used / (used + avail)) is at/above the trigger, and
/// - the filesystem spans (>= 90% of) the device — a thin fs below its cap is
///   the guest grow-watcher's job (it extends the fs online long before the
///   device matters); the device is only the binding constraint once the fs
///   has nowhere left to grow inside it.
///
/// The step doubles the device (whole GiB, current size rounded up), capped
/// at `max_gb` — the same amortization policy as the guest fs watcher.
///
/// `pct` is a parameter rather than read off the config because there are two
/// callers with two different prices: the idle-stop path grows a VM that is
/// stopping anyway (cheap, fires at `DiskGrowConfig::pct`), and the urgent
/// path stops a live one to do it (expensive, fires at
/// `DiskGrowConfig::urgent_pct`).
pub(crate) fn grow_verdict(
    fs: (u64, u64, u64),
    device_bytes: u64,
    pct: f64,
    max_gb: u64,
) -> GrowVerdict {
    let (total, used, avail) = fs;
    let Some(used_pct) = used_pct(used, avail) else {
        return GrowVerdict::NotNeeded;
    };
    if used_pct < pct {
        return GrowVerdict::NotNeeded;
    }
    if total < device_bytes.saturating_mul(9) / 10 {
        return GrowVerdict::NotNeeded;
    }
    let current_gb = device_bytes.div_ceil(GIB).max(1);
    if current_gb >= max_gb {
        return GrowVerdict::AtCap { current_gb };
    }
    GrowVerdict::Grow((current_gb * 2).min(max_gb))
}

/// The urgent grower's memory of one warm schema's last disk sample: enough
/// to turn two samples into a fill rate and to decide how soon to look again.
#[derive(Debug, Clone, Copy)]
struct GrowSample {
    /// Guest data filesystem bytes in use (df semantics), and when read.
    used: u64,
    at: Instant,
    /// Bytes per second since the previous sample; `None` until there are two.
    rate: Option<f64>,
    /// On the fast cadence: filling, near the threshold, or not yet rated.
    hot: bool,
}

impl GrowSample {
    /// How long until this schema is due another sample.
    fn every(&self) -> Duration {
        if self.hot {
            URGENT_GROW_FAST_INTERVAL
        } else {
            URGENT_GROW_CHECK_INTERVAL
        }
    }
}

/// Whether the urgent grower samples a schema this tick. Half a tick of
/// slack, so a schema read late in one pass is not pushed a whole tick past
/// its cadence by the next.
fn urgent_sample_due(last: Option<&GrowSample>, now: Instant) -> bool {
    last.is_none_or(|s| {
        now.saturating_duration_since(s.at) + URGENT_GROW_FAST_INTERVAL / 2 >= s.every()
    })
}

/// Fold a fresh `(total, used, avail)` reading taken `at` into a schema's
/// sample memory: the fill rate since `prev`, and whether the schema belongs
/// on the fast cadence.
fn next_grow_sample(
    prev: Option<&GrowSample>,
    fs: (u64, u64, u64),
    at: Instant,
    urgent_pct: f64,
) -> GrowSample {
    let (_, used, avail) = fs;
    let rate = prev.and_then(|p| {
        let secs = at.saturating_duration_since(p.at).as_secs_f64();
        (secs > 0.0).then(|| (used as f64 - p.used as f64) / secs)
    });
    let filling = rate.is_some_and(|r| r >= URGENT_GROW_FILLING_BYTES_PER_SEC);
    let near =
        used_pct(used, avail).is_some_and(|pct| pct >= urgent_pct - URGENT_GROW_WATCH_MARGIN_PCT);
    GrowSample {
        used,
        at,
        rate,
        hot: rate.is_none() || filling || near,
    }
}

/// `fs` with `rate` bytes/s of growth over `horizon` moved from avail to used:
/// the filesystem as the next check would find it. A flat, shrinking or
/// unknown rate projects nothing, and growth stops at full.
fn project_fs(fs: (u64, u64, u64), rate: Option<f64>, horizon: Duration) -> (u64, u64, u64) {
    let (total, used, avail) = fs;
    let Some(rate) = rate.filter(|r| *r > 0.0) else {
        return fs;
    };
    let more = ((rate * horizon.as_secs_f64()) as u64).min(avail);
    (total, used + more, avail - more)
}

/// The urgent grower's verdict for one reading: [`grow_verdict`] on the
/// filesystem as it is, or — for a schema filling fast enough to cross the
/// threshold before it is next sampled and stopped — as it will be by then.
/// A projected crossing on a device already at the cap stays `NotNeeded`: the
/// at-cap complaint is for a disk that is actually full.
fn urgent_verdict(
    fs: (u64, u64, u64),
    device_bytes: u64,
    sample: &GrowSample,
    urgent_pct: f64,
    max_gb: u64,
) -> GrowVerdict {
    let current = grow_verdict(fs, device_bytes, urgent_pct, max_gb);
    if current != GrowVerdict::NotNeeded {
        return current;
    }
    let horizon = sample.every() + URGENT_GROW_STOP_MARGIN;
    match grow_verdict(
        project_fs(fs, sample.rate, horizon),
        device_bytes,
        urgent_pct,
        max_gb,
    ) {
        GrowVerdict::AtCap { .. } => GrowVerdict::NotNeeded,
        verdict => verdict,
    }
}

/// Permanently delete sandbox `id` (kill = sandbox + disk; the SDK treats an
/// already-gone sandbox as success).
/// Which VM a manual image archive should target. `recorded` is the registry
/// binding; `viewed` is the VM the dashboard button was pressed on. Returns
/// `(sandbox_id, adopting)`, where `adopting` means the registry has no row
/// for the schema — the caller creates one from the verified archive. A
/// registry binding that contradicts the viewed VM is refused outright: two
/// disks claim the same schema, only one holds the real data, and choosing
/// automatically could archive (and then purge) the wrong bytes.
fn resolve_image_target(
    schema: &str,
    recorded: Option<&str>,
    viewed: Option<&str>,
) -> Result<(String, bool)> {
    match (recorded, viewed) {
        (Some(rec), Some(v)) if rec != v => bail!(
            "schema {schema} is bound to VM {rec} in the registry, but this is VM {v} — \
             two VMs claim this schema and only one disk holds the real data; compare \
             them (or archive from {rec}'s detail page) before touching either"
        ),
        (Some(rec), _) => Ok((rec.to_string(), false)),
        (None, Some(v)) => Ok((v.to_string(), true)),
        (None, None) => bail!(
            "schema {schema} has no VM in the registry and no VM was named — nothing to image"
        ),
    }
}

async fn kill_by_id(id: &str) -> Result<()> {
    let sb = heyo_sdk::Sandbox::connect(id.to_string(), vm::local_opts())
        .context("connecting to sandbox")?;
    sb.kill().await.context("killing sandbox")?;
    crate::inventory::remove_id(id);
    Ok(())
}

/// Best-effort CHECKPOINT over the warm pool, then stop the VM.
///
/// `sandbox.stop()` is an unclean power-off (Postgres never sees a shutdown
/// signal), and the VMs run `synchronous_commit=off` — so without the
/// checkpoint, up to the last ~600ms of acked commits ride on luck and every
/// restart replays WAL back to the previous checkpoint. One CHECKPOINT
/// flushes everything acked and empties the replay queue, making the next
/// boot's recovery a no-op. Best-effort throughout: if the checkpoint fails
/// or times out we stop anyway (crash recovery handles it — that's the
/// design), and a failed stop is logged, not propagated.
///
/// Used by the idle reaper and by the archive/freeze failure paths (a failed
/// dump must not leak the VM it booted).
async fn checkpoint_and_stop(entry: &SchemaEntry, schema: &str) {
    let checkpoint = async {
        let client = entry.pool.get().await?;
        client.batch_execute("CHECKPOINT").await?;
        Ok::<(), anyhow::Error>(())
    };
    match tokio::time::timeout(PRE_STOP_CHECKPOINT_TIMEOUT, checkpoint).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("pre-stop CHECKPOINT for schema {schema} failed: {e:#}"),
        Err(_) => warn!(
            "pre-stop CHECKPOINT for schema {schema} timed out after {PRE_STOP_CHECKPOINT_TIMEOUT:?}"
        ),
    }
    // Bounded: an unbounded stop against a wedged daemon parks the caller
    // forever, and both callers are background passes that must keep moving
    // (see [`IDLE_STOP_TIMEOUT`]). A stop that times out is not lost work —
    // the VM stays running, its warm entry is already gone, and the untracked
    // reaper picks it up on its next pass.
    match tokio::time::timeout(IDLE_STOP_TIMEOUT, entry.sandbox.stop()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!("failed to stop VM for schema {schema}: {e:#}"),
        Err(_) => warn!(
            "stopping VM for schema {schema} timed out after {IDLE_STOP_TIMEOUT:?}; \
             leaving it to the untracked reaper"
        ),
    }
}

/// Run a periodic background pass forever, surviving panics.
///
/// The pooler's reaper and eviction sweep are long-lived `loop { sleep; pass }`
/// tasks. A bare `tokio::spawn`ed loop that panics mid-pass simply vanishes —
/// no restart, only a generic task-drop — so reaping would silently stop for the
/// rest of the process with nothing in the log pointing at it. That is exactly
/// the class of failure we most want to avoid here.
///
/// So each pass runs in its own child task: a panic surfaces as a `JoinError`
/// this supervisor logs loudly and then *continues* from, rather than an abort
/// that kills the loop. Passes stay strictly sequential (the child is awaited
/// before the next tick), so this changes nothing about concurrency — only
/// survivability. Each pass also emits a heartbeat: `debug` every time, and an
/// `info` "still alive" line at most every [`SUPERVISOR_HEARTBEAT`], so a healthy
/// idle loop is visibly live without flooding the log.
///
/// `make_pass` returns the future for one pass; its `usize` output is a count of
/// work done (VMs stopped / schemas archived), surfaced in the heartbeat.
///
/// `first_delay` is how long to wait before the *first* pass; `tick` is the gap
/// between every pass after that. They differ because a long `tick` (the hourly
/// eviction sweep) combined with restarts would otherwise starve the loop: every
/// restart resets the timer, so a pooler redeployed more often than `tick` never
/// runs a single pass. A short `first_delay` makes the first pass land soon after
/// startup regardless. The reaper, whose `tick` is already short, just passes
/// `tick` for both.
async fn supervise<F, Fut>(
    name: &'static str,
    first_delay: Duration,
    tick: Duration,
    make_pass: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = usize> + Send + 'static,
{
    supervise_with_wake(name, first_delay, tick, None, Duration::ZERO, make_pass).await
}

/// [`supervise`] with an optional early-wake handle: a `notify_one` on `wake`
/// ends the current inter-pass wait immediately (or, if it lands mid-pass,
/// the next one — `Notify` stores the permit). Passes stay serialized through
/// this single loop, so an early wake can never race a tick into concurrent
/// passes.
///
/// `wake_floor` is the minimum gap between the end of one pass and the start
/// of the next, whatever the wake handle does. A per-event wake with an
/// expensive pass (the spare replenisher's full daemon listing, woken on
/// every claim) otherwise amplifies a claim storm into a listing storm —
/// exactly when the daemon is busiest. Wakes landing inside the floor
/// coalesce into the one pass that runs when it expires. `Duration::ZERO`
/// disables the floor.
async fn supervise_with_wake<F, Fut>(
    name: &'static str,
    first_delay: Duration,
    tick: Duration,
    wake: Option<Arc<tokio::sync::Notify>>,
    wake_floor: Duration,
    mut make_pass: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = usize> + Send + 'static,
{
    let mut passes: u64 = 0;
    let mut actions: u64 = 0;
    let mut last_beat: Option<Instant> = None;
    let mut last_end: Option<Instant> = None;
    loop {
        let delay = if passes == 0 { first_delay } else { tick };
        match &wake {
            Some(n) => {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = n.notified() => {}
                }
            }
            None => tokio::time::sleep(delay).await,
        }
        if let Some(end) = last_end {
            let since = end.elapsed();
            if since < wake_floor {
                tokio::time::sleep(wake_floor - since).await;
            }
        }
        passes += 1;
        let started = Instant::now();
        match tokio::spawn(make_pass()).await {
            Ok(n) => {
                actions += n as u64;
                let elapsed = started.elapsed();
                debug!("{name}: pass {passes} ok in {elapsed:?} (acted on {n})");
                // Throttle the info-level heartbeat; always beat on the first pass
                // so startup shows the loop is running.
                let due = last_beat.is_none_or(|t| t.elapsed() >= SUPERVISOR_HEARTBEAT);
                if due {
                    info!(
                        "{name}: alive — {passes} pass(es), {actions} action(s) total; \
                         last pass acted on {n} in {elapsed:?}"
                    );
                    last_beat = Some(Instant::now());
                }
            }
            // A panicked pass is isolated to its child task; recover and keep the
            // loop alive so one bad pass never disables reaping for good.
            Err(e) if e.is_panic() => error!(
                "{name}: pass {passes} PANICKED after {:?} — supervisor recovering, \
                 reaping continues: {}",
                started.elapsed(),
                panic_message(e.into_panic()),
            ),
            // Cancellation only happens on runtime shutdown; nothing to recover.
            Err(e) => warn!("{name}: pass {passes} did not complete: {e}"),
        }
        last_end = Some(Instant::now());
    }
}

/// Best-effort human text from a caught panic payload (`&str`/`String`, else a
/// placeholder) for the supervisor's error log.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Clears the `sweeping` flag on drop, so a panic or early return in the middle
/// of a sweep can't leave the registry permanently believing a sweep is running.
/// heyvmd's verdict on one sandbox id, from the authoritative per-id endpoint.
/// `Error` is kept distinct from `Gone` on purpose: only `Gone` may delete, so
/// a flaking daemon can never turn "I can't tell" into a destructive action.
enum DaemonState {
    /// The daemon knows this sandbox. `running` distinguishes a live VM (whose
    /// files are in use) from a stopped record (whose boot-time artefacts are
    /// dead weight — see the rootfs prune in [`SchemaRegistry::sweep_orphans`]).
    Present { running: bool },
    Gone,
    Error,
}

/// Advance the orphan sweep's daemon-error breaker by one probe. `run` is the
/// consecutive-error count carried through classification; reaching
/// [`ORPHAN_MAX_DAEMON_ERRORS`] aborts the pass.
///
/// Only an indeterminate `Error` extends the run. `Present` and `Gone` are both
/// answers from a daemon that is plainly responding, so either one clears it —
/// the breaker exists to catch a daemon that has stopped answering, not to
/// count how far apart two orphans are. The match is exhaustive on purpose: a
/// new [`DaemonState`] variant has to state which side of that line it is on.
fn daemon_error_run(run: usize, state: &DaemonState) -> usize {
    match state {
        DaemonState::Error => run + 1,
        DaemonState::Present { .. } | DaemonState::Gone => 0,
    }
}

/// Per-schema bring-up circuit breaker.
///
/// A failed bring-up is expensive — a cold create, or a 30+ minute S3 image
/// download — and a client that reconnects on every failure turns one broken
/// schema into a standing storm: another VM, another download, another
/// failure, forever (observed: ~14 concurrent `pg-<schema>` VMs for one
/// schema). After the first failure the schema is held off with a fast
/// explicit error: 1m, then 2m, 4m, … capped at [`BRINGUP_BREAKER_CAP`]. A
/// successful bring-up clears it. In-memory only (a pooler restart resets
/// it — fine: the hold exists to stop a tight loop, not to remember history).
#[derive(Default)]
struct BringupBreaker {
    state: StdMutex<HashMap<String, (u32, Instant)>>,
}

const BRINGUP_BREAKER_BASE: Duration = Duration::from_secs(60);
const BRINGUP_BREAKER_CAP: Duration = Duration::from_secs(15 * 60);

impl BringupBreaker {
    fn hold_for(failures: u32) -> Duration {
        let exp = failures.saturating_sub(1).min(10);
        (BRINGUP_BREAKER_BASE * 2u32.pow(exp)).min(BRINGUP_BREAKER_CAP)
    }

    /// `Some((failures, remaining))` while the schema is being held off.
    fn holding(&self, schema: &str) -> Option<(u32, Duration)> {
        let state = self.state.lock().unwrap();
        let (failures, last) = state.get(schema)?;
        let hold = Self::hold_for(*failures);
        let since = last.elapsed();
        (since < hold).then(|| (*failures, hold - since))
    }

    /// Returns `(consecutive failures, hold applied)`.
    fn record_failure(&self, schema: &str) -> (u32, Duration) {
        let mut state = self.state.lock().unwrap();
        let entry = state.entry(schema.to_string()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
        (entry.0, Self::hold_for(entry.0))
    }

    fn clear(&self, schema: &str) {
        self.state.lock().unwrap().remove(schema);
    }
}

struct SweepGuard<'a>(&'a AtomicBool);

impl Drop for SweepGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// What one drain-loop offload job came to, for the failure circuit breaker:
/// a benign claim race is neither success nor failure.
enum JobOutcome {
    Done,
    Skipped,
    Failed,
}

/// Sentinel for a benign claim conflict: the schema is already being offloaded
/// by someone else (another dispatcher worker, the pressure pass, a dashboard
/// button). Losing that race is normal under concurrent workers, not a schema
/// failure — callers downcast for this to skip the failure backoff and the
/// error journal, and the pressure pass doesn't count it toward its
/// consecutive-failure circuit breaker.
#[derive(Debug)]
struct AlreadyOffloading;

impl std::fmt::Display for AlreadyOffloading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another offload of this schema is already in flight")
    }
}

impl std::error::Error for AlreadyOffloading {}

/// RAII claim on the `archiving` set: inserts on `claim`, removes on `Drop`, so
/// a schema is never left stuck "archiving" if the operation errors or panics.
struct ArchivingGuard<'a> {
    set: &'a StdMutex<HashSet<String>>,
    schema: String,
}

impl<'a> ArchivingGuard<'a> {
    /// `Some` if this call inserted the schema; `None` if it was already present
    /// (another archive is in flight).
    fn claim(set: &'a StdMutex<HashSet<String>>, schema: &str) -> Option<Self> {
        if set.lock().unwrap().insert(schema.to_string()) {
            Some(Self {
                set,
                schema: schema.to_string(),
            })
        } else {
            None
        }
    }

    /// Whether this is the still-live claim for exactly `schema` in `set`.
    /// Checking both identities prevents a claim for another registry or
    /// schema from becoming a general maintenance bypass.
    fn owns(&self, set: &StdMutex<HashSet<String>>, schema: &str) -> bool {
        std::ptr::eq(self.set, set) && self.schema == schema
    }
}

impl Drop for ArchivingGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.schema);
    }
}

/// Normalized host load: the 1-minute loadavg divided by online cores, `None`
/// when it can't be read (no /proc — non-Linux dev hosts). Linux load counts
/// tasks in uninterruptible I/O sleep as well as runnable ones, so this rises
/// under disk saturation too — exactly the two resources an extra offload
/// worker would fight clients for.
fn normalized_load() -> Option<f64> {
    let load1: f64 = std::fs::read_to_string("/proc/loadavg")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let cores = std::thread::available_parallelism().ok()?.get() as f64;
    Some(load1 / cores)
}

/// Why the offload pacer is not dispatching (see
/// [`SchemaRegistry::dispatch_backpressure`]). Split by *kind* because only
/// one of them is negotiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backpressure {
    /// A client is parked waiting for a bring-up slot. Pure politeness: a job
    /// that boots no VM takes nothing that client is queued for, so a pacer
    /// starved this way past `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` may
    /// dispatch one no-boot job at a time anyway rather than let the backlog
    /// (and the disk) grow until the host happens to go quiet.
    ClientsQueued,
    /// A reclaim pass is fsck'ing/shrinking disks an offload would read.
    ///
    /// Deferring on it is a *progress* choice, not a safety one: the actual
    /// exclusion is per disk, taken by the job itself
    /// (`reclaim::try_disk_permit`, which never preempts a pass), so the worst
    /// a dispatch during a pass can do is find the one disk it wanted busy and
    /// skip that schema. What deferring buys is that the pass keeps its
    /// progress instead of the two of them trading disks — worth having while
    /// there is any other time to run, which is why this defers by default.
    ///
    /// It is overridable for the same reason [`Self::ClientsQueued`] is, and
    /// it matters more: a pass runs up to `RECLAIM_TIMEOUT` (30 minutes) and
    /// is re-triggered 30s after every idle reap, so on a churning host
    /// "later" was very nearly never — the pacer would stand down host-wide
    /// for most of the day while the disk it was supposed to be freeing
    /// climbed toward the pressure mark. Forced dispatches here are no-boot
    /// kinds only, single file, exactly as for queued clients.
    ReclaimPass,
    /// A manual or disk-pressure sweep is already draining through the same
    /// picker. Overriding it would only double-dispatch against the claims it
    /// already holds.
    Sweeping,
}

impl Backpressure {
    fn reason(self) -> &'static str {
        match self {
            Backpressure::ClientsQueued => "client bring-ups are queued",
            Backpressure::ReclaimPass => "a disk-reclaim pass is running",
            Backpressure::Sweeping => "a manual sweep is running",
        }
    }
}

/// May the dispatcher start another offload job right now? The first job is
/// always allowed (parity with the classic single pacer, which had no load
/// gate); every extra one requires both a free worker slot and known load
/// headroom — an unreadable load means no extras, never a stampede.
/// The starvation escape hatch: may the pacer dispatch a job even though
/// `bp` says the host is busy? `held` is how long the current unbroken stretch
/// of backpressure has run and `idle` whether the pacer has nothing in flight.
///
/// Three conditions, each load-bearing: the backpressure must be one of the
/// negotiable kinds (see [`Backpressure`] — `Sweeping` never is, because
/// overriding it would only double-dispatch against claims the sweep already
/// holds), only a pacer with nothing in flight may force one (so the override
/// can never stack), and only past the operator's holdoff — `None` keeps the
/// historical behavior of yielding forever.
///
/// Both negotiable kinds are counted by the same `held` clock on purpose. They
/// alternate on a busy host — clients queue, a reap fires a reclaim pass,
/// clients queue again — and a clock that reset on every changeover would
/// never reach the holdoff at all, which is exactly how the pacer could go
/// hours without dispatching while neither condition alone looked pathological.
fn forced_dispatch(
    bp: Backpressure,
    held: Duration,
    idle: bool,
    max_holdoff: Option<Duration>,
) -> bool {
    matches!(
        bp,
        Backpressure::ClientsQueued | Backpressure::ReclaimPass
    ) && idle
        && max_holdoff.is_some_and(|limit| held >= limit)
}

fn dispatch_allowance(in_flight: usize, workers: usize, load: Option<f64>, load_max: f64) -> bool {
    if in_flight >= workers {
        return false;
    }
    if in_flight == 0 {
        return true;
    }
    load.is_some_and(|l| l < load_max)
}

/// The password to challenge `role` with, composing the two credential
/// stores. Free-standing so the ordering can be tested without a registry.
fn challenge_password_in(
    repl: &crate::replication::ReplStore,
    ded: &Credentials,
    shared: Option<&str>,
    role: &str,
) -> Option<String> {
    repl.repl_password(role)
        .or_else(|| ded.password_for_role(role))
        .or_else(|| shared.map(str::to_string))
}

/// Whether `role` may route to `database`, composing the two stores.
///
/// The replication lookup must come **first**. A replication login's database
/// is by definition a dedicated one, so delegating first would have
/// `Credentials::authorize` reject it under "this database is dedicated and
/// can only be opened by its own role" — which is the one database it exists
/// to reach.
fn authorize_route_in(
    repl: &crate::replication::ReplStore,
    ded: &Credentials,
    role: &str,
    database: &str,
    physical: bool,
) -> Result<String, String> {
    if let Some(rec) = repl.by_repl_role(role) {
        if physical {
            // PostgreSQL discards the database parameter for a physical
            // walsender. pg_basebackup/walreceiver normally send "replication".
            // Only the already-authenticated replication identity selects a VM.
            return if rec.role == crate::replication::Role::Primary && rec.state.pins() {
                Ok(rec.database)
            } else {
                Err("physical replication requires a live primary pairing".into())
            };
        }
        return if rec.database == database {
            Ok(database.into())
        } else {
            Err(format!(
                "role \"{role}\" is a replication login for database \"{}\" only \
                 and cannot open any other database",
                rec.database
            ))
        };
    }
    if physical {
        return Err("physical replication requires a registered replication login".into());
    }
    ded.authorize(role, database).map(|()| database.into())
}

#[cfg(test)]
mod auth_composition_tests {
    use super::*;
    use crate::replication::{ReplRecord, ReplStore, Role, State};

    fn stores(tag: &str) -> (ReplStore, Credentials) {
        let dir = std::env::temp_dir();
        let stamp = format!("{}-{:?}-{tag}", std::process::id(), std::thread::current().id());
        let rp = dir.join(format!("pgvmpool-authrepl-{stamp}.tsv"));
        let dp = dir.join(format!("pgvmpool-authded-{stamp}.tsv"));
        let _ = std::fs::remove_file(&rp);
        let _ = std::fs::remove_file(&dp);
        let repl = ReplStore::load(rp);
        let ded = Credentials::load(dp);
        ded.create("acme", "acme", "tenantpassword").unwrap();
        let mut rec = ReplRecord::new("acme", Role::Primary, "node_b", "replpassword12");
        rec.state = State::Active;
        repl.create(rec, &|r| ded.by_role(r).is_some()).unwrap();
        (repl, ded)
    }

    #[test]
    fn each_login_is_challenged_with_its_own_password() {
        let (repl, ded) = stores("challenge");
        let shared = Some("sharedpassword");
        assert_eq!(
            challenge_password_in(&repl, &ded, shared, "acme_pgfcrepl").as_deref(),
            Some("replpassword12")
        );
        assert_eq!(
            challenge_password_in(&repl, &ded, shared, "acme").as_deref(),
            Some("tenantpassword")
        );
        assert_eq!(
            challenge_password_in(&repl, &ded, shared, "postgres").as_deref(),
            Some("sharedpassword")
        );
        // No shared password configured is the loopback default: no gate for
        // an unknown role, but a replication login is still challenged, so
        // enabling replication adds a gate where there was none.
        assert_eq!(challenge_password_in(&repl, &ded, None, "postgres"), None);
        assert_eq!(
            challenge_password_in(&repl, &ded, None, "acme_pgfcrepl").as_deref(),
            Some("replpassword12")
        );
    }

    #[test]
    fn a_replication_login_reaches_its_own_dedicated_database_and_nothing_else() {
        let (repl, ded) = stores("authorize");
        // The regression this ordering exists to prevent: `acme` IS a
        // dedicated database, so delegating to `Credentials::authorize` first
        // would reject the very login that has to reach it.
        assert!(authorize_route_in(&repl, &ded, "acme_pgfcrepl", "acme", false).is_ok());
        let err = authorize_route_in(&repl, &ded, "acme_pgfcrepl", "other", false).unwrap_err();
        assert!(err.contains("replication login"), "{err}");
        // Everything the dedicated rules already guaranteed still holds.
        assert!(authorize_route_in(&repl, &ded, "acme", "acme", false).is_ok());
        assert!(authorize_route_in(&repl, &ded, "acme", "other", false).is_err());
        assert!(authorize_route_in(&repl, &ded, "postgres", "acme", false).is_err());
        assert!(authorize_route_in(&repl, &ded, "postgres", "tenant1", false).is_ok());
    }

    #[test]
    fn physical_replication_routes_by_identity_not_claimed_database() {
        let (repl, ded) = stores("physical");
        for claimed in ["replication", "other_tenant", "postgres", "acme"] {
            assert_eq!(authorize_route_in(&repl, &ded, "acme_pgfcrepl", claimed, true).unwrap(), "acme");
        }
        for user in ["acme", "postgres", "unknown"] {
            assert!(authorize_route_in(&repl, &ded, user, "acme", true).is_err());
        }
        let mut replica = ReplRecord::new("standby", Role::Replica, "node_a", "replpassword34");
        replica.state = State::Active;
        repl.create(replica, &|r| ded.by_role(r).is_some()).unwrap();
        assert!(authorize_route_in(&repl, &ded, "standby_pgfcrepl", "replication", true).is_err());
        repl.set_state("acme", State::Detached, "test detached pairing").unwrap();
        assert!(authorize_route_in(&repl, &ded, "acme_pgfcrepl", "replication", true).is_err());
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One unit of offload work: move this schema one step down the ladder.
#[derive(Debug, PartialEq)]
struct OffloadJob {
    schema: String,
    kind: OffloadKind,
}

/// One step down the storage ladder.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum OffloadKind {
    /// Upload an already-offloaded schema's local file to S3 and delete it.
    /// No VM, no dump — a file upload that frees local disk outright.
    Promote,
    /// Image a stopped VM's disk to a local zstd file and delete the VM.
    /// Seconds of CPU, no boot, and it frees the whole ext4.
    Compact,
    /// Trim + compress a stopped VM's disk straight to S3 and delete the VM.
    /// Like `Compact` in cost and in needing no boot, but it leaves nothing
    /// behind on the host at all. Pressure-only, and only where the image
    /// tier is configured.
    ImageArchive,
    /// Dump a schema to S3 and delete its VM. Frees the most, costs the most
    /// (boot + `pg_dump` + upload).
    Archive,
    /// Dump a schema to a local file and delete its VM. Same cost as an
    /// archive but keeps the bytes on this host.
    Freeze,
}

impl OffloadKind {
    fn as_str(self) -> &'static str {
        match self {
            OffloadKind::Promote => "promoting",
            OffloadKind::Compact => "compacting",
            OffloadKind::ImageArchive => "image-archiving",
            OffloadKind::Archive => "archiving",
            OffloadKind::Freeze => "freezing",
        }
    }

    /// Whether this kind boots a VM to do its work — and therefore competes
    /// with waiting clients for the FIFO bring-up gate. The dispatcher caps
    /// boot kinds at one in flight however many workers are configured.
    /// (`pick_offload_job` only emits Archive/Freeze for `Tier::Live`
    /// records, so kind ⇒ boot is exact.)
    fn boots(self) -> bool {
        matches!(self, OffloadKind::Archive | OffloadKind::Freeze)
    }

    /// Preference order (lower wins) when several schemas are eligible at
    /// once. It differs by mode because the two modes optimise for different
    /// things — see [`OffloadMode`].
    fn rank(self, mode: OffloadMode) -> u8 {
        match mode {
            // Routine: cheapest-first. A promotion is a file upload that frees
            // local disk outright, so it goes before anything that touches a
            // VM; a dump-based archive beats a freeze because it gets the
            // bytes off the host.
            OffloadMode::Routine => match self {
                OffloadKind::Promote => 0,
                OffloadKind::Compact => 1,
                OffloadKind::ImageArchive => 2,
                OffloadKind::Archive => 3,
                OffloadKind::Freeze => 4,
            },
            // Pressure: bytes-per-second-of-work, and never boot a VM if
            // there is any alternative. Compacting frees ~96% of a schema's
            // footprint in about three seconds of CPU with no daemon call at
            // all; a promotion frees only the (already tiny) image; the
            // boot-and-dump path goes last because on a nearly-full host it is
            // both the slowest and the likeliest to fail — booting needs a
            // ~200MB rootfs clone that the disk may not have room for.
            OffloadMode::Pressure => match self {
                OffloadKind::Compact => 0,
                OffloadKind::ImageArchive => 1,
                OffloadKind::Promote => 2,
                OffloadKind::Archive => 3,
                OffloadKind::Freeze => 4,
            },
        }
    }
}

/// Why the pacer is picking work, which changes both what is eligible and
/// which job wins.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
enum OffloadMode {
    /// Routine housekeeping against the configured idle thresholds.
    #[default]
    Routine,
    /// The disk is past its high-water mark. Thresholds are ignored (every
    /// schema without live sessions is a candidate, coldest first) and the
    /// ranking shifts to whatever frees the most, fastest, without a boot.
    Pressure,
}

/// What the picker is allowed to propose: the configured idle thresholds in
/// seconds (`None` = that tier is off), plus the mode.
#[derive(Debug, Default, Clone, Copy)]
struct OffloadPolicy {
    compact_after: Option<u64>,
    freeze_after: Option<u64>,
    archive_after: Option<u64>,
    /// Whether the no-boot image archive is available (`PG_VM_POOL_IMAGE_ARCHIVE`
    /// + the S3 tier + a run dir). Only ever offered under pressure.
    image_archive: bool,
    /// When set, VM-booting kinds (archive/freeze) are ineligible this pick.
    /// The dispatcher sets it while a boot-kind job is already in flight so
    /// that at most one offload at a time competes with clients for the
    /// bring-up gate. Default `false` = all kinds allowed.
    no_boot: bool,
    mode: OffloadMode,
}

/// Pick the single best offload job across the whole registry, plus the
/// schemas whose durable `last_active` should be refreshed (they look stale
/// but are actually warm). Pure, so the tier ladder and its precedence are
/// testable without a registry, a daemon, or a clock.
///
/// Ties break toward the *coldest* schema: with a backlog, the one nobody has
/// touched in longest is both the least likely to be needed back and the one
/// whose disk has been dead weight longest.
fn pick_offload_job(
    records: &[(String, StoreRecord)],
    live: &HashMap<String, (usize, u64)>,
    t: OffloadPolicy,
    keepalive: &dyn Fn(&str) -> bool,
    backing_off: &dyn Fn(&str) -> bool,
    now: u64,
) -> (Option<OffloadJob>, Vec<String>) {
    let mut best: Option<(u8, u64, &str, OffloadKind)> = None;
    let mut refresh: Vec<String> = Vec::new();
    for (schema, rec) in records {
        if keepalive(schema) || backing_off(schema) {
            continue;
        }
        let idle = now.saturating_sub(rec.last_active);
        let warm = live.get(schema).copied();
        let kind = match rec.tier {
            // Already in S3 — the bottom of the ladder.
            Tier::Archived => continue,
            // Offloaded locally: the only remaining step is promotion, and
            // only once it is cold enough for the S3 threshold.
            Tier::Frozen | Tier::Compacted => match t.archive_after {
                Some(after) if idle >= after => OffloadKind::Promote,
                _ => continue,
            },
            Tier::Live => {
                let eligible = |after: Option<u64>, cross_check: Option<(usize, u64)>| {
                    after.is_some_and(|after| {
                        classify_candidate(rec, false, now, after, cross_check)
                            == SweepAction::Archive
                    })
                };
                // Compaction additionally requires no warm entry at all: a
                // warm entry means a VM process may still hold the disk open,
                // and the idle reaper (timeout far shorter than any sensible
                // compact threshold) stops those first. Waiting a scan is
                // cheaper than stalling in the disk-release wait.
                let compactable = warm.is_none() && eligible(t.compact_after, None);
                // The image archive is the other no-boot route off a stopped
                // disk, and the only one that leaves nothing behind. Same
                // warm-entry rule, for the same reason.
                let imageable = t.image_archive
                    && t.mode == OffloadMode::Pressure
                    && warm.is_none()
                    && eligible(t.archive_after, None);
                if compactable {
                    OffloadKind::Compact
                } else if imageable {
                    OffloadKind::ImageArchive
                } else if !t.no_boot && eligible(t.archive_after, warm) {
                    OffloadKind::Archive
                } else if !t.no_boot && eligible(t.freeze_after, warm) {
                    OffloadKind::Freeze
                } else {
                    // Durably stale but actually live: keep its clock honest
                    // so it isn't re-evaluated as a candidate every scan.
                    let stale_but_warm = [t.compact_after, t.archive_after, t.freeze_after]
                        .into_iter()
                        .flatten()
                        .any(|after| {
                            classify_candidate(rec, false, now, after, warm) == SweepAction::Refresh
                        });
                    if stale_but_warm {
                        refresh.push(schema.clone());
                    }
                    continue;
                }
            }
        };
        let rank = kind.rank(t.mode);
        if best.is_none_or(|(br, bi, _, _)| (rank, Reverse(idle)) < (br, Reverse(bi))) {
            best = Some((rank, idle, schema, kind));
        }
    }
    let job = best.map(|(_, _, schema, kind)| OffloadJob {
        schema: schema.to_string(),
        kind,
    });
    (job, refresh)
}

/// What the archive sweep should do with one schema.
#[derive(Debug, PartialEq)]
enum SweepAction {
    /// Not a candidate (keepalive, already archived, or not idle long enough).
    Skip,
    /// Durably stale but actually live (warm with sessions, or a young in-memory
    /// idle clock) — refresh its `last_active` and leave it running.
    Refresh,
    /// Genuinely cold: offload to S3 and kill the VM.
    Archive,
}

/// Pure decision for one schema, factored out of [`SchemaRegistry::sweep_archive`]
/// so the cross-check between durable and live state is testable. `live` is the
/// schema's warm `(active_sessions, in_memory_idle_secs)` if it's in the map.
fn classify_candidate(
    rec: &StoreRecord,
    keepalive: bool,
    now: u64,
    threshold_secs: u64,
    live: Option<(usize, u64)>,
) -> SweepAction {
    if rec.offloaded() || keepalive {
        return SweepAction::Skip;
    }
    if now.saturating_sub(rec.last_active) < threshold_secs {
        return SweepAction::Skip;
    }
    if let Some((active, idle_secs)) = live
        && (active > 0 || idle_secs < threshold_secs)
    {
        return SweepAction::Refresh;
    }
    SweepAction::Archive
}

#[cfg(test)]
mod archive_tests {
    use super::*;

    fn rec(last_active: u64, archived: bool) -> StoreRecord {
        StoreRecord {
            sandbox_id: "sb-x".into(),
            last_active,
            tier: if archived { Tier::Archived } else { Tier::Live },
            disk_gb: 0,
            bringup: None,
        }
    }

    #[test]
    fn classify_candidate_covers_the_cross_check() {
        let now = 1_000_000;
        let week = 604_800;

        // Cold and stopped (not in the warm map) → archive.
        assert_eq!(
            classify_candidate(&rec(now - week - 1, false), false, now, week, None),
            SweepAction::Archive
        );
        // Not idle long enough → skip.
        assert_eq!(
            classify_candidate(&rec(now - 10, false), false, now, week, None),
            SweepAction::Skip
        );
        // Already archived → skip (don't re-archive).
        assert_eq!(
            classify_candidate(&rec(now - week - 1, true), false, now, week, None),
            SweepAction::Skip
        );
        // Keepalive schema → never archived, however stale.
        assert_eq!(
            classify_candidate(&rec(0, false), true, now, week, None),
            SweepAction::Skip
        );
        // Durably stale but warm with a live session → refresh, don't archive
        // (a long-lived single connection with no new checkouts).
        assert_eq!(
            classify_candidate(&rec(now - week - 1, false), false, now, week, Some((1, week + 5))),
            SweepAction::Refresh
        );
        // Durably stale, warm, no sessions, but in-memory idle clock is young →
        // refresh (it's genuinely been used recently).
        assert_eq!(
            classify_candidate(&rec(now - week - 1, false), false, now, week, Some((0, 30))),
            SweepAction::Refresh
        );
        // Durably stale, warm, no sessions, and in-memory idle also past the
        // threshold → archive.
        assert_eq!(
            classify_candidate(&rec(now - week - 1, false), false, now, week, Some((0, week + 5))),
            SweepAction::Archive
        );
    }

    // ---- offload pacer job selection ----------------------------------------

    const NOW: u64 = 10_000_000;
    /// compact at 1h, archive at 1d — the shipped shape.
    const LADDER: OffloadPolicy = OffloadPolicy {
        compact_after: Some(3600),
        freeze_after: None,
        archive_after: Some(86_400),
        image_archive: false,
        no_boot: false,
        mode: OffloadMode::Routine,
    };

    fn tiered(tier: Tier, idle: u64) -> StoreRecord {
        StoreRecord {
            sandbox_id: "sb-x".into(),
            last_active: NOW - idle,
            tier,
            disk_gb: 0,
            bringup: None,
        }
    }

    fn pick(
        records: &[(String, StoreRecord)],
        live: &HashMap<String, (usize, u64)>,
        t: OffloadPolicy,
    ) -> Option<OffloadJob> {
        pick_offload_job(records, live, t, &|_| false, &|_| false, NOW).0
    }

    fn schemas(names: &[(&str, Tier, u64)]) -> Vec<(String, StoreRecord)> {
        names
            .iter()
            .map(|(n, tier, idle)| ((*n).to_string(), tiered(*tier, *idle)))
            .collect()
    }

    // ---- dispatcher worker-pool seams ---------------------------------------

    /// Concurrent workers exclude in-flight schemas through the same predicate
    /// as backoff: with the top-ranked schema excluded, the picker returns the
    /// next-best job instead of re-picking the same one forever.
    #[test]
    fn bringup_breaker_holds_then_clears() {
        let b = BringupBreaker::default();
        assert!(b.holding("a").is_none());
        assert_eq!(b.record_failure("a"), (1, Duration::from_secs(60)));
        assert_eq!(b.record_failure("a").1, Duration::from_secs(120));
        assert_eq!(b.record_failure("a").1, Duration::from_secs(240));
        let (n, remaining) = b.holding("a").expect("held after failures");
        assert_eq!(n, 3);
        assert!(remaining <= Duration::from_secs(240));
        // Exponent is capped, not overflowed, and the hold is capped at 15m.
        for _ in 0..40 {
            b.record_failure("a");
        }
        assert_eq!(b.holding("a").unwrap().1.as_secs().div_ceil(60), 15);
        // Other schemas are independent; success clears.
        assert!(b.holding("b").is_none());
        b.clear("a");
        assert!(b.holding("a").is_none());
    }

    /// The two-speed reaper's whole policy: price the warm hold off what the
    /// bring-up actually cost. The failure it exists for is a fleet of VMs
    /// that are cheap to restart sitting warm for the timeout a *create*
    /// deserves, holding RAM and disks the reclaim and offload ladders cannot
    /// touch until the VM is stopped.
    #[test]
    fn idle_budget_prices_the_warm_hold_off_the_measured_bringup() {
        let normal = Duration::from_secs(900);
        let fast = Some(Duration::from_secs(60));
        let threshold = Duration::from_secs(5);
        let budget = |took: u64| idle_budget(Duration::from_secs(took), normal, fast, threshold);

        // A restart of a VM still on disk: ~200ms, so a 900s hold buys the
        // next client 200ms. Short budget.
        assert_eq!(
            idle_budget(Duration::from_millis(200), normal, fast, threshold),
            Duration::from_secs(60)
        );
        // The boundary is inclusive — a bring-up exactly at the threshold is
        // still a cheap one.
        assert_eq!(budget(5), Duration::from_secs(60));
        // A create, a spare claim that had to initdb, an S3 thaw: expensive,
        // so the full hold is worth paying for.
        assert_eq!(budget(6), normal);
        assert_eq!(budget(40), normal);

        // The load backstop, which is why this is measured rather than keyed
        // on "was the VM already on disk". A saturated heyvmd turns a 200ms
        // restart into seconds; those VMs fall back to the long hold on their
        // own, so the reaper stops adding stop/start work to a daemon that is
        // already behind.
        assert_eq!(budget(30), normal);

        // Disabled: one timeout for everything, whatever the bring-up cost.
        assert_eq!(idle_budget(Duration::from_millis(200), normal, None, threshold), normal);
    }

    /// The sawtooth fix. A flat per-pass cap does not decide the drain shape:
    /// any cohort bigger than the cap keeps the reaper saturated at
    /// cap-per-tick regardless of how the deadlines spread, which is why
    /// widening the jitter cannot fix a mass expiry and bounding the rate can.
    #[test]
    fn drain_allowance_is_a_constant_slope_bounded_both_ways() {
        let tick = Duration::from_secs(15);
        let window = Some(Duration::from_secs(600));
        let a = |live| drain_allowance(live, tick, window);

        // live * tick / window, so the whole fleet takes one window to drain.
        assert_eq!(a(600), 15, "600 live over 600s at a 15s tick");
        assert_eq!(a(400), 10);

        // Floored: a small fleet is not a swing, so don't smooth it into one.
        assert_eq!(a(0), IDLE_MIN_STOPS_PER_PASS);
        assert_eq!(a(10), IDLE_MIN_STOPS_PER_PASS);

        // Ceilinged: the daemon's protection wins over the window, and a fleet
        // that big just drains over longer than the window.
        assert_eq!(a(100_000), IDLE_MAX_STOPS_PER_PASS);

        // Never zero while a window is set — a fractional allowance rounds up,
        // or the reaper would stall entirely on a tiny fleet.
        assert!(drain_allowance(1, Duration::from_secs(1), Some(Duration::from_secs(86_400))) >= 1);

        // Disabled: the flat ceiling, i.e. the pre-window behaviour.
        assert_eq!(drain_allowance(10_000, tick, None), IDLE_MAX_STOPS_PER_PASS);
        assert_eq!(
            drain_allowance(10_000, tick, Some(Duration::ZERO)),
            IDLE_MAX_STOPS_PER_PASS
        );
    }

    /// The property that actually matters to an operator watching a chart:
    /// draining a synchronized cohort must be a straight line, not a spike
    /// followed by a tail. That is why the allowance is sized off the
    /// live-tier count (which a stop does not change) and not the warm count
    /// (which shrinks under it, decaying the slope).
    #[test]
    fn a_synchronized_cohort_drains_as_a_ramp_not_a_cliff() {
        let tick = Duration::from_secs(15);
        let window = Some(Duration::from_secs(600));
        let live = 600;

        // Constant divisor ⇒ every pass of the drain gets the same allowance.
        let rates: Vec<usize> = (0..=live)
            // The point of the constant case: how many have already stopped
            // does not enter into it.
            .step_by(15)
            .map(|_stopped| drain_allowance(live, tick, window))
            .collect();
        assert!(
            rates.windows(2).all(|w| w[0] == w[1]),
            "the slope must not change as the cohort drains: {rates:?}"
        );

        // Had it been sized off the shrinking warm count, the rate would decay
        // — this is the shape being rejected, asserted so nobody reintroduces
        // it thinking the two are equivalent.
        let decaying: Vec<usize> = (0..=live)
            .step_by(15)
            .map(|stopped| drain_allowance(live - stopped, tick, window))
            .collect();
        assert!(
            decaying.first() > decaying.last(),
            "sanity: warm-count sizing really does decay: {decaying:?}"
        );

        // And the ramp is long enough to read as one: a full drain takes about
        // the window, never a handful of passes.
        let passes = live.div_ceil(drain_allowance(live, tick, window));
        let secs = passes as u64 * tick.as_secs();
        assert!((540..=660).contains(&secs), "drain took {secs}s, want ~600s");
    }

    /// End-to-end drain shape through the real `drain_allowance`, not a model
    /// of it: a cohort that all comes due at once must leave the fleet on a
    /// straight line whose per-minute peak is close to its median. The old
    /// flat cap is run alongside on the same cohort so the regression this
    /// fixes stays visible if anyone reverts the policy.
    #[test]
    fn a_mass_expiry_leaves_at_a_steady_rate() {
        let tick = Duration::from_secs(15);
        let live = 600usize;

        /// Drain `n` VMs, `per_pass` at a time, returning stops per minute.
        fn per_minute(n: usize, per_pass: usize, tick: Duration) -> Vec<usize> {
            let passes_per_min = (60 / tick.as_secs().max(1)) as usize;
            let mut left = n;
            let mut out = Vec::new();
            while left > 0 {
                let mut minute = 0;
                for _ in 0..passes_per_min {
                    let take = per_pass.min(left);
                    left -= take;
                    minute += take;
                }
                out.push(minute);
            }
            out
        }

        let limited = per_minute(
            live,
            drain_allowance(live, tick, Some(Duration::from_secs(600))),
            tick,
        );
        let flat = per_minute(live, drain_allowance(live, tick, None), tick);

        let peak = *limited.iter().max().unwrap();
        // Every full minute of the ramp moves the same number of VMs, so peak
        // and median coincide — that is what "a ramp, not a cliff" means.
        assert_eq!(peak, 60, "600 live / 600s window = 60 VMs a minute");
        assert!(limited.len() >= 9, "drain spans ~10 minutes, got {}", limited.len());

        // The policy this replaces runs every fleet at the ceiling regardless
        // of its size, which is the cliff. At 600 live the gap is 96 vs 60 a
        // minute; the gap widens as the fleet gets smaller, because the flat
        // cap does not scale down and the window does.
        assert_eq!(*flat.iter().max().unwrap(), 96);
        assert!(peak < *flat.iter().max().unwrap());
        let small = drain_allowance(120, tick, Some(Duration::from_secs(600)));
        assert_eq!(small * 4, 16, "120 live drains at 16/min, not the flat 96");
    }

    #[test]
    fn jittered_timeout_is_stable_bounded_and_spread() {
        let base = Duration::from_secs(1000);
        let a = jittered_timeout("acme", base);
        // Deterministic: same schema, same answer.
        assert_eq!(a, jittered_timeout("acme", base));
        // Bounded to [0.85, 1.15) x base for any schema.
        let mut distinct = std::collections::HashSet::new();
        for i in 0..100 {
            let t = jittered_timeout(&format!("schema-{i}"), base);
            assert!(t >= Duration::from_secs(850), "{t:?} below floor");
            assert!(t < Duration::from_secs(1150), "{t:?} above ceiling");
            distinct.insert(t);
        }
        // And actually spread, not collapsed onto a few values.
        assert!(distinct.len() > 50, "only {} distinct timeouts", distinct.len());
    }

    #[test]
    fn in_flight_exclusion_yields_the_second_best_job() {
        let ready = schemas(&[
            ("busy", Tier::Live, 300_000), // coldest — would win unexcluded
            ("next", Tier::Live, 200_000),
        ]);
        let live = HashMap::new();
        let (job, _) = pick_offload_job(&ready, &live, LADDER, &|_| false, &|s| s == "busy", NOW);
        let job = job.unwrap();
        assert_eq!(job.schema, "next");
        assert_eq!(job.kind, OffloadKind::Compact);
    }

    /// `no_boot` fences off the VM-booting kinds (archive/freeze) while a
    /// boot-kind job is in flight — no-boot work still flows, and the
    /// stale-but-warm refresh still fires.
    #[test]
    fn no_boot_policy_skips_dump_kinds_but_not_compact_or_promote() {
        let fenced = OffloadPolicy { no_boot: true, ..LADDER };
        let no_live: HashMap<String, (usize, u64)> = HashMap::new();

        // Warm (so not compactable) and cold enough to archive: the fence
        // withholds it entirely...
        let warm: HashMap<String, (usize, u64)> = [("w".to_string(), (0, 90_000))].into();
        let recs = schemas(&[("w", Tier::Live, 90_000)]);
        assert!(pick(&recs, &warm, fenced).is_none());
        // ...where the plain policy would dump it.
        assert_eq!(pick(&recs, &warm, LADDER).unwrap().kind, OffloadKind::Archive);

        // Compact and promote are untouched by the fence.
        let ready = schemas(&[("p", Tier::Frozen, 90_000), ("c", Tier::Live, 7200)]);
        assert_eq!(pick(&ready, &no_live, fenced).unwrap().kind, OffloadKind::Promote);
        assert_eq!(pick(&ready[1..], &no_live, fenced).unwrap().kind, OffloadKind::Compact);

        // A durably-stale-but-actually-warm schema still gets its clock
        // refreshed under the fence (nothing eligible, refresh intact).
        let young_warm: HashMap<String, (usize, u64)> = [("w".to_string(), (0, 30))].into();
        let (job, refresh) =
            pick_offload_job(&recs, &young_warm, fenced, &|_| false, &|_| false, NOW);
        assert!(job.is_none());
        assert_eq!(refresh, vec!["w".to_string()]);
    }

    /// The load gate: the first job is always allowed; extras need a free
    /// worker slot AND known headroom; unreadable load never stampedes.
    #[test]
    fn dispatch_allowance_matrix() {
        // Worker cap wins over everything.
        assert!(!dispatch_allowance(1, 1, Some(0.0), 0.75));
        assert!(!dispatch_allowance(4, 4, Some(0.0), 0.75));
        // First job: always, however loaded (or unreadable).
        assert!(dispatch_allowance(0, 4, Some(99.0), 0.75));
        assert!(dispatch_allowance(0, 4, None, 0.75));
        // Extras: only with measured headroom.
        assert!(dispatch_allowance(1, 4, Some(0.2), 0.75));
        assert!(!dispatch_allowance(1, 4, Some(0.75), 0.75));
        assert!(!dispatch_allowance(1, 4, Some(2.0), 0.75));
        assert!(!dispatch_allowance(1, 4, None, 0.75));
    }

    /// The starvation escape hatch. The failure it exists for is a pacer that
    /// dispatches nothing for hours because the bring-up queue is never empty
    /// for a whole tick, then drains the whole backlog in one burst against a
    /// disk already near the pressure line.
    #[test]
    fn forced_dispatch_overrides_deferrals_but_never_a_running_sweep() {
        let limit = Some(Duration::from_secs(300));
        let (under, over) = (Duration::from_secs(299), Duration::from_secs(300));

        // The case it exists for: starved on queued clients, nothing running.
        assert!(forced_dispatch(Backpressure::ClientsQueued, over, true, limit));
        // ...but not one second early.
        assert!(!forced_dispatch(Backpressure::ClientsQueued, under, true, limit));
        // ...and never stacked: a forced job runs strictly single-file.
        assert!(!forced_dispatch(Backpressure::ClientsQueued, over, false, limit));

        // A reclaim pass is the same shape of deferral, and the one that
        // starves the pacer hardest: a pass runs up to half an hour and is
        // re-triggered after every idle reap. The job's own per-disk permit
        // (`reclaim::try_disk_permit`) is what keeps the two off the same
        // disk, so the pacer no longer has to stand down host-wide for it.
        let forever = Duration::from_secs(86_400);
        assert!(forced_dispatch(Backpressure::ReclaimPass, over, true, limit));
        assert!(!forced_dispatch(Backpressure::ReclaimPass, under, true, limit));
        assert!(!forced_dispatch(Backpressure::ReclaimPass, over, false, limit));

        // A running sweep is different in kind: it drains through this very
        // picker and already holds per-schema claims, so forcing past it would
        // only double-dispatch. No holdoff, however long, overrides it.
        assert!(!forced_dispatch(Backpressure::Sweeping, forever, true, limit));

        // Disabled (PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS=0) keeps the strict
        // yield-to-everything behavior.
        assert!(!forced_dispatch(Backpressure::ClientsQueued, forever, true, None));
        assert!(!forced_dispatch(Backpressure::ReclaimPass, forever, true, None));
    }

    /// Kind ⇒ boot is exact: only the dump-based kinds take the bring-up gate,
    /// so only they are capped at one in flight.
    #[test]
    fn only_dump_kinds_boot() {
        assert!(!OffloadKind::Promote.boots());
        assert!(!OffloadKind::Compact.boots());
        assert!(!OffloadKind::ImageArchive.boots());
        assert!(OffloadKind::Archive.boots());
        assert!(OffloadKind::Freeze.boots());
    }

    /// The benign claim-race sentinel must survive anyhow context wrapping —
    /// the wrappers downcast through the chain to skip backoff and journaling.
    #[test]
    fn already_offloading_downcasts_through_context() {
        let e =
            anyhow::Error::new(AlreadyOffloading).context("schema x is already being archived");
        assert!(e.downcast_ref::<AlreadyOffloading>().is_some());
        let plain = anyhow::anyhow!("some other failure");
        assert!(plain.downcast_ref::<AlreadyOffloading>().is_none());
    }

    /// The pacer takes exactly one job per scan, and takes them in
    /// cost-to-benefit order: free local disk with a file upload before
    /// spending a boot on a `pg_dump`.
    #[test]
    fn the_cheapest_most_valuable_job_is_picked_first() {
        let ready = schemas(&[
            ("hot-dump", Tier::Frozen, 90_000),  // promote: file upload, no VM
            ("cold-live", Tier::Live, 200_000),  // compact: no boot
            ("older-live", Tier::Live, 300_000), // compact, colder
        ]);
        let live = HashMap::new();

        let job = pick(&ready, &live, LADDER).expect("work is available");
        assert_eq!(job.kind, OffloadKind::Promote);
        assert_eq!(job.schema, "hot-dump");

        // With promotions done, the coldest compactable schema goes next.
        let job = pick(&ready[1..], &live, LADDER).unwrap();
        assert_eq!(job.kind, OffloadKind::Compact);
        assert_eq!(job.schema, "older-live", "ties break toward the coldest");
    }

    /// A tier that isn't configured is never chosen — and with only the S3
    /// tier on, a cold live schema is archived directly rather than sitting
    /// there waiting for a compaction that will never come.
    #[test]
    fn only_configured_tiers_produce_jobs() {
        let live = HashMap::new();
        let cold = schemas(&[("cold", Tier::Live, 200_000)]);

        let s3_only = OffloadPolicy {
            archive_after: Some(86_400),
            ..Default::default()
        };
        assert_eq!(pick(&cold, &live, s3_only).unwrap().kind, OffloadKind::Archive);

        let compact_only = OffloadPolicy {
            compact_after: Some(3600),
            ..Default::default()
        };
        assert_eq!(
            pick(&cold, &live, compact_only).unwrap().kind,
            OffloadKind::Compact
        );

        // Nothing configured, nothing to do — and an already-archived schema
        // is never work under any configuration.
        assert!(pick(&cold, &live, OffloadPolicy::default()).is_none());
        assert!(pick(&schemas(&[("done", Tier::Archived, 999_999)]), &live, LADDER).is_none());
    }

    /// The guards that keep the pacer off schemas someone is using: keepalive,
    /// too-recent, warm-with-sessions, and per-schema failure backoff.
    #[test]
    fn in_use_and_backing_off_schemas_are_never_picked() {
        let recs = schemas(&[("s", Tier::Live, 200_000)]);
        let no_live = HashMap::new();

        assert!(
            pick_offload_job(&recs, &no_live, LADDER, &|_| true, &|_| false, NOW)
                .0
                .is_none(),
            "keepalive"
        );
        assert!(
            pick_offload_job(&recs, &no_live, LADDER, &|_| false, &|_| true, NOW)
                .0
                .is_none(),
            "in failure backoff"
        );
        assert!(
            pick(&schemas(&[("s", Tier::Live, 10)]), &no_live, LADDER).is_none(),
            "not idle long enough"
        );

        // Warm with a live session: not compactable (warm at all), not
        // archivable (the live cross-check refuses), and its durable clock is
        // refreshed so the next scan doesn't reconsider it.
        let warm: HashMap<String, (usize, u64)> = [("s".to_string(), (1usize, 5u64))].into();
        let (job, refresh) = pick_offload_job(&recs, &warm, LADDER, &|_| false, &|_| false, NOW);
        assert!(job.is_none());
        assert_eq!(refresh, vec!["s".to_string()]);
    }

    /// Under pressure the thresholds stop mattering: a schema idle for a
    /// minute is as evictable as one idle for a week, coldest first. That is
    /// the whole point — the disk is full *now*.
    #[test]
    fn pressure_ignores_the_idle_thresholds() {
        let reg = OffloadPolicy {
            compact_after: Some(3600),
            archive_after: Some(86_400),
            ..Default::default()
        };
        let pressure = OffloadPolicy {
            mode: OffloadMode::Pressure,
            ..reg
        };
        // Far too recent for either configured threshold.
        let fresh = schemas(&[("s", Tier::Live, 60)]);
        let live = HashMap::new();
        assert!(pick(&fresh, &live, reg).is_none(), "routine leaves it alone");

        let pressed = OffloadPolicy {
            compact_after: Some(0),
            archive_after: Some(0),
            ..pressure
        };
        assert_eq!(
            pick(&fresh, &live, pressed).unwrap().kind,
            OffloadKind::Compact
        );
    }

    /// The ordering that matters at 99% full: never spend a VM boot while a
    /// no-boot job is available. Compacting frees ~96% of a schema's
    /// footprint in seconds of CPU; booting to dump needs a ~200MB rootfs
    /// clone the disk may not have room for.
    #[test]
    fn pressure_prefers_no_boot_work_over_dumping() {
        let pressed = OffloadPolicy {
            compact_after: Some(0),
            freeze_after: None,
            archive_after: Some(0),
            image_archive: true,
            no_boot: false,
            mode: OffloadMode::Pressure,
        };
        // A compactable (stopped, not warm) schema and a warm one that could
        // only be reached by the boot-and-dump path.
        let recs = schemas(&[("stopped", Tier::Live, 1000), ("warm", Tier::Live, 5000)]);
        let live: HashMap<String, (usize, u64)> = [("warm".to_string(), (0usize, 5000u64))].into();

        let job = pick(&recs, &live, pressed).unwrap();
        assert_eq!(job.kind, OffloadKind::Compact);
        assert_eq!(
            job.schema, "stopped",
            "the colder schema loses to the one that needs no boot"
        );

        // With compaction unconfigured, the no-boot route is the image
        // archive — still ahead of dumping, and it leaves nothing on the host.
        let no_compact = OffloadPolicy {
            compact_after: None,
            ..pressed
        };
        assert_eq!(
            pick(&recs, &live, no_compact).unwrap().kind,
            OffloadKind::ImageArchive
        );

        // With neither, the dump path is all that's left — and it can serve
        // the warm schema the no-boot routes could not.
        let dumps_only = OffloadPolicy {
            compact_after: None,
            image_archive: false,
            ..pressed
        };
        assert_eq!(
            pick(&dumps_only_recs(), &live, dumps_only).unwrap().kind,
            OffloadKind::Archive
        );
    }

    fn dumps_only_recs() -> Vec<(String, StoreRecord)> {
        schemas(&[("warm", Tier::Live, 5000)])
    }

    /// Freezing is dropped under pressure however it is configured: it costs a
    /// boot *and* leaves the bytes on the host, which cannot relieve a full
    /// disk. And the image archive is never offered routinely — a dump is
    /// smaller and version-independent, so it stays the normal path.
    #[test]
    fn pressure_drops_freezing_and_routine_never_image_archives() {
        let recs = schemas(&[("s", Tier::Live, 999_999)]);
        let live = HashMap::new();

        let freeze_only_pressure = OffloadPolicy {
            freeze_after: Some(0),
            mode: OffloadMode::Pressure,
            ..Default::default()
        };
        // Pressure policy construction drops freeze; even handed one, there is
        // no S3/compact target, so nothing frees the disk.
        assert_eq!(
            pick(&recs, &live, freeze_only_pressure).unwrap().kind,
            OffloadKind::Freeze,
            "the picker honours what it is given — pressure_policy() is what drops freezing"
        );

        let routine_with_images = OffloadPolicy {
            archive_after: Some(0),
            image_archive: true,
            mode: OffloadMode::Routine,
            ..Default::default()
        };
        assert_eq!(
            pick(&recs, &live, routine_with_images).unwrap().kind,
            OffloadKind::Archive,
            "routine archiving dumps; images are the pressure-only shortcut"
        );
    }

    /// A stopped-but-warm entry (VM stopped, entry still cached) must not be
    /// compacted — the disk may still be held open — but is fair game for the
    /// S3 tier, whose cross-check handles it.
    #[test]
    fn a_warm_entry_blocks_compaction_but_not_archiving() {
        let recs = schemas(&[("s", Tier::Live, 200_000)]);
        let idle_warm: HashMap<String, (usize, u64)> = [("s".to_string(), (0usize, 200_000u64))].into();
        let job = pick(&recs, &idle_warm, LADDER).expect("still archivable");
        assert_eq!(job.kind, OffloadKind::Archive);
    }
}

/// Filesystem usage of the guest's Postgres data directory via
/// `COPY FROM PROGRAM 'df -kP …'` — `df` needs statvfs, which no `/proc`
/// read can provide. Runs in one transaction with an `ON COMMIT DROP` temp
/// table so nothing leaks onto the pooled session; any failure (no superuser,
/// no `df` in the image) rolls back and yields `None`.
async fn df_data_dir(client: &mut deadpool_postgres::Object) -> Option<(u64, u64, u64)> {
    let tx = client.transaction().await.ok()?;
    let datadir: String = tx
        .query_one("SELECT current_setting('data_directory')", &[])
        .await
        .ok()?
        .get(0);
    // The path is trusted (it's the server's own data_directory) but still
    // SQL-quoted (' → '') and shell-double-quoted for hygiene.
    let sql = format!(
        "CREATE TEMP TABLE _dash_df(line text) ON COMMIT DROP; \
         COPY _dash_df FROM PROGRAM 'df -kP \"{}\"'",
        datadir.replace('\'', "''")
    );
    tx.batch_execute(&sql).await.ok()?;
    let rows = tx.query("SELECT line FROM _dash_df", &[]).await.ok()?;
    let _ = tx.commit().await;
    parse_df(rows.iter().map(|r| r.get(0)))
}

/// Pull `MemTotal`/`MemAvailable` out of `/proc/meminfo` text → bytes.
fn parse_meminfo(s: &str) -> Option<(u64, u64)> {
    let kb = |line: &str| line.split_whitespace().nth(1)?.parse::<u64>().ok();
    let mut total = None;
    let mut avail = None;
    for line in s.lines() {
        if line.starts_with("MemTotal:") {
            total = kb(line);
        } else if line.starts_with("MemAvailable:") {
            avail = kb(line);
        }
    }
    Some((total? * 1024, avail? * 1024))
}

/// First three fields of `/proc/loadavg` (1/5/15-minute load).
fn parse_loadavg(s: &str) -> Option<(f64, f64, f64)> {
    let mut it = s.split_whitespace();
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

/// Parse `df -kP` (POSIX portable) output → (total, used, available) bytes.
/// Finds the first data line by its all-numeric 1024-block column, so the
/// header (whose second field is "1024-blocks") is skipped regardless of row
/// order.
fn parse_df<'a>(lines: impl Iterator<Item = &'a str>) -> Option<(u64, u64, u64)> {
    for line in lines {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 6 && !f[1].is_empty() && f[1].bytes().all(|b| b.is_ascii_digit()) {
            let total = f[1].parse::<u64>().ok()?;
            let used = f[2].parse::<u64>().ok()?;
            let avail = f[3].parse::<u64>().ok()?;
            return Some((total * 1024, used * 1024, avail * 1024));
        }
    }
    None
}

/// Percent-full of the filesystem holding `path`, read on the host via
/// `df -kP` (same basis as df's own Use%: `used / (used + avail)`, excluding
/// root-reserved blocks). `None` on any failure — the pressure loop treats
/// that as "can't tell", never as pressure.
async fn disk_used_pct(path: &std::path::Path) -> Option<f64> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("df").arg("-kP").arg(path).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (_total, used, avail) = parse_df(text.lines())?;
    used_pct(used, avail)
}

/// `used / (used + avail)` as a percentage; `None` when the denominator is 0.
fn used_pct(used: u64, avail: u64) -> Option<f64> {
    let denom = (used + avail) as f64;
    if denom <= 0.0 {
        return None;
    }
    Some(used as f64 / denom * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_pairings_keep_bringup_settings_without_becoming_live() {
        use crate::replication::{ReplRecord, Role, State};
        let dir = std::env::temp_dir().join(format!("pgfc-failed-role-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::from_env().unwrap();
        cfg.state_file = dir.join("registry.tsv");
        cfg.dedicated_file = dir.join("dedicated.tsv");
        cfg.peers_file = dir.join("peers.tsv");
        cfg.replication_file = dir.join("replication.tsv");
        let registry = SchemaRegistry::new(cfg).unwrap();
        for (database, role) in [("publisher", Role::Primary), ("subscriber", Role::Replica)] {
            registry
                .replication
                .create(
                ReplRecord::new(database, role, "peer", "replpassword12"),
                &|_| false,
                )
                .unwrap();
            for (state, expected) in [
                (State::Pending, None),
                (State::Syncing, Some(role)),
                (State::Active, Some(role)),
                (State::Failed, Some(role)),
                (State::Detached, None),
                (State::Promoted, None),
            ] {
                registry.replication.set_state(database, state, "test transition").unwrap();
                assert_eq!(registry.bring_up_for(database, None, None).replication, expected);
                assert_eq!(registry.replication.get(database).unwrap().state, state);
                if state == State::Failed {
                    assert!(!registry.replication.is_pinned(database));
                }
            }
        }
        assert_eq!(registry.bring_up_for("unpaired", None, None).replication, None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn owned_claim_checkout_progresses_while_ordinary_checkout_waits() {
        let dir = std::env::temp_dir().join(format!("pgfc-claimed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = Config::from_env().unwrap();
        cfg.state_file = dir.join("registry.tsv");
        cfg.dedicated_file = dir.join("dedicated.tsv");
        cfg.peers_file = dir.join("peers.tsv");
        cfg.replication_file = dir.join("replication.tsv");
        cfg.reclaim = None;
        cfg.run_dir = None;
        cfg.warm_spares = 0;
        cfg.freeze = None;
        cfg.archive = None;
        let registry = Arc::new(SchemaRegistry::new(cfg).unwrap());
        // Fail immediately after passing the maintenance gate, without any
        // daemon or database connection. The original apply path instead
        // waited forever on its own claim and never reached this breaker.
        registry.bringup_breaker.record_failure("tenant");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            registry.apply_replication_mode("tenant"),
        )
        .await
        .expect("replication mode checkout must not wait on its own claim");
        assert!(format!("{:#}", result.unwrap_err()).contains("holding off new attempts"));
        assert!(!registry.is_archiving("tenant"), "failed operation must release its claim");

        let claim = ArchivingGuard::claim(&registry.archiving, "tenant").unwrap();
        let ordinary = registry.checkout("tenant");
        tokio::pin!(ordinary);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut ordinary)
                .await
                .is_err(),
            "public checkout must remain blocked while maintenance owns the schema"
        );

        drop(claim);
        let result = tokio::time::timeout(Duration::from_secs(1), ordinary)
            .await
            .expect("ordinary checkout must resume after the claim is released");
        assert!(result.err().unwrap().to_string().contains("holding off new attempts"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The orphan sweep's abort breaker must count *consecutive* daemon
    /// errors. It once cleared its run only on `Gone`, which made it count
    /// "errors since the last orphan" instead — and a run dir's forgotten
    /// directories sort late in readdir order, so classification walks a long
    /// `Present`-heavy prefix first. Five strays anywhere in that prefix
    /// aborted the pass before it reached a single deletable dir, and the
    /// backlog sat still while every log line looked healthy.
    #[test]
    fn daemon_error_breaker_counts_only_consecutive_errors() {
        let err = DaemonState::Error;
        let present = DaemonState::Present { running: false };

        // A genuine burst still trips it: the safety property is the whole
        // point of the breaker and this fix must not soften it.
        let mut run = 0;
        for _ in 0..ORPHAN_MAX_DAEMON_ERRORS {
            run = daemon_error_run(run, &err);
        }
        assert!(run >= ORPHAN_MAX_DAEMON_ERRORS, "errors in a row must abort the pass");

        // The regression: strays separated by healthy probes are not a run,
        // however many of them a long scan accumulates.
        let mut run = 0;
        for _ in 0..ORPHAN_MAX_DAEMON_ERRORS * 3 {
            run = daemon_error_run(run, &err);
            assert!(run < ORPHAN_MAX_DAEMON_ERRORS, "one stray error must not abort a pass");
            run = daemon_error_run(run, &present);
            assert_eq!(run, 0, "a Present probe is the daemon answering");
        }

        // `Gone` clears it too — it always did, and must keep doing so.
        assert_eq!(daemon_error_run(ORPHAN_MAX_DAEMON_ERRORS - 1, &DaemonState::Gone), 0);
    }

    /// The age gate on the rootfs prune is what keeps a VM that is booting
    /// right now (fresh clone, not yet opened by Firecracker) out of the
    /// candidate set — so "can't tell" and "brand new" must both read false.
    #[test]
    fn file_age_gate_is_false_for_fresh_and_missing_files() {
        let dir = std::env::temp_dir().join(format!("pgfc-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("rootfs.ext4");
        std::fs::write(&f, b"x").unwrap();

        assert!(!file_older_than(&f, Duration::from_secs(1800)), "just written");
        assert!(file_older_than(&f, Duration::ZERO), "any age passes a zero floor");
        assert!(
            !file_older_than(&dir.join("nope.ext4"), Duration::ZERO),
            "a missing file is never a deletion candidate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The manual image archive must work for a registry-less stray (adopt
    /// the viewed VM), follow the registry when it agrees, and refuse — never
    /// guess — when the registry names a *different* VM for the schema.
    #[test]
    fn image_target_adopts_strays_and_refuses_conflicts() {
        // Normal: registry binding, viewed from that VM's page.
        assert_eq!(
            resolve_image_target("s", Some("sb-a"), Some("sb-a")).unwrap(),
            ("sb-a".to_string(), false)
        );
        // Non-dashboard caller with no viewed VM: the registry decides.
        assert_eq!(
            resolve_image_target("s", Some("sb-a"), None).unwrap(),
            ("sb-a".to_string(), false)
        );
        // Stray: the daemon knows pg-s, the registry has no row → adopt the
        // VM the button was pressed on.
        assert_eq!(
            resolve_image_target("s", None, Some("sb-b")).unwrap(),
            ("sb-b".to_string(), true)
        );
        // Conflict: two VMs claim the schema — refuse with both ids named.
        let err = resolve_image_target("s", Some("sb-a"), Some("sb-b"))
            .expect_err("a conflicting binding must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("sb-a") && msg.contains("sb-b"), "must name both VMs: {msg}");
        // Nothing to go on at all.
        assert!(resolve_image_target("s", None, None).is_err());
    }

    #[test]
    fn offload_backoff_doubles_caps_and_clears() {
        let b = OffloadBackoff::new();
        let t0 = Instant::now();
        assert!(b.active("s", t0).is_none(), "no failures yet");

        let (n, d) = b.record_failure("s", t0);
        assert_eq!((n, d), (1, Duration::from_secs(30 * 60)));
        assert!(b.active("s", t0 + Duration::from_secs(29 * 60)).is_some());
        assert!(b.active("s", t0 + Duration::from_secs(30 * 60)).is_none(), "window elapsed");

        // Second failure doubles; other schemas are unaffected.
        let (_, d2) = b.record_failure("s", t0);
        assert_eq!(d2, Duration::from_secs(60 * 60));
        assert!(b.active("other", t0).is_none());

        // Many failures clamp to the cap.
        for _ in 0..10 {
            b.record_failure("s", t0);
        }
        let (_, dcap) = b.record_failure("s", t0);
        assert_eq!(dcap, OFFLOAD_BACKOFF_CAP);

        // A success forgets everything.
        b.clear("s");
        assert!(b.active("s", t0).is_none());
        let (n, _) = b.record_failure("s", t0);
        assert_eq!(n, 1, "counter restarts after a clear");

        // A settled outcome skips for the whole cap at once, and a clear
        // (a restore) still forgets it.
        assert_eq!(b.record_settled("e", t0), OFFLOAD_BACKOFF_CAP);
        assert!(
            b.active("e", t0 + OFFLOAD_BACKOFF_CAP - Duration::from_secs(1))
                .is_some()
        );
        assert!(b.active("e", t0 + OFFLOAD_BACKOFF_CAP).is_none());
        b.clear("e");
        assert!(b.active("e", t0).is_none());

        assert_eq!(fmt_backoff(Duration::from_secs(30 * 60)), "30m");
        assert_eq!(fmt_backoff(Duration::from_secs(2 * 3600)), "2h");
    }

    #[test]
    fn grow_target_doubles_capped_and_gates_correctly() {
        let (pct, max_gb) = (80.0, 100);
        let gib = |n: u64| n * GIB;

        // 4GiB device, fs spans it, 90% used → double to 8.
        assert_eq!(
            grow_verdict((gib(4), gib(4) * 9 / 10, gib(4) / 10), gib(4), pct, max_gb),
            GrowVerdict::Grow(8)
        );
        // Below the trigger → no growth.
        assert_eq!(
            grow_verdict((gib(4), gib(2), gib(2)), gib(4), pct, max_gb),
            GrowVerdict::NotNeeded
        );
        // Full fs but THIN under a bigger device → the guest watcher's job.
        assert_eq!(
            grow_verdict((gib(4), gib(4) * 9 / 10, gib(4) / 10), gib(16), pct, max_gb),
            GrowVerdict::NotNeeded
        );
        // Doubling past the cap clamps to it.
        assert_eq!(
            grow_verdict((gib(64), gib(60), gib(4)), gib(64), pct, max_gb),
            GrowVerdict::Grow(100)
        );
        // Already at the cap → `AtCap`, NOT `NotNeeded`. The distinction is
        // the whole point: this schema is full and the pooler has no lever
        // left, which the urgent grower reports at error level instead of
        // quietly declining to act.
        assert_eq!(
            grow_verdict((gib(100), gib(95), gib(5)), gib(100), pct, max_gb),
            GrowVerdict::AtCap { current_gb: 100 }
        );
        // Unreadable df (0/0) → no decision.
        assert_eq!(
            grow_verdict((0, 0, 0), gib(4), pct, max_gb),
            GrowVerdict::NotNeeded
        );
    }

    /// The urgent threshold has to be strictly later than the idle-stop one:
    /// the cheap path must keep catching everything that does go idle, and the
    /// expensive path (which drops live sessions) must only fire on what it
    /// misses. Same filesystem, two thresholds, two answers.
    #[test]
    fn the_urgent_threshold_fires_later_than_the_idle_stop_one() {
        let gib = |n: u64| n * GIB;
        // 88% full on a device the fs spans: past the idle-stop trigger (85),
        // short of the urgent one (95).
        let fs = (gib(8), gib(8) * 88 / 100, gib(8) * 12 / 100);
        assert_eq!(grow_verdict(fs, gib(8), 85.0, 100), GrowVerdict::Grow(16));
        assert_eq!(grow_verdict(fs, gib(8), 95.0, 100), GrowVerdict::NotNeeded);

        // 96% full: both agree, and both pick the same target — the urgent
        // path is a different *trigger*, never a different growth policy.
        let full = (gib(8), gib(8) * 96 / 100, gib(8) * 4 / 100);
        assert_eq!(grow_verdict(full, gib(8), 85.0, 100), GrowVerdict::Grow(16));
        assert_eq!(grow_verdict(full, gib(8), 95.0, 100), GrowVerdict::Grow(16));
    }

    /// A bulk load is caught before its disk is full: two samples make a fill
    /// rate, the rate projects what the next check would find, and the grow
    /// fires while there is still room to stop cleanly.
    #[test]
    fn a_filling_disk_grows_before_it_reaches_the_threshold() {
        let mib = |n: u64| n * 1024 * 1024;
        let dev = 2 * GIB;
        let fs_at = |used: u64| (dev, used, dev - used);
        let t0 = Instant::now();

        // First reading, 40% used: no rate yet, so it is looked at again soon.
        let used0 = dev * 40 / 100;
        let first = next_grow_sample(None, fs_at(used0), t0, 95.0);
        assert_eq!(first.rate, None);
        assert!(first.hot);
        assert_eq!(
            urgent_verdict(fs_at(used0), dev, &first, 95.0, 100),
            GrowVerdict::NotNeeded
        );

        // 300MiB later, ten seconds on: 30MiB/s. The next check plus the stop
        // (20s) would land near 84% — not yet.
        let t1 = t0 + Duration::from_secs(10);
        let used1 = used0 + mib(300);
        let second = next_grow_sample(Some(&first), fs_at(used1), t1, 95.0);
        assert!((second.rate.unwrap() - mib(30) as f64).abs() < 1.0);
        assert!(second.hot);
        assert_eq!(
            urgent_verdict(fs_at(used1), dev, &second, 95.0, 100),
            GrowVerdict::NotNeeded
        );

        // Another 300MiB: 69% used, which alone is nowhere near 95% — but by
        // the next check it would be past it. Grow now, with ~600MiB to spare.
        let t2 = t1 + Duration::from_secs(10);
        let used2 = used1 + mib(300);
        let third = next_grow_sample(Some(&second), fs_at(used2), t2, 95.0);
        assert_eq!(
            grow_verdict(fs_at(used2), dev, 95.0, 100),
            GrowVerdict::NotNeeded
        );
        assert_eq!(
            urgent_verdict(fs_at(used2), dev, &third, 95.0, 100),
            GrowVerdict::Grow(4)
        );
    }

    /// The fast cadence is for schemas that earn it. Everything else keeps
    /// the one guest query a minute the warm set can afford.
    #[test]
    fn only_filling_or_nearly_full_schemas_get_the_fast_cadence() {
        let mib = |n: u64| n * 1024 * 1024;
        let dev = 8 * GIB;
        let fs_at = |used: u64| (dev, used, dev - used);
        let t0 = Instant::now();

        // Never sampled: due now. Sampled once: due again on the fast cadence.
        assert!(urgent_sample_due(None, t0));
        let first = next_grow_sample(None, fs_at(2 * GIB), t0, 95.0);
        assert!(urgent_sample_due(
            Some(&first),
            t0 + URGENT_GROW_FAST_INTERVAL
        ));

        // Quiet (1MiB in 10s) at 25%: back to once a minute.
        let t1 = t0 + Duration::from_secs(10);
        let quiet = next_grow_sample(Some(&first), fs_at(2 * GIB + mib(1)), t1, 95.0);
        assert!(!quiet.hot);
        assert!(!urgent_sample_due(
            Some(&quiet),
            t1 + URGENT_GROW_FAST_INTERVAL
        ));
        assert!(urgent_sample_due(
            Some(&quiet),
            t1 + URGENT_GROW_CHECK_INTERVAL
        ));

        // Filling at 2MiB/s: fast.
        let t2 = t1 + Duration::from_secs(10);
        let filling = next_grow_sample(Some(&quiet), fs_at(2 * GIB + mib(21)), t2, 95.0);
        assert!(filling.hot);

        // Flat, but within the watch margin of the threshold (82% vs 80%): fast.
        let flat_near = GrowSample {
            used: dev * 82 / 100,
            at: t1,
            rate: Some(0.0),
            hot: false,
        };
        let near = next_grow_sample(Some(&flat_near), fs_at(dev * 82 / 100), t2, 95.0);
        assert_eq!(near.rate, Some(0.0));
        assert!(near.hot);

        // Shrinking and far from the wall: not filling.
        let shrinking = next_grow_sample(Some(&quiet), fs_at(GIB), t2, 95.0);
        assert!(!shrinking.hot);
    }

    #[test]
    fn projection_never_invents_growth_or_a_cap_complaint() {
        let fs = (2 * GIB, GIB, GIB);
        let horizon = Duration::from_secs(20);
        // No rate, flat, or shrinking: the reading as it is.
        assert_eq!(project_fs(fs, None, horizon), fs);
        assert_eq!(project_fs(fs, Some(0.0), horizon), fs);
        assert_eq!(project_fs(fs, Some(-1e6), horizon), fs);
        // Growth beyond the space left stops at full.
        assert_eq!(project_fs(fs, Some(1e12), horizon), (2 * GIB, 2 * GIB, 0));

        // Projected to cross on a device already at the cap: not a complaint
        // yet — only a disk that is actually full gets the at-cap error.
        let racing = GrowSample {
            used: GIB,
            at: Instant::now(),
            rate: Some(1e9),
            hot: true,
        };
        assert_eq!(
            urgent_verdict(fs, 2 * GIB, &racing, 95.0, 2),
            GrowVerdict::NotNeeded
        );
        let full = (2 * GIB, 2 * GIB * 96 / 100, 2 * GIB * 4 / 100);
        assert_eq!(
            urgent_verdict(full, 2 * GIB, &racing, 95.0, 2),
            GrowVerdict::AtCap { current_gb: 2 }
        );
    }

    #[test]
    fn used_pct_matches_df_semantics() {
        // 850 used / 1000 (used+avail) → 85%, independent of `total` (which
        // includes root-reserved blocks df's Use% ignores).
        assert_eq!(used_pct(850, 150), Some(85.0));
        assert_eq!(used_pct(0, 100), Some(0.0));
        assert_eq!(used_pct(100, 0), Some(100.0));
        // An empty df line must read as "unknown", not 0% (which would
        // silently disable pressure eviction forever).
        assert_eq!(used_pct(0, 0), None);
    }

    #[test]
    fn meminfo_yields_total_and_available_bytes() {
        let s = "MemTotal:        8028896 kB\n\
                 MemFree:          734500 kB\n\
                 MemAvailable:    7600004 kB\n\
                 Buffers:           12345 kB\n";
        assert_eq!(parse_meminfo(s), Some((8_028_896 * 1024, 7_600_004 * 1024)));
        // Missing MemAvailable (ancient kernel) → None rather than garbage.
        assert_eq!(parse_meminfo("MemTotal: 100 kB\n"), None);
    }

    #[test]
    fn loadavg_yields_three_floats() {
        assert_eq!(
            parse_loadavg("0.52 0.30 0.18 2/213 4189\n"),
            Some((0.52, 0.30, 0.18))
        );
        assert_eq!(parse_loadavg(""), None);
    }

    #[test]
    fn df_skips_header_and_parses_first_data_line() {
        let out = [
            "Filesystem     1024-blocks    Used Available Capacity Mounted on",
            "/dev/vdb           4062912  950000   3112912      24% /workspace",
        ];
        assert_eq!(
            parse_df(out.into_iter()),
            Some((4_062_912 * 1024, 950_000 * 1024, 3_112_912 * 1024))
        );
        // Header only (df failed mid-flight) → None.
        assert_eq!(parse_df(out[..1].iter().copied()), None);
    }

    /// The whole point of the supervisor: a pass that panics must not kill the
    /// loop. If it did, `calls` would freeze at 1 (the panicking pass) and every
    /// later tick would never fire.
    #[tokio::test(start_paused = true)]
    async fn supervisor_survives_a_panicking_pass() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let task = tokio::spawn(supervise(
            "test",
            Duration::from_millis(10),
            Duration::from_millis(10),
            move || {
                let c = c.clone();
                async move {
                    // Panic on the first pass only; succeed forever after.
                    if c.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("boom on the first pass");
                    }
                    0usize
                }
            },
        ));
        // Paused clock: advancing time drives the ticks deterministically without
        // real waiting. Several ticks should elapse past the initial panic.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(
            calls.load(Ordering::SeqCst) >= 3,
            "loop stalled after the panic (only {} pass(es) ran)",
            calls.load(Ordering::SeqCst)
        );
    }
}
