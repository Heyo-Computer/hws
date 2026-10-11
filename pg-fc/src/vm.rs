//! Per-schema VM control loop: find-or-create-or-restart the `pg-<schema>`
//! microVM, open a raw-TCP tunnel to its Postgres, and bootstrap the database.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use deadpool_postgres::{Config as PgConfig, Pool, Runtime};
use heyo_sdk::{
    CommandResult, CommandRunOptions, DEFAULT_LOCAL_BASE_URL, HeyoClient, HeyoClientOptions,
    HeyoError, P2pTunnel, RequestOptions, Sandbox, SandboxCreateOptions, SandboxDriver,
    SandboxInfo,
};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::config::Config;
use crate::registry::{GIB, GrowVerdict, SchemaEntry};
use crate::s3::S3Config;
use crate::store::BringupKind;

const VM_PG_PORT: u16 = 5432;

/// How long Postgres gets to answer (or at least speak) before we conclude the
/// server process is dead inside a live VM. Generous on purpose: a healthy VM
/// answers in milliseconds, and a freshly booted one binds its port within a
/// couple of seconds of HEYVM_READY — only a crashed/absent postmaster stays
/// silent this long.
const PG_PROBE_WINDOW: Duration = Duration::from_secs(15);
/// How long to wait for the postmaster after an in-guest restart (the
/// replication WAL-level switch). Longer than [`PG_PROBE_WINDOW`] because a
/// `pg_ctl -m fast restart` on a busy cluster includes a shutdown checkpoint,
/// and much shorter than a boot because nothing is rebooting.
const PG_RESTART_WINDOW: Duration = Duration::from_secs(60);

/// Poll interval while waiting for Postgres to come up, two-speed. init.sh
/// signals HEYVM_READY ~1s *before* the postmaster binds 5432, so nearly
/// every bring-up spends its first probes hitting a not-yet-open port — at
/// the old flat 500ms quantum that rounded up to half a second of pure sleep
/// on EVERY cold start. Probe fast (a refused connect on the local bridge is
/// ~free) while the wait still looks like a normal boot, then back off to the
/// old cadence for the pathological waits `wait_pg_ready`'s 300s timeout
/// exists for.
const PG_POLL_FAST: Duration = Duration::from_millis(100);
const PG_POLL_SLOW: Duration = Duration::from_millis(500);
const PG_POLL_FAST_WINDOW: Duration = Duration::from_secs(5);

/// The poll interval for an in-flight Postgres wait that started `elapsed`
/// ago (see [`PG_POLL_FAST`]).
fn pg_poll_interval(elapsed: Duration) -> Duration {
    if elapsed < PG_POLL_FAST_WINDOW { PG_POLL_FAST } else { PG_POLL_SLOW }
}

/// Per-attempt bound inside that window. Only guards against a connect that
/// hangs forever (the pool has no create timeout); it is not a health
/// threshold — exceeding it yields `PgProbe::Stalled`, never `Unreachable`.
const PG_PROBE_ATTEMPT: Duration = Duration::from_secs(3);

/// The heyvmd daemon every call in this crate addresses. Defaults to the SDK's
/// local daemon (`http://127.0.0.1:34099`); `PG_VM_POOL_DAEMON_URL` overrides
/// it.
///
/// Read once and cached, because it is on the bring-up hot path and because a
/// per-call `env::var` takes a process-wide lock — which would show up as
/// contention in exactly the concurrent bring-up measurements this indirection
/// exists to make possible. The override has two uses: pointing the pooler at
/// a daemon on another port, and letting `crate::loadtest` aim the *whole*
/// pooler at an in-process daemon stub — the only way to put a
/// thousand-sandbox fleet under it without a thousand VMs.
pub(crate) fn daemon_base_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("PG_VM_POOL_DAEMON_URL")
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_LOCAL_BASE_URL.to_string())
    })
}

/// The bearer the daemon wants, if it wants one: `PG_VM_POOL_DAEMON_API_KEY`,
/// else `HEYO_API_KEY` (what heyo-sdk falls back to on its own).
///
/// A keyless `heyvm --api` needs neither. A daemon that requires one — us5's
/// runs with `CLOUD_INTERNAL_API_KEY` — answers 401 to every call that does not
/// carry it, and the calls below that go around the SDK (resize, the create
/// gate, the capability probe, create-on-image) would otherwise never send it.
pub(crate) fn daemon_api_key() -> Option<&'static str> {
    static KEY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        ["PG_VM_POOL_DAEMON_API_KEY", "HEYO_API_KEY"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .map(|v| v.trim().to_string())
            .find(|v| !v.is_empty())
    })
    .as_deref()
}

/// `request` with the daemon's bearer attached, when one is configured.
fn daemon_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    with_bearer(request, daemon_api_key())
}

fn with_bearer(request: reqwest::RequestBuilder, key: Option<&str>) -> reqwest::RequestBuilder {
    match key {
        Some(key) => request.bearer_auth(key),
        None => request,
    }
}

/// Fresh options targeting the local heyvmd daemon. Built per call so we don't
/// rely on `HeyoClientOptions: Clone`. Shared with the dashboard so its control
/// actions hit the same daemon.
pub(crate) fn local_opts() -> HeyoClientOptions {
    HeyoClientOptions {
        base_url: Some(daemon_base_url().to_string()),
        api_key: daemon_api_key().map(str::to_string),
        ..Default::default()
    }
}

/// HTTP timeout for the deploy POST specifically. Current heyvmd 202-accepts
/// the deploy and builds in the background, so this normally answers in
/// milliseconds — but an older daemon blocks the POST until the VM has fully
/// booted, and either way a client-side timeout doesn't cancel the server-side
/// build: the "failed" deploy still finishes and leaves an orphan VM behind.
/// Generous is the safe direction.
const DEPLOY_HTTP_TIMEOUT: Duration = Duration::from_secs(180);

/// How many VM bring-ups (deploys of new VMs, boots of stopped ones) may hit
/// the daemon at once. Overridden by `PG_VM_POOL_MAX_CONCURRENT_BRINGUPS`;
/// `0` disables the gate entirely.
///
/// Why a gate: heyvmd runs blocking work on its async worker threads during
/// every VM start (`debugfs` key injection, `mke2fs` for mounts, full rootfs
/// copies on non-CoW filesystems). Enough simultaneous bring-ups park every
/// worker, at which point the daemon stops answering *anything* — including
/// its own health endpoint, whose watchdog then restarts it. Because the
/// Firecracker VMM processes are the daemon's children (their stdio is the
/// guest serial console), that restart kills every running VM, so every
/// active schema cold-starts at once against the fresh daemon and wedges it
/// again. Queueing the excess here (FIFO, in the pooler) breaks that cycle:
/// the daemon only ever sees a herd it can survive.
const DEFAULT_BRINGUP_SLOTS: usize = 3;

/// The gate itself. `None` inside means the operator disabled it (`0`).
static BRINGUP_GATE: OnceLock<Option<Semaphore>> = OnceLock::new();

fn bringup_gate() -> Option<&'static Semaphore> {
    BRINGUP_GATE
        .get_or_init(|| {
            let slots = std::env::var("PG_VM_POOL_MAX_CONCURRENT_BRINGUPS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_BRINGUP_SLOTS);
            if slots == 0 {
                warn!("PG_VM_POOL_MAX_CONCURRENT_BRINGUPS=0: bring-up gate disabled");
            }
            (slots > 0).then(|| Semaphore::new(slots))
        })
        .as_ref()
}

/// Take a bring-up slot before any daemon call that builds or boots a VM.
/// Hold the returned permit only across the daemon-heavy call itself (deploy
/// POST, `start()`) — readiness polling is cheap for the daemon and must not
/// pin a slot. Waiting is logged so a queued bring-up is visible in the log
/// instead of reading as a hang.
pub(crate) async fn bringup_slot(what: &str) -> Option<SemaphorePermit<'static>> {
    let gate = bringup_gate()?;
    if let Ok(permit) = gate.try_acquire() {
        return Some(permit);
    }
    let queued = Instant::now();
    let _waiting = Waiting::new();
    info!("{what}: all VM bring-up slots busy; queueing");
    // The gate is never closed, so acquire() cannot fail.
    let permit = gate.acquire().await.expect("bring-up gate is never closed");
    info!("{what}: bring-up slot acquired after {:?} queued", queued.elapsed());
    Some(permit)
}

/// How many bring-ups are queued right now — waiting for an admission slot or
/// for a bring-up slot, i.e. work that has a client parked behind it.
///
/// Read by background work (the offload pacer) as backpressure: moving a cold
/// schema to S3 is never worth making a client wait longer, so that work waits
/// for this to be zero — with one bounded exception, a pacer starved past
/// `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS`, which then trickles jobs that take
/// no bring-up slot at all (see `registry::Backpressure`). Counted rather than
/// derived from `Semaphore::available_permits`, which says how many slots are
/// taken but not whether anyone is queued behind them.
static BRINGUPS_WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn bringups_waiting() -> usize {
    BRINGUPS_WAITING.load(std::sync::atomic::Ordering::Relaxed)
}

/// RAII counter for [`BRINGUPS_WAITING`]. A guard rather than a pair of
/// fetch_add/fetch_sub calls because these waits sit inside futures a
/// disconnecting client can cancel at any await point — a leaked increment
/// would wedge background offloading permanently.
struct Waiting;

impl Waiting {
    fn new() -> Self {
        BRINGUPS_WAITING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        BRINGUPS_WAITING.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// How many whole bring-ups (deploy through ready/restore) may be in flight at
/// once. Overridden by `PG_VM_POOL_MAX_PENDING_BRINGUPS`; `0` disables.
///
/// Why a second gate when [`BRINGUP_GATE`] exists: that one meters the daemon
/// calls that build or boot a VM — but heyvmd 202-accepts deploys and builds
/// in the background, so the deploy POST releases its slot in milliseconds and
/// a burst of N schemas still lands N concurrent builds (plus N ready-poll
/// loops) on the daemon. This gate bounds the *pending population*: request
/// N+1 queues here, at the pooler's front door, where waiting is free — the
/// client just sees a slower connect — instead of inside a daemon that wedges
/// under the herd. Sized well above the bring-up slots so the queue depth, not
/// the daemon-call rate, is what it controls.
const DEFAULT_PENDING_BRINGUPS: usize = 16;

/// The admission gate itself. `None` inside means the operator disabled it.
static ADMISSION_GATE: OnceLock<Option<Semaphore>> = OnceLock::new();

fn admission_gate() -> Option<&'static Semaphore> {
    ADMISSION_GATE
        .get_or_init(|| {
            let slots = std::env::var("PG_VM_POOL_MAX_PENDING_BRINGUPS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_PENDING_BRINGUPS);
            if slots == 0 {
                warn!("PG_VM_POOL_MAX_PENDING_BRINGUPS=0: bring-up admission gate disabled");
            }
            (slots > 0).then(|| Semaphore::new(slots))
        })
        .as_ref()
}

/// How long a client's bring-up may wait for an admission slot before it is
/// shed. Overridden by `PG_VM_POOL_ADMISSION_WAIT_SECS`; `0` waits forever
/// (the old behaviour).
///
/// Why shed at all: the queue is FIFO and unbounded in time, and its callers
/// are not. The Platform gives a new workbook's pooler build 12s before it
/// abandons it and builds elsewhere — but it never closes the connection it
/// was waiting on, so nothing here can tell it has left. A bring-up that
/// dequeues after that serves no one: it still builds an 8 GiB VM and holds
/// it until the idle reaper takes it, and every such VM is admission budget
/// the next real client can't get. In the 2026-09-15 storm queue waits ran
/// p50 17-25s and p90 around five minutes, so most bring-up work went to
/// clients that were already gone. Shedding instead hands the client a real
/// error it can act on (retry, or build somewhere else) and keeps the slots
/// for those still waiting. The default sits just past that 12s budget.
const DEFAULT_ADMISSION_WAIT: Duration = Duration::from_secs(15);

fn admission_wait() -> Option<Duration> {
    static WAIT: OnceLock<Option<Duration>> = OnceLock::new();
    *WAIT.get_or_init(|| {
        let secs = std::env::var("PG_VM_POOL_ADMISSION_WAIT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_ADMISSION_WAIT.as_secs());
        if secs == 0 {
            warn!("PG_VM_POOL_ADMISSION_WAIT_SECS=0: queued bring-ups wait for a slot forever");
        }
        (secs > 0).then(|| Duration::from_secs(secs))
    })
}

/// When a bring-up that began at `start` must give up its place in the
/// admission queue, or `None` to wait forever. See [`BringUp::admission_deadline`].
pub(crate) fn admission_deadline_from(start: Instant) -> Option<Instant> {
    admission_wait().map(|wait| start + wait)
}

/// A bring-up shed from the admission queue: it reached its deadline without
/// a slot and was dropped before any daemon call. Not a failure of the schema
/// — nothing was built, so the registry stops no VM for it and keeps it out of
/// the circuit breaker — and the client is told the pooler is busy rather
/// than that its database is broken.
#[derive(Debug)]
pub struct BringupShed {
    pub schema: String,
    pub waited: Duration,
    pub queued: usize,
}

impl std::fmt::Display for BringupShed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "schema {}: pooler at capacity — no bring-up slot after {:?} with {} bring-up(s) \
             queued; shed rather than served after the client has given up, retry shortly",
            self.schema, self.waited, self.queued
        )
    }
}

impl std::error::Error for BringupShed {}

/// Whether `e` is, or wraps, a [`BringupShed`].
pub fn is_shed(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| cause.is::<BringupShed>())
}

/// Wait for a permit until `deadline` — `None` once it passes — or forever
/// when there is none. Pulled out of [`admission_slot`] so the deadline can be
/// tested against a local semaphore rather than the process-wide gate.
async fn acquire_within(
    gate: &Semaphore,
    deadline: Option<Instant>,
) -> Option<SemaphorePermit<'_>> {
    let permit = match deadline {
        Some(deadline) => {
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), gate.acquire())
                .await
                .ok()?
        }
        None => gate.acquire().await,
    };
    Some(permit.expect("admission gate is never closed"))
}

/// Take an admission slot for one whole bring-up. Held across all of
/// `ensure_vm` — deploy, ready wait, Postgres bootstrap, restore — so it
/// bounds how many bring-ups exist at once, not how fast they start.
///
/// A bring-up still waiting at `deadline` is shed with a [`BringupShed`]
/// error; see [`DEFAULT_ADMISSION_WAIT`].
async fn admission_slot(
    schema: &str,
    deadline: Option<Instant>,
) -> Result<Option<SemaphorePermit<'static>>> {
    let Some(gate) = admission_gate() else {
        return Ok(None);
    };
    if let Ok(permit) = gate.try_acquire() {
        return Ok(Some(permit));
    }
    let queued = Instant::now();
    let _waiting = Waiting::new();
    info!("schema {schema}: all bring-up admission slots busy; queueing at the pooler");
    match acquire_within(gate, deadline).await {
        Some(permit) => {
            info!(
                "schema {schema}: bring-up admitted after {:?} queued",
                queued.elapsed()
            );
            Ok(Some(permit))
        }
        None => Err(BringupShed {
            schema: schema.to_string(),
            // Since the client's cold start began, not just this attempt's
            // turn in the queue: a client that sat behind another client's
            // attempt at the same schema is shed the moment its own turn
            // comes, and "no slot after 60ms" would hide the 15s it waited.
            waited: match (deadline, admission_wait()) {
                (Some(deadline), Some(wait)) => {
                    wait + Instant::now().saturating_duration_since(deadline)
                }
                _ => queued.elapsed(),
            },
            queued: bringups_waiting(),
        }
        .into()),
    }
}

/// How often [`wait_ready`] re-asks the daemon for a pending VM's status.
/// Fast while the VM is young: the per-id endpoint is a cheap lookup, and a
/// Firecracker boot can be ready in low single-digit seconds, so coarse
/// polling here is pure added latency against the upstream caller's deadline.
/// After [`READY_POLL_FAST_WINDOW`] the build is slow anyway — back off so a
/// long provision doesn't hammer the daemon for minutes.
const READY_POLL_FAST_INTERVAL: Duration = Duration::from_millis(250);
const READY_POLL_SLOW_INTERVAL: Duration = Duration::from_secs(2);
const READY_POLL_FAST_WINDOW: Duration = Duration::from_secs(15);

/// How long a *continuous* run of 404s on the per-id endpoint is tolerated
/// before the wait gives up on that sandbox id.
///
/// A 404 right after the deploy's 202 is normal for a moment (the daemon hands
/// out the id, then its provision tracker starts answering for it). A 404 that
/// persists is not a slow build: it means the record backing this id is gone —
/// overwhelmingly because heyvmd restarted (its watchdog does exactly that, and
/// the tracker is in-memory), taking the half-built VM with it. Waiting out the
/// full ready timeout there burns minutes of the caller's deadline plus an
/// admission slot on an id that can never resolve, and — since heyvmd restarts
/// kill every running VM — it happens to every in-flight bring-up at once. Fail
/// fast instead: the caller retries with a fresh create against the fresh
/// daemon, which is the only thing that can work.
const READY_NOTFOUND_GRACE: Duration = Duration::from_secs(45);

/// Ready budget for a warm spare specifically, floored against the (much
/// longer) client-facing `ready_timeout`. A spare has no client waiting on it
/// and no data to lose: one that hasn't booted in this long is a sick build to
/// throw away and retry, not something to keep a replenish pass parked on.
pub(crate) const SPARE_READY_TIMEOUT: Duration = Duration::from_secs(180);

/// How long a power-cycle waits for Firecracker to let go of a just-stopped
/// VM's data disk before checking whether it needs to grow. The daemon acks
/// the stop before the process exits; past this the restart goes ahead on the
/// disk as it is.
const POWER_CYCLE_DISK_SETTLE: Duration = Duration::from_secs(10);

/// Exclusive use of the process-wide VM state for the caller's whole test.
///
/// The daemon stub's fleet and counters, the environment a `Config` reads, the
/// bring-up gate, and the reclaim boot gate and its waiting-boot count are all
/// process-wide. `cargo test` runs test functions in parallel, so two tests
/// touching any of them measure each other — which is not a flaky result, it is
/// a wrong one. It cannot be delegated to `--test-threads=1` either: that flag
/// is for readable output, this is for correctness.
///
/// One lock rather than one per module, because the state is shared across
/// them: a `loadtest` bring-up takes a reclaim boot permit, and a `reclaim`
/// test asserting on the waiting-boot count sees it.
#[cfg(test)]
pub(crate) async fn test_exclusive() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

/// Pooler-side readiness wait: poll the *per-id* `GET /deployed-sandboxes/:id`
/// until the sandbox leaves `provisioning`, tolerating transient daemon
/// errors until the deadline.
///
/// Replaces the SDK's `Sandbox::wait_for_ready`, which (a) fetches the FULL
/// `/deployed-sandboxes` listing every poll and filters client-side — during a
/// deploy burst that's O(inventory × in-flight) serialization pressure on
/// exactly the endpoint that goes lock-contended first — and (b) aborts the
/// whole bring-up on the first transient transport error, which under load
/// converts one daemon hiccup into a synchronized batch of failed bring-ups,
/// each leaving an orphan VM. Here a poll error is just a poll that taught us
/// nothing: keep polling until the deadline, and report the last error if the
/// deadline passes.
pub(crate) async fn wait_ready(sandbox: &Sandbox, timeout: Duration, name: &str) -> Result<()> {
    wait_ready_within(sandbox, timeout, name, READY_NOTFOUND_GRACE).await
}

/// [`wait_ready`] with the 404 grace spelled out, so tests can exercise both
/// sides of it without waiting real minutes.
async fn wait_ready_within(
    sandbox: &Sandbox,
    timeout: Duration,
    name: &str,
    notfound_grace: Duration,
) -> Result<()> {
    use heyo_sdk::SandboxStatus;
    let started = Instant::now();
    let deadline = started + timeout;
    let mut last_err: Option<HeyoError> = None;
    let mut error_streak = 0u32;
    // Start of the current uninterrupted run of 404s, if any (see
    // READY_NOTFOUND_GRACE). Cleared by any answer that isn't a 404.
    let mut missing_since: Option<Instant> = None;
    loop {
        match sandbox.get().await {
            Ok(info) => {
                error_streak = 0;
                missing_since = None;
                match info.status {
                    SandboxStatus::Running => return Ok(()),
                    // Terminal: the daemon gave up on the build; waiting longer
                    // can't change the answer.
                    SandboxStatus::Failed => bail!(
                        "VM {name} ({}) failed to provision: {}",
                        sandbox.sandbox_id(),
                        info.error_message
                            .as_deref()
                            .unwrap_or("no reason reported")
                    ),
                    SandboxStatus::Provisioning | SandboxStatus::Unknown => {}
                    // Stopped/Paused/ColdStored: settled but not running. Same
                    // contract as the SDK's wait_for_ready — "no longer
                    // provisioning" ends the wait, and the Postgres probe that
                    // follows every bring-up is the real readiness authority.
                    _ => return Ok(()),
                }
            }
            // NotFound included: right after a 202 the record can lag the id,
            // and during an incident the daemon may briefly answer nonsense.
            // Only the deadline decides.
            Err(e) => {
                error_streak += 1;
                if error_streak == 1 {
                    warn!("{name}: readiness poll failed (retrying until deadline): {e:#}");
                }
                if matches!(e, HeyoError::NotFound(_)) {
                    let since = *missing_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= notfound_grace {
                        bail!(
                            "VM {name} ({}) has been unknown to heyvmd for {:?} — the record \
                             behind this id is gone (heyvmd restarts drop in-flight creates, \
                             and take every running VM with them). Not waiting out the ready \
                             timeout; retry with a fresh create. Last daemon error: {e:#}",
                            sandbox.sandbox_id(),
                            since.elapsed(),
                        );
                    }
                } else {
                    missing_since = None;
                }
                last_err = Some(e);
            }
        }
        if Instant::now() >= deadline {
            match last_err {
                Some(e) => bail!(
                    "VM {name} ({}) not ready within {timeout:?}; last daemon error: {e:#}",
                    sandbox.sandbox_id()
                ),
                None => bail!(
                    "VM {name} ({}) not ready within {timeout:?}: status never left provisioning",
                    sandbox.sandbox_id()
                ),
            }
        }
        let interval = if started.elapsed() < READY_POLL_FAST_WINDOW {
            READY_POLL_FAST_INTERVAL
        } else {
            READY_POLL_SLOW_INTERVAL
        };
        sleep(interval).await;
    }
}

/// Run a daemon call with bounded retries on transient failures. A momentarily
/// unreachable or 5xx-ing daemon (deploy bursts make this the norm, not the
/// exception) shouldn't instantly fail a bring-up or a cleanup that merely
/// needed an answer.
async fn with_daemon_retry<T, F, Fut>(what: &str, mut call: F) -> Result<T, HeyoError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, HeyoError>>,
{
    const ATTEMPTS: u32 = 4;
    let mut delay = Duration::from_millis(500);
    for attempt in 1..=ATTEMPTS {
        match call().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < ATTEMPTS && transient(&e) => {
                warn!(
                    "{what} failed (attempt {attempt}/{ATTEMPTS}, \
                     retrying in {delay:?}): {e:#}"
                );
                sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop returns on the last attempt")
}

/// `Sandbox::list` against the local daemon with bounded retries on transient
/// failures. Every successful listing warms the name→id cache for free.
pub(crate) async fn list_with_retry() -> Result<Vec<SandboxInfo>, HeyoError> {
    let list = with_daemon_retry("listing sandboxes", || Sandbox::list(local_opts())).await?;
    crate::inventory::absorb(&list);
    Ok(list)
}

/// Resolve one sandbox by exact name via `GET /deployed-sandboxes?name=`,
/// with the same transient-retry policy as [`list_with_retry`].
///
/// A daemon that understands the filter (heyvmd ≥0.44) answers with at most
/// one entry — O(1) instead of the O(fleet) inventory pull this call replaces.
/// An *old* daemon ignores the query and returns the full list; the exact
/// match is selected client-side either way (correct against both), and
/// whatever came back is absorbed into the cache — an old daemon's full list
/// warms it for free. Raw `HeyoClient::request` rather than an SDK method
/// because the pinned heyo-sdk 0.1.5 predates `Sandbox::find_by_name`
/// (precedent: the dashboard's inactive-page listing).
pub(crate) async fn find_by_name_with_retry(name: &str) -> Result<Option<SandboxInfo>, HeyoError> {
    let client = HeyoClient::new(local_opts())?;
    let response = with_daemon_retry("by-name sandbox lookup", || {
        let mut opts = RequestOptions::default();
        opts.query.push(("name".to_string(), name.to_string()));
        client.request::<Vec<SandboxInfo>>(
            reqwest::Method::GET,
            "/deployed-sandboxes",
            None::<&()>,
            opts,
        )
    })
    .await?;
    crate::inventory::absorb(&response);
    Ok(response.into_iter().find(|s| s.name == name))
}

/// Errors worth retrying: transport failures (the SDK mints status 0 for those)
/// and 5xx. A 4xx is the daemon answering coherently — retrying can't help.
fn transient(e: &HeyoError) -> bool {
    matches!(e, HeyoError::Api { status, .. } if *status == 0 || *status >= 500)
}

/// Bring up (or reattach to) the VM for `schema` and return a ready entry.
/// `known_id` is the sandbox id from a prior bring-up of this schema (if any);
/// reattaching by id avoids a data-loss race where a just-stopped VM is briefly
/// absent from list-by-name and we'd otherwise create a duplicate with a fresh
/// (empty) data disk.
/// Where a restore's dump bytes come from: the S3 archive tier or the local
/// frozen tier's dump server. Owned so the registry can hand it into the
/// bring-up closure without lifetime gymnastics.
pub enum RestoreSource {
    S3(S3Config),
    /// Raw-disk image archive (`{schema}.img.zst`): the VM is materialized by
    /// downloading the image and booting on it directly — no `pg_restore`, no
    /// spare claim, no guest job. Chosen when the schema's S3 archive is an
    /// image rather than a dump (see `imgarchive::pick_restore`).
    S3Image(S3Config),
    /// Locally compacted image (the `Compacted` tier): same materialize
    /// maneuver as `S3Image` minus the download — the compressed image is
    /// already on this host at the given path.
    LocalImage(std::path::PathBuf),
    Local {
        srv: std::sync::Arc<crate::dumpsrv::DumpServer>,
        port: u16,
    },
}

/// What the registry knows about a schema that a bring-up needs but cannot
/// derive from [`Config`] alone.
///
/// Bundled rather than passed as four more positional parameters: every one of
/// these is looked up from a different store on the registry, and threading
/// them individually through `ensure_vm` → `resolve_sandbox` →
/// `claim_restore_vehicle` made the arity grow with each feature.
pub struct BringUp<'a> {
    /// Nothing may idle-stop this VM — a `PG_VM_POOL_KEEPALIVE_SCHEMAS`
    /// schema, or one whose replication pairing depends on it staying up.
    /// See `SchemaRegistry::pinned`.
    pub pinned: bool,
    /// The dedicated database's owning role, if this is one. Re-applied on
    /// every bring-up because a restore rebuilds the cluster from a dump that
    /// carries no roles.
    pub owner: Option<&'a crate::dedicated::Credential>,
    /// This VM's replication role, if any. Decides the durable marker on the
    /// data disk and therefore the guest's WAL level — see
    /// [`ensure_replication_mode`].
    pub replication: Option<crate::replication::Role>,
    /// The `REPLICATION` login a replica uses to reach this primary,
    /// deliberately separate from `owner`: `REPLICATION` lets a role create
    /// logical slots, and an orphaned slot pins WAL until the disk fills, so
    /// it must stay outside what a leaked tenant password can reach.
    pub repl_login: Option<&'a crate::dedicated::Credential>,
    /// When this bring-up gives up waiting for an admission slot and is shed
    /// (see [`DEFAULT_ADMISSION_WAIT`]); `None` waits forever. Only a client
    /// checkout arms one — maintenance bring-ups (archive, freeze) have no
    /// client to lose, so they queue for as long as it takes.
    pub admission_deadline: Option<Instant>,
}

/// `disk_gb` is the data-device size this schema is known to need — the
/// registry's `disk_gb`, `None` when it was never observed. It is consulted
/// only where this bring-up has to *build* a VM: a reattach keeps the device
/// its VM already has, and an image restore brings its own. It exists for the
/// dump tiers, which delete the VM they came from: restoring one of those into
/// the default-size device is how a schema that had grown comes back into a
/// device too small for it and dies mid-`pg_restore`.
pub async fn ensure_vm(
    cfg: &Config,
    schema: &str,
    known_id: Option<&str>,
    restore: Option<&RestoreSource>,
    disk_gb: Option<u32>,
    spares: Option<(&crate::spares::SparePool, &std::collections::HashSet<String>)>,
    up: &BringUp<'_>,
) -> Result<Arc<SchemaEntry>> {
    // Bound the number of concurrent bring-ups before any daemon traffic. A
    // burst beyond the cap queues here (each waiter is one parked client
    // connection) instead of becoming daemon load. Held to the end of the
    // function: the pending *population* is what the daemon can't survive.
    // A client's wait is bounded too: past its deadline this returns a
    // `BringupShed` before anything has been built.
    let mut phase = Instant::now();
    let _admission = admission_slot(schema, up.admission_deadline).await?;
    let admission_took = std::mem::replace(&mut phase, Instant::now()).elapsed();
    // Everything from here to a serving Postgres is what this VM costs to
    // bring back, and therefore what the reaper's warm hold is buying (see
    // `SchemaEntry::idle_budget`). The admission wait above is excluded: it
    // measures how many other clients arrived at once, not this VM.
    let bringup_started = phase;
    let name = format!("pg-{schema}");
    let keepalive = up.pinned;
    // Floored at the configured starting size (a smaller recorded value is a
    // schema that has since shrunk — never a reason to build below the
    // default) and capped at what the daemon will accept.
    let disk_gb = disk_gb
        .unwrap_or(0)
        .max(cfg.data_disk_gb)
        .min(DAEMON_MAX_DISK_GB);

    // An archived schema's VM was killed, so its stored id is dead — never try
    // to reattach by id. Note this does NOT guarantee a clean disk: the
    // find-by-name fallback reuses a VM left behind by a previously *failed*
    // restore, whose database is partially loaded — which is why the restore
    // job runs `pg_restore --clean --if-exists` (idempotent over that débris).
    let known_id = if restore.is_some() { None } else { known_id };
    let (sandbox, provenance) = match restore {
        // An image restore builds its own VM (download, disk swap, boot on the
        // real data) — the database is complete before Postgres first starts,
        // so there is nothing to restore *into*. It still needs a booted VM to
        // swap the disk underneath, though, and a warm spare is by far the
        // cheapest one available: see [`claim_restore_vehicle`]. The
        // provenance it reports is what tells the failure path below how to
        // dispose of the VM — a claimed spare must be released through the
        // pool, never killed behind its back.
        Some(RestoreSource::S3Image(s3)) => {
            crate::imgarchive::materialize_from_image(cfg, schema, s3, spares, up.pinned)
                .await
                .with_context(|| format!("restoring schema {schema} from its S3 disk image"))?
        }
        Some(RestoreSource::LocalImage(path)) => {
            crate::imgarchive::materialize_from_local_image(cfg, schema, path, spares, up.pinned)
                .await
                .with_context(|| format!("thawing schema {schema} from its compacted image"))?
        }
        _ => resolve_sandbox(cfg, &name, keepalive, known_id, spares, disk_gb).await?,
    };

    let resolve_took = std::mem::replace(&mut phase, Instant::now()).elapsed();
    let sandbox_id = sandbox.sandbox_id().to_string();
    // What this bring-up was, for the registry row's per-VM record. A restore
    // is named by its source whatever vehicle carried it.
    let kind = match (restore, provenance) {
        (Some(RestoreSource::S3(_)), _) => BringupKind::RestoreS3Dump,
        (Some(RestoreSource::S3Image(_)), _) => BringupKind::RestoreS3Image,
        (Some(RestoreSource::Local { .. }), _) => BringupKind::RestoreLocalDump,
        (Some(RestoreSource::LocalImage(_)), _) => BringupKind::ThawCompacted,
        (None, Provenance::Created) => BringupKind::Create,
        (None, Provenance::Spare | Provenance::ChilledSpare) => BringupKind::Spare,
        (None, Provenance::Existing) => BringupKind::Reattach,
    };

    // The rest of the bring-up can still fail (ready-timeout, restore error).
    // When the sandbox is a freshly claimed spare, that failure must release
    // the claim — otherwise the id stays in the pool's `claimed` set for the
    // life of the process: a running VM + disk nothing can reclaim, invisible
    // to replenish inventory (which then builds a replacement on top).
    let result = async {
        // Pin keep-alive schemas idempotently: TTL 0 = never auto-stopped. This
        // covers a VM created before its schema was pinned (or created with a
        // non-zero TTL) — a freshly-created keep-alive VM is already TTL 0, so this
        // is a harmless no-op there. Best-effort: a failure here shouldn't block
        // serving the connection, so we warn rather than bail.
        if keepalive {
            if let Err(e) = sandbox.set_ttl(0).await {
                warn!("failed to pin keep-alive VM {name} (set_ttl 0): {e:#}");
            }
        }

        let (target, tunnel, pool) = ready_pg(cfg, &sandbox, &name).await?;
        let pg_ready_took = std::mem::replace(&mut phase, Instant::now()).elapsed();
        ensure_database(&pool, schema, up.owner, up.repl_login).await?;
        // The replication login can only stream what it can read, and it owns
        // nothing. These grants are per-database, so they need a connection to
        // the tenant database rather than the bootstrap pool's `postgres`.
        if let Some(cred) = up.repl_login {
            grant_repl_reads(cfg, &target, schema, &cred.role).await?;
        }
        // Durable per-VM replication marker, and the Postgres restart that
        // makes init.sh regenerate the WAL level from it. Before the restore
        // below, so a restored database lands in a cluster already configured
        // for its role.
        ensure_replication_mode(cfg, &sandbox, &pool, schema, up.replication).await?;
        let create_db_took = std::mem::replace(&mut phase, Instant::now()).elapsed();

        // Restore into the freshly-created, empty database before the entry is
        // handed to any client. A failure here must abort the bring-up: serving
        // an empty DB in place of a restored one would look like silent data loss.
        let mut restore_report = None;
        match restore {
            Some(RestoreSource::S3(s3)) => {
                restore_report = restore_from_s3(cfg, &sandbox, schema, s3, up.owner)
                    .await
                    .with_context(|| format!("restoring schema {schema} from S3"))?
            }
            Some(RestoreSource::Local { srv, port }) => {
                restore_report = restore_from_local(cfg, &sandbox, schema, srv, *port, up.owner)
                    .await
                    .with_context(|| format!("restoring schema {schema} from the local dump"))?
            }
            // Already restored above — the VM booted on the adopted disk. Counted
            // with the S3 restores on the monitoring charts: same tier, same cost
            // profile, and a fourth chart wouldn't earn its space.
            Some(RestoreSource::S3Image(_)) => crate::events::record(crate::events::Event::RestoreS3),
            // Ditto, but local (a compacted-image thaw): counted with the
            // local-dump restores.
            Some(RestoreSource::LocalImage(_)) => {
                crate::events::record(crate::events::Event::RestoreLocal)
            }
            None => {}
        }
        let restore_took = std::mem::replace(&mut phase, Instant::now()).elapsed();

        let slots = client_slot_budget(&pool, &name).await;
        let bootstrap_took = phase.elapsed();

        // One line per bring-up, next to the registry's total "VM ready in":
        // which phase ate the time is the whole diagnosis when cold starts
        // regress. `resolve+boot` spans create/reattach/spare-claim through
        // the guest boot; `pg-ready` is the wait for the postmaster. The gate
        // waits (admission, bring-up slot, boot gate) also log themselves
        // when they actually queued.
        let restore_detail = restore_report
            .as_ref()
            .map(|r| format!(" [{r}]"))
            .unwrap_or_default();
        info!(
            "schema {schema}: bring-up phases — admission {admission_took:?}, resolve+boot \
             {resolve_took:?}, pg-ready {pg_ready_took:?}, create-db {create_db_took:?}, \
             restore {restore_took:?}{restore_detail}, slots {bootstrap_took:?}",
        );

        // Time to a serving Postgres, per restore source — the same span the
        // line above breaks into phases, and the same bound `VmCreate` uses:
        // successful bring-ups only, admission wait excluded. A bring-up with
        // nothing to restore is already covered by `VmCreate`.
        if let Some(source) = restore {
            crate::events::record_timing(restore_timing(source), bringup_started.elapsed());
        }

        Ok(Arc::new(SchemaEntry::new(
            sandbox,
            target,
            tunnel,
            pool,
            keepalive,
            slots,
            bringup_started.elapsed(),
            Some(kind),
        )))
    }
    .await;

    if result.is_err() {
        match provenance {
            // Chilled or running, a claimed spare goes back through the pool:
            // `release_failed` kills it AND drops the claim, so the
            // replenisher rebuilds instead of the id staying claimed forever.
            Provenance::Spare | Provenance::ChilledSpare => {
                if let Some((pool, _)) = spares {
                    pool.release_failed(&sandbox_id).await;
                }
            }
            // A VM this attempt created held no data before it; leaving it
            // running after a failed bring-up is how a retrying client piles
            // up a dozen running VMs for one schema (each retry creates
            // another, the find-by-name reuse notwithstanding). Kill it and
            // drop its pending-ledger entry; the durable copy — S3 dump,
            // image, or nothing yet — is untouched, and the next attempt
            // starts clean.
            Provenance::Created => {
                warn!(
                    "schema {schema}: bring-up failed after creating VM {sandbox_id} — \
                     killing it so a retry does not leave another one running"
                );
                // `sandbox` moved into the bring-up future; connect by id.
                let kill = async {
                    Sandbox::connect(sandbox_id.clone(), local_opts())?.kill().await
                };
                match tokio::time::timeout(Duration::from_secs(60), kill).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(
                        "schema {schema}: killing failed-bring-up VM {sandbox_id} failed \
                         (the pending-bringup janitor will retry): {e:#}"
                    ),
                    Err(_) => warn!(
                        "schema {schema}: killing failed-bring-up VM {sandbox_id} timed out \
                         (the pending-bringup janitor will retry)"
                    ),
                }
                crate::pending::clear(schema).await;
                crate::inventory::remove_id(&sandbox_id);
            }
            Provenance::Existing => {}
        }
    }
    result
}

/// Reattach only to an already-bound fenced VM. Never creates/restores a
/// sandbox or database and never opens the tenant database for grants.
pub async fn ensure_fenced_vm(cfg: &Config, schema: &str, sandbox_id: &str) -> Result<Arc<SchemaEntry>> {
    let sandbox = Sandbox::connect(sandbox_id.to_string(), local_opts())?;
    sandbox.set_ttl(0).await.context("pinning fenced VM")?;
    let name = format!("pg-{schema}");
    let (target, tunnel, pool) = ready_pg(cfg, &sandbox, &name).await?;
    let client = pool.get().await.context("connecting to fenced VM maintenance database")?;
    if client.query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&schema]).await?.is_none() {
        bail!("fenced database {schema} is missing from VM {sandbox_id}");
    }
    drop(client);
    let slots = client_slot_budget(&pool, &name).await;
    Ok(Arc::new(SchemaEntry::new(sandbox, target, tunnel, pool, true, slots, Duration::ZERO, None)))
}

/// Validity window for a presigned S3 URL handed to the guest. Generous enough
/// to cover a slow upload/download of a large dump, short enough that a URL that
/// leaks (e.g. into a guest shell-history) expires quickly.
const PRESIGN_TTL: Duration = Duration::from_secs(3600);

/// Client-side HTTP timeout for a single guest exec round-trip. The guest exec
/// API itself hard-caps any one foreground command at ~30s server-side (and the
/// SDK has no way to raise that — the exec body carries no timeout field), so
/// this only has to comfortably outlast that cap to receive the response,
/// including the 500 the server returns when it kills a command at 30s.
const GUEST_EXEC_HTTP_TIMEOUT: Duration = Duration::from_secs(45);

/// Total wall-clock the pooler will wait for a *detached* dump+upload to finish
/// before giving up. Because the transfer runs detached in the guest (§
/// [`dump_to_s3`]) rather than as one foreground exec, this bounds only the
/// pooler's patience — the guest job is never itself subject to the ~30s exec
/// cap. The sweep retries a timed-out schema next pass.
const ARCHIVE_DEADLINE: Duration = Duration::from_secs(1800);

/// How often we check on a running dump job. Each pass is one S3 HEAD from the
/// pooler plus (at most) one trivial guest exec. Deliberately not tighter: every
/// guest exec contends for the VM's single serial console against a `pg_dump`
/// that is saturating the same one-vCPU guest, and polling harder makes the
/// starvation it is trying to observe worse.
const ARCHIVE_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Per-request timeout for the pooler's own S3 HEAD.
const ARCHIVE_HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Smallest object accepted as a real archive. A `pg_dump -Fc` of even an
/// empty database is ~1.5KB — nothing legitimate is under 512 bytes. Small
/// objects happen for real: with the host disk full, the guest's dump file is
/// torn to zero length by failed writeback while `pg_dump` and `curl` both
/// exit 0, and production accepted such a 0-byte "archive" and then killed the
/// VM — destroying the only copy of the data. Size is checked on the dump side
/// (never report a tiny upload durable) *and* the restore side (fail with the
/// truth instead of feeding `pg_restore` an empty file).
const MIN_ARCHIVE_BYTES: u64 = 512;

/// How many *consecutive* failed guest probes we tolerate before we stop asking
/// the guest and let S3 alone decide. The guest exec channel failing says
/// nothing about the detached job (which does not use that channel), so giving
/// up on it must not give up on the archive — it only costs us the fast,
/// detailed error path.
const ARCHIVE_MAX_PROBE_FAILURES: u32 = 3;

/// The same tolerance for a job with *no* out-of-band signal (the restore),
/// where losing the guest means losing the only way to ever confirm it. Much
/// more generous, because here running out means failing the operation: probes
/// fail exactly when the guest is busiest, and each failure already costs up to
/// a full [`GUEST_EXEC_HTTP_TIMEOUT`], so this is many minutes of silence — not
/// a brief stall — before we conclude the guest is gone.
const UNWITNESSED_MAX_PROBE_FAILURES: u32 = 10;

/// How long the pooler keeps trying to see the object after the guest says it
/// finished uploading. A completed PUT is visible immediately (S3 is
/// read-after-write consistent for new objects), so this only covers a HEAD or
/// two of transient trouble; past it, the disagreement is structural and waiting
/// out [`ARCHIVE_DEADLINE`] would only delay the same error.
const ARCHIVE_CONFIRM_GRACE: Duration = Duration::from_secs(60);

/// Attempts at the pre-dump HEAD. It has to succeed for the dump to be
/// verifiable at all, so a transient blip shouldn't cost a reap — but a
/// persistent failure must, and loudly.
const BASELINE_HEAD_ATTEMPTS: u32 = 3;

/// Fixed in-guest scratch paths for the dump. One VM backs exactly one schema,
/// so a constant name is unambiguous — and unlike a schema-derived name it can't
/// be broken by a schema containing `/` or a quote.
const DUMP_PATH: &str = "/workspace/_archive.dump";
const RESTORE_PATH: &str = "/workspace/_restore.dump";

/// Heredoc delimiter used to plant a job script from its launch exec. Quoted at
/// the use site (`<<'…'`) so the body — which contains `$ec`, `$?` and a
/// presigned URL full of `&`/`=`/`%` — is written through verbatim, with no
/// expansion and no shell-quoting layer to survive.
const JOB_HEREDOC_EOF: &str = "HEYO_JOB_EOF";

/// Framing token for a probe reply. Distinctive enough that no kernel log line
/// or shell echo can be mistaken for one.
const PROBE_TAG: &str = "HEYOJOB:";

/// A long-running guest job that must outlive the exec that starts it, plus the
/// in-guest scratch paths it is watched through: the shell script we plant, the
/// sentinel holding its exit code once done, and its combined log (read back
/// only to surface an error).
///
/// Both transfers need this shape for the same reason — see [`dump_to_s3`] for
/// why a foreground exec cannot carry either one.
#[derive(Clone, Copy)]
struct DetachedJob {
    /// Human name for logs and error messages ("dump", "restore").
    what: &'static str,
    script: &'static str,
    done: &'static str,
    log: &'static str,
    /// How long [`await_detached_job`] waits for the sentinel. Per-job rather
    /// than one shared constant because the schema copy is a `pg_dump` across
    /// a WAN link plus a `psql` replaying it — a different cost profile from a
    /// local dump-and-upload, and one an operator sizes with
    /// `PG_VM_POOL_REPL_SETUP_SECS`.
    deadline: Duration,
    /// How [`await_detached_job`] spaces its probes: `poll_first` before the
    /// first one, doubling after each still-running answer up to `poll_max`.
    /// Per-job because the jobs are waited on by different parties. A restore
    /// or schema copy is a bring-up with a client parked on it, and a flat
    /// [`ARCHIVE_POLL_INTERVAL`] rounded every one of those up to the next
    /// 10s mark — a 2s restore was served at 10s, a 10.1s one at 20s. The
    /// probe is builtins-only, so a sub-second first look costs the guest
    /// next to nothing; the doubling keeps a long load from paying for a
    /// console exec every 250ms.
    poll_first: Duration,
    poll_max: Duration,
    /// A guest file the job leaves a one-line report in before its sentinel
    /// (the restore's phase timings). Read by the completion probe in the
    /// same exec as the sentinel, so a report costs no extra console round
    /// trip.
    report: Option<&'static str>,
}

/// Probe spacing for a detached job a client is waiting on. Same shape as
/// [`READY_POLL_FAST_INTERVAL`]/[`READY_POLL_SLOW_INTERVAL`]: a short job is
/// seen within a quarter-second, a long one is probed at most every 2s.
const CLIENT_JOB_POLL_FIRST: Duration = Duration::from_millis(250);
const CLIENT_JOB_POLL_MAX: Duration = Duration::from_secs(2);

/// The next probe gap after a still-running answer: doubled, capped.
fn next_poll(cur: Duration, max: Duration) -> Duration {
    (cur * 2).min(max)
}

const ARCHIVE_JOB: DetachedJob = DetachedJob {
    what: "dump",
    script: "/workspace/_archive.job.sh",
    done: "/workspace/_archive.done",
    log: "/workspace/_archive.log",
    deadline: ARCHIVE_DEADLINE,
    // Waited on by `await_archive`, on its own cadence; carried for
    // completeness. No client waits on a dump.
    poll_first: ARCHIVE_POLL_INTERVAL,
    poll_max: ARCHIVE_POLL_INTERVAL,
    report: None,
};

const RESTORE_JOB: DetachedJob = DetachedJob {
    what: "restore",
    script: "/workspace/_restore.job.sh",
    done: "/workspace/_restore.done",
    log: "/workspace/_restore.log",
    deadline: ARCHIVE_DEADLINE,
    poll_first: CLIENT_JOB_POLL_FIRST,
    poll_max: CLIENT_JOB_POLL_MAX,
    report: Some(RESTORE_TIMING_PATH),
};

/// tmpfs marker recording that the *producer* of the schema-copy pipeline
/// failed. POSIX `sh` has no `pipefail`, so `pg_dump | psql` reports only
/// psql's status — and a psql that successfully replays nothing exits 0, which
/// would turn "the primary was unreachable" into "the replica is seeded and
/// empty". Same device as [`STREAM_FAIL_MARK`], and on tmpfs for the same
/// reason: touching it never allocates a data-disk block.
const SCHEMA_COPY_FAIL_MARK: &str = "/tmp/_replinit.failed";

/// The schema copy that seeds a replica before its subscription starts.
/// `deadline` is replaced per call from `PG_VM_POOL_REPL_SETUP_SECS`.
const SCHEMA_COPY_JOB: DetachedJob = DetachedJob {
    what: "schema copy",
    script: "/workspace/_replinit.job.sh",
    done: "/workspace/_replinit.done",
    log: "/workspace/_replinit.log",
    deadline: Duration::from_secs(3600),
    poll_first: CLIENT_JOB_POLL_FIRST,
    poll_max: CLIENT_JOB_POLL_MAX,
    report: None,
};

/// Dump `schema`'s database to S3 using the guest's own `pg_dump` + `curl`
/// against a pooler-presigned PUT URL. The dump bytes stream straight from the
/// guest to S3 and never transit the pooler. Dumps to a file first (not a pipe)
/// so `curl -T` sends a `Content-Length` — S3 rejects a chunked PUT.
///
/// The transfer runs **detached** in the guest, not as one foreground exec: the
/// guest exec API hard-caps a single command at 30s server-side, far too short
/// for a multi-workbook dump+upload, and the SDK can't raise it. So we launch
/// the dump under `setsid` (a new session with stdio fully redirected, so it
/// outlives the launch exec) and watch for its completion out-of-band. Each exec
/// we issue — the launch and every probe — is trivially short; only the
/// pooler-side [`ARCHIVE_DEADLINE`] bounds the wait.
///
/// Everything guest-side goes through `exec` rather than the SDK's `files()`
/// API, which is **not usable on these VMs**: `write-file`/`read-file` resolve a
/// path against a *host-side bind mount* declared at create time, so on a
/// Firecracker sandbox whose `/workspace` is a guest block device (`/dev/vdb`)
/// there is no matching mount and the daemon answers `Mount not found:
/// /workspace (available mounts: [])`.
///
/// # Why success is decided in S3, not in the guest
///
/// On these VMs `exec` is not a reliable channel. The daemon drives a **single
/// shared shell on the guest's serial console**, writing a marker-delimited
/// command and reading until the end marker, under a fixed 30s timeout
/// (`execute_via_serial` in mvm-ctrl's Firecracker driver). While `pg_dump` and
/// `curl` saturate the one-vCPU guest and its single virtio disk, even `[ -f x ]`
/// can miss that window — so a probe times out and the daemon answers `500
/// Command timed out after 30 seconds`.
///
/// That failure is about the *channel*, not the job: the detached dump neither
/// uses nor cares about the serial console. Treating it as a dump failure — as
/// this did — aborted archives that were running fine, precisely when the VM was
/// busiest, i.e. for the largest workbooks.
///
/// So the authoritative completion signal is an S3 `HEAD` issued **by the
/// pooler**: it answers over the pooler's own network, needs nothing from the
/// guest, and checks the thing actually at stake — that the object exists —
/// rather than a guest's claim about it. That matters because the caller kills
/// the VM and reclaims its disk on our `Ok`, destroying the only other copy.
/// The guest sentinel is kept as a best-effort fast path: it turns a failed dump
/// into an immediate, explained error instead of a 30-minute timeout.
/// How long to keep looking for a killed VM's `sb-<id>/` directory to vanish
/// before declaring the disk leaked. heyvmd answers the DELETE and *then*
/// tears the sandbox down, so the directory can linger a moment after `kill()`
/// returns; poll briefly and exit the instant it's gone rather than crying leak
/// on the first look. A genuinely stranded disk simply never disappears and we
/// warn after the cap — cheap, since the check is a single `stat`.
const KILL_VERIFY_ATTEMPTS: u32 = 8;
const KILL_VERIFY_INTERVAL: Duration = Duration::from_millis(500);

/// Kill `sandbox` and confirm its data-disk directory is actually gone.
///
/// The kill is `DELETE /deployed-sandboxes/:id`, and the SDK treats a 404 as
/// success — so `Ok` proves only that the daemon no longer holds the record,
/// **not** that the VM's `sb-<id>/` directory (its `data.ext4`, rootfs copy,
/// logs) left the host. We have seen the daemon drop the record while leaving
/// the directory behind: the VM count falls but the bytes don't come back, and
/// nothing else reclaims them (`reclaim-disks.sh` only trims *live* schemas'
/// disks, it never deletes dead sandboxes). Left unchecked this silently
/// strands hundreds of GB. So after a successful kill we poll for the directory
/// and, if it survives, log it loudly with the path and on-disk size instead of
/// the usual "disk reclaimed".
///
/// `accomplished` is the tier-specific thing the caller just did (e.g. "dumped
/// to s3://…" / "frozen to a 12345-byte local dump"), woven into the one log
/// line so it reads naturally. Best-effort and non-fatal: the data is already
/// durable in its new tier before we get here, so a surviving disk is a reclaim
/// task, never a reason to fail the operation. Returns the kill call's own
/// error so the caller can report an outright kill *failure* — the worse case,
/// since the VM may still be running.
pub async fn kill_and_reclaim(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    accomplished: &str,
) -> Result<()> {
    let id = sandbox.sandbox_id().to_string();
    sandbox.kill().await.context("killing the VM")?;

    let Some(dir) = cfg.run_dir.as_ref().map(|d| d.join(&id)) else {
        info!(
            "schema {schema}: {accomplished}; VM {id} killed \
             (disk removal unverified — set PG_VM_POOL_RUN_DIR to confirm)"
        );
        return Ok(());
    };

    for attempt in 0..KILL_VERIFY_ATTEMPTS {
        if !dir.exists() {
            info!("schema {schema}: {accomplished}; VM {id} killed, data disk reclaimed");
            return Ok(());
        }
        if attempt + 1 < KILL_VERIFY_ATTEMPTS {
            sleep(KILL_VERIFY_INTERVAL).await;
        }
    }

    // The daemon acked the kill but the directory survived — its known
    // failure mode (an acked kill that never removes the dir). The data is
    // durably offloaded and the space is needed NOW, not on some later sweep
    // pass — so re-confirm the daemon no longer knows the id, then remove the
    // directory ourselves. The confirm matters: only a daemon-forgotten id is
    // provably nobody's VM (the per-id GET checks the persisted store too).
    // Bounded: this confirm runs against the same per-id endpoint that can
    // wedge on a struggling daemon — an unanswered probe means "not provably
    // gone", which lands in the leave-it-for-the-sweep arm below.
    match tokio::time::timeout(Duration::from_secs(5), sandbox.get()).await {
        Ok(Err(HeyoError::NotFound(_))) => {
            let size = crate::orphans::dir_allocated_bytes(dir.clone()).await;
            match tokio::fs::remove_dir_all(&dir).await {
                Ok(()) => info!(
                    "schema {schema}: {accomplished}; VM {id} killed — the daemon left {} \
                     behind, removed it directly ({} freed)",
                    dir.display(),
                    crate::orphans::human_iec(size),
                ),
                Err(e) => warn!(
                    "schema {schema}: {accomplished}, but removing the surviving disk dir {} \
                     failed ({e}) — {} stranded until the orphan sweep gets it",
                    dir.display(),
                    crate::orphans::human_iec(size),
                ),
            }
        }
        // The daemon still claims the id (or can't answer): removing the dir
        // under it could destroy a VM it still tracks. Leave it to the sweep,
        // which re-checks with the same per-id probe.
        _ => {
            let size = crate::orphans::dir_allocated_bytes(dir.clone()).await;
            warn!(
                "schema {schema}: {accomplished}, but its VM's data disk survived the kill \
                 and the daemon still answers for {id} — {} left for the orphan-disk sweep \
                 ({} stranded)",
                dir.display(),
                crate::orphans::human_iec(size),
            );
        }
    }
    Ok(())
}

/// Archive `schema`'s database to S3. Two routes:
///
/// * **Via the dump server** (default whenever one is running): the guest
///   *streams* `pg_dump` to the host — zero guest-disk writes — and the
///   pooler uploads the landed file to S3 (multipart above 100MB) and deletes
///   it. The file-based route inflated the very disk being archived: the
///   guest's `-f /workspace/_archive.dump` permanently converted sparse holes
///   into allocated host blocks (no discard passthrough), on failures too.
/// * **Legacy, direct from the guest** (`PG_VM_POOL_ARCHIVE_VIA_GUEST=1`, or
///   no dump server running): dump to a guest file, `curl -T` it to a
///   presigned PUT. Kept one release as an escape hatch.
pub async fn dump_to_s3(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    s3: &S3Config,
    dumps: Option<(&crate::dumpsrv::DumpServer, u16)>,
) -> Result<()> {
    let via_guest = std::env::var("PG_VM_POOL_ARCHIVE_VIA_GUEST")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if let Some((srv, port)) = dumps
        && !via_guest
    {
        return dump_to_s3_via_server(cfg, sandbox, schema, s3, srv, port).await;
    }

    let key = s3.object_key(schema);
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);

    let http = reqwest::Client::builder()
        .build()
        .context("building HTTP client for S3 HEAD")?;

    // What's at this key *before* the dump — the reference point that makes
    // "the object is there" mean something. A schema's archive key is stable, so
    // the previous archive already sits there; presence alone is no evidence,
    // and mistaking it for this run's upload would report success for a dump
    // that never happened and then reclaim the live disk.
    //
    // This runs before anything is presigned, because it is also where a
    // wrong-region bucket gets discovered and corrected — see
    // `S3Config::head_object`. Signing the guest's PUT first would hand it a URL
    // for the wrong host.
    let baseline = baseline_head(&http, s3, &key, schema).await?;

    let url = s3.presign_put(&key, PRESIGN_TTL);
    let resolve = s3_resolve_flag(s3).await;

    ARCHIVE_JOB
        .launch(
            cfg,
            sandbox,
            &archive_job_body(&user, &db, &resolve, &url),
            DUMP_PATH,
        )
        .await?;

    await_archive(cfg, sandbox, schema, s3, &http, &key, baseline.as_ref()).await
}

/// The streaming S3 archive: guest dump → host dump server (committed, so the
/// bytes are a verified-complete archive) → pooler upload to S3 → HEAD-verify
/// against a pre-upload baseline → local file removed. The guest's data disk
/// is never written.
async fn dump_to_s3_via_server(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    s3: &S3Config,
    srv: &crate::dumpsrv::DumpServer,
    port: u16,
) -> Result<()> {
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);
    let token = srv.issue(schema, crate::dumpsrv::Mode::Put)?;
    let url = format!("http://$GW:{port}/d/{token}");
    let body = format!(
        "{}{}",
        gw_prelude(ARCHIVE_JOB.done),
        streaming_dump_job_body(&user, &db, &url)
    );
    ARCHIVE_JOB.launch(cfg, sandbox, &body, STREAM_FAIL_MARK).await?;
    let bytes = await_server_upload(cfg, sandbox, schema, srv, &token).await?;

    // The landed file is this tier's scratch: uploaded then removed on every
    // exit path. (On failure it must not linger either — a later *freeze*
    // would trust a file at this exact path as that schema's frozen dump.)
    let path = srv.dump_path(schema);
    let res = upload_dump_to_s3(s3, schema, &path, bytes).await;
    let _ = tokio::fs::remove_file(&path).await;
    res
}

/// Pooler-side upload of a landed dump file to the schema's S3 dump key, with
/// the same baseline-HEAD verification discipline as the guest path: the
/// caller reclaims the source disk on success, so presence-at-key alone is
/// never trusted.
async fn upload_dump_to_s3(s3: &S3Config, schema: &str, path: &std::path::Path, len: u64) -> Result<()> {
    let http = reqwest::Client::builder()
        .build()
        .context("building HTTP client for the S3 upload")?;
    let key = s3.object_key(schema);
    let baseline = baseline_head(&http, s3, &key, schema).await?;
    crate::imgarchive::upload_path(s3, &http, &key, path, len)
        .await
        .with_context(|| format!("uploading {} to s3://{}/{key}", path.display(), s3.bucket))?;
    match s3.head_object(&http, &key, ARCHIVE_HEAD_TIMEOUT).await {
        Ok(Some(id)) if id.content_length == len && Some(&id) != baseline.as_ref() => {
            info!(
                "schema {schema}: archive uploaded to s3://{}/{key} ({len} bytes)",
                s3.bucket
            );
            Ok(())
        }
        Ok(Some(id)) => bail!(
            "uploaded s3://{}/{key} but the HEAD reports {} bytes against a {len}-byte \
             dump (baseline unchanged: {}) — refusing to trust it",
            s3.bucket,
            id.content_length,
            Some(&id) == baseline.as_ref(),
        ),
        Ok(None) => bail!("uploaded s3://{}/{key} but a HEAD finds nothing", s3.bucket),
        Err(e) => Err(e.context("verifying the uploaded archive")),
    }
}

/// Read what is at the archive key before dumping, retrying a few times.
///
/// Failing here aborts the dump before any work is done, which is the point: the
/// caller reclaims the source disk when we report success, and success is only
/// meaningful against this baseline. A pooler that cannot read the bucket cannot
/// establish that any dump landed, so it must not archive into it — the VM
/// simply stays up and the next reap tries again.
async fn baseline_head(
    http: &reqwest::Client,
    s3: &S3Config,
    key: &str,
    schema: &str,
) -> Result<Option<crate::s3::ObjectId>> {
    let mut last = None;
    for attempt in 1..=BASELINE_HEAD_ATTEMPTS {
        match s3.head_object(http, key, ARCHIVE_HEAD_TIMEOUT).await {
            Ok(id) => return Ok(id),
            Err(e) => {
                warn!(
                    "schema {schema}: pre-dump HEAD of s3://{}/{key} failed \
                     (attempt {attempt}/{BASELINE_HEAD_ATTEMPTS}): {e:#}",
                    s3.bucket
                );
                last = Some(e);
            }
        }
        if attempt < BASELINE_HEAD_ATTEMPTS {
            sleep(ARCHIVE_POLL_INTERVAL).await;
        }
    }
    Err(last.expect("at least one attempt ran")).with_context(|| {
        format!(
            "schema {schema}: cannot read s3://{}/{key}, so no dump into it could be \
             verified; refusing to archive (the source VM is reclaimed on success, \
             so an unverifiable archive is a lost workbook)",
            s3.bucket
        )
    })
}

/// tmpfs marker recording that `pg_dump` itself failed inside the streaming
/// pipeline (POSIX sh has no pipefail). `/tmp` is RAM in the guest image, so
/// touching it never allocates data-disk blocks.
const STREAM_FAIL_MARK: &str = "/tmp/_dump_stream.failed";

/// The *streaming* dump job body: `pg_dump` pipes straight into `curl -T -`
/// against the host dump server — no `/workspace/_archive.dump`, so the dump
/// payload allocates zero blocks on the guest's data disk (the few-KB job
/// sentinel/log still land there). That matters because the virtio-blk has no
/// discard passthrough: any block a dump file ever touched stays allocated in
/// the host's sparse `data.ext4` after `rm`, permanently — the file-based job
/// inflated every disk it tried to archive, failed attempts included (the
/// snowball emergency-drain.sh documents).
///
/// A chunked upload whose producer dies just *ends* — the server can't tell
/// torn from complete — so the upload is two-phase: the streamed bytes are
/// held pending, and only this job, which alone knows pg_dump's exit code,
/// commits them (or aborts on failure). The pooler's wait loop trusts nothing
/// before the server records the commit.
fn streaming_dump_job_body(user: &str, db: &str, url: &str) -> String {
    let done = ARCHIVE_JOB.done;
    format!(
        "ec=0\n\
         rm -f {STREAM_FAIL_MARK}\n\
         code=$({{ pg_dump -h 127.0.0.1 -U {user} -Fc -d {db} || echo 1 > {STREAM_FAIL_MARK}; }} \
         | curl -sS -T - -o /dev/null -w '%{{http_code}}' \"{url}\") || ec=$?\n\
         if [ -f {STREAM_FAIL_MARK} ]; then\n\
         \techo 'pg_dump failed before the stream ended' >&2\n\
         \tec=1\n\
         fi\n\
         {}\
         if [ \"$ec\" = 0 ]; then\n\
         \tcode=$(curl -sS -X POST -o /dev/null -w '%{{http_code}}' \"{url}/commit\") || ec=$?\n\
         {}\
         else\n\
         \tcurl -sS -X POST -o /dev/null \"{url}/abort\" >/dev/null 2>&1 || true\n\
         fi\n\
         printf %s \"$ec\" > {done}.tmp && mv {done}.tmp {done}\n",
        require_2xx("upload"),
        require_2xx("commit"),
    )
}

/// The dump job body, planted as a *file* rather than run as `sh -c '…'`, so
/// the presigned URL — full of `&`/`=` query params — never has to survive a
/// layer of shell quoting. `ec` captures the first failing step so a failed
/// pg_dump never uploads a truncated object, and the sentinel records it.
/// `user`/`db` arrive already shell-quoted.
///
/// Only used against *S3* today (presigned PUTs need a Content-Length, so the
/// guest must dump to a file first) — and only as the legacy fallback when no
/// dump server is running (see [`dump_to_s3`]): the `-f {DUMP_PATH}` write is
/// exactly the disk-inflating behavior the streaming body exists to avoid.
fn archive_job_body(user: &str, db: &str, resolve: &str, url: &str) -> String {
    let done = ARCHIVE_JOB.done;
    format!(
        "ec=0\n\
         if pg_dump -h 127.0.0.1 -U {user} -Fc -d {db} -f {DUMP_PATH}; then\n\
         \tsync {DUMP_PATH} 2>/dev/null || true\n\
         \tif [ -s {DUMP_PATH} ]; then\n\
         \t\tcode=$(curl -sS {resolve} -T {DUMP_PATH} -o /dev/null -w '%{{http_code}}' \"{url}\") || ec=$?\n\
         {}\
         \telse\n\
         \t\techo \"dump file empty/missing after pg_dump reported success (disk trouble?)\" >&2\n\
         \t\tec=1\n\
         \tfi\n\
         else\n\
         \tec=$?\n\
         fi\n\
         rm -f {DUMP_PATH}\n\
         printf %s \"$ec\" > {done}.tmp && mv {done}.tmp {done}\n",
        require_2xx("upload")
    )
}

/// Shell prelude for jobs that talk to the *local* dump server: resolve the
/// host's address as the guest's default gateway (the host side of its tap)
/// from `/proc/net/route` — the guest image has no `iproute2`, and the pooler
/// can't know each VM's gateway from outside. Sets `$GW`, which the job's URL
/// references (`http://$GW:port/...`, expanded by the shell inside the curl's
/// double quotes). On failure it writes the job's failure sentinel and exits,
/// so the pooler gets a prompt, explained error instead of a deadline wait.
/// `/proc/net/route` stores the gateway as little-endian hex, hence the
/// byte-reversing `cut`s (POSIX sh has no substring expansion).
fn gw_prelude(done: &str) -> String {
    format!(
        "GW=$(awk '$2==\"00000000\" {{print $3; exit}}' /proc/net/route)\n\
         if [ -n \"$GW\" ]; then\n\
         \tGW=$(printf '%d.%d.%d.%d' \"0x$(echo \"$GW\" | cut -c7-8)\" \"0x$(echo \"$GW\" | cut -c5-6)\" \"0x$(echo \"$GW\" | cut -c3-4)\" \"0x$(echo \"$GW\" | cut -c1-2)\")\n\
         fi\n\
         if [ -z \"$GW\" ]; then\n\
         \techo 'cannot determine host gateway from /proc/net/route' >&2\n\
         \tprintf %s 1 > {done}.tmp && mv {done}.tmp {done}\n\
         \texit 0\n\
         fi\n"
    )
}

/// Fail the job unless S3 answered the transfer with a 2xx.
///
/// `curl -f` is not enough on its own: `--fail` only trips on 4xx/5xx, so a
/// **3xx** — notably the `301 Moved Permanently` S3 returns for a bucket in
/// another region — exits 0 with nothing transferred. That made a dump that
/// uploaded no bytes report success, and the caller then reclaimed the disk it
/// had just "archived". So the status code is checked explicitly, and anything
/// that is not 2xx is a failed job.
///
/// A curl-level failure (`ec` already non-zero) keeps its own exit code; only an
/// otherwise-clean run with a bad status is attributed to 22, curl's own
/// "HTTP error returned". `$code` is empty when curl died before a response.
fn require_2xx(what: &str) -> String {
    format!(
        "\tcase \"$code\" in\n\
         \t2??) ;;\n\
         \t*) echo \"{what} rejected by S3: HTTP $code\" >&2; \
         if [ \"$ec\" = 0 ]; then ec=22; fi ;;\n\
         \tesac\n"
    )
}

/// Guest file the restore job leaves its phase timings in, as one line:
/// `mode download_ms load_ms finalize_ms` (`-` for a phase that did not run).
/// Read back by the completion probe itself ([`DetachedJob::probe_command`]),
/// so the timings cost no extra exec.
const RESTORE_TIMING_PATH: &str = "/workspace/_restore.timing";

/// pipefail surrogate for the streamed restore: curl's exit code, when it
/// failed, so a download that died mid-stream is never mistaken for
/// `pg_restore`'s own verdict on a truncated archive.
const RESTORE_CURL_FAIL_MARK: &str = "/workspace/_restore.curl-ec";

/// Where the streamed restore's response headers land (`curl -D`), since the
/// body goes down the pipe and `-w '%{http_code}'` would land in it too.
const RESTORE_HEADERS_PATH: &str = "/workspace/_restore.hdr";

/// The restore-time Postgres settings, read through the
/// `include_if_exists` that `init.sh` keeps last in `postgresql.conf`. On
/// `/run` — a tmpfs — so a VM that reboots mid-restore comes back with its
/// normal durability whatever the job managed to do.
const RESTORE_TUNING_CONF: &str = "/run/pg-fc-restore.conf";

/// Whether restore jobs load with `fsync` and `full_page_writes` off.
/// `PG_VM_POOL_RESTORE_FAST_LOAD`, default on; `0`/`false`/`no`/`off` turn it
/// off. Read lazily, the same way the bring-up gates are.
fn restore_fast_load() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !std::env::var("PG_VM_POOL_RESTORE_FAST_LOAD")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false)
    })
}

/// The restore job body: fetch the archive, load it into the already-created
/// database, make it durable, and leave its phase timings behind. Same
/// `ec`/sentinel discipline as the dump, so a failed download never looks like
/// a successful restore of nothing.
///
/// **How it loads.** On a one-vCPU guest — every size class this pooler runs
/// today — the dump is streamed straight from `curl` into a serial
/// `pg_restore --single-transaction`: the download and the load overlap
/// instead of running back to back, the dump never takes a round trip through
/// the data disk, and with `wal_level=minimal` the COPY into tables created in
/// that same transaction skips the WAL entirely. `-j` buys nothing on one
/// core. A guest with more cores keeps the download-then-`pg_restore -j` path,
/// because parallel restore needs a seekable file. If the stream fails *after*
/// S3 answered 2xx, the job retries once the classic way: a dump streamed
/// from `pg_dump` into S3 carries no data offsets in its TOC, and `pg_restore`
/// refuses some orders on non-seekable input it would accept from a file. The
/// single transaction rolled the failed stream back, so the retry starts from
/// the same empty database.
///
/// **How it makes the load cheap.** With `fast_load`, the job switches the
/// cluster to `fsync = off` and `full_page_writes = off` for the load and back
/// afterwards — then `CHECKPOINT` and `sync` before the sentinel, so a
/// restore reported done is durable. That is only safe because nothing on
/// this VM matters until the restore succeeds: a bring-up whose restore fails
/// kills its VM, and the settings live on a tmpfs, so a reboot drops them.
/// The guest job owns the reset rather than the pooler, so a pooler restart
/// mid-restore still puts durability back. `max_wal_size` is deliberately left
/// alone: with fsync and full-page images off, a checkpoint is cheap anyway,
/// and init.sh's WAL ceiling is what keeps a big load off ENOSPC.
///
/// `--clean --if-exists` makes the load idempotent: a *previous* restore
/// attempt that died partway (host outage, kill mid-load) leaves a partially
/// restored database on the reused VM's persistent disk, and without it every
/// retry fails on `relation already exists` — one interrupted restore wedged
/// the schema forever. Object-level clean handles that; `--if-exists` keeps it
/// a no-op on the genuinely fresh, empty database of the common case.
/// `keep_ownership` is set for a *dedicated* database ([`crate::dedicated`]),
/// and it matters: the default `--no-owner --no-privileges` makes every
/// restored object belong to the restoring superuser and drops the dump's
/// grants, which for an ordinary schema is exactly right (the dump may name
/// roles this cluster has never heard of) but for a dedicated one silently
/// hands the tenant back a database it cannot read — its tables would come back
/// owned by `postgres`. The owning role is guaranteed to exist before any
/// restore runs (`ensure_database` creates it first), so here the dump's own
/// ownership and grants can and must be replayed.
fn restore_job_body(
    user: &str,
    db: &str,
    resolve: &str,
    url: &str,
    keep_ownership: bool,
    fast_load: bool,
) -> String {
    let done = RESTORE_JOB.done;
    let ownership = if keep_ownership {
        ""
    } else {
        "--no-owner --no-privileges "
    };
    let restore = format!("pg_restore -h 127.0.0.1 -U {user} --clean --if-exists {ownership}");
    let psql = format!("psql -h 127.0.0.1 -U {user} -d postgres -qAtX");
    let tune = if fast_load {
        format!(
            "if printf 'fsync = off\\nfull_page_writes = off\\n' > {RESTORE_TUNING_CONF} \
             && chmod 644 {RESTORE_TUNING_CONF} \
             && {psql} -c 'select pg_reload_conf()' >/dev/null; then\n\
             \ttuned=1\n\
             else\n\
             \trm -f {RESTORE_TUNING_CONF}\n\
             \techo 'restore-time tuning unavailable; loading with normal durability' >&2\n\
             fi\n"
        )
    } else {
        String::new()
    };
    format!(
        "ec=0\n\
         tuned=0\n\
         mode=file\n\
         dl_ms=-\n\
         load_ms=-\n\
         fin_ms=-\n\
         now_ms() {{ t=$(date +%s%3N 2>/dev/null); case \"$t\" in ''|*[!0-9]*) echo 0 ;; *) echo \"$t\" ;; esac; }}\n\
         rm -f {RESTORE_TIMING_PATH} {RESTORE_CURL_FAIL_MARK} {RESTORE_HEADERS_PATH}\n\
         {tune}\
         if [ \"$(nproc)\" -le 1 ]; then\n\
         \tmode=stream\n\
         \tt0=$(now_ms)\n\
         \t{{ curl -sS {resolve} -D {RESTORE_HEADERS_PATH} -o - \"{url}\" \
         || echo $? > {RESTORE_CURL_FAIL_MARK}; }} \
         | {restore}--single-transaction -d {db} || ec=$?\n\
         \tload_ms=$(( $(now_ms) - t0 ))\n\
         \tcode=$(awk 'toupper($1) ~ /^HTTP\\// {{c=$2}} END {{print c}}' {RESTORE_HEADERS_PATH} 2>/dev/null)\n\
         \tif [ -f {RESTORE_CURL_FAIL_MARK} ]; then read ec < {RESTORE_CURL_FAIL_MARK}; fi\n\
         {}\
         \tcase \"$ec:$code\" in\n\
         \t0:*) ;;\n\
         \t*:2??) echo \"streamed restore failed (exit $ec); retrying from a downloaded file\" >&2\n\
         \t\tmode=file_after_stream; ec=0 ;;\n\
         \tesac\n\
         fi\n\
         if [ \"$mode\" != stream ]; then\n\
         \tt0=$(now_ms)\n\
         \tcode=$(curl -sS {resolve} -o {RESTORE_PATH} -w '%{{http_code}}' \"{url}\") || ec=$?\n\
         {}\
         \tdl_ms=$(( $(now_ms) - t0 ))\n\
         \tif [ \"$ec\" = 0 ]; then\n\
         \t\tt0=$(now_ms)\n\
         \t\t{restore}-j \"$(nproc)\" -d {db} {RESTORE_PATH} || ec=$?\n\
         \t\tload_ms=$(( $(now_ms) - t0 ))\n\
         \tfi\n\
         \trm -f {RESTORE_PATH}\n\
         fi\n\
         if [ \"$tuned\" = 1 ]; then\n\
         \tt0=$(now_ms)\n\
         \trm -f {RESTORE_TUNING_CONF}\n\
         \t{psql} -c 'select pg_reload_conf()' >/dev/null || {{ [ \"$ec\" = 0 ] && ec=1; }}\n\
         \tif [ \"$ec\" = 0 ]; then\n\
         \t\t{psql} -c CHECKPOINT >/dev/null || ec=$?\n\
         \t\tsync\n\
         \tfi\n\
         \tfin_ms=$(( $(now_ms) - t0 ))\n\
         fi\n\
         rm -f {RESTORE_CURL_FAIL_MARK} {RESTORE_HEADERS_PATH}\n\
         printf '%s %s %s %s\\n' \"$mode\" \"$dl_ms\" \"$load_ms\" \"$fin_ms\" > {RESTORE_TIMING_PATH}\n\
         printf %s \"$ec\" > {done}.tmp && mv {done}.tmp {done}\n",
        indent(&require_2xx("download")),
        indent(&require_2xx("download")),
    )
}

/// One more tab in front of every line of a job fragment, for splicing a
/// top-level fragment like [`require_2xx`] into a branch.
fn indent(fragment: &str) -> String {
    fragment.lines().map(|l| format!("\t{l}\n")).collect()
}

/// What a finished restore job reported about itself: which way it loaded and
/// how long each phase took. `None` for a phase that did not run (a streamed
/// load has no separate download; an untuned load has no finalize).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreReport {
    /// `stream`, `file`, or `file_after_stream` (a stream that failed and was
    /// retried from a downloaded file).
    pub(crate) mode: String,
    pub(crate) download: Option<Duration>,
    pub(crate) load: Option<Duration>,
    pub(crate) finalize: Option<Duration>,
}

impl RestoreReport {
    /// Parse the job's timing line. `None` when it is missing or garbled — a
    /// guest image whose job predates the timing file, or a probe that lost
    /// the race with the write — which costs the sub-phase figures and nothing
    /// else.
    fn parse(line: &str) -> Option<Self> {
        let mut f = line.split_whitespace();
        let mode = f.next()?.to_string();
        if !matches!(mode.as_str(), "stream" | "file" | "file_after_stream") {
            return None;
        }
        let mut ms = || -> Option<Option<Duration>> {
            match f.next()? {
                "-" => Some(None),
                v => v
                    .parse::<u64>()
                    .ok()
                    .map(|n| Some(Duration::from_millis(n))),
            }
        };
        Some(Self {
            download: ms()?,
            load: ms()?,
            finalize: ms()?,
            mode,
        })
    }

    fn record(&self) {
        use crate::events::{Timing, record_timing};
        for (kind, took) in [
            (Timing::RestoreDumpDownload, self.download),
            (Timing::RestoreDumpLoad, self.load),
            (Timing::RestoreDumpFinalize, self.finalize),
        ] {
            if let Some(took) = took {
                record_timing(kind, took);
            }
        }
    }
}

impl std::fmt::Display for RestoreReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let d = |v: Option<Duration>| v.map_or_else(|| "-".to_string(), |d| format!("{d:?}"));
        write!(
            f,
            "{} (download {}, load {}, finalize {})",
            self.mode,
            d(self.download),
            d(self.load),
            d(self.finalize)
        )
    }
}

impl DetachedJob {
    /// One exec that plants `job` and launches it: clear any prior run's
    /// sentinel/scratch (`scratch` is the job's own transfer file), write the
    /// body through a quoted heredoc (verbatim — no expansion, so `$ec`/`$?` and
    /// the URL land intact), then background it in a fresh session so it
    /// survives the exec returning. `echo` keeps the exec itself instant.
    /// PGPASSWORD is set on the launch exec and inherited by the detached job.
    ///
    /// `job` must end in a newline — the heredoc delimiter has to start its own
    /// line or `sh` never closes the redirect.
    fn launch_script(&self, job: &str, scratch: &str) -> String {
        let (script, done, log) = (self.script, self.done, self.log);
        format!(
            "rm -f {done} {scratch} {log}\n\
             cat > {script} <<'{JOB_HEREDOC_EOF}'\n\
             {job}{JOB_HEREDOC_EOF}\n\
             setsid sh {script} </dev/null >{log} 2>&1 &\n\
             echo launched\n"
        )
    }

    async fn launch(
        &self,
        cfg: &Config,
        sandbox: &Sandbox,
        job: &str,
        scratch: &str,
    ) -> Result<()> {
        self.launch_with_env(cfg, sandbox, job, scratch, None).await
    }

    /// As [`Self::launch`], but with an explicit environment for the launch
    /// exec — which the detached child inherits.
    ///
    /// This is how the schema copy receives the *primary's* password: in
    /// `PGPASSWORD`, so it is in neither the planted script (which sits on the
    /// data disk) nor any argv. `None` keeps the historical behaviour of
    /// passing this pooler's own `PG_VM_POOL_PASSWORD`.
    async fn launch_with_env(
        &self,
        cfg: &Config,
        sandbox: &Sandbox,
        job: &str,
        scratch: &str,
        env: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let what = self.what;
        let script = self.launch_script(job, scratch);
        let res = match env {
            Some(env) => exec_guest_env(cfg, sandbox, &script, Some(env), &format!("{what} job (launch)")).await?,
            None => exec_guest(cfg, sandbox, &script, true, &format!("{what} job (launch)")).await?,
        };
        if res.exit_code != 0 {
            bail!(
                "launching detached {what} failed (exit {}): {}",
                res.exit_code,
                truncate(exec_detail(&res), 800)
            );
        }
        Ok(())
    }

    /// The status probe. Built to be as cheap as a guest command can be, because
    /// it competes for the serial console with a `pg_dump`/`pg_restore`
    /// saturating the VM: `[`, `printf` and `read` are shell builtins, so this
    /// forks nothing.
    ///
    /// With a [`Self::report`] file, a finished job's reply carries it on an
    /// `R` line ahead of the `D` line — still builtins only.
    fn probe_command(&self) -> String {
        let done = self.done;
        let report = match self.report {
            Some(path) => format!(
                "r=; {{ read r < {path}; }} 2>/dev/null; printf '{PROBE_TAG}R%s\\n' \"$r\"; "
            ),
            None => String::new(),
        };
        format!(
            "if [ -f {done} ]; then read c < {done}; \
             {report}printf '{PROBE_TAG}D%s\\n' \"$c\"; \
             else printf '{PROBE_TAG}P\\n'; fi"
        )
    }

    async fn probe(&self, cfg: &Config, sandbox: &Sandbox) -> Result<(JobState, Option<String>)> {
        let what = self.what;
        let res = exec_guest(
            cfg,
            sandbox,
            &self.probe_command(),
            false,
            &format!("probing {what} job"),
        )
        .await?;
        Ok((parse_probe(&res.stdout), parse_probe_report(&res.stdout)))
    }

    /// Best-effort tail of the job's guest-side log, so a failure (bad
    /// credentials, S3 4xx, disk-full) is visible in the error instead of dying
    /// with the VM. Read through the guest shell, not `files()` (see
    /// [`dump_to_s3`]); an unreadable log must not mask the job's own failure,
    /// so this degrades to an empty tail.
    async fn log_tail(&self, cfg: &Config, sandbox: &Sandbox) -> String {
        let tail = format!("tail -c 2000 {} 2>/dev/null || true", self.log);
        exec_guest(cfg, sandbox, &tail, false, "reading job log")
            .await
            .map(|r| r.stdout)
            .unwrap_or_default()
    }
}

/// Wait for the detached dump to land, on two independent signals:
///
/// * **S3 `HEAD`** (authoritative, when there is a [`Baseline::Known`]). An
///   object at `key` differing from the baseline means this run's upload
///   completed. Costs nothing from the guest, so it survives a wedged exec
///   channel — and it is the only signal that proves the archive exists before
///   the caller reclaims the source disk.
/// * **the guest sentinel** (best-effort). Turns a *failed* dump into an
///   immediate, explained error rather than a [`ARCHIVE_DEADLINE`]-long wait.
///   Every failure mode of this signal — timeout, garbled read, VM too busy to
///   answer — is treated as "no information", never as a failed dump.
///
/// Neither signal alone can be dropped: with a [`Baseline::Unknown`] the S3 side
/// cannot distinguish this archive from the previous one at the same key, so the
/// sentinel becomes load-bearing and is never muted.
///
/// Only [`ARCHIVE_DEADLINE`] ends the wait unsuccessfully.
async fn await_archive(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    s3: &S3Config,
    http: &reqwest::Client,
    key: &str,
    baseline: Option<&crate::s3::ObjectId>,
) -> Result<()> {
    let deadline = Instant::now() + ARCHIVE_DEADLINE;
    let mut probe_failures: u32 = 0;
    let mut probes_muted = false;
    // When the guest first claimed the upload was done. Once it has, waiting the
    // full deadline out is pointless — either the object shows up within a few
    // polls or it is not coming — and a prompt, specific error beats a generic
    // half-hour timeout.
    let mut claimed_done: Option<Instant> = None;
    loop {
        sleep(ARCHIVE_POLL_INTERVAL).await;

        // 1. Did the object land? Strongly-consistent for a fresh PUT, so an
        //    object that differs from the baseline is proof, not a hint — but
        //    only where there *is* a baseline to differ from.
        //
        //    The binding records whether this HEAD could not be completed at
        //    all, as opposed to completing and reporting the object
        //    absent/unchanged — the two mean opposite things when the guest
        //    claims success below.
        let head_unavailable = match s3.head_object(http, key, ARCHIVE_HEAD_TIMEOUT).await {
            Ok(now) => {
                if let Some(now) = &now
                    && Some(now) != baseline
                {
                    // A new object landed — but existence is not validity. An
                    // implausibly small object is a failed dump that still
                    // uploaded (torn dump file under disk pressure); reporting
                    // it durable would let the caller destroy the source disk.
                    if now.content_length < MIN_ARCHIVE_BYTES {
                        bail!(
                            "schema {schema}: upload at s3://{}/{key} is only {} bytes — \
                             no pg_dump archive is that small, so the dump itself \
                             produced no data (disk-full tears the dump file this way); \
                             refusing to report this archive durable. Guest log: {}",
                            s3.bucket,
                            now.content_length,
                            truncate(ARCHIVE_JOB.log_tail(cfg, sandbox).await.trim(), 800)
                        );
                    }
                    info!(
                        "schema {schema}: archive present in s3://{}/{key} ({} bytes)",
                        s3.bucket, now.content_length
                    );
                    return Ok(());
                }
                false
            }
            // A HEAD failure is about our S3 path, not the dump. Keep waiting;
            // the deadline still bounds us.
            Err(e) => {
                warn!("schema {schema}: HEAD while waiting for archive failed: {e:#}");
                true
            }
        };

        // 2. Ask the guest, unless it has stopped answering — see
        //    `ARCHIVE_MAX_PROBE_FAILURES`. Never fatal on its own.
        if !probes_muted {
            match ARCHIVE_JOB
                .probe(cfg, sandbox)
                .await
                .map(|(state, _)| state)
            {
                Ok(JobState::Failed(code)) => {
                    let log = ARCHIVE_JOB.log_tail(cfg, sandbox).await;
                    bail!(
                        "detached dump job for schema {schema} failed (exit {code}): {}",
                        truncate(log.trim(), 800)
                    );
                }
                // The job says it uploaded successfully — which is a claim, not
                // proof, and never sufficient on its own. Keep looping and let a
                // HEAD confirm it.
                //
                // This deliberately does *not* fall back to trusting the guest
                // when the pooler can't reach S3. It used to, on the reasoning
                // that a clean `curl` exit meant S3 had accepted the PUT; that
                // reasoning was wrong twice over. `curl -f` also exits 0 on a
                // 3xx, so a `301` for a wrong-region bucket read as success —
                // and when the pooler cannot HEAD the object, the most likely
                // cause is the very same misconfiguration that is breaking the
                // guest's upload, so the two "independent" signals fail
                // together. Accepting the guest's word there archived nothing
                // and then reclaimed the disk.
                //
                // A dump that cannot be confirmed therefore fails. The cost is
                // an unreaped VM and a retry; the cost of the other choice is
                // the workbook.
                Ok(JobState::Succeeded) => {
                    probe_failures = 0;
                    claimed_done.get_or_insert_with(Instant::now);
                }
                Ok(JobState::Running) => probe_failures = 0,
                Err(e) => {
                    // Safe to give up on the guest: S3 decides this one, and the
                    // probe is only here to turn a failed dump into a prompt
                    // error rather than a deadline-long wait.
                    let budget = ARCHIVE_MAX_PROBE_FAILURES;
                    probe_failures += 1;
                    warn!(
                        "schema {schema}: dump-job probe {probe_failures}/{budget} failed \
                         (the dump itself is unaffected — it does not use this channel): {e:#}"
                    );
                    if probe_failures >= budget {
                        probes_muted = true;
                        warn!(
                            "schema {schema}: guest exec channel is not answering; \
                             waiting on S3 alone until {ARCHIVE_DEADLINE:?} elapses"
                        );
                    }
                }
            }
        }

        // The guest finished and S3 still doesn't show the object. Something
        // between the two is lying — a wrong-region redirect the guest read as
        // success, a bucket policy, a key mismatch — and none of it will resolve
        // by waiting. Fail now, naming both halves, rather than at the deadline.
        if let Some(at) = claimed_done
            && at.elapsed() >= ARCHIVE_CONFIRM_GRACE
        {
            bail!(
                "dump job for schema {schema} reported success but s3://{}/{key} \
                 {} {ARCHIVE_CONFIRM_GRACE:?} later — refusing to report this \
                 archive as durable while the source VM is about to be reclaimed. \
                 Guest log: {}",
                s3.bucket,
                if head_unavailable {
                    "could not be checked"
                } else {
                    "still holds no new object"
                },
                truncate(ARCHIVE_JOB.log_tail(cfg, sandbox).await.trim(), 800)
            );
        }

        if Instant::now() >= deadline {
            bail!(
                "dump of schema {schema} did not appear at s3://{}/{key} within \
                 {ARCHIVE_DEADLINE:?}",
                s3.bucket
            );
        }
    }
}

/// Dump `schema` to the local dump server (the frozen tier's counterpart of
/// [`dump_to_s3`]). Same detached guest job — `pg_dump` then `curl -T` — but
/// the upload lands on the host, and completion is confirmed *in-process* by
/// the server having fully written, fsync'd, and renamed the file: an even
/// stronger signal than the S3 tier's HEAD, with the same refusal to trust
/// the guest's word alone. Returns the completed dump's byte count.
pub async fn dump_to_local(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    srv: &crate::dumpsrv::DumpServer,
    port: u16,
) -> Result<u64> {
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);
    let token = srv.issue(schema, crate::dumpsrv::Mode::Put)?;
    let url = format!("http://$GW:{port}/d/{token}");
    let body = format!(
        "{}{}",
        gw_prelude(ARCHIVE_JOB.done),
        streaming_dump_job_body(&user, &db, &url)
    );
    ARCHIVE_JOB.launch(cfg, sandbox, &body, STREAM_FAIL_MARK).await?;
    await_server_upload(cfg, sandbox, schema, srv, &token).await
}

/// Wait out a detached dump against *our* dump server, on two signals — the
/// server's own completion record (authoritative: bytes fully written,
/// fsync'd, renamed after the guest's commit) and the guest sentinel
/// (best-effort, for prompt explained failures). Mirrors [`await_archive`]'s
/// trust posture: an unconfirmed dump is a failed dump.
async fn await_server_upload(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    srv: &crate::dumpsrv::DumpServer,
    token: &str,
) -> Result<u64> {
    let deadline = Instant::now() + ARCHIVE_DEADLINE;
    let mut probe_failures: u32 = 0;
    let mut probes_muted = false;
    let mut claimed_done: Option<Instant> = None;
    loop {
        sleep(ARCHIVE_POLL_INTERVAL).await;
        // Authoritative: our own server fully wrote and renamed the upload.
        if let Some(bytes) = srv.upload_completed(token) {
            if bytes < MIN_ARCHIVE_BYTES {
                bail!(
                    "schema {schema}: local dump is only {bytes} bytes — no pg_dump \
                     archive is that small, so the dump itself produced no data; \
                     refusing to trust it. Guest log: {}",
                    truncate(ARCHIVE_JOB.log_tail(cfg, sandbox).await.trim(), 800)
                );
            }
            info!("schema {schema}: local dump complete ({bytes} bytes)");
            return Ok(bytes);
        }
        // Guest sentinel: turns a failed dump into a prompt, explained error.
        if !probes_muted {
            match ARCHIVE_JOB
                .probe(cfg, sandbox)
                .await
                .map(|(state, _)| state)
            {
                Ok(JobState::Failed(code)) => {
                    let log = ARCHIVE_JOB.log_tail(cfg, sandbox).await;
                    bail!(
                        "detached local-dump job for schema {schema} failed (exit {code}): {}",
                        truncate(log.trim(), 800)
                    );
                }
                Ok(JobState::Succeeded) => {
                    probe_failures = 0;
                    claimed_done.get_or_insert_with(Instant::now);
                }
                Ok(JobState::Running) => probe_failures = 0,
                Err(e) => {
                    probe_failures += 1;
                    warn!(
                        "schema {schema}: local-dump probe {probe_failures}/\
                         {ARCHIVE_MAX_PROBE_FAILURES} failed (the dump itself is \
                         unaffected): {e:#}"
                    );
                    if probe_failures >= ARCHIVE_MAX_PROBE_FAILURES {
                        probes_muted = true;
                    }
                }
            }
        }
        // The guest claims success but our server never saw a committed upload
        // land — same trust posture as the S3 path: unconfirmed means failed.
        if let Some(at) = claimed_done
            && at.elapsed() >= ARCHIVE_CONFIRM_GRACE
        {
            bail!(
                "local-dump job for schema {schema} reported success but the dump \
                 server never received a committed upload — refusing to trust it"
            );
        }
        if Instant::now() >= deadline {
            bail!("local dump of schema {schema} did not complete within {ARCHIVE_DEADLINE:?}");
        }
    }
}

/// Restore `schema` from the local dump server (frozen tier). The preflight is
/// a direct file check — stronger than the S3 HEAD — then the same detached
/// guest job as the S3 restore, against a tokened local URL.
pub async fn restore_from_local(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    srv: &crate::dumpsrv::DumpServer,
    port: u16,
    owner: Option<&crate::dedicated::Credential>,
) -> Result<Option<RestoreReport>> {
    let path = srv.dump_path(schema);
    match crate::dumpsrv::dump_size(&path) {
        None => bail!(
            "schema {schema} is marked frozen but its local dump {} does not exist — \
             nothing to restore (was PG_VM_POOL_DUMP_DIR changed or the file removed?)",
            path.display()
        ),
        Some(n) if n < MIN_ARCHIVE_BYTES => bail!(
            "schema {schema}: local dump {} is only {n} bytes — produced by a failed \
             dump; it holds no data and cannot be restored",
            path.display()
        ),
        Some(_) => {}
    }
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);
    let token = srv.issue(schema, crate::dumpsrv::Mode::Get)?;
    let url = format!("http://$GW:{port}/d/{token}");
    let body = format!(
        "{}{}",
        gw_prelude(RESTORE_JOB.done),
        restore_job_body(&user, &db, "", &url, owner.is_some(), restore_fast_load())
    );
    RESTORE_JOB.launch(cfg, sandbox, &body, RESTORE_PATH).await?;
    let report = await_detached_job(cfg, sandbox, schema, RESTORE_JOB).await?;
    crate::events::record(crate::events::Event::RestoreLocal);
    Ok(finish_restore_report(schema, report))
}

/// Record a finished restore job's phase timings and hand the report up for
/// the bring-up's phase line. A missing or unreadable report is logged once
/// and otherwise ignored — the restore itself succeeded.
fn finish_restore_report(schema: &str, line: Option<String>) -> Option<RestoreReport> {
    let report = line.as_deref().and_then(RestoreReport::parse);
    match &report {
        Some(r) => r.record(),
        None => warn!(
            "schema {schema}: the restore job left no readable timing report ({line:?}) — \
             its phase timings are not recorded"
        ),
    }
    report
}

/// What the guest says about a detached job.
enum JobState {
    Running,
    Succeeded,
    Failed(i32),
}

/// Locate and read a probe reply in whatever the shared console handed back.
///
/// The reply is framed with a distinctive token and located *anywhere* in the
/// output rather than at its start: the console is shared, so a line of kernel
/// log or the tail of a previously timed-out command can precede ours. An
/// unparseable reply is `Running` — the safe reading, since the sentinel's own
/// zero grants success and its non-zero declares failure; neither should be
/// inferred from noise.
fn parse_probe(stdout: &str) -> JobState {
    // Last match wins: stale framing from an earlier, abandoned command sits
    // ahead of this reply in the stream.
    let Some(reply) = stdout
        .lines()
        .filter_map(|l| l.trim().rsplit_once(PROBE_TAG).map(|(_, r)| r))
        .rfind(|r| r.starts_with('D') || r.starts_with('P'))
    else {
        return JobState::Running;
    };
    match reply.strip_prefix('D') {
        // A sentinel we can't parse is a real completion with an unreadable
        // code — treat it as failed rather than spin until the deadline.
        Some(code) => match code.trim().parse::<i32>() {
            Ok(0) => JobState::Succeeded,
            Ok(c) => JobState::Failed(c),
            Err(_) => JobState::Failed(-1),
        },
        None => JobState::Running,
    }
}

/// The `R` line of a probe reply ([`DetachedJob::report`]), if any. Last
/// match wins, for the same stale-framing reason as [`parse_probe`]; an empty
/// report (the file was missing) is `None`.
fn parse_probe_report(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter_map(|l| l.trim().rsplit_once(PROBE_TAG).map(|(_, r)| r))
        .rfind(|r| r.starts_with('R'))
        .map(|r| r[1..].trim().to_string())
        .filter(|r| !r.is_empty())
}

/// Restore `schema`'s database from S3 into the (already-created, empty) target
/// database, using the guest's `curl` + `pg_restore` against a presigned GET.
///
/// Detached and polled, exactly like [`dump_to_s3`] and for the same reason: as
/// one foreground exec this could only ever restore a database small enough to
/// download *and* load inside the guest exec channel's hard 30s cap. Every real
/// workbook exceeds that, so the restore would be killed mid-`pg_restore` and
/// the bring-up would fail — leaving a schema that archives fine and then cannot
/// come back.
///
/// Unlike the dump there is no out-of-band signal to fall back on: S3 can attest
/// that the *source* object exists, not that this guest finished loading it. So
/// the sentinel decides, and a guest that stops answering long enough eventually
/// fails the restore. The asymmetry is deliberate — an unconfirmed restore
/// aborts a bring-up and costs a retry, whereas an unconfirmed dump would have
/// cost the disk it was dumping.
async fn restore_from_s3(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    s3: &S3Config,
    owner: Option<&crate::dedicated::Credential>,
) -> Result<Option<RestoreReport>> {
    let key = s3.object_key(schema);

    // Pre-flight: is there actually a restorable archive at the key? Feeding
    // `pg_restore` a missing or torn (sub-minimum) object costs a full VM
    // bring-up and yields a generic guest error; checking here yields the
    // truth. Best-effort on transport failure — the guest's own download would
    // surface that anyway.
    if let Ok(http) = reqwest::Client::builder().build() {
        match s3.head_object(&http, &key, ARCHIVE_HEAD_TIMEOUT).await {
            Ok(None) => bail!(
                "schema {schema} is marked archived but s3://{}/{key} does not exist — \
                 there is no archive to restore{}",
                s3.bucket,
                s3.fallback_prefix()
                    .map(|p| format!(
                        " (the legacy prefix {p} is read only when this host's prefix is \
                         known to hold nothing for the schema)"
                    ))
                    .unwrap_or_default()
            ),
            Ok(Some(id)) if id.content_length < MIN_ARCHIVE_BYTES => bail!(
                "schema {schema}: the archive at s3://{}/{key} is only {} bytes — it was \
                 produced by a failed dump (accepted before the size guard existed) and \
                 holds no data; this workbook cannot be restored from S3",
                s3.bucket,
                id.content_length
            ),
            Ok(Some(_)) => {}
            Err(e) => warn!(
                "schema {schema}: pre-restore HEAD failed (continuing — the guest's \
                 own download will decide): {e:#}"
            ),
        }
    }

    let url = s3.presign_get(&key, PRESIGN_TTL);
    let resolve = s3_resolve_flag(s3).await;
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);

    RESTORE_JOB
        .launch(
            cfg,
            sandbox,
            &restore_job_body(
                &user,
                &db,
                &resolve,
                &url,
                owner.is_some(),
                restore_fast_load(),
            ),
            RESTORE_PATH,
        )
        .await?;
    let report = await_detached_job(cfg, sandbox, schema, RESTORE_JOB).await?;
    crate::events::record(crate::events::Event::RestoreS3);
    Ok(finish_restore_report(schema, report))
}

/// Wait for a detached job whose only completion signal is its own sentinel.
///
/// Probe failures are tolerated — they describe the exec channel, not the job —
/// but not indefinitely: with nothing else to ask, a channel that never comes
/// back means we can never confirm the job, and reporting failure is the honest
/// answer. Bounded by the job's own `deadline` either way.
///
/// Returns the job's [`DetachedJob::report`] line when it left one.
async fn await_detached_job(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    job: DetachedJob,
) -> Result<Option<String>> {
    let what = job.what;
    let deadline = Instant::now() + job.deadline;
    let mut probe_failures: u32 = 0;
    let mut poll = job.poll_first;
    loop {
        sleep(poll).await;
        poll = next_poll(poll, job.poll_max);
        match job.probe(cfg, sandbox).await {
            Ok((JobState::Succeeded, report)) => return Ok(report),
            Ok((JobState::Failed(code), _)) => {
                let log = job.log_tail(cfg, sandbox).await;
                bail!(
                    "detached {what} job for schema {schema} failed (exit {code}): {}",
                    truncate(log.trim(), 800)
                );
            }
            Ok((JobState::Running, _)) => probe_failures = 0,
            Err(e) => {
                probe_failures += 1;
                warn!(
                    "schema {schema}: {what}-job probe {probe_failures}/{UNWITNESSED_MAX_PROBE_FAILURES} \
                     failed (the {what} itself does not use this channel): {e:#}"
                );
                if probe_failures >= UNWITNESSED_MAX_PROBE_FAILURES {
                    bail!(
                        "lost contact with the guest while waiting for the {what} of \
                         schema {schema} ({probe_failures} consecutive probe failures); \
                         last error: {e:#}"
                    );
                }
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "detached {what} job for schema {schema} did not finish within {:?}",
                job.deadline
            );
        }
    }
}

/// Build a `curl --resolve host:443:IP[,IP…]` flag for the S3 host by resolving
/// it **on the pooler's host**, because the guest microVM ships without a DNS
/// resolver (`/etc/resolv.conf` is empty). Only applies to the AWS
/// virtual-hosted path; a custom endpoint (MinIO/R2) is left to the guest to
/// resolve. Returns an empty string when there's nothing to pin (custom
/// endpoint, or resolution fails/times out) — curl then behaves exactly as
/// before, falling back to the guest's own DNS, so this never makes a working
/// setup worse.
///
/// ASSUMPTION: the guest reaches S3 through the host's NAT egress (it shares the
/// host's outbound path), so a public IP the host resolves is reachable from the
/// guest. True for a co-located host talking to public S3; it would misroute
/// under split-horizon DNS — e.g. an S3 VPC endpoint that resolves to
/// subnet-private IPs valid only from certain subnets. Revisit this if the guest
/// ever gets a distinct egress path or S3 moves behind a VPC endpoint.
async fn s3_resolve_flag(s3: &S3Config) -> String {
    let Some(host) = s3.resolve_host() else {
        return String::new();
    };
    const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
    // Cap the number of IPs pinned: enough for curl to fail over across a couple
    // of front-ends at connect time without an unwieldy flag.
    const MAX_IPS: usize = 4;
    let lookup = tokio::net::lookup_host((host.as_str(), 443u16));
    let addrs = match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => {
            warn!(
                "resolving {host} on host for guest curl failed ({e}); guest will use its own DNS"
            );
            return String::new();
        }
        Err(_) => {
            warn!("resolving {host} on host for guest curl timed out; guest will use its own DNS");
            return String::new();
        }
    };
    // v4 only: the guest tap/NAT is IPv4 (a v6 address the host prefers would be
    // unreachable from the guest).
    let mut ips: Vec<String> = addrs
        .filter_map(|sa| match sa.ip() {
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();
    ips.sort();
    ips.dedup();
    ips.truncate(MAX_IPS);
    build_resolve_flag(&host, &ips)
}

/// Assemble the `--resolve` flag from a host and already-resolved IPv4 strings.
/// Pure (no I/O) so it's unit-testable. Empty when there are no IPs. The value
/// is single-quoted; host is our own `{bucket}.s3.{region}.amazonaws.com` and
/// the IPs are validated v4, so nothing here can break out of the guest shell.
fn build_resolve_flag(host: &str, ips: &[String]) -> String {
    if ips.is_empty() {
        return String::new();
    }
    // curl takes a comma-separated address list in one --resolve entry and tries
    // them in order at connect time (repeating the flag for the same host:port
    // would NOT add addresses — curl keeps the first entry).
    format!("--resolve '{host}:443:{}'", ips.join(","))
}

/// Issue one guest exec and hand back its raw result without judging the exit
/// code — the caller decides. `with_pgpassword` injects `PGPASSWORD` for commands
/// that shell out to `pg_dump`/`pg_restore`; a bare `cat`/`test` poll doesn't need
/// it. The exec's own foreground command must finish inside the guest API's ~30s
/// server-side cap; [`dump_to_s3`] keeps every call it makes trivially short.
async fn exec_guest(
    cfg: &Config,
    sandbox: &Sandbox,
    command: &str,
    with_pgpassword: bool,
    what: &str,
) -> Result<CommandResult> {
    let env = if with_pgpassword {
        cfg.pg_password.as_ref().map(|pw| {
            let mut m = HashMap::new();
            m.insert("PGPASSWORD".to_string(), pw.clone());
            m
        })
    } else {
        None
    };
    exec_guest_env(cfg, sandbox, command, env, what).await
}

/// [`exec_guest`] with a caller-supplied environment, so a job can be handed a
/// credential out of band instead of having it interpolated into the command.
async fn exec_guest_env(
    _cfg: &Config,
    sandbox: &Sandbox,
    command: &str,
    env: Option<HashMap<String, String>>,
    what: &str,
) -> Result<CommandResult> {
    let opts = CommandRunOptions {
        timeout: Some(GUEST_EXEC_HTTP_TIMEOUT),
        env,
        ..Default::default()
    };
    sandbox
        .commands()
        .run(command, opts)
        .await
        .with_context(|| format!("{what}: guest exec failed"))
}

pub(crate) async fn physical_exec(
    cfg: &Config, sandbox: &Sandbox, command: &str, env: HashMap<String, String>, what: &str,
) -> Result<CommandResult> {
    let command = physical_exec_command(command);
    exec_guest_env(cfg, sandbox, &command, Some(env), what).await
}

fn physical_exec_command(command: &str) -> String {
    use base64::Engine;
    // No literal newlines may reach the serial shell, even inside quotes:
    // console framing can finish capture before multiline bodies print.
    let body = format!("for pgbin in /usr/lib/postgresql/*/bin; do [ ! -d \"$pgbin\" ] || export PATH=\"$pgbin:$PATH\"; done\n{command}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    format!("printf '%s' '{encoded}' | base64 -d | sh")
}

/// Resolve by the operation's unique durable name before creating.  This is
/// the lost-create-response recovery path; physical candidates deliberately
/// bypass normal schema checkout and are never entered in the serving store.
pub(crate) async fn physical_candidate(cfg: &Config, name: &str, allow_create: bool, own: &(dyn Fn(&str) -> Result<()> + Send + Sync)) -> Result<Sandbox> {
    if !name.starts_with("repl-seed-") { bail!("invalid physical candidate name"); }
    if let Some(info) = find_by_name_with_retry(name).await.context("finding physical candidate")? {
        own(&info.id).context("durably adopting named physical candidate")?;
        return bring_up_existing(cfg, name, &info.id).await?.context("physical candidate disappeared while resuming");
    }
    if !allow_create {
        bail!("physical create outcome is unknown and named candidate is not visible; refusing a second create");
    }
    create_vm_within(cfg, name, true, cfg.ready_timeout, cfg.data_disk_gb, Some(own)).await
}

pub(crate) async fn connect_physical_candidate(cfg: &Config, name: &str, id: &str) -> Result<Sandbox> {
    bring_up_existing(cfg, name, id).await?.context("recorded physical candidate no longer exists")
}

/// Best-effort human-readable detail from a failed guest command: the combined
/// output if the backend populated it, else stderr.
fn exec_detail(res: &CommandResult) -> &str {
    if res.output.trim().is_empty() {
        res.stderr.trim()
    } else {
        res.output.trim()
    }
}

/// Single-quote a string for POSIX `sh`, escaping embedded single quotes as
/// `'\''`. Schema/user names are already validated (no control chars) upstream;
/// this is defense in depth so a name with a space or quote can't break out.
fn shell_squote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Trim guest output to `max` bytes (on a char boundary) so an error log can't
/// dump a whole dump-tool backtrace.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// How many client connections this VM's Postgres can actually take, read from
/// the server itself rather than assumed.
///
/// init.sh derives `max_connections` per size class, so the pooler must not
/// hardcode it: the number differs across size classes, and a VM that changes
/// class picks up a new one on its next boot. Ask the server.
///
/// The budget is what's left for *ordinary clients* after the two claims that
/// aren't theirs: `superuser_reserved_connections`, and this pooler's own
/// housekeeping pool (probes, bootstrap, stats, pre-stop CHECKPOINT), which
/// connects as superuser and so draws from the same well.
///
/// On any failure, fall back to a conservative floor rather than refusing to
/// serve — an unknown limit shouldn't take the VM down, and a low guess only
/// costs queueing.
async fn client_slot_budget(pool: &Pool, name: &str) -> usize {
    const FALLBACK_SLOTS: usize = 20;
    let read = async {
        let client = pool.get().await.ok()?;
        let max: i64 = client
            .query_one("SELECT current_setting('max_connections')::int8", &[])
            .await
            .ok()?
            .get(0);
        let reserved: i64 = client
            .query_one(
                "SELECT current_setting('superuser_reserved_connections')::int8",
                &[],
            )
            .await
            .ok()?
            .get(0);
        Some((max, reserved))
    };
    match read.await {
        Some((max, reserved)) => {
            let slots = slots_from_limits(max, reserved);
            info!(
                "{name}: admitting at most {slots} client connections \
                 (max_connections={max}, superuser_reserved={reserved}, \
                 pooler pool={POOL_MAX_SIZE})"
            );
            slots
        }
        None => {
            warn!("{name}: could not read max_connections; admitting at most {FALLBACK_SLOTS}");
            FALLBACK_SLOTS
        }
    }
}

/// Client slots left over from `max_connections` once the reserved superuser
/// slots and the pooler's own housekeeping pool are subtracted.
///
/// Saturates at 1 rather than 0: admitting nobody would make the VM useless,
/// and a guest configured this tightly is better served by letting one client
/// through at a time than by refusing every client. Never returns more than the
/// arithmetic allows — over-admitting is the exact failure this exists to stop.
fn slots_from_limits(max: i64, reserved: i64) -> usize {
    let budget = max - reserved - POOL_MAX_SIZE as i64;
    usize::try_from(budget.max(1)).unwrap_or(1)
}

/// Resolve the splice target and connection pool for a running VM's Postgres:
/// reached either directly over the host tap (guest_ip:5432) when the pooler
/// shares the host with the VM, or via a local iroh tunnel otherwise. Direct
/// connect skips iroh entirely — no relay dependency, lower latency, faster
/// bring-up.
async fn connect_pg(
    cfg: &Config,
    sandbox: &Sandbox,
    name: &str,
) -> Result<(SocketAddr, Option<P2pTunnel>, Pool)> {
    let (target, tunnel) = if cfg.direct_connect {
        match direct_target(sandbox).await {
            Ok(Some(addr)) => {
                info!("direct connection to {name} at {addr} (no tunnel)");
                (addr, None)
            }
            Ok(None) => {
                warn!("{name}: daemon reported no guest_ip; falling back to iroh tunnel");
                let (addr, t) = open_tunnel(cfg, sandbox, name).await?;
                (addr, Some(t))
            }
            Err(e) => {
                warn!("{name}: guest_ip lookup failed ({e:#}); falling back to iroh tunnel");
                let (addr, t) = open_tunnel(cfg, sandbox, name).await?;
                (addr, Some(t))
            }
        }
    } else {
        let (addr, t) = open_tunnel(cfg, sandbox, name).await?;
        (addr, Some(t))
    };

    // deadpool against the VM's default `postgres` db: used to probe readiness
    // (the VM status can be Running before Postgres accepts connections) and to
    // create the per-schema database the client will ask for.
    let host = target.ip().to_string();
    let pool = build_pool(
        &host,
        target.port(),
        "postgres",
        &cfg.pg_user,
        cfg.pg_password.as_deref(),
    )?;
    Ok((target, tunnel, pool))
}

/// Get the VM's Postgres to a ready state, power-cycling the VM if the server
/// process is dead inside it.
///
/// Postgres can crash while its VM stays alive (OOM kill, segfault): init.sh
/// runs Postgres as a background child of the PID-1 shell, so the sandbox
/// still reports Running, `start()` no-ops, and without this check every
/// connect would burn the full `ready_timeout` against a port nobody listens
/// on. Instead, probe briefly and classify what's there:
///   - answers `SELECT 1`      → ready, proceed;
///   - speaks Postgres protocol (e.g. 57P03 "the database system is starting
///     up" during WAL replay)  → the server is alive, wait out `ready_timeout`
///     like before — restarting mid-recovery would only restart recovery;
///   - stalled (accepted but never answered) → ambiguous, and a power-cycle
///     here is destructive: an ingest-loaded VM can hold a connect past the
///     probe bound while perfectly healthy. Treat it like `Responding` and
///     wait. If it really is wedged, the client gets a timeout error and the
///     next connect re-probes from scratch — recoverable, unlike a reboot
///     that kills an in-flight load;
///   - refusing                → the postmaster is gone; stop+start the VM
///     (a fresh boot re-runs init.sh, which relaunches Postgres) and wait for
///     readiness on the rebuilt connection. One cycle per connect attempt —
///     if PG still won't come up on a fresh boot, that's a real error the
///     client should see (and the next connect retries from scratch).
async fn ready_pg(
    cfg: &Config,
    sandbox: &Sandbox,
    name: &str,
) -> Result<(SocketAddr, Option<P2pTunnel>, Pool)> {
    let (target, tunnel, pool) = connect_pg(cfg, sandbox, name).await?;
    match probe_pg_window(&pool, PG_PROBE_WINDOW).await {
        PgProbe::Ready => Ok((target, tunnel, pool)),
        PgProbe::Responding(msg) => {
            info!("{name}: Postgres up but not ready yet ({msg}); waiting");
            wait_pg_ready(&pool, cfg.ready_timeout, name).await?;
            Ok((target, tunnel, pool))
        }
        PgProbe::Stalled(msg) => {
            warn!(
                "{name}: Postgres slow to answer ({msg}); waiting out \
                 ready_timeout before considering a power-cycle"
            );
            // Don't reboot on a stall alone — but don't wedge forever either.
            // A loaded server answers well inside ready_timeout; a black-holed
            // forward never answers at all. Silence for the *whole* window is
            // the evidence that separates them, so the reboot survives for the
            // dead-tunnel case it exists for without firing at a busy VM.
            if wait_pg_ready(&pool, cfg.ready_timeout, name).await.is_ok() {
                return Ok((target, tunnel, pool));
            }
            warn!("{name}: still silent after ready_timeout; power-cycling the VM");
            power_cycle(cfg, sandbox, name, pool, tunnel).await
        }
        PgProbe::Unreachable(msg) => {
            warn!(
                "{name}: Postgres unreachable inside a running VM ({msg}); \
                 power-cycling the VM"
            );
            power_cycle(cfg, sandbox, name, pool, tunnel).await
        }
    }
}

/// Stop+start the VM and reconnect. A fresh boot re-runs init.sh, which
/// relaunches Postgres and rebuilds the tunnel. One cycle per connect attempt —
/// if PG still won't come up on a fresh boot, that's a real error the client
/// should see (and the next connect retries from scratch).
///
/// Destructive: the stop is an unclean kill, so anything in flight on this VM
/// dies with it. Only call this on evidence that nothing is listening — never
/// on evidence that the server is merely slow.
async fn power_cycle(
    cfg: &Config,
    sandbox: &Sandbox,
    name: &str,
    pool: Pool,
    tunnel: Option<P2pTunnel>,
) -> Result<(SocketAddr, Option<P2pTunnel>, Pool)> {
    // Drop the stale pool/tunnel before the restart so nothing holds the old
    // forward open across the reboot.
    drop(pool);
    drop(tunnel);
    // The stop→start gap makes the disk look reclaimable; hold the boot permit
    // across both so a reclaim pass can't start working on it in between.
    // The bring-up slot bounds how many such boots hit the daemon at once, and
    // is taken *after* the permit (see `bring_up_existing`).
    {
        let _permit = crate::reclaim::boot_permit(sandbox.sandbox_id()).await;
        let _slot = bringup_slot(name).await;
        sandbox
            .stop()
            .await
            .with_context(|| format!("stopping {name} for power-cycle"))?;
        // A postmaster that died of a full disk dies again on a fresh boot
        // into it. The daemon acks the stop before Firecracker lets go of the
        // disk, hence the settle.
        if let Err(e) =
            grow_stopped_disk(cfg, name, sandbox.sandbox_id(), POWER_CYCLE_DISK_SETTLE).await
        {
            warn!("{name}: {e:#}; restarting it on the disk it has");
        }
        sandbox
            .start()
            .await
            .with_context(|| format!("restarting {name} after power-cycle"))?;
    }
    wait_ready(sandbox, cfg.ready_timeout, name)
        .await
        .with_context(|| format!("waiting for {name} after power-cycle"))?;
    // Reconnect from scratch: the guest_ip/tunnel from before the reboot may no
    // longer be valid.
    let (target, tunnel, pool) = connect_pg(cfg, sandbox, name).await?;
    match wait_pg_ready(&pool, cfg.ready_timeout, name).await {
        Ok(()) => {}
        Err(e) => {
            // Postgres didn't come up even on a FRESH boot — a persistently
            // sick guest (unmountable data disk killing init, a crash-looping
            // postmaster, an incompatible pgdata). The timeout alone is a dead
            // end to debug, so grab whatever the guest can still say. Exec
            // rides the serial console, which only answers while PID-1
            // survived — an exec failure here usually means init.sh itself
            // died (e.g. `set -e` at the data-disk mount), which is evidence
            // too, and is reported as such.
            let evidence = boot_evidence(cfg, sandbox).await;
            return Err(e).with_context(|| format!("{name} failed a fresh boot ({evidence})"));
        }
    }
    info!("{name}: Postgres recovered after power-cycle");
    Ok((target, tunnel, pool))
}

/// Best-effort one-line diagnosis of a guest whose Postgres won't start.
/// Ordered by decisiveness:
///
/// 1. cluster major (`PG_VERSION`) vs server major — a mismatch is the
///    instant-death "database files are incompatible" case (a disk adopted
///    under a newer image) and explains everything by itself;
/// 2. live postgres process count (0 = it died, not "it's slow");
/// 3. this boot's startup stderr (`pg-startup.log`, written by init.sh —
///    where pre-logging-collector fatals land);
/// 4. the newest server-log tail — which can be DAYS old on a VM whose
///    current boot never got far enough to log; the timestamps say so.
///
/// Never fails — every failure mode becomes descriptive text.
async fn boot_evidence(cfg: &Config, sandbox: &Sandbox) -> String {
    let cmd = "v=$(cat /workspace/pgdata/PG_VERSION 2>/dev/null || echo '?'); \
               s=$(ls /usr/lib/postgresql 2>/dev/null | sort -n | tail -1); [ -n \"$s\" ] || s='?'; \
               echo \"pgdata=v$v server=v$s pg-procs=$(pgrep -c postgres 2>/dev/null || echo 0)\"; \
               tail -n 4 /workspace/pg-startup.log 2>/dev/null; \
               tail -n 3 \"$(ls -t /workspace/pgdata/log/*.log 2>/dev/null | head -1)\" 2>/dev/null \
               || dmesg 2>/dev/null | tail -n 3";
    match exec_guest(cfg, sandbox, cmd, false, "collecting boot evidence").await {
        Ok(res) => {
            let text = exec_detail(&res).replace(['\n', '\r'], " | ");
            let text = text.trim();
            if text.is_empty() {
                "guest exec answered but produced no output".to_string()
            } else {
                truncate(text, 400).to_string()
            }
        }
        Err(e) => format!(
            "guest exec unavailable — init likely died during boot (data-disk \
             mount failure?): {e:#}"
        ),
    }
}

/// What a bounded `SELECT 1` attempt tells us about the server behind `pool`.
pub(crate) enum PgProbe {
    Ready,
    /// Got a Postgres protocol response that isn't readiness (server error
    /// with a SQLSTATE, e.g. "starting up") — the process is alive.
    Responding(String),
    /// The attempt ran out of time with no answer either way. Ambiguous: a
    /// loaded server can take seconds to fork a backend, so this is NOT
    /// evidence the postmaster is gone. See `probe_pg`.
    Stalled(String),
    /// No protocol response at all: connection refused or closed. Nothing is
    /// listening on the port.
    Unreachable(String),
}

pub(crate) async fn probe_pg(pool: &Pool) -> PgProbe {
    use deadpool_postgres::PoolError;
    let attempt = async {
        match pool.get().await {
            Ok(client) => match client.simple_query("SELECT 1").await {
                Ok(_) => PgProbe::Ready,
                Err(e) => classify_pg_error(&e),
            },
            Err(PoolError::Backend(e)) => classify_pg_error(&e),
            // Everything else `PoolError` reports (queued past `wait`, pool
            // closed, no runtime) is a fact about *our* pool, not about the
            // VM's postmaster — a probe that never left this process is not
            // evidence the server is gone, and must never reach the verdict
            // that power-cycles it.
            Err(e) => PgProbe::Stalled(format!("pool checkout failed locally: {e}")),
        }
    };
    // The pool has no create timeout, so a black-holed TCP connect (dead iroh
    // tunnel forward) would hang `get()` — bound each attempt.
    //
    // A timeout is deliberately NOT `Unreachable`. A dead postmaster means a
    // closed port, and a closed port answers *fast* (ECONNREFUSED) — it does
    // not hang. Hanging means something accepted the connection and is slow to
    // finish it: a backend fork behind heavy checkpoint I/O, or an allocation
    // stalling under the guest's strict overcommit. Calling that "dead" is how
    // a busy-but-healthy VM used to get power-cycled mid-ingest, which is
    // strictly worse than the slowness it was reacting to.
    match tokio::time::timeout(PG_PROBE_ATTEMPT, attempt).await {
        Ok(probe) => probe,
        Err(_) => PgProbe::Stalled(format!("no answer within {PG_PROBE_ATTEMPT:?}")),
    }
}

/// A SQLSTATE means the *server* composed an error message — the postmaster is
/// alive whatever the code says. No SQLSTATE means we never got a protocol
/// reply (io error, refused, EOF): nothing is listening.
fn classify_pg_error(e: &tokio_postgres::Error) -> PgProbe {
    if e.code().is_some() {
        PgProbe::Responding(pg_error_text(e))
    } else {
        PgProbe::Unreachable(pg_error_text(e))
    }
}

/// `tokio_postgres::Error` displays only its kind, so a server refusing the
/// connection — the very case the readiness waits exist for — prints as a
/// bare "db error", its SQLSTATE and reason behind `source()`. Spell them out:
/// the readiness logs are the only place a boot's refusal ever surfaces.
fn pg_error_text(e: &tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("{} {}: {}", db.severity(), db.code().code(), db.message());
    }
    match std::error::Error::source(e) {
        Some(cause) => format!("{e}: {cause}"),
        None => e.to_string(),
    }
}

/// Probe until the window closes: `Ready`/`Responding` short-circuit (the
/// server exists — the caller decides how long to wait for readiness). Only a
/// full window of *refusals* returns `Unreachable`; if anything in the window
/// merely stalled, the port was open at least once and `Stalled` wins, since
/// the caller must not take a destructive action on that evidence.
async fn probe_pg_window(pool: &Pool, window: Duration) -> PgProbe {
    let start = Instant::now();
    let deadline = start + window;
    let mut last_err = String::new();
    let mut stalled: Option<String> = None;
    loop {
        match probe_pg(pool).await {
            PgProbe::Unreachable(msg) => last_err = msg,
            PgProbe::Stalled(msg) => stalled = Some(msg),
            verdict => return verdict,
        }
        if Instant::now() >= deadline {
            return match stalled {
                Some(msg) => PgProbe::Stalled(msg),
                None => PgProbe::Unreachable(last_err),
            };
        }
        sleep(pg_poll_interval(start.elapsed())).await;
    }
}

/// Find or bring up the VM. Prefers reattaching by `known_id` (a prior bring-up
/// of this schema): querying a sandbox by id is consistent, whereas a VM that
/// was just stopped is briefly missing from list-by-name — reattaching by name
/// in that window would create a *duplicate* VM with a fresh, empty data disk
/// and silently lose the schema's data. Only when there's no known id (a
/// genuinely new schema) or it was deleted do we list-by-name / create.
/// `pub(crate)` for `crate::loadtest`, which times this phase on its own: it is
/// the whole "silent" window between a client connecting and the daemon seeing
/// any traffic for its VM, and measuring it without a real Postgres behind the
/// VM is the only way to attribute cold-start latency to fleet size.
/// Where `resolve_sandbox`'s VM came from — what a failed bring-up must do
/// with it. An `Existing` VM (reattached by id or name) is never touched on
/// failure: its disk is the schema's data. A `Spare` claim is released (the
/// pool kills it). A `Created` VM is killed: it held nothing before this
/// attempt, and leaving it running is how one retrying client piles up a
/// dozen running VMs for a single schema.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Provenance {
    Existing,
    Spare,
    /// A spare claimed off the pool's *chilled* shelf: already stopped, so an
    /// image restore can overwrite its disk without stopping anything first.
    /// Disposed of exactly like [`Provenance::Spare`] — it is a claimed spare,
    /// and a failed restore leaves its disk just as ambiguous.
    ChilledSpare,
    Created,
}

impl Provenance {
    /// Whether the VM is already stopped and the caller may skip its own stop.
    /// Only a chilled spare promises this; everything else arrives running.
    ///
    /// Disposal does *not* go through a helper like this one: both spare
    /// variants must be released through the pool rather than killed behind
    /// its back, and spelling them out at each `match` is what makes the
    /// compiler point at those sites when a variant is added.
    pub(crate) fn is_stopped(self) -> bool {
        matches!(self, Provenance::ChilledSpare)
    }
}

/// The warm-spare pool and the set of sandbox ids already bound to a schema,
/// as threaded through a bring-up. `None` when the pool is disabled.
pub(crate) type Spares<'a> = Option<(
    &'a crate::spares::SparePool,
    &'a std::collections::HashSet<String>,
)>;

pub(crate) async fn resolve_sandbox(
    cfg: &Config,
    name: &str,
    keepalive: bool,
    known_id: Option<&str>,
    spares: Option<(&crate::spares::SparePool, &std::collections::HashSet<String>)>,
    disk_gb: u32,
) -> Result<(Sandbox, Provenance)> {
    // 1. Reattach to the VM we last used for this schema, by id.
    if let Some(id) = known_id {
        match bring_up_existing(cfg, name, id).await {
            Ok(Some(sb)) => return Ok((sb, Provenance::Existing)),
            Ok(None) => info!("known VM {name} ({id}) is gone; find-or-create by name"),
            Err(e) => warn!("reattaching {name} ({id}) failed ({e:#}); find-or-create by name"),
        }
    }

    // 2. Fall back to by-name resolution (first connect on a fresh pooler, or
    //    the known id was deleted). The positive-only cache answers repeat
    //    lookups without any daemon traffic; a hit is verified by id (a stale
    //    entry evicts itself), and a miss goes to the authoritative `?name=`
    //    daemon lookup — never the O(fleet) inventory pull this used to be,
    //    and never straight to create.
    if let Some(id) = crate::inventory::lookup(name) {
        match bring_up_existing(cfg, name, &id).await? {
            Some(sb) => return Ok((sb, Provenance::Existing)),
            None => {
                crate::inventory::remove_id(&id);
                info!("cached VM {name} ({id}) is gone; asking the daemon by name");
            }
        }
    }
    if let Some(info) = find_by_name_with_retry(name)
        .await
        .context("by-name sandbox lookup")?
    {
        crate::inventory::insert(name, &info.id);
        match bring_up_existing(cfg, name, &info.id).await? {
            Some(sb) => return Ok((sb, Provenance::Existing)),
            None => crate::inventory::remove_id(&info.id),
        }
    }

    // 3. Genuinely new VM needed. Claim a warm spare if one is available —
    //    already booted with initdb done, so the whole create+boot+init cost
    //    is skipped. It keeps its spare name; the registry's id mapping (put
    //    on successful bring-up) is what binds it to the schema. The `true`
    //    tells `ensure_vm` this sandbox is a claim it must release (kill)
    //    if the rest of the bring-up fails.
    //
    //    Unless this bring-up needs a bigger data device than a spare has.
    //    Spares are minted at the default size before anyone knows which
    //    schema will claim one, so a restore of a schema whose device had
    //    grown cannot use one: the dump would fill it and leave a half-loaded
    //    cluster. Paying the create is the cheap half of that trade.
    if !spare_can_serve(disk_gb, cfg.data_disk_gb) {
        info!(
            "{name}: needs a {disk_gb}GiB data device, larger than a warm spare's \
             {}GiB — creating a right-sized VM instead of claiming one",
            cfg.data_disk_gb
        );
    } else if let Some((pool, bound)) = spares
        && let Some(sb) = pool.take(bound).await
    {
        info!("claiming warm spare {} for {name}", sb.sandbox_id());
        return Ok((sb, Provenance::Spare));
    }

    // 4. No spare: create from scratch.
    create_vm(cfg, name, keepalive, disk_gb)
        .await
        .map(|sb| (sb, Provenance::Created))
}

/// Which total a restore of this source records. Kept apart rather than
/// summed into one "restore" figure: a dump reloads through Postgres while an
/// image swaps a disk under a booted VM, and the S3 pair pays a download the
/// local pair does not — one percentile over all four would describe no
/// restore anyone actually waited for.
fn restore_timing(source: &RestoreSource) -> crate::events::Timing {
    use crate::events::Timing;
    match source {
        RestoreSource::S3(_) => Timing::RestoreS3Dump,
        RestoreSource::S3Image(_) => Timing::RestoreS3Image,
        RestoreSource::Local { .. } => Timing::RestoreLocalDump,
        RestoreSource::LocalImage(_) => Timing::RestoreLocalImage,
    }
}

/// A booted, ready VM for an image restore to use as its *vehicle*: the caller
/// stops it immediately, overwrites its data disk with the restored image, and
/// boots it on the real data.
///
/// A warm spare is the ideal vehicle *because* the restore throws its contents
/// away. The expensive part of a cold create is the guest's first boot — mkfs,
/// the swapfile, a full `initdb` — and the disk swap discards every bit of it.
/// Claiming a spare skips that work, and with it the daemon's fixed
/// serial-console readiness window, which is what made image restores the
/// slowest and most failure-prone bring-up on a loaded host while net-new
/// schemas (which have always claimed spares, via [`resolve_sandbox`] step 3)
/// stayed fast. The pool's own docs name S3 restores as its reason to exist;
/// this is the wiring that was missing.
///
/// The returned [`Provenance`] must reach every failure path: a claimed spare
/// is disposed of through [`crate::spares::SparePool::release_failed`] (kill
/// *and* unclaim), never a bare `kill`, or its id stays in the pool's
/// `claimed` set for the life of the process — a running VM and disk nothing
/// can reclaim, with the replenisher building a replacement on top of it.
pub(crate) async fn claim_restore_vehicle(
    cfg: &Config,
    schema: &str,
    spares: Spares<'_>,
    pinned: bool,
) -> Result<(Sandbox, Provenance)> {
    // A chilled vehicle first: it is already stopped, which is the state this
    // restore wants and the only one it can use without paying for a
    // transition. Taking a *running* spare means stopping it (~2.1s for the
    // daemon to SIGKILL Firecracker and ack) and then waiting for the disk fd
    // to be released before the swap — ~4.8s of a ~6.9s thaw, spent undoing a
    // boot whose every result the restore is about to overwrite.
    if let Some((pool, bound)) = spares
        && let Some(sb) = pool.take_chilled(bound).await
    {
        info!(
            "schema {schema}: claiming chilled vehicle {} for the image restore (already \
             stopped — no stop, no disk-release wait)",
            sb.sandbox_id()
        );
        return Ok((sb, Provenance::ChilledSpare));
    }
    // Fallback: a running spare, stopped on the client's time. Still far
    // cheaper than a create, and the only stop-free alternative would be a
    // sandbox created without booting, which the daemon does not offer.
    if let Some((pool, bound)) = spares
        && let Some(sb) = pool.take(bound).await
    {
        info!(
            "schema {schema}: no chilled vehicle free — claiming running warm spare {} and \
             stopping it for the image restore",
            sb.sandbox_id()
        );
        return Ok((sb, Provenance::Spare));
    }
    let name = format!("pg-{schema}");
    // The default size is right here whatever the schema's device used to be:
    // an image restore swaps the archived disk in under this VM, so the disk
    // it is created with is scratch that never sees the data.
    create_vm(cfg, &name, pinned, cfg.data_disk_gb)
        .await
        .map(|sb| (sb, Provenance::Created))
}

/// May a warm spare serve a bring-up that needs a `disk_gb` data device?
///
/// Spares are minted at `PG_VM_POOL_DATA_DISK_GB` before anyone knows which
/// schema will claim one, so the answer is no as soon as the bring-up needs
/// more than that. It matters because the alternative is silent: a restore
/// that claims a default-size spare gets a VM that boots fine, serves fine,
/// and dies in the middle of `pg_restore` with `No space left on device` —
/// the schema's data does not fit in the device it was handed. Paying a
/// create is the cheap half of that trade.
fn spare_can_serve(disk_gb: u32, default_gb: u32) -> bool {
    disk_gb <= default_gb
}

/// The largest data device heyvmd will create or resize to. A recorded size
/// beyond it is clamped rather than refused: a too-small device is a broken
/// restore, a clamped one is at worst the same failure the daemon would have
/// given anyway, arrived at with a log line naming the cap.
pub(crate) const DAEMON_MAX_DISK_GB: u32 = 250;

/// Grow a sandbox's persistent data device to `target_gb` through the
/// daemon's offline workspace resize (`POST /sandboxes/{id}/resize` with
/// `disk_size_gb`; heyvmd's workspace-resize feature, grow-only).
///
/// The daemon takes the sandbox's lifecycle lock, stops it, grows the image
/// and its ext4 in place, cold-boots once to verify the new capacity from
/// inside the guest, and restores the stopped state — so calling this on a
/// VM that was just idle-stopped is free of client disruption. The whole
/// round-trip can take minutes (a cold boot is embedded in it); the timeout
/// reflects that.
///
/// Raw HTTP rather than the SDK: the published heyo-sdk (0.1.5) predates
/// `Sandbox::resize_disk`. Before swapping to the SDK call once it ships, check
/// the route it targets: the SDK's size-class `resize` posts to
/// `/deployed-sandboxes/{id}/resize`, which the local daemon doesn't serve at
/// all — a disk grow sent there is an empty-bodied 404, and every growth
/// attempt fails.
pub(crate) async fn resize_disk(sandbox_id: &str, target_gb: u64) -> Result<()> {
    resize_disk_at(daemon_base_url(), sandbox_id, target_gb).await
}

/// [`resize_disk`] against an explicit daemon base URL — split out so tests
/// can exercise the real HTTP round-trip against an in-process server.
async fn resize_disk_at(base_url: &str, sandbox_id: &str, target_gb: u64) -> Result<()> {
    anyhow::ensure!(
        (1..=u64::from(DAEMON_MAX_DISK_GB)).contains(&target_gb),
        "disk_size_gb must be within 1–{DAEMON_MAX_DISK_GB} GiB (daemon limit)"
    );
    let url = format!("{base_url}/sandboxes/{sandbox_id}/resize");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .context("building HTTP client for daemon resize")?;
    let resp = daemon_auth(client
        .post(&url))
        .header("content-type", "application/json")
        .body(format!("{{\"disk_size_gb\":{target_gb}}}"))
        .send()
        .await
        .context("calling the daemon's workspace resize")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "daemon workspace resize returned {status}: {} (a 404 with an empty \
             body means the deployed heyvmd has no workspace-resize route)",
            body.trim()
        );
    }
    Ok(())
}

/// What an online device grow came to. See [`resize_disk_online`].
#[derive(Debug)]
pub(crate) enum OnlineGrow {
    /// The device and the guest filesystem on it both reached the target and
    /// the daemon verified it from inside the guest. Nothing was stopped.
    Grown,
    /// The online route could not do it, for a reason the offline resize can
    /// get past: an older daemon without the route (404), a VM that is not
    /// running (409), or a failure partway through (5xx, or no answer). Each
    /// leaves the VM as the offline path expects to find it — at worst a
    /// backing file or device larger than its filesystem, which the offline
    /// resize's host-side `resize2fs` finishes.
    FallBack(String),
}

/// Grow a **running** sandbox's data device to `target_gb` without stopping
/// it, through the daemon's online workspace resize
/// (`POST /sandboxes/{id}/resize-online` with `disk_size_gb`).
///
/// The daemon extends the backing file, tells Firecracker the drive grew,
/// runs `resize2fs` in the guest and verifies both sizes before answering, so
/// `Grown` means the space is usable now. Sessions, the tunnel and the
/// housekeeping pool are untouched.
///
/// `Err` only for a request the daemon refused as invalid (400: a shrink, a
/// size past its cap, host storage below its reserve). The offline resize
/// would refuse it the same way, so falling back would just fail slower.
pub(crate) async fn resize_disk_online(sandbox_id: &str, target_gb: u64) -> Result<OnlineGrow> {
    resize_disk_online_at(daemon_base_url(), sandbox_id, target_gb).await
}

/// [`resize_disk_online`] against an explicit daemon base URL.
async fn resize_disk_online_at(
    base_url: &str,
    sandbox_id: &str,
    target_gb: u64,
) -> Result<OnlineGrow> {
    anyhow::ensure!(
        (1..=u64::from(DAEMON_MAX_DISK_GB)).contains(&target_gb),
        "disk_size_gb must be within 1–{DAEMON_MAX_DISK_GB} GiB (daemon limit)"
    );
    let url = format!("{base_url}/sandboxes/{sandbox_id}/resize-online");
    // No cold boot inside: the daemon bounds its in-guest grow and
    // verification at 120s + 60s, and the file extend is one fallocate.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(240))
        .build()
        .context("building HTTP client for daemon online resize")?;
    let resp = match daemon_auth(client
        .post(&url))
        .header("content-type", "application/json")
        .body(format!("{{\"disk_size_gb\":{target_gb}}}"))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(OnlineGrow::FallBack(format!(
                "online resize request failed: {e}"
            )))
        }
    };
    let status = resp.status();
    if status.is_success() {
        return Ok(OnlineGrow::Grown);
    }
    let body = resp.text().await.unwrap_or_default();
    let body = body.trim();
    match status {
        reqwest::StatusCode::BAD_REQUEST => {
            bail!("daemon online workspace resize returned {status}: {body}")
        }
        reqwest::StatusCode::NOT_FOUND if body.is_empty() => Ok(OnlineGrow::FallBack(
            "the deployed heyvmd has no online resize route".to_string(),
        )),
        _ => Ok(OnlineGrow::FallBack(format!(
            "daemon online workspace resize returned {status}: {body}"
        ))),
    }
}

/// Remaining slots in heyvm's process-wide create gate, or `None` when it has
/// not been sampled (or the daemon did not report one).
///
/// The gate is a `Semaphore` whose width defaults to **4** regardless of host
/// size, and its permit is held across a create *and* its boot. It is
/// therefore the real bound on create throughput — not CPU, RAM or disk, all
/// of which sit idle while creates queue FIFO behind it. A burst deeper than
/// the gate turns into a queue whose wait is bounded by nothing
/// (`HEYVMD_CREATE_TIMEOUT_SECS` bounds one slot's execution, not the line
/// behind it), which is how a create p99 reaches minutes on an idle-looking
/// host. Worth a tile next to spare depth for exactly that reason: it is the
/// difference between "the host is busy" and "we are queued".
static CREATE_GATE_AVAILABLE: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(-1);

/// Sample the daemon's create-gate depth. Called once per warm-spare pass —
/// the pool is both the biggest source of concurrent creates and the thing
/// most starved when the gate is full, so its cadence is the right one.
pub(crate) async fn refresh_create_gate() {
    let url = format!("{}/health", daemon_base_url());
    let read = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .ok()?;
        let body: serde_json::Value = daemon_auth(client.get(&url)).send().await.ok()?.json().await.ok()?;
        body.get("createGate")?.get("available")?.as_i64()
    };
    let value = read.await.unwrap_or(-1);
    CREATE_GATE_AVAILABLE.store(value, std::sync::atomic::Ordering::Relaxed);
}

/// Last sampled create-gate depth; `None` when unknown.
pub(crate) fn create_gate_available() -> Option<i64> {
    match CREATE_GATE_AVAILABLE.load(std::sync::atomic::Ordering::Relaxed) {
        v if v < 0 => None,
        v => Some(v),
    }
}

/// Does the local daemon understand `data_image_path` on create — i.e. can it
/// build a VM straight onto an image we already hold, with no vehicle to
/// borrow, stop and overwrite?
///
/// Probed once and cached. It **must** be an explicit positive. heyvm's request
/// structs carry no `deny_unknown_fields`, so a daemon that predates the field
/// does not reject it — it silently drops it and provisions a *blank* disk.
/// Optimistically sending it would turn every restore against an older daemon
/// into a VM serving an empty cluster while reporting success, which is
/// indistinguishable from data loss. Anything short of a daemon naming the
/// capability sends us down the vehicle path: slower, and correct.
pub(crate) async fn daemon_adopts_data_images() -> bool {
    static CAP: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
    *CAP.get_or_init(|| async {
        let url = format!("{}/health", daemon_base_url());
        let probe = async {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .ok()?;
            let body: serde_json::Value = daemon_auth(client.get(&url)).send().await.ok()?.json().await.ok()?;
            Some(
                body.get("capabilities")?
                    .as_array()?
                    .iter()
                    .any(|c| c.as_str() == Some("data_image_path")),
            )
        };
        let supported = probe.await.unwrap_or(false);
        if supported {
            info!(
                "daemon advertises data_image_path: image restores will build a VM directly on \
                 the restored disk (no vehicle, no stop, no copy)"
            );
        } else {
            info!(
                "daemon does not advertise data_image_path: image restores keep using the \
                 chilled-vehicle path"
            );
        }
        supported
    })
    .await
}

/// Create a VM whose data disk **is** `image` — the daemon renames the file
/// into the new sandbox and boots on it once.
///
/// The SDK has no field for this (it predates the route), so this speaks raw
/// HTTP to the daemon's synchronous `POST /sandboxes`, exactly as
/// [`resize_disk_at`] does for the workspace resize. Field names are heyvm's
/// `CreateSandboxRequest` (snake_case, no rename_all); `size_class` and
/// `backend_type` are both `rename_all = "lowercase"` on each side, so the
/// SDK's `as_str()` is the right wire value.
///
/// `adopt: "move"` hands the file over: on the run dir's own filesystem that
/// is a `rename(2)`, so the image is attached without copying a byte. The
/// caller must therefore treat `image` as consumed once this returns.
pub(crate) async fn create_vm_on_image(
    cfg: &Config,
    name: &str,
    keepalive: bool,
    image: &std::path::Path,
) -> Result<Sandbox> {
    let _slot = bringup_slot(name).await;
    let started = Instant::now();
    let body = serde_json::json!({
        "name": name,
        "image": cfg.image,
        "backend_type": "firecracker",
        "size_class": cfg.size_class.as_str(),
        "open_ports": [VM_PG_PORT],
        // Always 0: the pooler owns VM lifecycle, as in `create_vm`.
        "ttl_seconds": 0,
        "data_image_path": image.to_string_lossy(),
        "data_image_adopt": "move",
    });
    let url = format!("{}/sandboxes", daemon_base_url());
    let client = reqwest::Client::builder()
        .timeout(DEPLOY_HTTP_TIMEOUT)
        .build()
        .context("building HTTP client for the adopt-image create")?;
    let resp = daemon_auth(client
        .post(&url))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .context("calling the daemon's create-on-image")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "daemon create-on-image returned {status}: {} (a 404 means this daemon has no \
             /sandboxes route; a 422 naming data_image_path means it predates the field)",
            text.trim()
        );
    }
    let id = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str().map(str::to_string)))
        .ok_or_else(|| anyhow::anyhow!("daemon create-on-image returned no sandbox id: {text}"))?;
    let sandbox = Sandbox::connect(id.clone(), local_opts())
        .with_context(|| format!("connecting to adopted-image VM {id}"))?;
    if let Some(schema) = name.strip_prefix("pg-") {
        crate::pending::record(schema, &id).await;
    }
    crate::inventory::insert(name, &id);
    // The synchronous create returns only once the guest has been started, so
    // this is a confirmation rather than a wait — but it is the same guard
    // `create_vm` uses, and a daemon that 201s an unstarted VM must not slip
    // through to a client.
    let ready_timeout = cfg.ready_timeout;
    if let Err(e) = wait_ready(&sandbox, ready_timeout, name).await {
        warn!("{name}: adopted-image VM {id} never became ready; killing it");
        let _ = tokio::time::timeout(Duration::from_secs(30), sandbox.kill()).await;
        crate::inventory::remove_id(&id);
        if let Some(schema) = name.strip_prefix("pg-") {
            crate::pending::clear(schema).await;
        }
        return Err(e).with_context(|| format!("waiting for adopted-image VM {name}"));
    }
    if keepalive && let Err(e) = sandbox.set_ttl(0).await {
        warn!("failed to pin keep-alive VM {name} (set_ttl 0): {e:#}");
    }
    crate::events::record_timing(crate::events::Timing::VmCreate, started.elapsed());
    info!("created VM {name} on the restored disk in {:?}", started.elapsed());
    Ok(sandbox)
}

/// Best-effort stop of whatever VM a failed offload bring-up may have left
/// running — the ready-timeout case: the sandbox started, but Postgres never
/// answered (sick disk, wedged boot), so `ensure_vm` errored without ever
/// returning a handle to stop. Nothing else owns such a VM (the warm entry
/// was evicted before the attempt), so without this it runs forever, burning
/// RAM and pinning its disk against reclaim. Matches by the stored id and by
/// `pg-<schema>` name (covers a VM freshly created inside the failed
/// attempt); every step is logged, none propagate.
pub(crate) async fn stop_after_failed_bringup(schema: &str, known_id: Option<&str>) {
    // Act on ids we already hold — the pending ledger names the VM this very
    // attempt created, `known_id` names a reattach target — so the common case
    // needs no listing at all. Listing is the fallback, not the front door: a
    // failed bring-up usually means a struggling daemon, and the old
    // list-first version failed its listing in exactly those moments and
    // silently cleaned up nothing (that's where the stranded-VM pileups came
    // from). The stop (not delete) is deliberate: a post-ready failure can
    // leave partial restore state on the disk, and the next attempt reuses
    // the VM idempotently; a VM that stays unbound is the pending janitor's
    // to delete.
    let mut ids: Vec<String> = crate::pending::get(schema).into_iter().collect();
    if let Some(id) = known_id
        && !ids.iter().any(|i| i == id)
    {
        ids.push(id.to_string());
    }
    if ids.is_empty() {
        let name = format!("pg-{schema}");
        match find_by_name_with_retry(&name).await {
            Ok(found) => ids.extend(found.map(|i| i.id)),
            Err(e) => {
                warn!(
                    "schema {schema}: cannot resolve {name} to stop a leaked bring-up: {e:#}"
                );
                return;
            }
        }
    }
    for id in ids {
        let Ok(sb) = Sandbox::connect(id.clone(), local_opts()) else {
            continue;
        };
        match tokio::time::timeout(Duration::from_secs(30), sb.stop()).await {
            Ok(Ok(())) => info!(
                "schema {schema}: stopped VM {id} left running by the failed bring-up"
            ),
            Ok(Err(e)) => warn!(
                "schema {schema}: stopping leaked VM {id} failed (may already be stopped): {e:#}"
            ),
            Err(_) => warn!("schema {schema}: stopping leaked VM {id} timed out"),
        }
    }
}

/// Create one warm-spare VM (see `spares`): identical to a schema VM — same
/// image, size class, thin data disk, TTL 0 — just parked with an empty
/// cluster until claimed.
pub(crate) async fn create_spare(cfg: &Config, name: &str) -> Result<Sandbox> {
    // Always the default size: a spare is claimed before anyone knows which
    // schema it will serve, and an oversized-restore claim is refused in
    // `resolve_sandbox` rather than guessed at here.
    create_vm_within(
        cfg,
        name,
        false,
        cfg.ready_timeout.min(SPARE_READY_TIMEOUT),
        cfg.data_disk_gb,
        None,
    )
    .await
}

/// Is this VM's Postgres accepting connections? A plain TCP connect to the
/// guest's 5432 — enough to prove the guest booted, mounted its data disk,
/// finished `initdb` and started the postmaster, which is the whole point of
/// holding a spare. Cheap (no daemon call beyond the id lookup, no auth, no
/// pool) so the replenisher can run it over the pool every pass.
///
/// `Ok(None)` means the check doesn't apply: the daemon reports no `guest_ip`
/// (non-tap backend, or not assigned yet), so there is no direct address to
/// probe and the caller must fall back to the daemon's own status.
pub(crate) async fn pg_listening(sandbox: &Sandbox) -> Result<Option<bool>> {
    let Some(target) = direct_target(sandbox).await? else {
        return Ok(None);
    };
    let connected = tokio::time::timeout(PG_PROBE_ATTEMPT, tokio::net::TcpStream::connect(target))
        .await
        .is_ok_and(|r| r.is_ok());
    Ok(Some(connected))
}

/// Grow a stopped VM's data device before booting it, when its filesystem is
/// at the grow trigger and fills the device.
///
/// A VM whose Postgres died of `No space left on device` never gets warm
/// again — crash recovery has to write before the server accepts a
/// connection — so neither grow path that samples through Postgres ever sees
/// it, and every bring-up boots it back into the same full disk (pg-0rtk7Stq
/// retried all day on a 2GiB disk 94% full). So read it offline, the way a
/// restored image is: dumpe2fs on the disk file, judged by
/// [`crate::imgarchive::offline_grow_verdict`].
///
/// Does nothing without a run dir or disk file, or while anything holds the
/// disk open: a running VM's filesystem is the guest's to report, and there
/// is no resizing under it. `settle` is how long to wait for a just-stopped
/// VM's Firecracker to let go. The caller holds the boot permit — the
/// daemon's resize fscks the file, which must not interleave with a reclaim
/// pass. The registry banks the new size from its first sample of the booted
/// VM, as it does for every warm schema.
async fn grow_stopped_disk(cfg: &Config, name: &str, id: &str, settle: Duration) -> Result<()> {
    let Some(run_dir) = cfg.run_dir.as_ref() else {
        return Ok(());
    };
    let disk = run_dir.join(id).join("data.ext4");
    let Ok(md) = tokio::fs::metadata(&disk).await else {
        return Ok(());
    };
    let deadline = Instant::now() + settle;
    while crate::imgarchive::disk_held_open(&disk).await {
        if Instant::now() >= deadline {
            return Ok(());
        }
        sleep(Duration::from_secs(1)).await;
    }
    let Some(usage) = crate::imgarchive::offline_fs_usage(&disk).await else {
        return Ok(());
    };
    let (total_blocks, free_blocks, _) = usage;
    let used_pct = 100.0 * (1.0 - free_blocks as f64 / total_blocks.max(1) as f64);
    let size_gb = md.len().div_ceil(GIB);
    match crate::imgarchive::offline_grow_verdict(usage, md.len(), cfg.disk_grow) {
        GrowVerdict::NotNeeded => Ok(()),
        GrowVerdict::AtCap { current_gb } => {
            warn!(
                "{name}: stopped data disk is {used_pct:.0}% full and its {current_gb}GiB device \
                 is already at the growth cap — Postgres may not start on it (raise \
                 PG_VM_POOL_DISK_MAX_GB)"
            );
            Ok(())
        }
        GrowVerdict::Grow(target) => {
            info!(
                "{name}: stopped data disk is {used_pct:.0}% full on a {size_gb}GiB device — \
                 growing it to {target}GiB before booting {id}, so Postgres has room to start"
            );
            resize_disk(id, target).await.with_context(|| {
                format!("growing {name}'s data device to {target}GiB before boot")
            })?;
            crate::events::journal_info(
                "disk-grow",
                format!("{name}: device grown to {target}GiB before boot ({id})"),
            );
            Ok(())
        }
    }
}

/// Connect to an existing sandbox by id and force it to a running, ready state.
/// `Ok(None)` means it no longer exists (deleted out-of-band → caller creates).
///
/// Issues `start()` directly rather than checking status first. Two reasons:
/// (1) a status check via `get()` has a *side effect* on the daemon — for a
/// stopped Firecracker VM it rehydrates a handle that reports `running`, which
/// then makes the subsequent `start()` a no-op (VM stays down) and previously
/// deadlocked the daemon. (2) `start()` is the right primitive regardless: it
/// starts a stopped VM and no-ops a genuinely running one. A `NotFound` means
/// the sandbox was deleted, so the caller should create a fresh one.
async fn bring_up_existing(cfg: &Config, name: &str, id: &str) -> Result<Option<Sandbox>> {
    let sb = Sandbox::connect(id.to_string(), local_opts())
        .with_context(|| format!("connecting to VM {name} by id {id}"))?;
    info!("bringing up existing VM {name} ({id})");
    // A stopped VM's disk may be mid-fsck/shrink under a reclaim pass; booting
    // over that destroys the filesystem. Hold the permit only across start():
    // once the VM process has the disk open, the reclaim script's in-use checks
    // protect it — the pass-start snapshot between passes, and the live
    // re-check it runs under this same per-disk lock during one.
    //
    // Permit first, slot second — the order everywhere a boot takes both. The
    // permit can block (it preempts a reclaim pass, but the pass still has to
    // reach a yield point); waiting for it while holding one of the three
    // bring-up slots would spend the pooler's scarcest resource on a wait that
    // needs no daemon at all, and three such boots would freeze every
    // bring-up on the host. Reclaim never takes a bring-up slot, so there is
    // no cycle to deadlock on.
    let started = {
        let _permit = crate::reclaim::boot_permit(id).await;
        // Under the permit, before the slot: the check reads the disk offline
        // and a grow resizes it, neither of which is boot traffic. A failed
        // grow still boots, on the disk it had.
        if let Err(e) = grow_stopped_disk(cfg, name, id, Duration::ZERO).await {
            warn!("{name}: {e:#}; booting it on the disk it has");
        }
        let _slot = bringup_slot(name).await;
        sb.start().await
    };
    match started {
        Ok(()) => {}
        Err(HeyoError::NotFound(_)) => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("starting VM {name}"))),
    }
    wait_ready(&sb, cfg.ready_timeout, name)
        .await
        .with_context(|| format!("waiting for VM {name}"))?;
    crate::inventory::insert(name, id);
    Ok(Some(sb))
}

/// Create a brand-new VM for a schema, with a `disk_gb` persistent data disk.
/// `pub(crate)` for the image-restore path, which creates the VM itself and
/// swaps the restored disk in under it before first use.
pub(crate) async fn create_vm(
    cfg: &Config,
    name: &str,
    keepalive: bool,
    disk_gb: u32,
) -> Result<Sandbox> {
    create_vm_within(cfg, name, keepalive, cfg.ready_timeout, disk_gb, None).await
}

/// [`create_vm`] with an explicit readiness budget — warm spares get a shorter
/// one than a client-facing bring-up (see [`SPARE_READY_TIMEOUT`]).
async fn create_vm_within(
    cfg: &Config,
    name: &str,
    keepalive: bool,
    ready_timeout: Duration,
    disk_gb: u32,
    own: Option<&(dyn Fn(&str) -> Result<()> + Send + Sync)>,
) -> Result<Sandbox> {
    info!(
        "creating VM {name}{}{}",
        if keepalive { " (keep-alive)" } else { "" },
        if disk_gb == cfg.data_disk_gb {
            String::new()
        } else {
            format!(" with a {disk_gb}GiB data device (default is {}GiB)", cfg.data_disk_gb)
        }
    );
    let (sandbox, create_started) = {
        let _slot = bringup_slot(name).await;
        // The clock for the VmCreate timing starts once the daemon is actually
        // ours to talk to. The wait for a bring-up slot above measures how many
        // other creates are already in flight — a queue depth, not a cost of
        // this create — and folding it in would make the percentiles a
        // function of concurrency rather than of how fast the daemon builds.
        let started = Instant::now();
        let sandbox = Sandbox::create(
            SandboxCreateOptions {
                name: Some(name.to_string()),
                image: Some(cfg.image.clone()),
                driver: Some(SandboxDriver::Firecracker),
                open_ports: vec![VM_PG_PORT],
                size_class: Some(cfg.size_class),
                // Persistent data disk → /dev/vdb → /workspace → PGDATA, so the
                // schema's data survives VM stop/start/restart. Normally
                // `cfg.data_disk_gb`, but a restore of a schema whose device
                // had grown asks for the size it actually needs — building it
                // right is the only chance, since growth is an offline
                // operation and `pg_restore` is about to run.
                disk_size_gb: Some(disk_gb),
                // Always 0: the pooler owns VM lifecycle. Keep-alive schemas stay up;
                // others are stopped by the pooler's idle reaper, which tracks
                // connections — something the daemon's absolute TTL can't do.
                ttl_seconds: Some(0),
                // ZERO = return as soon as the deploy POST answers; the ready
                // poll runs below, outside the bring-up gate, so a slot is held
                // only while the daemon is actually building and booting.
                wait_for_ready: Some(Duration::ZERO),
                ..Default::default()
            },
            HeyoClientOptions {
                timeout: Some(DEPLOY_HTTP_TIMEOUT),
                ..local_opts()
            },
        )
        .await
        .with_context(|| format!("creating VM {name}"))?;
        (sandbox, started)
    };
    if let Some(own) = own { own(sandbox.sandbox_id()).context("durably owning physical candidate VM")?; }
    // The daemon 202-accepts deploys, so this id exists (with a daemon-side
    // record behind it) long before the VM is usable — and until the registry
    // binds schema→id on full bring-up success, this variable is the only
    // owner. Ledger it immediately so a failure anywhere downstream leaves a
    // *named* leak the failure path and the pending janitor can kill by id,
    // instead of an anonymous `provisioning` record nothing ever reaps.
    // (Spare creates skip the ledger: `spare-pg-*` are covered by purge.)
    if let Some(schema) = name.strip_prefix("pg-") {
        crate::pending::record(schema, sandbox.sandbox_id()).await;
    }
    crate::inventory::insert(name, sandbox.sandbox_id());
    if let Err(e) = wait_ready(&sandbox, ready_timeout, name).await {
        if own.is_some() { return Err(e).with_context(|| format!("waiting for owned physical candidate {name}")); }
        // Kill the half-built VM now, by the id in hand — no listing, which is
        // exactly what's unreachable when bring-ups fail en masse. It never
        // served a client, so its disk holds nothing worth keeping. Best
        // effort: if the kill can't land either, the ledger entry stays and
        // the janitor retries once the daemon recovers.
        match tokio::time::timeout(Duration::from_secs(30), sandbox.kill()).await {
            Ok(Ok(())) => {
                info!(
                    "{name}: deleted half-provisioned VM {} after failed bring-up",
                    sandbox.sandbox_id()
                );
                crate::inventory::remove_id(sandbox.sandbox_id());
                if let Some(schema) = name.strip_prefix("pg-") {
                    crate::pending::clear(schema).await;
                }
            }
            Ok(Err(kill_err)) => warn!(
                "{name}: deleting half-provisioned VM {} failed (janitor will retry): {kill_err:#}",
                sandbox.sandbox_id()
            ),
            Err(_) => warn!(
                "{name}: deleting half-provisioned VM {} timed out (janitor will retry)",
                sandbox.sandbox_id()
            ),
        }
        return Err(e).with_context(|| format!("waiting for created VM {name}"));
    }
    let took = create_started.elapsed();
    // Success only, and paired with the event so the "VMs created" chart and
    // these percentiles always describe the same set of creates. A failed
    // create is bounded by `ready_timeout` rather than by how fast the daemon
    // works, so counting it would pull every percentile toward that ceiling.
    info!("created VM {name} in {took:?}");
    crate::events::record(crate::events::Event::VmCreated);
    crate::events::record_timing(crate::events::Timing::VmCreate, took);
    Ok(sandbox)
}

/// Resolve the VM's direct host-reachable Postgres address from the daemon's
/// `guest_ip` (populated for tap backends). `None` when the daemon doesn't
/// report one (non-tap backend, or not yet assigned) so the caller can fall
/// back to a tunnel.
async fn direct_target(sandbox: &Sandbox) -> Result<Option<SocketAddr>> {
    let info = sandbox.get().await.context("fetching sandbox info")?;
    let Some(ip) = info.guest_ip.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let addr: IpAddr = ip
        .parse()
        .with_context(|| format!("parsing guest_ip {ip:?}"))?;
    Ok(Some(SocketAddr::new(addr, VM_PG_PORT)))
}

/// Expose the VM's Postgres over an iroh tunnel and return the local splice
/// address plus the tunnel handle (aborted when dropped, so the caller must
/// hold it for the entry's lifetime). `P2pTunnel::connect` has no internal
/// timeout — when iroh's relays churn (host IP flapping on WiFi) it can block
/// for minutes — so bound the whole handshake and fail fast for a retry.
async fn open_tunnel(
    cfg: &Config,
    sandbox: &Sandbox,
    name: &str,
) -> Result<(SocketAddr, P2pTunnel)> {
    let handshake = async {
        let ticket = sandbox
            .expose_tcp(VM_PG_PORT)
            .await
            .context("exposing VM Postgres port")?;
        P2pTunnel::connect(&ticket, None)
            .await
            .context("connecting P2P tunnel")
    };
    let tunnel = match tokio::time::timeout(cfg.connect_timeout, handshake).await {
        Ok(res) => res?,
        Err(_) => bail!(
            "tunnel setup for {name} timed out after {:?} — iroh relays likely \
             churning (host network unstable); will retry on next connect",
            cfg.connect_timeout
        ),
    };
    let local_port = tunnel.local_port();
    info!("tunnel for {name} ready on 127.0.0.1:{local_port}");
    Ok((SocketAddr::from(([127, 0, 0, 1], local_port)), tunnel))
}

/// Cap on the pooler's own connections to a VM's Postgres.
///
/// This pool is not the client data path — client bytes are spliced straight to
/// the VM — so it only ever serves the pooler's own housekeeping: the liveness
/// probe, the one-time database bootstrap, the dashboard's stat queries, and
/// the pre-stop CHECKPOINT. A handful of slots covers all of that concurrently.
///
/// Left unset, deadpool defaults `max_size` to `logical_cpus * 2`, sized for a
/// pool that *is* the data path. That default is read off the **pooler host**,
/// which has nothing to do with the guest's `max_connections` — a 16-core host
/// yields 32, so the pooler could hold a third of a large VM's 100 connections
/// just to ask "are you alive?". Worse, `entry_alive` probes on every client
/// checkout, so a burst of client connects grows this pool straight to its cap
/// at exactly the moment the VM can least afford it, and the pool connects as
/// superuser — so it eats the reserved slots and survives while the app starves.
const POOL_MAX_SIZE: usize = 4;

fn build_pool(
    host: &str,
    port: u16,
    dbname: &str,
    user: &str,
    password: Option<&str>,
) -> Result<Pool> {
    let mut pg = PgConfig::new();
    pg.host = Some(host.to_string());
    pg.port = Some(port);
    pg.dbname = Some(dbname.to_string());
    pg.user = Some(user.to_string());
    // Only set a password when configured; leaving it None keeps `trust` auth
    // working (an empty-string password would be sent as a real credential).
    pg.password = password.map(str::to_string);
    pg.pool = Some(deadpool_postgres::PoolConfig {
        max_size: POOL_MAX_SIZE,
        // Bound the queue for a slot. Callers treat a local checkout failure as
        // `Stalled` (never `Unreachable`), so this can only cost a probe, never
        // trigger a power-cycle. `create` bounds the TCP connect itself, which
        // otherwise has no timeout at all.
        timeouts: deadpool_postgres::Timeouts {
            wait: Some(PG_PROBE_ATTEMPT),
            create: Some(PG_PROBE_ATTEMPT),
            recycle: Some(PG_PROBE_ATTEMPT),
        },
        ..Default::default()
    });
    pg.create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)
        .context("building deadpool pool")
}

/// Retry until Postgres answers a trivial query or the timeout elapses. Logs a
/// periodic warning while it waits so a VM that boots but never brings Postgres
/// up (e.g. a missing data disk → no PGDATA) shows the reason in the log
/// instead of the caller silently blocking for the whole `timeout`.
async fn wait_pg_ready(pool: &Pool, timeout: Duration, name: &str) -> Result<()> {
    let start = Instant::now();
    let deadline = start + timeout;
    let mut last_log = start;
    loop {
        let last_err = match pool.get().await {
            Ok(client) => match client.simple_query("SELECT 1").await {
                Ok(_) => return Ok(()),
                Err(e) => pg_error_text(&e),
            },
            Err(deadpool_postgres::PoolError::Backend(e)) => pg_error_text(&e),
            Err(e) => e.to_string(),
        };
        if Instant::now() >= deadline {
            bail!("Postgres on {name} not ready within {timeout:?}: {last_err}");
        }
        if last_log.elapsed() >= Duration::from_secs(15) {
            warn!(
                "still waiting for Postgres on {name} ({:?} elapsed, timeout {timeout:?}): {last_err}",
                start.elapsed()
            );
            last_log = Instant::now();
        }
        sleep(pg_poll_interval(start.elapsed())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `swap_and_boot` skips its stop on this answer alone, so only the
    /// variant that is genuinely handed over stopped may say yes. A `Spare`
    /// answering true here would send a `cp` at the disk of a running
    /// Firecracker.
    #[test]
    fn only_a_chilled_vehicle_reports_itself_already_stopped() {
        assert!(Provenance::ChilledSpare.is_stopped());
        assert!(!Provenance::Spare.is_stopped());
        assert!(!Provenance::Created.is_stopped());
        assert!(!Provenance::Existing.is_stopped());
    }

    #[test]
    fn physical_exec_preserves_one_shell_body_and_exit_status() {
        let command = physical_exec_command("cat <<'SQL'\nSELECT :'db', '$literal';\nSQL\nprintf '%s\\n' \"$PGFC_VALUE\"\nexit 17");
        assert!(!command.contains('\n'), "serial capture needs one physical line");
        let output = std::process::Command::new("sh").args(["-c", &command])
            .env("PGFC_VALUE", "a'b $unchanged").output().unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "SELECT :'db', '$literal';\na'b $unchanged\n");
    }

    fn pool_at(port: u16) -> Pool {
        build_pool("127.0.0.1", port, "postgres", "postgres", None).unwrap()
    }

    /// The cause has to survive into the text: the error's own Display is just
    /// its kind, which is how readiness logs used to say only "db error".
    #[tokio::test]
    async fn pg_error_text_carries_the_cause() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let err = tokio_postgres::connect(
            &format!("host=127.0.0.1 port={port} user=postgres connect_timeout=2"),
            tokio_postgres::NoTls,
        )
        .await
        .err()
        .expect("nothing listens on a just-released port");
        let text = pg_error_text(&err);
        assert!(text.starts_with(&err.to_string()), "{text}");
        assert!(text.len() > err.to_string().len(), "cause dropped: {text}");
    }

    /// Exhaust the gate, confirm nothing is left, and confirm dropped permits
    /// return to the pool — a leaked permit here would silently serialize all
    /// production bring-ups down to N-1 slots forever. Capacity-agnostic so an
    /// inherited PG_VM_POOL_MAX_CONCURRENT_BRINGUPS doesn't break the test.
    #[tokio::test]
    async fn bringup_gate_bounds_and_recycles_slots() {
        let Some(gate) = bringup_gate() else {
            return; // gate disabled via env — nothing to check
        };
        let cap = gate.available_permits();
        assert!(cap > 0, "an enabled gate must have at least one slot");
        let mut held = Vec::new();
        for i in 0..cap {
            held.push(bringup_slot(&format!("test-{i}")).await);
        }
        assert_eq!(gate.available_permits(), 0, "gate must be exhaustible");
        held.pop();
        assert_eq!(gate.available_permits(), 1, "dropped permits must recycle");
        drop(held);
        assert_eq!(gate.available_permits(), cap);
    }

    /// The admission deadline: no slot by the deadline sheds the waiter, a
    /// slot freed before it is taken, and no deadline waits it out.
    #[tokio::test]
    async fn acquire_within_sheds_at_its_deadline_and_admits_before_it() {
        let gate = Semaphore::new(1);
        let held = gate.acquire().await.unwrap();

        let deadline = Instant::now() + Duration::from_millis(50);
        assert!(acquire_within(&gate, Some(deadline)).await.is_none());
        assert!(Instant::now() >= deadline, "shed before its deadline");
        // A deadline already past sheds at once rather than hanging.
        assert!(acquire_within(&gate, Some(Instant::now())).await.is_none());

        let release = async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(held);
        };
        let (admitted, ()) = tokio::join!(
            acquire_within(&gate, Some(Instant::now() + Duration::from_secs(5))),
            release
        );
        assert!(admitted.is_some(), "a slot freed before the deadline is taken");
        drop(admitted);
        assert!(acquire_within(&gate, None).await.is_some());
    }

    /// The registry and the connection handler both recognise a shed through
    /// whatever context the bring-up path wraps it in.
    #[test]
    fn a_shed_is_recognised_through_context() {
        let shed: anyhow::Error = BringupShed {
            schema: "s".into(),
            waited: Duration::from_secs(15),
            queued: 3,
        }
        .into();
        assert!(is_shed(&shed.context("bringing up s")));
        assert!(!is_shed(&anyhow::anyhow!("host memory capacity unavailable")));
    }


    /// The launch script is parsed by the guest's `sh`, and its heredoc carries
    /// a presigned URL (`&`, `=`, `%`, `?`) plus literal `$ec`/`$?`. Run the
    /// real thing through a real shell — with `cat`/`setsid`/`pg_dump` shadowed
    /// by stubs on PATH — and assert the file that lands is byte-identical to
    /// the job we asked for. A quoting slip here is invisible until an archive
    /// silently uploads nothing.
    fn schema_copy_conninfo() -> crate::replication::sql::Conninfo {
        crate::replication::sql::Conninfo {
            hostaddr: "203.0.113.10".parse().unwrap(),
            port: 6432,
            dbname: "acme".into(),
            user: "acme_pgfcrepl".into(),
            password: "s3cr3tpassword".into(),
            sslmode: "require".into(),
            application_name: "pgfc_node_b".into(),
        }
    }

    /// The primary's password is a durable credential — there is no
    /// presigned-URL-style expiry to fall back on — so the mitigation is that
    /// it never touches the guest's disk or process table. Pin both halves:
    /// the body carries no password, and the script deletes itself before it
    /// signals completion so even the rest of the conninfo does not linger.
    #[test]
    fn schema_copy_body_carries_no_password_and_self_deletes() {
        let c = schema_copy_conninfo();
        let body = schema_copy_job_body(
            &shell_squote("postgres"),
            &shell_squote("acme"),
            &shell_squote(&c.without_password()),
        );
        assert!(!body.contains("s3cr3tpassword"), "{body}");
        assert!(!body.contains("PGPASSWORD"), "it arrives via the exec env: {body}");
        assert!(body.contains("acme_pgfcrepl"), "the role is still there: {body}");
        assert!(body.contains(r#"rm -f "$0""#), "{body}");
        // Same sentinel discipline as every other detached job: written to a
        // temp name and renamed, so a torn write is never read as a result.
        assert!(body.contains(".tmp && mv "), "{body}");
    }

    /// `sh` has no `pipefail`, so `pg_dump | psql` reports only psql's status
    /// — and a psql that replays an empty stream exits 0. Without the marker,
    /// an unreachable primary would look like a successfully seeded (empty)
    /// replica, and the subscription would then sync nothing.
    #[test]
    fn schema_copy_body_records_a_producer_failure() {
        let body = schema_copy_job_body("'postgres'", "'acme'", "'x'");
        assert!(body.contains(SCHEMA_COPY_FAIL_MARK), "{body}");
        assert!(body.contains("ec=1"), "{body}");
        // Schema only: the rows come from the subscription's own copy_data,
        // under the slot's snapshot. A dump of the data would not line up with
        // the change stream that follows.
        assert!(body.contains("--schema-only"), "{body}");
        // A publication or subscription copied from the primary would make the
        // replica try to publish or subscribe on its own behalf.
        assert!(body.contains("--no-publications") && body.contains("--no-subscriptions"), "{body}");
        assert!(body.contains("ON_ERROR_STOP=1") && body.contains(" -1 "), "{body}");
        // The mirrored tenant must retain table ownership and grants after
        // promotion; restoring everything as postgres would break app writes.
        assert!(!body.contains("--no-owner") && !body.contains("--no-privileges"), "{body}");
    }

    #[test]
    fn launch_script_plants_the_job_verbatim() {
        let url = "https://wb.s3.us-east-2.amazonaws.com/x.dump?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                   &X-Amz-Credential=AK%2F20260721%2Fus-east-2%2Fs3%2Faws4_request\
                   &X-Amz-Signature=deadbeef&x=`whoami`&y=$(id)";
        let user = shell_squote("postgres");
        let db = shell_squote("Kb0s7KwS");
        let resolve = build_resolve_flag("wb.s3.us-east-2.amazonaws.com", &["3.5.130.160".into()]);

        for (job_desc, body, scratch, planted_as) in [
            (
                ARCHIVE_JOB,
                archive_job_body(&user, &db, &resolve, url),
                DUMP_PATH,
                "_archive.job.sh",
            ),
            (
                RESTORE_JOB,
                restore_job_body(&user, &db, &resolve, url, false, true),
                RESTORE_PATH,
                "_restore.job.sh",
            ),
        ] {
            plants_verbatim(job_desc, &body, scratch, planted_as, url);
        }
    }

    /// The streaming body must be real `sh`, never touch the data disk, and
    /// keep commit strictly on the success path (a commit reachable after a
    /// failed pg_dump would finalize torn bytes as a durable archive).
    #[test]
    fn streaming_dump_job_is_valid_sh_and_commits_only_on_success() {
        let user = shell_squote("postgres");
        let db = shell_squote("Kb0s7KwS");
        let body = streaming_dump_job_body(&user, &db, "http://$GW:6433/d/tok0123");

        // Syntax-check the exact bytes with a real shell.
        let f = std::env::temp_dir().join(format!("pgfc-streamjob-{}.sh", std::process::id()));
        std::fs::write(&f, &body).unwrap();
        let ok = std::process::Command::new("sh")
            .arg("-n")
            .arg(&f)
            .status()
            .unwrap()
            .success();
        let _ = std::fs::remove_file(&f);
        assert!(ok, "streaming job body must parse as sh:\n{body}");

        // No payload writes to the data disk: the whole point of the streaming
        // route. (The job's sentinel/log still land there — a few KB, versus
        // the full dump the file-based route wrote.)
        assert!(!body.contains(DUMP_PATH), "streaming job must not write the dump to the data disk");
        assert!(body.contains(STREAM_FAIL_MARK), "pipefail surrogate present");

        // Commit only inside the ec=0 branch; abort on the other side. The
        // anchor is the branch on its own line — require_2xx's inline
        // `; if [ "$ec" = 0 ]; then ec=22` must not match.
        let branch = "\nif [ \"$ec\" = 0 ]; then\n";
        let success_branch = body.split(branch).nth(1).unwrap();
        let (commit_side, abort_side) = success_branch.split_once("\nelse\n").unwrap();
        assert!(commit_side.contains("/commit"));
        assert!(!commit_side.contains("/abort"));
        assert!(abort_side.contains("/abort"));
        assert!(!abort_side.contains("/commit"));
        // And nothing commits before the branch.
        let preamble = body.split(branch).next().unwrap();
        assert!(!preamble.contains("/commit"));
    }

    /// Run one job's real launch script through a real `sh` — with every command
    /// it calls shadowed by stubs — and assert the file that lands is
    /// byte-identical to the job we asked for.
    fn plants_verbatim(
        job_desc: DetachedJob,
        body: &str,
        scratch: &str,
        planted_as: &str,
        url: &str,
    ) {
        let job = body.to_string();
        let script = job_desc.launch_script(&job, scratch);

        let dir = std::env::temp_dir().join(format!(
            "pgfc-launch-{}-{}",
            std::process::id(),
            job_desc.what
        ));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        // Redirect the guest's absolute /workspace paths into the temp dir, and
        // stub every command the script calls so nothing actually runs. The same
        // rewrite applies to the expected body, since it is embedded in the
        // script we run.
        let root = format!("{}/", dir.display());
        let script = script.replace("/workspace/", &root);
        let job = job.replace("/workspace/", &root);
        for cmd in ["setsid", "pg_dump", "pg_restore", "curl"] {
            let p = dir.join("bin").join(cmd);
            std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .env("PATH", format!("{}/bin:/usr/bin:/bin", dir.display()))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "launch script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "launched");

        let planted = std::fs::read_to_string(dir.join(planted_as)).unwrap();
        assert_eq!(
            planted, job,
            "heredoc must plant the {} job byte-for-byte — no expansion, no requoting",
            job_desc.what
        );
        // The URL's `&`/`%`/backticks must have survived intact: a mangled URL
        // yields an S3 403 long after the VM that could explain it is gone.
        assert!(
            planted.contains(url),
            "presigned URL was altered in transit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dump whose upload S3 *redirected* must record failure, not success.
    ///
    /// This is the bug that cost a workbook: the bucket lived in a region other
    /// than the configured one, S3 answered the PUT `301 Moved Permanently`, and
    /// `curl -fsS` exited 0 — `--fail` only trips on 4xx/5xx. The job wrote a `0`
    /// sentinel, the pooler reported the archive durable, and the caller killed
    /// the VM and reclaimed the disk. Nothing had been uploaded.
    #[test]
    fn a_redirected_upload_is_a_failed_dump() {
        // Every status a misrouted or rejected transfer can come back as, plus
        // the ones that must still count as success.
        for (code, want_ok) in [
            ("200", true),
            ("204", true),
            ("301", false), // the production failure
            ("307", false),
            ("403", false),
            ("500", false),
            ("000", false), // curl never got a response
        ] {
            let ec = run_archive_job_with_curl_status(code);
            assert_eq!(
                ec == "0",
                want_ok,
                "HTTP {code} upload recorded exit code {ec:?}; \
                 a non-2xx must never write a zero sentinel"
            );
        }
    }

    /// Run the real archive job body under a real `sh`, with `curl` stubbed to
    /// report `code` the way curl's `-w '%{http_code}'` does, and return the exit
    /// code the job wrote to its sentinel.
    fn run_archive_job_with_curl_status(code: &str) -> String {
        let dir = std::env::temp_dir().join(format!("pgfc-status-{}-{code}", std::process::id()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let root = format!("{}/", dir.display());

        let body = archive_job_body(
            &shell_squote("postgres"),
            &shell_squote("s"),
            "",
            "https://x/y",
        )
        .replace("/workspace/", &root);

        // pg_dump succeeds and produces a non-empty dump (the empty-file guard
        // would otherwise fail the job before curl runs); curl prints the
        // status to stdout and — as curl does for a redirect it isn't
        // following — exits 0 regardless.
        let stubs = [
            (
                "pg_dump",
                format!("#!/bin/sh\nprintf dumpbytes > {root}_archive.dump\nexit 0\n"),
            ),
            ("curl", format!("#!/bin/sh\nprintf %s '{code}'\nexit 0\n")),
        ];
        for (cmd, script) in stubs {
            let p = dir.join("bin").join(cmd);
            std::fs::write(&p, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&body)
            .env("PATH", format!("{}/bin:/usr/bin:/bin", dir.display()))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "job body itself must not error: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let sentinel =
            std::fs::read_to_string(dir.join(ARCHIVE_JOB.done.trim_start_matches("/workspace/")))
                .expect("job must always write a sentinel");
        let _ = std::fs::remove_dir_all(&dir);
        sentinel
    }

    /// The production failure of 2026-07-23: with the host disk full, the
    /// guest's dump file was torn to zero length while `pg_dump` and `curl`
    /// both exited 0 — a 0-byte "archive" was accepted and the VM (the only
    /// copy of the data) was killed. The job must fail before uploading when
    /// the dump file is empty or missing.
    #[test]
    fn an_empty_dump_file_never_uploads() {
        for create_file in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "pgfc-empty-{}-{create_file}",
                std::process::id()
            ));
            std::fs::create_dir_all(dir.join("bin")).unwrap();
            let root = format!("{}/", dir.display());
            let body = archive_job_body(
                &shell_squote("postgres"),
                &shell_squote("s"),
                "",
                "https://x/y",
            )
            .replace("/workspace/", &root);

            // pg_dump "succeeds" but leaves the dump empty (or absent); curl
            // records that it ran — it must not.
            let dump_script = if create_file {
                format!("#!/bin/sh\n: > {root}_archive.dump\nexit 0\n")
            } else {
                "#!/bin/sh\nexit 0\n".to_string()
            };
            let stubs = [
                ("pg_dump", dump_script),
                ("curl", format!("#!/bin/sh\ntouch {root}curl-ran\nprintf 200\nexit 0\n")),
            ];
            for (cmd, script) in stubs {
                let p = dir.join("bin").join(cmd);
                std::fs::write(&p, script).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&body)
                .env("PATH", format!("{}/bin:/usr/bin:/bin", dir.display()))
                .output()
                .unwrap();
            assert!(out.status.success(), "job body itself must not error");
            let sentinel = std::fs::read_to_string(
                dir.join(ARCHIVE_JOB.done.trim_start_matches("/workspace/")),
            )
            .expect("job must always write a sentinel");
            assert_ne!(sentinel, "0", "an empty dump must never write a zero sentinel");
            assert!(
                !dir.join("curl-ran").exists(),
                "an empty dump must never be uploaded at all"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The probe shares a serial console with kernel logs and with the leftover
    /// output of commands the daemon already gave up on at its 30s timeout. The
    /// parser must find its own reply in that noise, and — critically — must
    /// never invent a `Succeeded` from it, since the caller destroys the source
    /// disk on success.
    #[test]
    fn probe_parser_survives_a_noisy_shared_console() {
        use JobState::*;
        let s = parse_probe;

        assert!(matches!(s("HEYOJOB:P"), Running));
        assert!(matches!(s("HEYOJOB:D0"), Succeeded));
        assert!(matches!(s("HEYOJOB:D22"), Failed(22)));
        // Trailing CR from the console's line discipline.
        assert!(matches!(s("HEYOJOB:D0\r\n"), Succeeded));

        // Kernel log + the tail of an abandoned earlier command ahead of ours.
        let noisy = "[  512.3] blk_update_request: I/O error\n\
                     HEYOJOB:P\n\
                     __HEYVM_1a2b_END__ 0\n\
                     HEYOJOB:D0\n";
        assert!(matches!(s(noisy), Succeeded), "last reply must win");

        // Nothing recognisable → keep waiting. Never `Succeeded`: an empty or
        // garbled read is exactly what a wedged console produces, and treating
        // it as success would kill a VM whose dump never uploaded.
        for junk in ["", "\n\n", "sh: read: not found", "HEYOJOB:", "D0"] {
            assert!(
                matches!(s(junk), Running),
                "unrecognised probe output {junk:?} must read as Running"
            );
        }
        // A completed job whose code is unreadable is a completion, not a hang.
        assert!(matches!(s("HEYOJOB:Dxx"), Failed(-1)));
    }

    /// Dump and restore must not share scratch paths: a restore reads its
    /// sentinel while the VM may still carry the previous dump's, and crossed
    /// paths would have one job read the other's exit code.
    #[test]
    fn detached_jobs_have_disjoint_scratch_paths() {
        let paths = [
            ARCHIVE_JOB.script,
            ARCHIVE_JOB.done,
            ARCHIVE_JOB.log,
            DUMP_PATH,
            RESTORE_JOB.script,
            RESTORE_JOB.done,
            RESTORE_JOB.log,
            RESTORE_PATH,
        ];
        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(
            unique.len(),
            paths.len(),
            "scratch paths collide: {paths:?}"
        );
    }

    /// The probe runs on a VM whose single vCPU is saturated by `pg_dump`, so it
    /// must fork nothing — every builtin it uses (`[`, `read`, `printf`) has to
    /// really be a builtin. Run it under a PATH with *no* external commands at
    /// all: if the script reaches for `cat`/`tail`, it fails here.
    #[test]
    fn probe_command_is_fork_free_and_reports_both_states() {
        let dir = std::env::temp_dir().join(format!("pgfc-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let done = dir.join("_archive.done");
        let cmd = ARCHIVE_JOB
            .probe_command()
            .replace(ARCHIVE_JOB.done, done.to_str().unwrap());

        // Point PATH at an empty directory: `sh` itself is spawned by absolute
        // path, so nothing the script names can resolve to an external binary.
        let empty = dir.join("empty-path");
        std::fs::create_dir_all(&empty).unwrap();
        let run = || {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd)
                .env("PATH", &empty)
                .output()
                .unwrap();
            assert!(
                out.stderr.is_empty(),
                "probe must not shell out: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };

        // No sentinel yet → pending.
        assert!(matches!(parse_probe(&run()), JobState::Running));
        // Sentinel written by the job → its exit code comes back intact.
        std::fs::write(&done, "0").unwrap();
        assert!(matches!(parse_probe(&run()), JobState::Succeeded));
        std::fs::write(&done, "7\n").unwrap();
        assert!(matches!(parse_probe(&run()), JobState::Failed(7)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_flag_pins_ips_or_stays_empty() {
        // No IPs → no flag, so curl falls back to the guest's own DNS unchanged.
        assert_eq!(build_resolve_flag("wb.s3.us-east-2.amazonaws.com", &[]), "");
        // One or more IPs → a single quoted, comma-joined --resolve entry.
        let one = build_resolve_flag("wb.s3.us-east-2.amazonaws.com", &["3.5.130.160".into()]);
        assert_eq!(
            one,
            "--resolve 'wb.s3.us-east-2.amazonaws.com:443:3.5.130.160'"
        );
        let many = build_resolve_flag(
            "wb.s3.us-east-2.amazonaws.com",
            &["3.5.130.160".into(), "52.219.0.1".into()],
        );
        assert_eq!(
            many,
            "--resolve 'wb.s3.us-east-2.amazonaws.com:443:3.5.130.160,52.219.0.1'"
        );
    }

    /// The pooler's pool is housekeeping-only and must not scale with the
    /// *pooler host's* core count — that number is unrelated to the guest's
    /// max_connections, and the default (logical_cpus * 2 = 32 on a 16-core
    /// host) would let the pooler hold a third of a large VM's connections
    /// just to run liveness probes.
    #[test]
    fn pool_is_capped_independently_of_host_cores() {
        let p = pool_at(5432);
        assert_eq!(
            p.status().max_size,
            POOL_MAX_SIZE,
            "pool must be explicitly capped, not inherited from host cores"
        );
        assert!(
            POOL_MAX_SIZE * 4 < 100,
            "several schema pools must still fit inside a guest's max_connections"
        );
    }

    /// A checkout that fails inside our own pool (queued past `wait`, pool
    /// closed) says nothing about the VM. It must never reach `Unreachable`,
    /// which is the verdict that power-cycles.
    #[tokio::test]
    async fn local_pool_exhaustion_is_not_unreachable() {
        // A listener that accepts but never speaks: checkouts occupy every slot
        // and stall, so further checkouts queue past `wait` and fail locally.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                std::mem::forget(sock);
            }
        });
        let pool = std::sync::Arc::new(pool_at(port));
        // Saturate every slot, then probe against the exhausted pool.
        for _ in 0..POOL_MAX_SIZE {
            let p = pool.clone();
            tokio::spawn(async move { p.get().await.map(|c| std::mem::forget(c)) });
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !matches!(probe_pg(&pool).await, PgProbe::Unreachable(_)),
            "a local pool checkout failure must not be reported as Unreachable"
        );
    }

    /// The budget must never exceed what the server will actually accept —
    /// over-admitting reintroduces the `too many clients` FATAL this exists to
    /// prevent. A guest with a tiny max_connections must clamp down, not fall
    /// back to some default larger than the server allows.
    #[test]
    fn slot_budget_never_over_admits() {
        // The `large` VM in init.sh: 100 max, 5 reserved, 4 for our pool.
        assert_eq!(slots_from_limits(100, 5), 91);
        // The `micro` VM: 25 max.
        assert_eq!(slots_from_limits(25, 5), 16);
        // Degenerate guests: clamp to 1, never to a fallback bigger than the
        // server's own limit.
        for (max, reserved) in [(10, 5), (9, 5), (5, 5), (3, 5), (1, 0), (0, 0)] {
            let slots = slots_from_limits(max, reserved);
            assert!(slots >= 1, "must admit at least one client");
            assert!(
                slots as i64 <= max.max(1),
                "slots_from_limits({max}, {reserved}) = {slots} exceeds max_connections={max}"
            );
        }
    }

    #[tokio::test]
    async fn refused_port_probes_unreachable() {
        // Bind-then-drop to find a port nothing listens on.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // A closed port is the dead-postmaster signal: it refuses immediately.
        // This is the one verdict that may power-cycle, so it must stay exact.
        match probe_pg_window(&pool_at(port), Duration::from_secs(1)).await {
            PgProbe::Unreachable(_) => {}
            PgProbe::Ready => panic!("refused port reported Ready"),
            PgProbe::Responding(m) => panic!("refused port reported Responding: {m}"),
            PgProbe::Stalled(m) => panic!("refused port reported Stalled: {m}"),
        }
    }

    #[tokio::test]
    async fn black_holed_listener_probes_stalled_not_unreachable() {
        // Accepts TCP but never answers. Two very different things share this
        // shape: a tunnel whose far end is dead, and a healthy Postgres too
        // loaded to finish a backend fork inside the probe bound. They are
        // indistinguishable here, so the probe must report the ambiguity
        // (`Stalled`) rather than assert death — `ready_pg` resolves it by
        // waiting out ready_timeout, which only the live server survives.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                std::mem::forget(sock); // hold the socket open, say nothing
            }
        });

        match probe_pg_window(&pool_at(port), Duration::from_secs(1)).await {
            PgProbe::Stalled(_) => {}
            PgProbe::Ready => panic!("black-holed listener reported Ready"),
            PgProbe::Responding(m) => panic!("black-holed listener reported Responding: {m}"),
            PgProbe::Unreachable(m) => {
                panic!(
                    "black-holed listener reported Unreachable ({m}) — this verdict can power-cycle a VM, and an accepted-but-slow connect is exactly what a loaded server looks like"
                )
            }
        }
    }

    /// The regression that motivated `Stalled`: a warm VM that accepts but is
    /// slow must stay in the map. Evicting it drops into a re-init that
    /// power-cycles the VM, killing whatever load made it slow in the first
    /// place.
    #[tokio::test]
    async fn slow_listener_is_not_evicted_from_the_warm_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                std::mem::forget(sock);
            }
        });

        // `entry_alive` keeps the entry for anything that isn't Unreachable.
        assert!(
            !matches!(probe_pg(&pool_at(port)).await, PgProbe::Unreachable(_)),
            "a slow-but-listening VM must not be classified Unreachable"
        );
    }

    /// Spin an in-process daemon stub for `GET /deployed-sandboxes/:id` that
    /// 404s the first `misses` calls and reports `running` after that.
    /// Returns the base URL to point a `Sandbox` at.
    async fn status_stub(misses: usize) -> String {
        use axum::response::IntoResponse;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/deployed-sandboxes/{id}",
            axum::routing::get(move |axum::extract::Path(id): axum::extract::Path<String>| {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < misses {
                        return (
                            axum::http::StatusCode::NOT_FOUND,
                            format!("Sandbox not found: {id}"),
                        )
                            .into_response();
                    }
                    axum::Json(serde_json::json!({
                        "id": id,
                        "status": "running",
                        "status_changed_at": "2026-08-19T00:00:00Z",
                    }))
                    .into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        base
    }

    fn stub_sandbox(base: &str) -> Sandbox {
        Sandbox::connect(
            "sb-test".to_string(),
            HeyoClientOptions {
                base_url: Some(base.to_string()),
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// A sandbox id heyvmd has permanently forgotten (its restart dropped the
    /// in-flight create) must fail fast, not hold the caller — and its
    /// admission slot — for the whole ready timeout.
    #[tokio::test]
    async fn a_sustained_404_ends_the_ready_wait_well_inside_the_timeout() {
        let base = status_stub(usize::MAX).await;
        let sb = stub_sandbox(&base);
        let started = Instant::now();
        let err = wait_ready_within(
            &sb,
            Duration::from_secs(30),
            "pg-x",
            Duration::from_millis(200),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unknown to heyvmd"),
            "the 404 grace, not the deadline, ended the wait: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "gave up after {:?} — should be ~the grace",
            started.elapsed()
        );
    }

    /// The moment after a 202 where the daemon hasn't published the record yet
    /// is normal and must not fail the bring-up.
    #[tokio::test]
    async fn a_brief_404_right_after_the_deploy_is_tolerated() {
        let base = status_stub(3).await;
        let sb = stub_sandbox(&base);
        wait_ready_within(&sb, Duration::from_secs(30), "pg-x", Duration::from_secs(5))
            .await
            .expect("a short 404 window must be ridden out, not treated as a dead id");
    }

    /// Spin an in-process daemon stub that records resize requests and answers
    /// with `status`, returning (base_url, received-request log).
    async fn resize_stub(
        status: axum::http::StatusCode,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>) {
        use axum::extract::Path as AxPath;
        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> = Default::default();
        let log = seen.clone();
        let app = axum::Router::new().route(
            "/sandboxes/{id}/resize",
            axum::routing::post(move |AxPath(id): AxPath<String>, req_body: String| {
                log.lock().unwrap().push((id, req_body));
                async move { (status, body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        (base, seen)
    }

    /// The spare pool is sized for the common case, and the uncommon one must
    /// not quietly borrow from it: a schema whose device had grown needs a
    /// bigger VM than any spare on the shelf.
    #[test]
    fn a_bigger_restore_never_claims_a_default_sized_spare() {
        // The ordinary bring-up: a spare is exactly what it wants.
        assert!(spare_can_serve(2, 2));
        assert!(spare_can_serve(1, 2), "a shrunken schema still fits a default spare");
        // The restore this exists for.
        assert!(!spare_can_serve(4, 2));
        assert!(!spare_can_serve(DAEMON_MAX_DISK_GB, 2));
    }

    #[tokio::test]
    async fn resize_disk_posts_the_daemon_wire_format() {
        let (base, seen) = resize_stub(axum::http::StatusCode::OK, "{}").await;
        resize_disk_at(&base, "sb-abc123", 8).await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        // Exactly the SDK's ResizeDiskRequest shape, addressed to the right VM.
        assert_eq!(seen[0].0, "sb-abc123");
        assert_eq!(seen[0].1, r#"{"disk_size_gb":8}"#);
    }

    /// Spin an in-process daemon stub for the online route; answers every
    /// request with `status` and `body`.
    async fn online_resize_stub(
        status: axum::http::StatusCode,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>) {
        use axum::extract::Path as AxPath;
        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> = Default::default();
        let log = seen.clone();
        let app = axum::Router::new().route(
            "/sandboxes/{id}/resize-online",
            axum::routing::post(move |AxPath(id): AxPath<String>, req_body: String| {
                log.lock().unwrap().push((id, req_body));
                async move { (status, body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, app).into_future());
        (base, seen)
    }

    #[tokio::test]
    async fn resize_disk_online_posts_the_daemon_wire_format() {
        let (base, seen) = online_resize_stub(axum::http::StatusCode::OK, "{}").await;
        let grown = resize_disk_online_at(&base, "sb-abc123", 8).await.unwrap();
        assert!(matches!(grown, OnlineGrow::Grown), "{grown:?}");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "sb-abc123");
        assert_eq!(seen[0].1, r#"{"disk_size_gb":8}"#);
    }

    /// Everything the offline resize can get past falls back to it; only a
    /// request the daemon calls invalid is an error, since offline would
    /// refuse it too.
    #[tokio::test]
    async fn resize_disk_online_falls_back_unless_the_request_is_invalid() {
        use axum::http::StatusCode;
        for (status, body) in [
            (StatusCode::CONFLICT, "sandbox sb-x is not running; resize it offline"),
            (StatusCode::INTERNAL_SERVER_ERROR, "in-guest filesystem grow failed (exit 127)"),
            (StatusCode::NOT_FOUND, "Sandbox not found: sb-x"),
        ] {
            let (base, _) = online_resize_stub(status, body).await;
            match resize_disk_online_at(&base, "sb-x", 8).await.unwrap() {
                OnlineGrow::FallBack(why) => {
                    assert!(why.contains(status.as_str()) && why.contains(body), "{why}")
                }
                other => panic!("{status} must fall back, got {other:?}"),
            }
        }

        let (base, _) = online_resize_stub(
            StatusCode::BAD_REQUEST,
            "workspace disk cannot shrink from 8 to 4 GiB",
        )
        .await;
        let err = resize_disk_online_at(&base, "sb-x", 8).await.unwrap_err().to_string();
        assert!(err.contains("400") && err.contains("cannot shrink"), "{err}");
    }

    /// A daemon that predates the route answers an empty-bodied 404 — the
    /// capability probe. It must read as "resize offline", not as a failure.
    #[tokio::test]
    async fn resize_disk_online_treats_a_missing_route_as_unsupported() {
        // This stub serves only the offline route.
        let (base, _) = resize_stub(axum::http::StatusCode::OK, "{}").await;
        match resize_disk_online_at(&base, "sb-x", 8).await.unwrap() {
            OnlineGrow::FallBack(why) => assert!(why.contains("no online resize route"), "{why}"),
            other => panic!("a missing route must fall back, got {other:?}"),
        }
        // No daemon at all falls back too; the offline call then reports it.
        match resize_disk_online_at("http://127.0.0.1:9", "sb-x", 8).await.unwrap() {
            OnlineGrow::FallBack(why) => assert!(why.contains("request failed"), "{why}"),
            other => panic!("an unreachable daemon must fall back, got {other:?}"),
        }
        let (base, seen) = online_resize_stub(axum::http::StatusCode::OK, "{}").await;
        assert!(resize_disk_online_at(&base, "sb-x", 251).await.is_err());
        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resize_disk_surfaces_daemon_errors_with_body() {
        let (base, _) = resize_stub(
            axum::http::StatusCode::BAD_REQUEST,
            "insufficient host storage for 8 GiB workspace",
        )
        .await;
        let err = resize_disk_at(&base, "sb-x", 8).await.unwrap_err().to_string();
        assert!(err.contains("400"), "status surfaced: {err}");
        assert!(
            err.contains("insufficient host storage"),
            "daemon's own reason surfaced: {err}"
        );
    }

    /// A dedicated database's role must never be able to grow past the one
    /// database it was provisioned for, even from inside its own VM — that is
    /// the guest-side half of the guarantee `dedicated::Credentials::authorize`
    /// makes at the pooler. Pin the attribute set so a future edit can't
    /// quietly hand out CREATEDB or superuser.
    #[test]
    fn dedicated_role_ddl_is_unprivileged_and_quoted() {
        let cred = crate::dedicated::Credential {
            database: "acme".into(),
            role: "acme_app".into(),
            password: "hunter2hunter2".into(),
            created_at: 0,
        };
        let create = role_ddl(&cred, false, false);
        assert!(create.starts_with("CREATE ROLE \"acme_app\" WITH LOGIN "), "{create}");
        for attr in ["NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE"] {
            assert!(create.contains(attr), "{attr} missing from: {create}");
        }
        assert!(create.contains("PASSWORD 'hunter2hunter2'"), "{create}");
        // An existing role is realigned rather than re-created, so a restore
        // into a fresh VM and a plain restart both converge on the same shape.
        assert!(role_ddl(&cred, true, false).starts_with("ALTER ROLE \"acme_app\" WITH LOGIN "));
        // A tenant's role never gets REPLICATION; the separate `<db>_pgfcrepl`
        // login is the only thing that does. A REPLICATION login can create
        // logical slots, and an orphaned slot pins WAL until the data disk
        // fills — an unrecoverable PANIC on this image — so it must stay
        // outside what a leaked tenant password can reach.
        assert!(create.contains(" NOREPLICATION "), "{create}");
        assert!(role_ddl(&cred, false, true).contains(" REPLICATION "));
        assert!(!role_ddl(&cred, false, true).contains("NOREPLICATION"));

        // Quoting: identifiers double their quotes, password literals double
        // theirs. `dedicated`'s validation rejects both shapes, so this is
        // defense in depth against a hand-edited credential file.
        let odd = crate::dedicated::Credential {
            database: "acme".into(),
            role: "we\"ird".into(),
            password: "it's-fine".into(),
            created_at: 0,
        };
        let ddl = role_ddl(&odd, false, false);
        assert!(ddl.contains(r#"ROLE "we""ird" WITH"#), "{ddl}");
        assert!(ddl.contains("PASSWORD 'it''s-fine'"), "{ddl}");
    }

    /// A dedicated database restored from the frozen or S3-dump tier must come
    /// back owned by its tenant role. `--no-owner --no-privileges` would land
    /// every table on the restoring superuser instead, so the tenant would
    /// reconnect to its own database and get "permission denied" on all of it —
    /// data that looks lost. Pin that the flags are dropped exactly for the
    /// dedicated case and kept for every other schema.
    /// A restore job a client is waiting on is probed early and then backs
    /// off — never the flat 10s that rounded every restore up to the next
    /// 10s mark.
    #[test]
    fn client_jobs_poll_fast_then_back_off() {
        for job in [RESTORE_JOB, SCHEMA_COPY_JOB] {
            let mut gaps = vec![job.poll_first];
            for _ in 0..6 {
                gaps.push(next_poll(*gaps.last().unwrap(), job.poll_max));
            }
            let ms: Vec<u128> = gaps.iter().map(|d| d.as_millis()).collect();
            assert_eq!(ms, [250, 500, 1000, 2000, 2000, 2000, 2000], "{}", job.what);
        }
        // The dump keeps its slow cadence: no client waits on it.
        assert_eq!(ARCHIVE_JOB.poll_first, ARCHIVE_POLL_INTERVAL);
        assert_eq!(
            next_poll(ARCHIVE_JOB.poll_first, ARCHIVE_JOB.poll_max),
            ARCHIVE_POLL_INTERVAL
        );
    }

    /// The restore probe carries the job's timing line in the same exec as the
    /// sentinel, still without forking anything.
    #[test]
    fn restore_probe_reads_the_report_with_builtins_only() {
        let dir = std::env::temp_dir().join(format!("pgfc-probe-report-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("empty-path")).unwrap();
        let root = format!("{}/", dir.display());
        let cmd = RESTORE_JOB.probe_command().replace("/workspace/", &root);
        let run = || {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd)
                .env("PATH", dir.join("empty-path"))
                .output()
                .unwrap();
            assert!(
                out.stderr.is_empty(),
                "probe must not shell out: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        let done = dir.join("_restore.done");
        let timing = dir.join("_restore.timing");

        assert!(matches!(parse_probe(&run()), JobState::Running));
        assert_eq!(parse_probe_report(&run()), None);
        // Done, but from a job that left no report: still a success, no report.
        std::fs::write(&done, "0").unwrap();
        let out = run();
        assert!(matches!(parse_probe(&out), JobState::Succeeded), "{out}");
        assert_eq!(parse_probe_report(&out), None);
        // Done with a report.
        std::fs::write(&timing, "stream - 4321 87\n").unwrap();
        let out = run();
        assert!(matches!(parse_probe(&out), JobState::Succeeded), "{out}");
        let report = RestoreReport::parse(&parse_probe_report(&out).unwrap()).unwrap();
        assert_eq!(
            report,
            RestoreReport {
                mode: "stream".into(),
                download: None,
                load: Some(Duration::from_millis(4321)),
                finalize: Some(Duration::from_millis(87)),
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_report_rejects_garbage() {
        for bad in [
            "",
            "stream",
            "stream 1 2",
            "turbo 1 2 3",
            "file x 2 3",
            "file 1 2 -3",
        ] {
            assert_eq!(RestoreReport::parse(bad), None, "{bad:?}");
        }
        let r = RestoreReport::parse("file_after_stream 10 20 -").unwrap();
        assert_eq!(r.download, Some(Duration::from_millis(10)));
        assert_eq!(r.finalize, None);
    }

    /// What one run of the real restore job body did, under stubs.
    struct RestoreRun {
        sentinel: String,
        timing: String,
        /// One line per stubbed command invocation: `<cmd> <args…>`.
        calls: Vec<String>,
        /// Whether `pg_restore` saw the restore-time tuning in place.
        tuned_during_load: bool,
        /// Whether the tuning file was left behind.
        tuning_left: bool,
    }

    /// Run the real restore job body under a real `sh`. Every command it
    /// calls is a stub steered by `env`:
    /// `NPROC`; `CURL_CODE` (HTTP status), `CURL_EXIT`; `PGR_STREAM_EXIT` /
    /// `PGR_FILE_EXIT` (pg_restore reading stdin / a file);
    /// `PSQL_CHECKPOINT_EXIT`.
    fn run_restore_job(tag: &str, fast_load: bool, env: &[(&str, &str)]) -> RestoreRun {
        let dir =
            std::env::temp_dir().join(format!("pgfc-restorejob-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let root = format!("{}/", dir.display());
        let conf = format!("{root}run-pg-fc-restore.conf");
        let body = restore_job_body(
            &shell_squote("postgres"),
            &shell_squote("s"),
            "",
            "https://x/y?X-Amz-Signature=ab&c=d",
            false,
            fast_load,
        )
        .replace(RESTORE_TUNING_CONF, &conf)
        .replace("/workspace/", &root);
        let log = format!("{root}calls");
        let stubs = [
            ("nproc", "#!/bin/sh\necho \"${NPROC:-1}\"\n".to_string()),
            (
                "curl",
                format!(
                    "#!/bin/sh\necho \"curl $*\" >> {log}\n\
                     hdr=; out=; w=\n\
                     while [ $# -gt 0 ]; do case \"$1\" in\n\
                     -D) hdr=$2; shift ;; -o) out=$2; shift ;; -w) w=1 ;; esac; shift; done\n\
                     [ -n \"$hdr\" ] && printf 'HTTP/1.1 %s OK\\r\\n\\r\\n' \"${{CURL_CODE:-200}}\" > \"$hdr\"\n\
                     if [ \"$out\" = - ]; then printf PGDMP; elif [ -n \"$out\" ]; then printf PGDMP > \"$out\"; fi\n\
                     [ -n \"$w\" ] && printf %s \"${{CURL_CODE:-200}}\"\n\
                     exit \"${{CURL_EXIT:-0}}\"\n"
                ),
            ),
            (
                "pg_restore",
                format!(
                    "#!/bin/sh\necho \"pg_restore $*\" >> {log}\n\
                     grep -q 'fsync = off' {conf} 2>/dev/null && touch {root}tuned\n\
                     case \"$*\" in\n\
                     *--single-transaction*) cat > /dev/null; exit \"${{PGR_STREAM_EXIT:-0}}\" ;;\n\
                     *) exit \"${{PGR_FILE_EXIT:-0}}\" ;;\n\
                     esac\n"
                ),
            ),
            (
                "psql",
                format!(
                    "#!/bin/sh\necho \"psql $*\" >> {log}\n\
                     case \"$*\" in *CHECKPOINT*) exit \"${{PSQL_CHECKPOINT_EXIT:-0}}\" ;; esac\n\
                     exit 0\n"
                ),
            ),
            ("sync", "#!/bin/sh\nexit 0\n".to_string()),
        ];
        for (cmd, script) in stubs {
            let p = dir.join("bin").join(cmd);
            std::fs::write(&p, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c")
            .arg(&body)
            .env("PATH", format!("{}/bin:/usr/bin:/bin", dir.display()));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "job body itself must not error: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        let run = RestoreRun {
            sentinel: read("_restore.done"),
            timing: read("_restore.timing").trim().to_string(),
            calls: read("calls").lines().map(str::to_string).collect(),
            tuned_during_load: dir.join("tuned").exists(),
            tuning_left: std::path::Path::new(&conf).exists(),
        };
        // Scratch never outlives the job, whatever happened.
        for scratch in ["_restore.dump", "_restore.curl-ec", "_restore.hdr"] {
            assert!(!dir.join(scratch).exists(), "{tag}: {scratch} left behind");
        }
        let _ = std::fs::remove_dir_all(&dir);
        run
    }

    fn restores(run: &RestoreRun) -> Vec<&String> {
        run.calls
            .iter()
            .filter(|c| c.starts_with("pg_restore"))
            .collect()
    }

    #[test]
    fn a_one_core_guest_streams_the_dump_into_one_transaction() {
        let run = run_restore_job("stream", true, &[("NPROC", "1")]);
        assert_eq!(run.sentinel, "0");
        let r = RestoreReport::parse(&run.timing).unwrap();
        assert_eq!(r.mode, "stream");
        assert_eq!(r.download, None, "a streamed load has no separate download");
        assert!(r.load.is_some() && r.finalize.is_some(), "{}", run.timing);
        let pgr = restores(&run);
        assert_eq!(pgr.len(), 1, "{:?}", run.calls);
        assert!(
            pgr[0].contains("--single-transaction") && !pgr[0].contains(" -j "),
            "{}",
            pgr[0]
        );
        assert!(
            pgr[0].contains("--clean --if-exists --no-owner --no-privileges"),
            "{}",
            pgr[0]
        );
        assert!(
            run.calls
                .iter()
                .any(|c| c.starts_with("curl") && c.contains("-o -"))
        );
        // Tuned for the load, durable before the sentinel, nothing left behind.
        assert!(run.tuned_during_load);
        assert!(!run.tuning_left);
        let psql: Vec<_> = run.calls.iter().filter(|c| c.starts_with("psql")).collect();
        assert_eq!(psql.len(), 3, "reload, reload, checkpoint: {psql:?}");
        assert!(psql[2].contains("CHECKPOINT"), "{psql:?}");
    }

    #[test]
    fn a_multi_core_guest_keeps_the_parallel_file_restore() {
        let run = run_restore_job("file", true, &[("NPROC", "4")]);
        assert_eq!(run.sentinel, "0");
        let r = RestoreReport::parse(&run.timing).unwrap();
        assert_eq!(r.mode, "file");
        assert!(r.download.is_some() && r.load.is_some());
        let pgr = restores(&run);
        assert_eq!(pgr.len(), 1);
        assert!(
            pgr[0].contains("-j 4") && !pgr[0].contains("--single-transaction"),
            "{}",
            pgr[0]
        );
        assert!(run.tuned_during_load && !run.tuning_left);
    }

    /// A stream S3 answered 2xx but `pg_restore` refused (the non-seekable
    /// input case) is retried once from a downloaded file.
    #[test]
    fn a_failed_stream_falls_back_to_a_file_restore() {
        let run = run_restore_job("fallback", true, &[("PGR_STREAM_EXIT", "1")]);
        assert_eq!(run.sentinel, "0", "{:?}", run.calls);
        assert!(
            run.timing.starts_with("file_after_stream "),
            "{}",
            run.timing
        );
        let pgr = restores(&run);
        assert_eq!(pgr.len(), 2, "{:?}", run.calls);
        assert!(pgr[1].contains("-j 1"), "{}", pgr[1]);
        assert!(!run.tuning_left);

        // Both attempts failing is a failed restore, and still untuned after.
        let run = run_restore_job(
            "fallback-fails",
            true,
            &[("PGR_STREAM_EXIT", "1"), ("PGR_FILE_EXIT", "1")],
        );
        assert_ne!(run.sentinel, "0");
        assert!(!run.tuning_left);
        assert!(
            !run.calls.iter().any(|c| c.contains("CHECKPOINT")),
            "a failed restore is never checkpointed as if served: {:?}",
            run.calls
        );
    }

    /// curl dying mid-stream must decide the attempt even when `pg_restore`
    /// happens to accept what arrived — POSIX sh has no pipefail.
    #[test]
    fn a_download_that_dies_mid_stream_is_not_a_restore() {
        // The file retry succeeds once the network does... here it never
        // does, so the restore fails.
        let run = run_restore_job("curl-dies", true, &[("CURL_EXIT", "56")]);
        assert_ne!(run.sentinel, "0", "{:?}", run.calls);
        assert_eq!(
            restores(&run).len(),
            1,
            "the file retry never loads a failed download"
        );
    }

    /// A redirect or rejection is a failed restore with no retry: the second
    /// GET would get the same answer.
    #[test]
    fn a_rejected_stream_is_not_retried() {
        for code in ["301", "403"] {
            let run = run_restore_job(
                &format!("rejected-{code}"),
                true,
                &[("CURL_CODE", code), ("PGR_STREAM_EXIT", "1")],
            );
            assert_ne!(run.sentinel, "0", "HTTP {code}");
            assert_eq!(restores(&run).len(), 1, "HTTP {code}: {:?}", run.calls);
            assert!(run.timing.starts_with("stream "), "{}", run.timing);
        }
        // Even when pg_restore "succeeds" on the error body, the status wins.
        let run = run_restore_job("rejected-200-restore", true, &[("CURL_CODE", "301")]);
        assert_ne!(run.sentinel, "0");
    }

    #[test]
    fn a_failed_checkpoint_is_a_failed_restore() {
        let run = run_restore_job("checkpoint", true, &[("PSQL_CHECKPOINT_EXIT", "2")]);
        assert_eq!(run.sentinel, "2");
        assert!(!run.tuning_left);
    }

    #[test]
    fn fast_load_off_leaves_durability_alone() {
        let run = run_restore_job("untuned", false, &[]);
        assert_eq!(run.sentinel, "0");
        assert!(!run.tuned_during_load);
        assert!(
            !run.calls.iter().any(|c| c.starts_with("psql")),
            "{:?}",
            run.calls
        );
        assert!(
            run.timing.ends_with(" -"),
            "no finalize phase: {}",
            run.timing
        );
    }

    #[test]
    fn restore_keeps_ownership_only_for_a_dedicated_database() {
        let shared = restore_job_body("postgres", "tenant1", "", "http://x/y", false, true);
        assert!(shared.contains("--no-owner --no-privileges"), "{shared}");

        let dedicated = restore_job_body("postgres", "beta", "", "http://x/y", true, true);
        assert!(!dedicated.contains("--no-owner"), "{dedicated}");
        assert!(!dedicated.contains("--no-privileges"), "{dedicated}");
        // Everything else about the invocation is unchanged — notably the
        // idempotent clean that lets an interrupted restore be retried.
        for expected in ["pg_restore -h 127.0.0.1 -U postgres --clean --if-exists", "-d beta"] {
            assert!(dedicated.contains(expected), "{expected} missing from: {dedicated}");
        }
    }

    #[test]
    fn replication_marker_round_trips_through_the_boot_shell_reader() {
        let dir = std::env::temp_dir().join(format!("pgfc-repl-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        for role in ["primary", "replica"] {
            let command = replication_marker_command(Some(role))
                .replace(REPL_MARKER, marker.to_str().unwrap());
            let out = std::process::Command::new("sh").args(["-c", &command]).output().unwrap();
            assert!(out.status.success(), "{:?}", out);
            assert_eq!(std::fs::read(&marker).unwrap(), format!("{role}\n").as_bytes());
            let out = std::process::Command::new("sh")
                .args(["-c", "read -r role < \"$1\" && printf %s \"$role\"", "sh"])
                .arg(&marker).output().unwrap();
            assert!(out.status.success());
            assert_eq!(out.stdout, role.as_bytes());
        }
        let command = replication_marker_command(None).replace(REPL_MARKER, marker.to_str().unwrap());
        assert!(std::process::Command::new("sh").args(["-c", &command]).status().unwrap().success());
        assert!(!marker.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn replication_restart_supplies_role_settings_and_preserves_failures() {
        use std::os::unix::fs::PermissionsExt;
        use crate::replication::Role;
        let dir = std::env::temp_dir().join(format!("pgfc-repl-restart-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in [
            ("gosu", "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PGDATA/args\"\nexit \"$TEST_RC\"\n"),
            ("nproc", "#!/bin/sh\necho 3\n"),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(dir.join("replication-restart.log"), "restart failure detail\n").unwrap();
        for (role, code, expected) in [
            (Some(Role::Primary), 0, "wal_level=logical -c max_wal_senders=10 -c max_replication_slots=10"),
            (Some(Role::Replica), 0, "wal_level=minimal -c max_wal_senders=0 -c max_replication_slots=8"),
            (None, 0, "wal_level=minimal -c max_wal_senders=0 -c max_replication_slots=10"),
            (Some(Role::Primary), 7, "wal_level=logical -c max_wal_senders=10 -c max_replication_slots=10"),
        ] {
            let out = std::process::Command::new("sh")
                .args(["-c", &replication_restart_command(role)])
                .env("PATH", format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()))
                .env("PGDATA", &dir).env("TEST_RC", code.to_string())
                .output().unwrap();
            assert_eq!(out.status.code(), Some(code), "{:?}", out);
            let args = std::fs::read_to_string(dir.join("args")).unwrap();
            assert!(args.contains(&format!("-o\n-c {expected}")), "{args}");
            if role == Some(Role::Replica) {
                assert!(args.contains("max_worker_processes=15"), "{args}");
            }
            if code != 0 {
                assert!(String::from_utf8_lossy(&out.stderr).contains("restart failure detail"));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn quote_ident_escapes_embedded_quotes() {
        assert_eq!(quote_ident("acme"), "\"acme\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }


    /// The calls that go around the SDK carry the daemon's bearer when one is
    /// configured, and nothing when it is not (a keyless `heyvm --api`).
    #[test]
    fn raw_daemon_calls_carry_the_bearer_only_when_configured() {
        let client = reqwest::Client::new();
        let with = super::with_bearer(client.post("http://daemon/sandboxes/x/resize"), Some("k-1"))
            .build()
            .unwrap();
        assert_eq!(with.headers()["authorization"], "Bearer k-1");
        let without = super::with_bearer(client.get("http://daemon/health"), None).build().unwrap();
        assert!(without.headers().get("authorization").is_none());
    }
    #[tokio::test]
    async fn resize_disk_rejects_out_of_range_sizes_without_calling_out() {
        let (base, seen) = resize_stub(axum::http::StatusCode::OK, "{}").await;
        assert!(resize_disk_at(&base, "sb-x", 0).await.is_err());
        assert!(resize_disk_at(&base, "sb-x", 251).await.is_err());
        assert!(
            seen.lock().unwrap().is_empty(),
            "invalid sizes must be rejected before any daemon call"
        );
    }
}

/// The schema-copy job body: stream the primary's *schema* straight into this
/// (already created, empty) database.
///
/// Schema only, never data. The rows come from the subscription's own
/// `copy_data`, which takes them under the replication slot's snapshot and is
/// therefore consistent with the change stream that follows; a `pg_dump` of
/// the data would not be, and would leave a gap or an overlap at the seam.
///
/// Detached for the same reason as [`restore_from_s3`]: a `pg_dump` across a
/// WAN link plus a `psql` replaying it easily outlasts the guest exec
/// channel's hard 30s server-side cap, and the SDK cannot raise it.
///
/// `psql -1 -v ON_ERROR_STOP=1` is deliberate. A *partial* schema is worse
/// than none: the subscription would sync the tables that exist and error
/// forever on the rest, which reads as "replication is broken" rather than
/// "setup failed". One transaction means a failure leaves the database exactly
/// as it was and the job is simply retryable.
///
/// `conninfo` arrives already shell-quoted and already password-free — the
/// password rides `PGPASSWORD` on the launch exec (see
/// [`DetachedJob::launch_with_env`]), so it is in neither this script, which
/// sits on the data disk, nor any argv. The script removes itself before
/// writing its sentinel so the rest of the conninfo does not linger either.
fn schema_copy_job_body(user: &str, db: &str, conninfo: &str) -> String {
    let done = SCHEMA_COPY_JOB.done;
    format!(
        "ec=0\n\
         rm -f {SCHEMA_COPY_FAIL_MARK}\n\
         {{ pg_dump --schema-only --no-publications --no-subscriptions \
         --no-security-labels -d {conninfo} \
         || echo 1 > {SCHEMA_COPY_FAIL_MARK}; }} \
         | psql -h 127.0.0.1 -U {user} -d {db} -v ON_ERROR_STOP=1 -1 -q || ec=$?\n\
         if [ -f {SCHEMA_COPY_FAIL_MARK} ]; then\n\
         \techo 'pg_dump of the primary failed before the stream ended' >&2\n\
         \tec=1\n\
         fi\n\
         rm -f \"$0\"\n\
         printf %s \"$ec\" > {done}.tmp && mv {done}.tmp {done}\n"
    )
}

/// Copy the primary's schema into this replica's (empty) database, and wait
/// for it.
pub(crate) async fn copy_schema_from_primary(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    conninfo: &crate::replication::sql::Conninfo,
    deadline: Duration,
) -> Result<()> {
    let db = shell_squote(schema);
    let user = shell_squote(&cfg.pg_user);
    // Shell-quoted as one argument to `pg_dump -d`, and password-free: libpq
    // parses it as a keyword/value string, and the credential arrives in the
    // environment instead.
    let conn = shell_squote(&conninfo.without_password());
    let mut env = HashMap::new();
    env.insert("PGPASSWORD".to_string(), conninfo.password.clone());

    let job = DetachedJob { deadline, ..SCHEMA_COPY_JOB };
    info!(
        "schema {schema}: copying the schema from the primary at {}",
        conninfo.redacted()
    );
    job.launch_with_env(
        cfg,
        sandbox,
        &schema_copy_job_body(&user, &db, &conn),
        SCHEMA_COPY_JOB.script,
        Some(env),
    )
    .await?;
    await_detached_job(cfg, sandbox, schema, job)
        .await
        .map(|_| ())
}

/// The durable per-VM replication marker `init.sh` reads to decide this
/// cluster's WAL level. On the data disk, not the rootfs and not the kernel
/// cmdline (the SDK exposes no way to set one), so it survives every reboot,
/// resize and restore.
const REPL_MARKER: &str = "/workspace/heyvm-replication";

/// A superuser connection to one *schema's own* database.
///
/// [`SchemaEntry::pool`] is deliberately pinned to `postgres` — it exists to
/// probe readiness and to `CREATE DATABASE` — but publications, subscriptions,
/// grants and every replication status view are per-database objects, so they
/// need their own connection. Built fresh per call rather than pooled: these
/// are operator-paced actions and a monitor tick, not a hot path.
/// Whether `schema`'s database holds any user relation — the SQL answer to
/// the question [`crate::imgarchive::cluster_contents_of`] answers offline,
/// used where a running Postgres is in hand (the dump archive path).
///
/// `None` when the question couldn't be answered at all: an unreachable
/// database is never a reason to call a workbook empty.
pub(crate) async fn has_user_relations(
    cfg: &Config,
    target: &SocketAddr,
    schema: &str,
) -> Option<bool> {
    let ask = async {
        let client = db_client(cfg, target, schema).await.ok()?;
        let row = client
            .query_one(
                "SELECT count(*) FROM pg_class c                  JOIN pg_namespace n ON n.oid = c.relnamespace                  WHERE c.relkind IN ('r', 'p', 'm', 'f')                  AND n.nspname NOT IN ('pg_catalog', 'information_schema')",
                &[],
            )
            .await
            .ok()?;
        let relations: i64 = row.get(0);
        Some(relations > 0)
    };
    tokio::time::timeout(Duration::from_secs(30), ask)
        .await
        .ok()?
}

pub(crate) async fn db_client(
    cfg: &Config,
    target: &SocketAddr,
    dbname: &str,
) -> Result<deadpool_postgres::Object> {
    let pool = build_pool(
        &target.ip().to_string(),
        target.port(),
        dbname,
        &cfg.pg_user,
        cfg.pg_password.as_deref(),
    )?;
    pool.get()
        .await
        .with_context(|| format!("connecting to database {dbname} on {target}"))
}

/// Give the replication login the reads it needs. `pg_read_all_data` is a
/// predefined role (PG 14+); the schema `USAGE` grant is what makes those
/// tables reachable by name. Both are per-database, hence [`db_client`].
async fn grant_repl_reads(
    cfg: &Config,
    target: &SocketAddr,
    schema: &str,
    role: &str,
) -> Result<()> {
    let client = db_client(cfg, target, schema).await?;
    for stmt in crate::replication::sql::grant_repl_reads(role) {
        client
            .batch_execute(&stmt)
            .await
            .with_context(|| format!("granting replication reads to {role} on {schema}"))?;
    }
    Ok(())
}

/// Reconcile this VM's durable replication marker with `want`, and restart
/// Postgres if the running cluster's WAL level doesn't match what the marker
/// now implies.
///
/// # Why a restart, and why it is safe here
///
/// `wal_level` is not SIGHUP-reloadable, so there is no way to raise it
/// without bouncing the postmaster. What makes that cheap on this image is
/// that Postgres is **not** PID 1: `init.sh` backgrounds it and PID 1 `exec`s
/// a shell on the serial console, so `pg_ctl restart` bounces the database
/// without touching the VM, its disk, or the pooler's binding to it. Compared
/// with stopping and starting the VM this skips a full boot and, more
/// importantly, avoids the reclaim-lock and orphan-sweep interactions a stop
/// would drag in.
///
/// Idempotent, and deliberately cheap in the common case: a VM with no
/// pairing and a cluster already at `minimal` costs one `SHOW`.
async fn ensure_replication_mode(
    cfg: &Config,
    sandbox: &Sandbox,
    pool: &Pool,
    schema: &str,
    want: Option<crate::replication::Role>,
) -> Result<()> {
    // What the running cluster is actually at, which is the only thing worth
    // reconciling against — the marker says what the NEXT start will do.
    let client = pool.get().await.context("checkout for wal_level check")?;
    let settings = client
        .query_one(
            "SELECT current_setting('wal_level'), current_setting('max_wal_senders')::int4, \
             current_setting('max_replication_slots')::int4",
            &[],
        )
        .await
        .context("reading replication settings")?;
    let have: String = settings.get(0);
    let senders: i32 = settings.get(1);
    let slots: i32 = settings.get(2);
    drop(client);
    let (want_level, want_senders, want_slots) = replication_settings(want);

    write_replication_marker(cfg, sandbox, schema, want.map(|r| r.as_str())).await?;

    // A subscriber can already be at minimal WAL while lacking the slots
    // needed for replication origins. Compare the complete role settings.
    if have == want_level && senders == want_senders && slots == want_slots {
        return Ok(());
    }
    info!(
        "schema {schema}: wal_level is {have}, replication needs {want_level} — \
         restarting Postgres in-guest"
    );
    // init.sh consumes the marker only on a VM boot. A postmaster-only
    // restart must supply the same settings explicitly; otherwise it reloads
    // the old tuning file. Command-line settings also override stale manual
    // ALTER SYSTEM values without rewriting unrelated operator configuration.
    let restart = replication_restart_command(want);
    let res = exec_guest(cfg, sandbox, &restart, false, "restarting Postgres").await?;
    if res.exit_code != 0 {
        bail!(
            "restarting Postgres in schema {schema}'s VM failed (exit {}): {}",
            res.exit_code,
            truncate(exec_detail(&res), 400)
        );
    }
    // The restart is only believed once the postmaster answers again AND
    // reports the level we asked for: `pg_ctl` returning 0 says the process
    // started, not that it started with this configuration (a bad tuning file
    // would leave it at the old level, or down).
    match probe_pg_window(pool, PG_RESTART_WINDOW).await {
        PgProbe::Ready => {}
        other => bail!(
            "schema {schema}: Postgres did not come back after the replication restart: {}",
            match other {
                PgProbe::Responding(e) => format!("still starting up ({e})"),
                PgProbe::Stalled(e) => format!("no answer within {PG_RESTART_WINDOW:?} ({e})"),
                PgProbe::Unreachable(e) => format!("nothing listening ({e})"),
                PgProbe::Ready => unreachable!(),
            }
        ),
    }
    let client = pool.get().await.context("checkout after restart")?;
    let settings = client
        .query_one(
            "SELECT current_setting('wal_level'), current_setting('max_wal_senders')::int4, \
             current_setting('max_replication_slots')::int4",
            &[],
        )
        .await
        .context("re-reading replication settings")?;
    let now: String = settings.get(0);
    if now != want_level || settings.get::<_, i32>(1) != want_senders
        || settings.get::<_, i32>(2) != want_slots
    {
        bail!(
            "schema {schema}: Postgres restarted but replication settings do not match \
             the requested role (wal_level={now}, expected {want_level})"
        );
    }
    info!("schema {schema}: wal_level is now {now}");
    Ok(())
}

fn replication_settings(role: Option<crate::replication::Role>) -> (&'static str, i32, i32) {
    match role {
        Some(crate::replication::Role::Primary) => ("logical", 10, 10),
        Some(crate::replication::Role::Replica) => ("minimal", 0, 8),
        None => ("minimal", 0, 10),
    }
}

fn replication_restart_command(role: Option<crate::replication::Role>) -> String {
    let (level, senders, slots) = replication_settings(role);
    let workers = if role == Some(crate::replication::Role::Replica) {
        " -c max_logical_replication_workers=4 -c max_sync_workers_per_subscription=2 \
         -c max_worker_processes=$(( $(nproc) + 12 ))"
    } else {
        ""
    };
    format!(
        "for pgbin in /usr/lib/postgresql/*/bin; do \
           [ ! -d \"$pgbin\" ] || export PATH=\"$pgbin:$PATH\"; done; \
         PGDATA=\"${{PGDATA:-/workspace/pgdata}}\"; \
         if gosu postgres pg_ctl -D \"$PGDATA\" -m fast -w -t 60 \
           -l \"$PGDATA/replication-restart.log\" \
           -o \"-c wal_level={level} -c max_wal_senders={senders} -c max_replication_slots={slots}{workers}\" restart; \
         then :; else rc=$?; tail -c 2000 \"$PGDATA/replication-restart.log\" >&2; exit \"$rc\"; fi"
    )
}

fn replication_marker_command(role: Option<&str>) -> String {
    match role {
        Some(r) => format!(
            "printf '%s\\n' {} > {REPL_MARKER}.tmp && mv {REPL_MARKER}.tmp {REPL_MARKER} && sync && echo ok",
            shell_squote(r)
        ),
        None => format!("rm -f {REPL_MARKER} {REPL_MARKER}.tmp && sync && echo ok"),
    }
}

/// Plant or remove [`REPL_MARKER`] on the data disk.
///
/// Written temp-then-rename and `sync`ed for exactly the reason `init.sh`'s
/// `heal_line` documents: the pooler stops VMs with an unclean kill, and ext4
/// delayed allocation can leave an un-fsynced write as NUL bytes. A marker
/// eaten that way would boot the VM back at `wal_level = minimal` with a live
/// subscriber still attached — the failure that reports itself only as a
/// replica falling quietly behind.
///
/// One short foreground exec: a `printf`, a rename and a `sync`, trivially
/// inside the guest exec channel's hard 30s cap.
async fn write_replication_marker(
    cfg: &Config,
    sandbox: &Sandbox,
    schema: &str,
    role: Option<&str>,
) -> Result<()> {
    let cmd = replication_marker_command(role);
    let res = exec_guest(cfg, sandbox, &cmd, false, "writing the replication marker").await?;
    if res.exit_code != 0 {
        bail!(
            "schema {schema}: writing {REPL_MARKER} failed (exit {}): {}",
            res.exit_code,
            truncate(exec_detail(&res), 400)
        );
    }
    Ok(())
}

/// `CREATE DATABASE` has no `IF NOT EXISTS`, so check the catalog first. The
/// schema name is client-supplied — it's already validated in main, and we
/// double-quote-escape it here as defense in depth (identifiers can't be bound
/// as parameters).
///
/// `owner` is set for a *dedicated* database ([`crate::dedicated`]): its login
/// role is created (or brought back in line) first and the database is created
/// owned by it, so the tenant's own credential can create schemas and tables
/// in it. Run on **every** bring-up rather than only at provisioning time,
/// because it has to be idempotent anyway and because a restore from the
/// frozen or archived tier materializes a *fresh* cluster — `pg_dump` of a
/// single database carries no roles, so without this the restored VM would
/// have the data but no role able to log into it.
///
/// `repl_login` is the separate `REPLICATION` role a replica uses to reach
/// this primary. Re-applied on every bring-up for exactly the same reason as
/// the owner role, and kept distinct from it deliberately — see [`role_ddl`].
async fn ensure_database(
    pool: &Pool,
    schema: &str,
    owner: Option<&crate::dedicated::Credential>,
    repl_login: Option<&crate::dedicated::Credential>,
) -> Result<()> {
    let client = pool.get().await.context("checkout for db bootstrap")?;
    if let Some(cred) = owner {
        ensure_role(&client, cred, false).await?;
    }
    if let Some(cred) = repl_login {
        ensure_role(&client, cred, true).await?;
    }
    let exists = client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&schema])
        .await
        .context("checking pg_database")?
        .is_some();
    let quoted = quote_ident(schema);
    if !exists {
        let owned = match owner {
            Some(cred) => format!(" OWNER {}", quote_ident(&cred.role)),
            None => String::new(),
        };
        client
            .batch_execute(&format!("CREATE DATABASE {quoted}{owned}"))
            .await
            .with_context(|| format!("creating database {schema}"))?;
        info!("created database {schema}");
    } else if let Some(cred) = owner {
        // The database predates its credential (provisioned over an existing
        // schema VM) or was recreated by a restore under the bootstrap role.
        // Ownership is what gives the tenant role CREATE on the database and,
        // through `pg_database_owner`, on its `public` schema — so reconcile
        // it rather than leaving a database its own role cannot write to.
        let owned_by_role = client
            .query_opt(
                "SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba \
                 WHERE d.datname = $1 AND r.rolname = $2",
                &[&schema, &cred.role],
            )
            .await
            .context("checking database ownership")?
            .is_some();
        if !owned_by_role {
            client
                .batch_execute(&format!(
                    "ALTER DATABASE {quoted} OWNER TO {}",
                    quote_ident(&cred.role)
                ))
                .await
                .with_context(|| {
                    format!("giving role {} ownership of database {schema}", cred.role)
                })?;
            info!("database {schema}: owner set to {}", cred.role);
        }
    }
    Ok(())
}

/// Create (or re-align) the login role behind a dedicated database.
///
/// Deliberately unprivileged — `NOSUPERUSER NOCREATEDB NOCREATEROLE` — so the
/// credential can't grow past the one database it was provisioned for even
/// inside its own VM. Ownership of that database (granted by the caller) is
/// what gives it full control of its own data. Note that `NOSUPERUSER` also
/// keeps it away from `COPY ... FROM PROGRAM` and `pg_read_file`, which the
/// pooler's own bootstrap role uses and which would otherwise expose the
/// guest's presigned-URL restore scripts.
///
/// The password is re-applied on every bring-up so the guest role always
/// matches the record the pooler authenticates against — belt-and-braces,
/// since the pg-fc image's `pg_hba.conf` is `trust` and the pooler is the layer
/// that actually checks it.
async fn ensure_role(
    client: &deadpool_postgres::Object,
    cred: &crate::dedicated::Credential,
    replication: bool,
) -> Result<()> {
    let exists = client
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&cred.role])
        .await
        .context("checking pg_roles")?
        .is_some();
    client
        .batch_execute(&role_ddl(cred, exists, replication))
        .await
        .with_context(|| format!("provisioning role {}", cred.role))?;
    if !exists {
        info!(
            "created role {} for dedicated database {}",
            cred.role, cred.database
        );
    }
    Ok(())
}

/// The `CREATE`/`ALTER ROLE` statement behind a dedicated database. Split out
/// from [`ensure_role`] so the attribute set — the thing that decides how much
/// the credential can do inside its own VM — and the quoting are testable
/// without a live server.
fn role_ddl(cred: &crate::dedicated::Credential, exists: bool, replication: bool) -> String {
    let verb = if exists { "ALTER" } else { "CREATE" };
    // `REPLICATION` is set only for the `<db>_pgfcrepl` login a replica uses
    // to reach this primary — never for a tenant's own role. It lets a login
    // create logical slots, and an orphaned slot pins WAL until the data disk
    // fills, which on this image is an unrecoverable cluster-wide PANIC. That
    // has to stay outside what a leaked tenant password can reach, which is
    // what the rest of this attribute list is for.
    let repl = if replication { "REPLICATION " } else { "NOREPLICATION " };
    let literal = cred.password.replace('\'', "''");
    format!(
        "{verb} ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE {repl}PASSWORD '{literal}'",
        quote_ident(&cred.role)
    )
}

/// Double-quote a Postgres identifier, escaping any embedded quote. Identifiers
/// can't be bound as query parameters, so every interpolated name goes through
/// here.
fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
