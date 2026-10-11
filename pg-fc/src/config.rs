//! Runtime configuration, sourced from the environment with sensible defaults.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use heyo_sdk::SandboxSize;

/// Default for [`Config::idle_timeout_fast`]: a VM the pooler can bring back in
/// well under a second does not earn a multi-minute warm hold. 60s still
/// absorbs the common "client reconnects between statements" pattern while
/// cutting the standing warm fleet — and every VM it stops is one the reclaim
/// and offload ladders can finally work on.
const DEFAULT_IDLE_TIMEOUT_FAST: Duration = Duration::from_secs(60);

/// Default for [`Config::idle_drain_window`]: the minimum time in which the
/// idle reaper may stop the whole live fleet. Ten minutes is long enough that
/// a fleet-wide expiry reads as a ramp on a chart (and on the host's disk and
/// CPU) rather than a cliff, and short enough that a cohort's stragglers are
/// not left running for an hour past their budget.
const DEFAULT_IDLE_DRAIN_WINDOW: Duration = Duration::from_secs(600);

/// Default for [`Config::fast_bringup`]. Deliberately far above a healthy
/// restart (~0.2–1s) and far below a create or a thaw (tens of seconds to
/// minutes), so it separates the two populations without needing to be tuned.
const DEFAULT_FAST_BRINGUP: Duration = Duration::from_secs(5);

/// Default [`Config::client_statement_timeout`]: the 2 minutes Platform's code
/// assumes every server gives it (its RDS databases do), raising it per
/// session around the operations it knows run longer.
const DEFAULT_CLIENT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct Config {
    /// Where the pooler listens for Postgres clients.
    pub listen_addr: SocketAddr,
    /// Firecracker image name to boot per schema (`heyvm mvm build --name pg`).
    pub image: String,
    /// VM resource tier for every schema's VM (same tier for all of them —
    /// there's no per-schema override). `Micro` (the default) is 1 vCPU
    /// throttled to 0.25 core and 512MB memory; see heyo's `SizeClass` for
    /// the full tier table. Env `PG_VM_POOL_SIZE_CLASS`.
    pub size_class: SandboxSize,
    /// Postgres role the pooler uses for the readiness probe + bootstrap. With
    /// the pg-fc image's `trust` host auth this needs no password.
    pub pg_user: String,
    /// Password for [`Self::pg_user`], and — doing double duty — the password
    /// the pooler itself requires from clients before proxying them anywhere.
    /// `None` (unset) means both: no client auth gate (any client that reaches
    /// `listen_addr` is proxied straight through) and the pg-fc image's
    /// `trust` host auth for the probe. Set it whenever the pooler is
    /// reachable beyond localhost (see [`Self::listen_addr`]) — the backend
    /// VM's own Postgres can stay on `trust`, since this is the layer meant to
    /// gate access instead. Sent in the clear absent client TLS, so pair it
    /// with [`Self::tls_cert`]/[`Self::tls_key`] on any non-loopback listener.
    pub pg_password: Option<String>,
    /// Inactivity timeout: a non-keep-alive VM is stopped after this long with
    /// no open client connections. `None` disables idle reaping (VMs stay up
    /// until manually stopped). The pooler tracks connections and owns this —
    /// the daemon's own TTL can't, since it's absolute from VM boot and the
    /// daemon doesn't see connections. Keep-alive schemas are exempt.
    pub idle_timeout: Option<Duration>,
    /// The *short* inactivity timeout, applied to a VM the pooler measured as
    /// cheap to bring back — see [`Self::fast_bringup`]. `None` disables the
    /// two-speed reaper (every VM waits out [`Self::idle_timeout`]).
    ///
    /// Why two timeouts at all: [`Self::idle_timeout`] is really a bet on the
    /// *next* bring-up. Keeping a VM warm buys the next client whatever that
    /// bring-up would have cost, and for a schema whose VM still exists on
    /// disk that is a daemon `start()` plus a Postgres restart — a fraction of
    /// a second on a healthy host, against the ~40s create+`initdb` the same
    /// number has to cover for a schema being built from scratch. One timeout
    /// for both means the cheap case is priced like the expensive one, and the
    /// fleet fills up with running VMs nobody is using: RAM held, and disks
    /// the reclaim and offload ladders cannot touch (both need the VM stopped).
    ///
    /// Clamped to `<= idle_timeout` at parse time — a "fast" timeout longer
    /// than the normal one would silently keep VMs up *longer* than the
    /// operator's own setting.
    ///
    /// Env `PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS` (default 60); `0` disables.
    pub idle_timeout_fast: Option<Duration>,
    /// How fast a bring-up has to have been for its VM to be reaped on
    /// [`Self::idle_timeout_fast`] instead of [`Self::idle_timeout`].
    ///
    /// Measured, not assumed — the entry records what its own bring-up
    /// actually cost (everything after the admission queue: resolve/boot,
    /// Postgres readiness, database setup), and the reaper compares that. A
    /// warm restart on an idle host lands ~0.2–1s; a create, a spare claim
    /// that still has to `initdb`, or any thaw lands far above this.
    ///
    /// The point of measuring rather than keying on "was this VM already on
    /// disk" is the loaded host. When heyvmd is saturated, a restart that
    /// normally takes 200ms takes seconds — and that is exactly when a short
    /// timeout would be most harmful, churning stop/start work into a daemon
    /// already behind. Pricing the timeout off the observed cost backs the
    /// reaper off automatically, with no extra knob.
    ///
    /// Env `PG_VM_POOL_FAST_BRINGUP_SECS` (default 5).
    pub fast_bringup: Duration,
    /// The shortest time in which the idle reaper may stop the *entire* live
    /// fleet — the knob that turns a synchronized expiry into a slope.
    ///
    /// Idle reaping is deadline-driven, so a workload that arrives in a burst
    /// goes idle in a burst and every one of its VMs comes due inside the same
    /// few seconds (the per-schema jitter is ±15%, which on a 60s budget is a
    /// spread of only ~18s). Left to run flat out, the reaper answers that by
    /// stopping hundreds of VMs a minute: the fleet falls off a cliff, the
    /// disks all get trimmed at once, and the schemas all come back cold
    /// together. That is the sawtooth.
    ///
    /// This bounds the *rate of change* instead. Each pass may stop at most
    /// `live_schemas × tick / window` VMs (clamped to
    /// [`crate::registry`]'s per-pass floor and ceiling), so however
    /// synchronized the expiry, the fleet drains along a straight line of
    /// known gradient. Sized off the live-tier schema count rather than the
    /// warm count because stopping a VM does not change its tier: the divisor
    /// holds still while a cohort drains, which is what keeps the slope
    /// constant instead of decaying into a long tail.
    ///
    /// The trade is explicit: in a large synchronized expiry a VM can stop
    /// well after its own idle budget. That lateness is bounded by this
    /// window, and it buys a fleet that does not swing.
    ///
    /// `None` disables the rate limit — every pass may stop up to the flat
    /// per-pass ceiling, which is the pre-window behavior.
    ///
    /// Env `PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS` (default 600); `0` disables.
    pub idle_drain_window: Option<Duration>,
    /// How long to wait for a VM (and then Postgres) to become ready.
    pub ready_timeout: Duration,
    /// Cap on the iroh tunnel handshake (`expose_tcp` + `P2pTunnel::connect`).
    /// These have no internal timeout, so when iroh's relays churn (e.g. the
    /// host IP flapping on WiFi → "Local IP no longer valid") a bring-up can
    /// block for minutes. Bounding it lets the pooler fail fast and the client
    /// retry, instead of hanging past what the app tolerates. Much shorter than
    /// `ready_timeout` on purpose.
    pub connect_timeout: Duration,
    /// How long a client waits for a free connection slot on its schema's VM
    /// before the pooler gives up and errors it.
    ///
    /// The pooler splices 1:1, so the guest's `max_connections` would
    /// otherwise be enforced by Postgres as a hard `FATAL: too many clients`
    /// on the (N+1)th client. Queueing here turns that into backpressure. Env
    /// `PG_VM_POOL_ADMIT_TIMEOUT_SECS`; `0` disables the wait (fail
    /// immediately when full).
    pub admit_timeout: Duration,
    /// Session-default `statement_timeout` for client sessions, injected into
    /// the StartupMessage the pooler replays upstream as `options=-c
    /// statement_timeout=<ms>` (see [`crate::startup::with_default_option`]).
    /// Guests otherwise run with no statement timeout at all, so one runaway
    /// query holds a backend, its locks and its I/O until the VM stops. Scoped
    /// to client sessions on purpose: the pooler's own maintenance connections
    /// (probes, CREATE DATABASE, CHECKPOINT, dumps, restores, replication
    /// setup) dial the guest directly and never carry it. A client can still
    /// `SET statement_timeout` per session, and `RESET` returns to this value.
    /// Env `PG_VM_POOL_CLIENT_STATEMENT_TIMEOUT_SECS`; default 120, `0` (None)
    /// leaves the guest's own setting alone.
    pub client_statement_timeout: Option<Duration>,
    /// Size (GiB) of the per-schema persistent data disk attached at
    /// `/dev/vdb` and mounted at `/workspace` (where `PGDATA` lives). This is
    /// what makes a schema's data survive a VM stop/start/restart — without it
    /// the VM falls back to the ephemeral rootfs.
    pub data_disk_gb: u32,
    /// Schemas whose VM should be pinned as a permanent keep-alive: exempt from
    /// idle reaping. For a DB under constant access that shouldn't churn through
    /// stop/restart. Others are subject to [`Self::idle_timeout`].
    pub keepalive_schemas: HashSet<String>,
    /// When true (the default), dial the VM's Postgres directly at its host-
    /// reachable `guest_ip` and skip the iroh tunnel — valid only when the
    /// pooler shares the host with the VMs (the local-daemon deployment). Set
    /// `PG_VM_POOL_DIRECT_CONNECT=0` to force the tunnel path (e.g. if the
    /// pooler ever runs on a different machine than the VMs). Falls back to a
    /// tunnel automatically if the daemon reports no `guest_ip`.
    pub direct_connect: bool,
    /// Where the `schema → sandbox-id` map is persisted so the pooler reattaches
    /// to the right VM (by id) after a restart instead of creating a duplicate
    /// with a fresh data disk. Env `PG_VM_POOL_STATE_FILE`.
    pub state_file: PathBuf,
    /// Where dedicated-database credentials (`database → role + password`)
    /// persist. These are the provisioned databases whose clients authenticate
    /// with their own password instead of [`Self::pg_password`] and may open
    /// only the one database they were created for — see [`crate::dedicated`].
    /// Holds cleartext passwords, so it is written `0600`. Env
    /// `PG_VM_POOL_DEDICATED_FILE`; defaults to `dedicated.tsv` next to the
    /// state file.
    pub dedicated_file: PathBuf,
    /// Where the trusted-peer records live — another pg-fc node's dashboard
    /// URL, its Basic-auth credentials, and the pooler address a guest on
    /// *this* host dials to reach it. Holds another node's admin password, so
    /// it is written `0600`. Env `PG_VM_POOL_PEERS_FILE`; defaults to
    /// `peers.tsv` next to the state file. See [`crate::peers`].
    pub peers_file: PathBuf,
    /// Where replication pairings persist (`database → role + peer + state`).
    /// Loaded regardless of whether [`Self::replication`] is enabled: this
    /// file holds the pin that keeps a replicating VM off the idle reaper and
    /// the offload ladder, and dropping that because a flag was turned off
    /// would break live pairings silently. Env `PG_VM_POOL_REPLICATION_FILE`;
    /// defaults to `replication.tsv` next to the state file. See
    /// [`crate::replication`].
    pub replication_file: PathBuf,
    /// Cross-host logical replication settings. `None` (the default) hides
    /// the dashboard routes and refuses new pairings; existing records still
    /// load and still pin their VMs.
    pub replication: Option<ReplicationConfig>,
    /// Where the monitoring event metrics keep their daily partition files
    /// (`events-YYYY-MM-DD.tsv`), so the restore/create charts survive
    /// restarts. Env `PG_VM_POOL_METRICS_DIR`; defaults to `metrics/` next to
    /// the state file.
    pub metrics_dir: PathBuf,
    /// Automatic on-demand growth of a VM's data *device* through the
    /// daemon's offline workspace resize. `None` (the default) disables it —
    /// enabled by `PG_VM_POOL_DISK_GROW_PCT`, and requires a heyvmd with the
    /// workspace-resize feature. Pairs with a small
    /// `PG_VM_POOL_DATA_DISK_GB` so VMs start at the minimum and the ceiling
    /// grows with real data instead of being provisioned at the maximum.
    pub disk_grow: Option<DiskGrowConfig>,
    /// TLS certificate chain + private key (PEM) for client-facing TLS. Both
    /// set → the pooler answers the Postgres `SSLRequest` with `S` and speaks
    /// TLS; unset → it declines (`N`) as before. Files are re-read on change,
    /// so an external renewer (certbot) rotating them needs no restart.
    /// Envs `PG_VM_POOL_TLS_CERT` / `PG_VM_POOL_TLS_KEY`.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Admin dashboard settings. `dashboard.is_none()` (the default) means the
    /// dashboard is disabled — it's enabled by setting `PG_VM_POOL_DASHBOARD_LISTEN`.
    pub dashboard: Option<DashboardConfig>,
    /// S3 cold-storage (eviction) tier. `None` (the default) disables it. When
    /// `Some`, a background sweep offloads any schema untouched for
    /// [`ArchiveConfig::archive_after`] to S3 and kills its VM to reclaim disk;
    /// the next connect restores it. Enabled by `PG_VM_POOL_ARCHIVE_AFTER_SECS`.
    pub archive: Option<ArchiveConfig>,
    /// Image-level archive fallback: when a schema cannot be archived
    /// logically (its Postgres won't boot or won't dump), stream its stopped
    /// VM's raw `data.ext4` — zstd-compressed — to S3 instead, with no boot
    /// required. `None` (the default) disables it — enabled by
    /// `PG_VM_POOL_IMAGE_ARCHIVE=1`; requires both the S3 tier and
    /// [`Self::run_dir`] (soft-disabled with a warning otherwise).
    pub image_archive: Option<ImageArchiveConfig>,
    /// Local "frozen" tier: dump long-idle schemas to a local file and delete
    /// their VM entirely, so a cold schema costs dump-file bytes (~1-5MB)
    /// instead of a filesystem image. `None` (default) disables it — enabled
    /// by `PG_VM_POOL_FREEZE_AFTER_SECS`. Sits between the idle reaper (stops
    /// the VM, keeps the disk) and the S3 tier (offloads off-host).
    pub freeze: Option<FreezeConfig>,
    /// Local dump store location + server bind, shared by the frozen tier and
    /// the S3 archive tier's streamed dumps. Always parsed (cheap, pure
    /// defaults); the server only runs when freeze or archive is enabled.
    pub dump_net: DumpNetConfig,
    /// Local compacted tier: stopped schemas kept as trimmed zstd images
    /// instead of full ext4 disks. `None` (default) disables it — enabled by
    /// `PG_VM_POOL_COMPACT_AFTER_SECS`; needs the run dir.
    pub compact: Option<CompactConfig>,
    /// How many warm-spare VMs (pre-booted, initdb done, parked empty) to keep
    /// ready for claiming, so a cold bring-up — notably a restore from S3 —
    /// skips create + boot + initdb. `0` (default) disables the pool. Each
    /// spare holds its size class's RAM while parked. Env
    /// `PG_VM_POOL_WARM_SPARES` (capped at 16).
    pub warm_spares: usize,
    /// How many of the spare VMs to keep deliberately **stopped**, reserved as
    /// image-restore vehicles. An image restore overwrites its vehicle's data
    /// disk wholesale, so it needs a stopped sandbox, not a running one —
    /// handing it a booted warm spare means stopping the VM the pool just
    /// booted and waiting for Firecracker to release the disk, ~4.8s of the
    /// ~6.9s a compacted-image thaw used to take. A chilled spare skips both:
    /// the restore writes the disk and starts the VM once.
    ///
    /// Stopped VMs hold no RAM, so these do not compete with `warm_spares` for
    /// memory — they cost one thin data disk each. Env
    /// `PG_VM_POOL_CHILLED_VEHICLES`, default 2, forced to 0 when the spare
    /// pool is off (there is no replenisher to maintain them).
    pub chilled_vehicles: usize,
    /// Automatic disk-slack reclamation: periodically offline-trim stopped VMs'
    /// sparse data disks so freed guest blocks return to the host (Firecracker's
    /// virtio-blk has no discard passthrough, so they never come back on their
    /// own). `None` (the default) disables it — enabled by `PG_VM_POOL_RECLAIM_CMD`.
    pub reclaim: Option<ReclaimConfig>,
    /// The heyvmd run dir (e.g. `/workbooks/heyvm/run`), under which each VM
    /// owns an `sb-<id>/` directory holding its `data.ext4`. Used only to
    /// *verify* that killing a VM actually removed its disk: after a successful
    /// `kill()`, the pooler checks that `run_dir/sb-<id>` is gone, so a daemon
    /// that drops the sandbox record but leaves the directory (stranding the
    /// disk) is caught in the log instead of silently leaking storage. `None`
    /// (the default) leaves that removal unverified. Env `PG_VM_POOL_RUN_DIR`;
    /// falls back to `PG_VM_POOL_PRESSURE_PATH` when that points at the run dir.
    pub run_dir: Option<PathBuf>,
    /// How often to sweep the run dir for **orphaned** VM disk directories: an
    /// `sb-<id>/` whose sandbox heyvmd no longer knows about (a kill the daemon
    /// acked but didn't act on, leaving the disk behind). The sweep deletes only
    /// directories the daemon confirms gone (per-id 404) that are also not held
    /// open and belong to an offloaded/unreferenced schema — never a `live`
    /// schema's disk. `None` (the default) disables it. Requires [`Self::run_dir`];
    /// set without it, it stays off with a warning. Env
    /// `PG_VM_POOL_ORPHAN_SWEEP_SECS`.
    pub orphan_sweep: Option<Duration>,
    /// How many offload jobs the pacer may run concurrently. `1` (the
    /// default) preserves the classic one-schema-at-a-time pacing; higher
    /// values let no-boot offloads (compact/promote) overlap. Dispatch is
    /// still gated on client backpressure, host load
    /// ([`Self::offload_load_max`]), and at most ONE VM-booting job
    /// (archive/freeze) at a time — those share the bring-up gate with
    /// clients. Env `PG_VM_POOL_OFFLOAD_WORKERS` (clamped to 1..=16).
    pub offload_workers: usize,
    /// Normalized host load (1-minute loadavg / online cores) at or above
    /// which the dispatcher stops adding offload jobs beyond the first.
    /// Linux load counts uninterruptible-I/O tasks too, so this backs off
    /// under disk saturation as well as CPU. Env
    /// `PG_VM_POOL_OFFLOAD_LOAD_MAX` (default 0.75).
    pub offload_load_max: f64,
    /// How long the pacer may be held off by *client* backpressure before it
    /// starts dispatching anyway, single-file and no-boot only. `None`
    /// (`PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS=0`) restores the strict
    /// yield-to-every-client behavior.
    ///
    /// Without this the gate is all-or-nothing: on a host whose bring-up queue
    /// is never empty for a whole tick — the steady state once enough schemas
    /// are offloaded, since every cold connect is then a thaw — the pacer
    /// dispatches *nothing* for hours, the disk climbs toward the pressure
    /// high-water mark, and the whole backlog then drains in one burst the
    /// moment the host finally goes quiet. That sawtooth is what this bounds:
    /// past the holdoff the pacer keeps trickling one job at a time until the
    /// host is quiet again, so the same total work is spread across the busy
    /// hours instead of landing against the 85% line.
    ///
    /// Only the client gate is overridable, and only by jobs that boot no VM
    /// (compact / image-archive / promote): those take no bring-up slot, so
    /// nothing a client is queued for moves behind them — they cost host disk
    /// I/O, which the nice-19 children and the single-file cap bound. A
    /// reclaim pass or a running sweep is a real conflict over the same disks,
    /// never politeness, and is never overridden. Env
    /// `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` (default 300).
    pub offload_max_holdoff: Option<Duration>,
}

/// Settings for automatic disk-slack reclamation. Present (`Some`) only when
/// `PG_VM_POOL_RECLAIM_CMD` is set — that env var is the on/off switch.
#[derive(Clone)]
pub struct ReclaimConfig {
    /// Shell command (run via `sh -c`) that offline-trims stopped VMs' data
    /// disks — normally `sudo -n /path/to/reclaim-disks.sh <run-dir>` behind a
    /// NOPASSWD sudoers entry, since loop-setup/mount need root. The script
    /// skips disks a running VM holds open, so invoking it at any time is safe.
    /// Env `PG_VM_POOL_RECLAIM_CMD`.
    pub cmd: String,
    /// How often the periodic run fires. The pooler also triggers an extra run
    /// shortly after the idle reaper stops VMs, so this is a backstop cadence,
    /// not the reclaim latency. Env `PG_VM_POOL_RECLAIM_INTERVAL_SECS`
    /// (default 3600).
    pub interval: Duration,
}

impl ReclaimConfig {
    /// Build the reclaim config from the environment. `None` when
    /// `PG_VM_POOL_RECLAIM_CMD` is unset/empty (reclamation disabled).
    pub fn from_env() -> Option<Self> {
        let cmd = std::env::var("PG_VM_POOL_RECLAIM_CMD")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let interval = std::env::var("PG_VM_POOL_RECLAIM_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(3600));
        Some(Self { cmd, interval })
    }
}

/// Settings for the optional S3 eviction tier. Present (`Some`) only when
/// `PG_VM_POOL_ARCHIVE_AFTER_SECS` is a positive number — that env var is the
/// on/off switch. When on, the S3 bucket and credentials are required (a
/// half-configured tier fails fast, mirroring the TLS/dashboard pairings).
#[derive(Clone)]
pub struct ArchiveConfig {
    /// A non-keepalive schema untouched (no client connections) for at least
    /// this long is dumped to S3 and its VM killed. This is the slow, disk-
    /// reclaiming tier that sits *below* [`Config::idle_timeout`] (which only
    /// stops the VM). Env `PG_VM_POOL_ARCHIVE_AFTER_SECS`.
    pub archive_after: Duration,
    /// How often the archive sweep scans for eviction candidates. Env
    /// `PG_VM_POOL_ARCHIVE_SWEEP_SECS` (default 3600).
    pub sweep_interval: Duration,
    /// Emergency disk-pressure eviction. `None` (default) disables it —
    /// enabled by `PG_VM_POOL_PRESSURE_PATH`.
    pub pressure: Option<PressureConfig>,
    /// S3 addressing + credentials the pooler uses to presign the guest's
    /// dump upload / restore download.
    pub s3: crate::s3::S3Config,
}

/// Settings for the local "frozen" tier. Present (`Some`) only when
/// `PG_VM_POOL_FREEZE_AFTER_SECS` is a positive number.
#[derive(Clone)]
pub struct FreezeConfig {
    /// A non-keepalive schema untouched this long is dumped to a local file
    /// and its VM killed; the next connect restores it (onto a warm spare when
    /// the pool is enabled). Env `PG_VM_POOL_FREEZE_AFTER_SECS`.
    pub freeze_after: Duration,
    /// How often the freeze sweep scans for candidates. Env
    /// `PG_VM_POOL_FREEZE_SWEEP_SECS` (default 900).
    pub sweep_interval: Duration,
    /// Where local dump files live. Env `PG_VM_POOL_DUMP_DIR`
    /// (default `~/.heyo/pg-vm-pool/dumps`).
    pub dump_dir: PathBuf,
    /// Where the local dump HTTP server listens. Guests reach it at their
    /// default gateway (the host side of their tap), so this must bind an
    /// address reachable from the VM bridge — the default binds all
    /// interfaces. Access is token-gated per operation. Env
    /// `PG_VM_POOL_DUMP_LISTEN` (default `0.0.0.0:6433`).
    pub listen: SocketAddr,
}

impl FreezeConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let freeze_after = match std::env::var("PG_VM_POOL_FREEZE_AFTER_SECS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) | Err(_) => return Ok(None),
                Ok(secs) => Duration::from_secs(secs),
            },
            Err(_) => return Ok(None),
        };
        let sweep_interval = std::env::var("PG_VM_POOL_FREEZE_SWEEP_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(900));
        let net = DumpNetConfig::from_env()?;
        Ok(Some(Self {
            freeze_after,
            sweep_interval,
            dump_dir: net.dump_dir,
            listen: net.listen,
        }))
    }
}

/// Where the local dump store lives and where its HTTP server listens. Parsed
/// independently of the frozen tier because two consumers share the server:
/// freeze/thaw, and the S3 archive tier's *streamed* dumps (the guest pipes
impl Config {
    /// Create and write-probe every configured offload output directory, so a
    /// bad path or root-owned parent fails startup with a named fix instead of
    /// degrading at job time. The degradation is expensive and quiet: an
    /// unwritable compact dir fails every compact into backoff, the picker
    /// falls back to BOOT-based dump archiving, the dump then fails too (dump
    /// dir), and the image fallback rescues it — after paying a boot that
    /// inflates (rootfs clone + swapfile + WAL) the very disk the offload was
    /// meant to drain.
    pub fn preflight_offload_dirs(&self) -> anyhow::Result<()> {
        let mut dirs: Vec<(&str, &std::path::Path)> = Vec::new();
        // The dump server's landing dir carries both the frozen tier and the
        // S3 tier's streamed dumps — probe it whenever either consumer is on.
        if self.freeze.is_some() || self.archive.is_some() {
            dirs.push(("dump dir (PG_VM_POOL_DUMP_DIR)", &self.dump_net.dump_dir));
        }
        if let Some(c) = &self.compact {
            dirs.push(("compact dir (PG_VM_POOL_COMPACT_DIR)", &c.compact_dir));
        }
        if let Some(i) = &self.image_archive {
            dirs.push(("image spool dir (PG_VM_POOL_IMAGE_SPOOL_DIR)", &i.spool_dir));
        }
        for (what, dir) in dirs {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!(
                    "{what}: cannot create {}: {e} — if the parent is root-owned, create                      it owned by the pooler's user: sudo install -d -o $(id -un) -g $(id -gn) {}",
                    dir.display(),
                    dir.display()
                )
            })?;
            let probe = dir.join(".pg-vm-pool-write-probe");
            std::fs::write(&probe, b"probe")
                .and_then(|_| std::fs::remove_file(&probe))
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{what}: {} exists but is not writable by this process: {e} —                          likely created with sudo and root-owned; fix:                          sudo chown $(id -un):$(id -gn) {}",
                        dir.display(),
                        dir.display()
                    )
                })?;
        }
        Ok(())
    }
}

/// `pg_dump` to this server so the archive never touches its own data disk;
/// the pooler then uploads the landed file to S3). Always present on `Config`;
/// the server itself runs only when a consumer is enabled.
#[derive(Clone)]
pub struct DumpNetConfig {
    /// Env `PG_VM_POOL_DUMP_DIR` (default `~/.heyo/pg-vm-pool/dumps`).
    pub dump_dir: PathBuf,
    /// Env `PG_VM_POOL_DUMP_LISTEN` (default `0.0.0.0:6433`) — must be
    /// reachable from the VM bridge (guests dial it at their gateway).
    pub listen: SocketAddr,
}

impl DumpNetConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let dump_dir = std::env::var("PG_VM_POOL_DUMP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".heyo/pg-vm-pool/dumps")
            });
        let listen = std::env::var("PG_VM_POOL_DUMP_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:6433".to_string());
        let listen: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid PG_VM_POOL_DUMP_LISTEN {listen:?}: {e}"))?;
        Ok(Self { dump_dir, listen })
    }
}

/// Settings for the local *compacted* tier: a schema whose VM has sat stopped
/// past `compact_after` has its data disk trimmed, zstd-compressed into
/// `compact_dir`, and the VM + disk deleted. Unlike the frozen tier this
/// never boots the VM (no pg_dump — the disk is imaged as-is, the same
/// pipeline as the S3 image archive but kept local), and thawing is a
/// decompress + boot rather than a pg_restore. Measured on real pool disks:
/// ~26x smaller than the untrimmed ext4, seconds each way.
#[derive(Clone)]
pub struct CompactConfig {
    /// Idle time after which a stopped schema is compacted. Env
    /// `PG_VM_POOL_COMPACT_AFTER_SECS` — setting it (> 0) is the switch.
    pub compact_after: Duration,
    /// Sweep cadence. Env `PG_VM_POOL_COMPACT_SWEEP_SECS` (default 900).
    pub sweep_interval: Duration,
    /// Where `<schema>.img.zst` files live. Env `PG_VM_POOL_COMPACT_DIR`
    /// (default `compact/` next to the state file).
    pub compact_dir: PathBuf,
}

impl CompactConfig {
    fn from_env(state_file: &std::path::Path) -> anyhow::Result<Option<Self>> {
        let compact_after = match std::env::var("PG_VM_POOL_COMPACT_AFTER_SECS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) | Err(_) => return Ok(None),
                Ok(secs) => Duration::from_secs(secs),
            },
            Err(_) => return Ok(None),
        };
        let sweep_interval = std::env::var("PG_VM_POOL_COMPACT_SWEEP_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(900));
        let compact_dir = std::env::var("PG_VM_POOL_COMPACT_DIR")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                state_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("compact")
            });
        Ok(Some(Self {
            compact_after,
            sweep_interval,
            compact_dir,
        }))
    }

    /// A schema's compact-file path (mirrors `DumpServer::dump_path`).
    pub fn compact_path(&self, schema: &str) -> PathBuf {
        self.compact_dir.join(format!("{schema}.img.zst"))
    }
}

/// Settings for the image-level archive fallback (see `Config::image_archive`).
#[derive(Clone)]
pub struct ImageArchiveConfig {
    /// Where the compressed image is spooled before upload (so the PUT has a
    /// known length and the file is integrity-checked before any bytes leave
    /// the box). Needs roughly the disk's *allocated* size free — compressed
    /// images are smaller, the allocated size is just the safe bound checked
    /// up front. Env `PG_VM_POOL_IMAGE_SPOOL_DIR`; defaults to `spool/` next
    /// to the state file.
    pub spool_dir: PathBuf,
}

impl ImageArchiveConfig {
    /// `Ok(None)` when `PG_VM_POOL_IMAGE_ARCHIVE` is unset/falsy. The archive
    /// tier and run-dir requirements are checked by the caller (`from_env`),
    /// which has both in hand.
    fn from_env(state_file: &std::path::Path) -> Option<Self> {
        let on = std::env::var("PG_VM_POOL_IMAGE_ARCHIVE")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if !on {
            return None;
        }
        let spool_dir = std::env::var("PG_VM_POOL_IMAGE_SPOOL_DIR")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                state_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("spool")
            });
        Some(Self { spool_dir })
    }
}

/// Default for `PG_VM_POOL_DISK_GROW_URGENT_PCT` — see
/// [`DiskGrowConfig::urgent_pct`]. High on purpose: this path costs live
/// sessions, so it is a last resort ahead of `No space left on device`, not a
/// second routine trigger.
const DEFAULT_DISK_GROW_URGENT_PCT: f64 = 95.0;

/// Settings for automatic data-device growth (see `Config::disk_grow`).
#[derive(Clone, Copy)]
pub struct DiskGrowConfig {
    /// Guest-filesystem used% at or above which the device is grown at the
    /// next idle stop. Env `PG_VM_POOL_DISK_GROW_PCT` — setting it (> 0) is
    /// the on/off switch; sensible range 50–95.
    pub pct: f64,
    /// Guest-filesystem used% at or above which a **warm** VM's device is
    /// grown without waiting for it to go idle — online under the running VM
    /// when the daemon supports it, else stop, resize, start, dropping
    /// whatever sessions it had.
    ///
    /// Why a second, higher threshold rather than reusing [`Self::pct`]: the
    /// idle-stop grow is free (the VM is stopping anyway), so it can afford to
    /// fire early. The offline fallback costs every live session on the
    /// schema, so the default fires late — only once the filesystem is
    /// genuinely at the wall. Where every host's heyvmd has the online resize
    /// route, that cost is gone and this can be lowered (70–80) to grow early.
    ///
    /// Without it a schema under continuous write load can never grow at all.
    /// The guest's own watcher extends the filesystem *inside* the device and
    /// then exits ("filesystem spans $DATA_DEV; watcher done"); past that only
    /// a host-side device resize helps, the resize was offline-only, and the
    /// one trigger for it was an idle stop that a busy schema never reaches.
    /// The database wedges on `No space left on device` and stays wedged until
    /// its traffic happens to pause for a whole idle timeout.
    ///
    /// Env `PG_VM_POOL_DISK_GROW_URGENT_PCT` (default 95); `0` disables the
    /// online path, restoring idle-stop-only growth. Never below
    /// [`Self::pct`] — a lower value would preempt the free path with the
    /// expensive one.
    pub urgent_pct: Option<f64>,
    /// Ceiling the device is never grown past, in GiB. Env
    /// `PG_VM_POOL_DISK_MAX_GB` (default 100; the daemon caps at 250).
    pub max_gb: u64,
}

impl DiskGrowConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let pct = match std::env::var("PG_VM_POOL_DISK_GROW_PCT") {
            Ok(v) => match v.trim().parse::<f64>() {
                Ok(p) if p > 0.0 => p,
                Ok(_) => return Ok(None),
                Err(_) => anyhow::bail!("invalid PG_VM_POOL_DISK_GROW_PCT: {v:?}"),
            },
            Err(_) => return Ok(None),
        };
        anyhow::ensure!(
            (1.0..=99.0).contains(&pct),
            "PG_VM_POOL_DISK_GROW_PCT ({pct}) must be within 1–99"
        );
        let max_gb = std::env::var("PG_VM_POOL_DISK_MAX_GB")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(100);
        anyhow::ensure!(
            (1..=250).contains(&max_gb),
            "PG_VM_POOL_DISK_MAX_GB ({max_gb}) must be within 1–250 (daemon limit)"
        );
        let urgent_pct = match std::env::var("PG_VM_POOL_DISK_GROW_URGENT_PCT") {
            Ok(v) => match v.trim().parse::<f64>() {
                Ok(p) if p > 0.0 => Some(p),
                // An explicit 0 is the documented off switch, not an error.
                Ok(_) => None,
                Err(_) => anyhow::bail!("invalid PG_VM_POOL_DISK_GROW_URGENT_PCT: {v:?}"),
            },
            Err(_) => Some(DEFAULT_DISK_GROW_URGENT_PCT),
        };
        if let Some(u) = urgent_pct {
            anyhow::ensure!(
                (1.0..=99.0).contains(&u),
                "PG_VM_POOL_DISK_GROW_URGENT_PCT ({u}) must be within 1–99"
            );
            anyhow::ensure!(
                u >= pct,
                "PG_VM_POOL_DISK_GROW_URGENT_PCT ({u}) must be >= \
                 PG_VM_POOL_DISK_GROW_PCT ({pct}) — the urgent path stops a live VM and \
                 drops its sessions, so it must never fire before the free idle-stop grow"
            );
        }
        Ok(Some(Self {
            pct,
            urgent_pct,
            max_gb,
        }))
    }
}

/// Settings for emergency disk-pressure eviction: when the VM-disk filesystem
/// crosses a high-water mark, the pooler archives the *oldest-idle* schemas to
/// S3 — ignoring `archive_after`; pressure overrides the TTL — until usage
/// drops below the low-water mark. The backstop that keeps a filling disk from
/// becoming the `No space left on device` outage where nothing (VM creates,
/// Postgres, the dumps themselves) works anymore.
#[derive(Clone)]
pub struct PressureConfig {
    /// Path on the filesystem holding the VM disks (the heyvmd run dir, e.g.
    /// `/workbooks/heyvm/run`). Its filesystem's usage is what's watched. Env
    /// `PG_VM_POOL_PRESSURE_PATH` — setting it is the on/off switch.
    pub path: PathBuf,
    /// Usage percentage at/above which emergency eviction starts. Env
    /// `PG_VM_POOL_PRESSURE_HIGH_PCT` (default 85).
    pub high_pct: f64,
    /// Usage percentage below which it stops. Env
    /// `PG_VM_POOL_PRESSURE_LOW_PCT` (default 75).
    pub low_pct: f64,
    /// How often usage is checked. Env `PG_VM_POOL_PRESSURE_CHECK_SECS`
    /// (default 60).
    pub check_interval: Duration,
}

impl PressureConfig {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Some(path) = std::env::var("PG_VM_POOL_PRESSURE_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
        else {
            return Ok(None);
        };
        let pct = |key: &str, default: f64| -> anyhow::Result<f64> {
            match std::env::var(key) {
                Ok(v) => v
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|p| (1.0..=99.0).contains(p))
                    .ok_or_else(|| anyhow::anyhow!("invalid {key} {v:?}: expected 1-99")),
                Err(_) => Ok(default),
            }
        };
        let high_pct = pct("PG_VM_POOL_PRESSURE_HIGH_PCT", 85.0)?;
        let low_pct = pct("PG_VM_POOL_PRESSURE_LOW_PCT", 75.0)?;
        if low_pct >= high_pct {
            anyhow::bail!(
                "PG_VM_POOL_PRESSURE_LOW_PCT ({low_pct}) must be below \
                 PG_VM_POOL_PRESSURE_HIGH_PCT ({high_pct})"
            );
        }
        let check_interval = std::env::var("PG_VM_POOL_PRESSURE_CHECK_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(60));
        Ok(Some(Self {
            path: PathBuf::from(path),
            high_pct,
            low_pct,
            check_interval,
        }))
    }
}

/// Settings for cross-host logical replication. Present (`Some`) only when
/// `PG_VM_POOL_REPLICATION` is truthy — that env var is the on/off switch.
///
/// Note what this gates and what it does not. Turning it off hides the
/// dashboard routes and refuses *new* pairings; it deliberately does **not**
/// stop the peers and replication stores from loading, because those hold the
/// pin that keeps an already-replicating VM off the idle reaper and the
/// offload ladder. A feature flag that silently un-pinned live pairings would
/// break them on the next restart with nothing in the log to say why.
#[derive(Clone)]
pub struct ReplicationConfig {
    /// This node's name in a peering. Sent in the handshake so a node can
    /// refuse to peer with itself, and used as the subscriber's
    /// `application_name` so it is identifiable in the primary's
    /// `pg_stat_replication`. Env `PG_VM_POOL_NODE_NAME`; defaults to the
    /// hostname.
    pub node_name: String,
    /// Host or IPv4 literal that a *peer's guest VMs* dial to reach this
    /// node's `PG_VM_POOL_LISTEN`. Required before this node can act as a
    /// replication primary, and deliberately separate from `listen_addr`,
    /// which is frequently `0.0.0.0` or a private address that means nothing
    /// to another host. Env `PG_VM_POOL_ADVERTISE_PG_HOST`.
    pub advertise_host: Option<String>,
    /// The port that goes with it. Env `PG_VM_POOL_ADVERTISE_PG_PORT`;
    /// defaults to `PG_VM_POOL_LISTEN`'s port.
    pub advertise_port: u16,
    /// libpq `sslmode` for the replication link. `require` by default:
    /// it encrypts the one hop that leaves the host. It does not
    /// *authenticate* the server — `verify-full` cannot work against a bare
    /// IP, and the guests carry no pinned CA.
    pub sslmode: String,
    /// Permit an `sslmode` weaker than `require`, and permit acting as a
    /// primary with no TLS configured. Lab escape hatch; off by default,
    /// because the replication login's password crosses the network on this
    /// link. Env `PG_VM_POOL_REPL_ALLOW_INSECURE`.
    pub allow_insecure: bool,
    /// Per-request bound on any call to a peer's dashboard API. Env
    /// `PG_VM_POOL_REPL_PEER_TIMEOUT_SECS` (default 20).
    pub peer_timeout: Duration,
    /// Bound on the in-guest schema-copy job. This is a `pg_dump` across a WAN
    /// link plus a `psql` replaying it, so it is sized like the archive
    /// deadline rather than like an exec. Env `PG_VM_POOL_REPL_SETUP_SECS`
    /// (default 3600).
    pub setup_deadline: Duration,
    /// How often the background sampler refreshes each pairing's lag and
    /// health. `None` (`0`) disables it — the dashboard then shows only what
    /// a page load fetches. Env `PG_VM_POOL_REPL_MONITOR_SECS` (default 60).
    pub monitor_interval: Option<Duration>,
    /// How long a replication slot may sit inactive before the monitor says
    /// so loudly. An inactive slot pins WAL on the primary's data disk, and a
    /// full data disk is a cluster-wide PANIC — this is the warning before
    /// the guest's own `max_slot_wal_keep_size` invalidates the slot. Env
    /// `PG_VM_POOL_REPL_SLOT_STALE_SECS` (default 3600).
    pub slot_stale: Duration,
    /// Retained-WAL figure above which a pairing is reported as lagging. Env
    /// `PG_VM_POOL_REPL_LAG_WARN_BYTES` (default 256MiB).
    pub lag_warn_bytes: u64,
    /// Re-seed column-owned sequences during a promote. Logical replication
    /// carries no sequence values, so without this the first insert after a
    /// promote collides with a replicated row. Env
    /// `PG_VM_POOL_REPL_FIX_SEQUENCES` (default on).
    pub fix_sequences: bool,
}

impl ReplicationConfig {
    fn from_env(listen_addr: SocketAddr) -> anyhow::Result<Option<Self>> {
        let on = std::env::var("PG_VM_POOL_REPLICATION")
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false" | "no"))
            .unwrap_or(false);
        if !on {
            return Ok(None);
        }
        let node_name = std::env::var("PG_VM_POOL_NODE_NAME")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(default_node_name);
        // The name is embedded in replication slot names, which are narrower
        // than Postgres identifiers — refuse a bad one at startup rather than
        // at the first pairing.
        crate::dedicated::validate_identifier(&node_name, "node name")?;

        let advertise_host = std::env::var("PG_VM_POOL_ADVERTISE_PG_HOST")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let advertise_port = match std::env::var("PG_VM_POOL_ADVERTISE_PG_PORT") {
            Ok(v) => v
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("PG_VM_POOL_ADVERTISE_PG_PORT must be a port number"))?,
            Err(_) => listen_addr.port(),
        };
        let allow_insecure = std::env::var("PG_VM_POOL_REPL_ALLOW_INSECURE")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
            .unwrap_or(false);
        let sslmode = std::env::var("PG_VM_POOL_REPL_SSLMODE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "require".to_string());
        const WEAK: &[&str] = &["disable", "allow", "prefer"];
        if WEAK.contains(&sslmode.as_str()) && !allow_insecure {
            anyhow::bail!(
                "PG_VM_POOL_REPL_SSLMODE={sslmode} would send the replication login's \
                 password across the network in cleartext; use `require` (or set \
                 PG_VM_POOL_REPL_ALLOW_INSECURE=1 if both nodes share a trusted link)"
            );
        }
        const VALID: &[&str] = &[
            "disable", "allow", "prefer", "require", "verify-ca", "verify-full",
        ];
        if !VALID.contains(&sslmode.as_str()) {
            anyhow::bail!("PG_VM_POOL_REPL_SSLMODE={sslmode} is not a libpq sslmode");
        }

        let secs = |name: &str, default: u64| -> u64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        let monitor = secs("PG_VM_POOL_REPL_MONITOR_SECS", 60);
        Ok(Some(Self {
            node_name,
            advertise_host,
            advertise_port,
            sslmode,
            allow_insecure,
            peer_timeout: Duration::from_secs(secs("PG_VM_POOL_REPL_PEER_TIMEOUT_SECS", 20).max(1)),
            setup_deadline: Duration::from_secs(secs("PG_VM_POOL_REPL_SETUP_SECS", 3600).max(60)),
            monitor_interval: (monitor > 0).then(|| Duration::from_secs(monitor.max(5))),
            slot_stale: Duration::from_secs(secs("PG_VM_POOL_REPL_SLOT_STALE_SECS", 3600).max(60)),
            lag_warn_bytes: std::env::var("PG_VM_POOL_REPL_LAG_WARN_BYTES")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(256 * 1024 * 1024),
            fix_sequences: std::env::var("PG_VM_POOL_REPL_FIX_SEQUENCES")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
        }))
    }
}

/// The machine's hostname, lowercased and with anything outside the
/// identifier charset mapped to `_`, so the default node name is usable in a
/// replication slot without the operator having to think about it.
fn default_node_name() -> String {
    let raw = std::fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    let cleaned: String = raw
        .trim()
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Must start with a lowercase letter to pass `validate_identifier`.
    match cleaned.chars().next() {
        Some(c) if c.is_ascii_lowercase() => cleaned,
        Some(_) => format!("node_{cleaned}"),
        None => "node".to_string(),
    }
}

/// Settings for the optional server-side-rendered admin dashboard. Present
/// (`Some`) only when `PG_VM_POOL_DASHBOARD_LISTEN` is set — that env var is the
/// on/off switch.
#[derive(Clone)]
pub struct DashboardConfig {
    /// Where the dashboard's HTTP server listens. Prefer a loopback/private
    /// address; pair a public bind with basic auth. Env `PG_VM_POOL_DASHBOARD_LISTEN`.
    pub listen: SocketAddr,
    /// HTTP Basic auth `(user, password)`. `None` disables the auth gate (a
    /// warning is logged when bound non-loopback). Both must be set together.
    /// Envs `PG_VM_POOL_DASHBOARD_USER` / `PG_VM_POOL_DASHBOARD_PASSWORD`.
    pub basic_auth: Option<(String, String)>,
    /// Path to the pooler's own log file (supervisord captures stdout+stderr
    /// here). Env `PG_VM_POOL_POOLER_LOG`.
    pub pooler_log: PathBuf,
    /// Path to heyvmd's log file. Env `PG_VM_POOL_HEYVMD_LOG`.
    pub heyvmd_log: PathBuf,
    /// How many trailing lines to show when tailing a log. Env
    /// `PG_VM_POOL_DASHBOARD_LOG_LINES` (default 200).
    pub log_lines: usize,
    /// Where the monitoring page's webhook alert rules persist. Defaults to a
    /// sibling of the schema registry under the heyo data dir. Env
    /// `PG_VM_POOL_DASHBOARD_ALERTS_FILE`.
    pub alerts_file: PathBuf,
    /// How often the background evaluator samples host metrics and fires any
    /// crossed alerts. Env `PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS` (default 60).
    pub alert_interval: std::time::Duration,
    /// The other pooler dashboards the `/fleet` rollup reads, in display
    /// order. Empty disables nothing: `/fleet` then shows this instance alone.
    /// Env `PG_VM_POOL_DASHBOARD_FLEET` — see [`parse_fleet`].
    pub fleet: Vec<FleetMember>,
    /// What this instance is called in the rollup, and the name a fleet entry
    /// must carry to be recognised as this instance and read in-process
    /// rather than over HTTP — so one fleet list can be shared by every host.
    /// Env `PG_VM_POOL_DASHBOARD_FLEET_NAME` (default `local`).
    pub fleet_name: String,
    /// Per-instance deadline for a rollup's reads. Env
    /// `PG_VM_POOL_DASHBOARD_FLEET_TIMEOUT_SECS` (default 5).
    pub fleet_timeout: std::time::Duration,
}

/// One other pooler dashboard the fleet rollup reads.
#[derive(Clone, PartialEq, Eq)]
pub struct FleetMember {
    pub name: String,
    /// Dashboard base URL, credentials stripped and no trailing slash.
    pub base_url: String,
    /// Basic auth for that dashboard: the URL's own `user:pass@`, else this
    /// dashboard's credentials (a fleet usually shares one login), else none.
    pub basic_auth: Option<(String, String)>,
}

// Hand-written so a `{:?}` in a log line can never print a password.
impl std::fmt::Debug for FleetMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FleetMember")
            .field("name", &self.name)
            .field("base_url", &self.base_url)
            .field(
                "basic_auth",
                &self.basic_auth.as_ref().map(|(u, _)| (u, "<redacted>")),
            )
            .finish()
    }
}

/// Parse `PG_VM_POOL_DASHBOARD_FLEET`: comma-separated `name=url` entries,
/// e.g. `mia1=http://10.0.0.1:34199,mia3=https://admin:pw@mia3.pool.example`.
///
/// Credentials go in the URL's userinfo (percent-encode a `:`/`@` in them);
/// an entry without them uses `default_auth`, this dashboard's own login. An
/// entry named `self_name` is this instance and is dropped, so the same list
/// can be deployed to every host. Names must be unique and URLs http(s).
pub fn parse_fleet(
    spec: &str,
    self_name: &str,
    default_auth: Option<&(String, String)>,
) -> anyhow::Result<Vec<FleetMember>> {
    let mut out: Vec<FleetMember> = Vec::new();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let Some((name, url)) = entry.split_once('=') else {
            anyhow::bail!(
                "PG_VM_POOL_DASHBOARD_FLEET entry {:?} is not name=url",
                redact_userinfo(entry)
            );
        };
        let name = name.trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            anyhow::bail!(
                "PG_VM_POOL_DASHBOARD_FLEET name {name:?} must be non-empty letters, digits, \
                 '-', '_' or '.'"
            );
        }
        let mut url = reqwest::Url::parse(url.trim()).map_err(|e| {
            anyhow::anyhow!(
                "PG_VM_POOL_DASHBOARD_FLEET url for {name} ({}) is invalid: {e}",
                redact_userinfo(url)
            )
        })?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            anyhow::bail!("PG_VM_POOL_DASHBOARD_FLEET url for {name} must be http(s)://host…");
        }
        let decode = |v: &str| {
            percent_decode(v).map_err(|e| {
                anyhow::anyhow!("PG_VM_POOL_DASHBOARD_FLEET credentials for {name}: {e}")
            })
        };
        let own_auth = match (url.username(), url.password()) {
            ("", None) => None,
            (u, Some(p)) => Some((decode(u)?, decode(p)?)),
            (_, None) => anyhow::bail!(
                "PG_VM_POOL_DASHBOARD_FLEET url for {name} has a user but no password"
            ),
        };
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        if name == self_name {
            continue;
        }
        if out.iter().any(|m| m.name == name) {
            anyhow::bail!("PG_VM_POOL_DASHBOARD_FLEET lists {name} twice");
        }
        out.push(FleetMember {
            name: name.to_string(),
            base_url: url.as_str().trim_end_matches('/').to_string(),
            basic_auth: own_auth.or_else(|| default_auth.cloned()),
        });
    }
    Ok(out)
}

/// `scheme://user:pass@host` → `scheme://***@host`, for error messages.
fn redact_userinfo(s: &str) -> String {
    match (s.find("://"), s.rfind('@')) {
        (Some(i), Some(j)) if j > i => format!("{}***{}", &s[..i + 3], &s[j..]),
        _ => s.to_string(),
    }
}

fn percent_decode(s: &str) -> anyhow::Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).filter(|h| h.len() == 2);
            let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) else {
                anyhow::bail!("bad percent-escape");
            };
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| anyhow::anyhow!("not UTF-8 once decoded"))
}

impl Config {
    /// Whether `schema`'s VM should be a permanent keep-alive (TTL 0).
    pub fn is_keepalive(&self, schema: &str) -> bool {
        self.keepalive_schemas.contains(schema)
    }
}

/// Every env var the pooler reads. `from_env` warns about any other
/// `PG_VM_POOL_*` in the environment: a typo'd name (PG_VM_POOL_SIZE for
/// PG_VM_POOL_SIZE_CLASS) otherwise silently falls back to the default and
/// reads as "the pooler ignored my config".
const KNOWN_VARS: &[&str] = &[
    "PG_VM_POOL_LISTEN",
    "PG_VM_POOL_IMAGE",
    "PG_VM_POOL_SIZE_CLASS",
    "PG_VM_POOL_USER",
    "PG_VM_POOL_PASSWORD",
    "PG_VM_POOL_IDLE_TIMEOUT_SECS",
    "PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS",
    "PG_VM_POOL_FAST_BRINGUP_SECS",
    "PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS",
    "PG_VM_POOL_READY_TIMEOUT_SECS",
    "PG_VM_POOL_CONNECT_TIMEOUT_SECS",
    "PG_VM_POOL_ADMIT_TIMEOUT_SECS",
    "PG_VM_POOL_CLIENT_STATEMENT_TIMEOUT_SECS",
    "PG_VM_POOL_DIRECT_CONNECT",
    "PG_VM_POOL_DATA_DISK_GB",
    "PG_VM_POOL_KEEPALIVE_SCHEMAS",
    "PG_VM_POOL_STATE_FILE",
    "PG_VM_POOL_DEDICATED_FILE",
    "PG_VM_POOL_METRICS_DIR",
    "PG_VM_POOL_DISK_GROW_PCT",
    "PG_VM_POOL_DISK_GROW_URGENT_PCT",
    "PG_VM_POOL_DISK_MAX_GB",
    "PG_VM_POOL_TLS_CERT",
    "PG_VM_POOL_TLS_KEY",
    "PG_VM_POOL_DASHBOARD_LISTEN",
    "PG_VM_POOL_DASHBOARD_USER",
    "PG_VM_POOL_DASHBOARD_PASSWORD",
    "PG_VM_POOL_POOLER_LOG",
    "PG_VM_POOL_HEYVMD_LOG",
    "PG_VM_POOL_DASHBOARD_LOG_LINES",
    "PG_VM_POOL_DASHBOARD_ALERTS_FILE",
    "PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS",
    "PG_VM_POOL_DASHBOARD_FLEET",
    "PG_VM_POOL_DASHBOARD_FLEET_NAME",
    "PG_VM_POOL_DASHBOARD_FLEET_TIMEOUT_SECS",
    "PG_VM_POOL_ARCHIVE_AFTER_SECS",
    "PG_VM_POOL_ARCHIVE_SWEEP_SECS",
    "PG_VM_POOL_IMAGE_ARCHIVE",
    "PG_VM_POOL_IMAGE_SPOOL_DIR",
    "PG_VM_POOL_RECLAIM_CMD",
    "PG_VM_POOL_RECLAIM_INTERVAL_SECS",
    "PG_VM_POOL_RUN_DIR",
    "PG_VM_POOL_ORPHAN_SWEEP_SECS",
    "PG_VM_POOL_OFFLOAD_WORKERS",
    "PG_VM_POOL_OFFLOAD_LOAD_MAX",
    "PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS",
    "PG_VM_POOL_WARM_SPARES",
    "PG_VM_POOL_FREEZE_AFTER_SECS",
    "PG_VM_POOL_FREEZE_SWEEP_SECS",
    "PG_VM_POOL_DUMP_DIR",
    "PG_VM_POOL_DUMP_LISTEN",
    "PG_VM_POOL_PRESSURE_PATH",
    "PG_VM_POOL_PRESSURE_HIGH_PCT",
    "PG_VM_POOL_PRESSURE_LOW_PCT",
    "PG_VM_POOL_PRESSURE_CHECK_SECS",
    "PG_VM_POOL_S3_BUCKET",
    "PG_VM_POOL_S3_PREFIX",
    "PG_VM_POOL_S3_LEGACY_PREFIX",
    "PG_VM_POOL_S3_REGION",
    "PG_VM_POOL_S3_ENDPOINT",
    "PG_VM_POOL_S3_ACCESS_KEY_ID",
    "PG_VM_POOL_S3_SECRET_ACCESS_KEY",
    "PG_VM_POOL_DAEMON_URL",
    "PG_VM_POOL_DAEMON_API_KEY",
    // Read by `CompactConfig::from_env` and `vm.rs`, set by the shipped
    // supervisor conf, but historically missing here — so a correctly
    // configured production host logged five "ignoring unknown env var"
    // warnings at every start.
    "PG_VM_POOL_COMPACT_AFTER_SECS",
    "PG_VM_POOL_COMPACT_SWEEP_SECS",
    "PG_VM_POOL_COMPACT_DIR",
    "PG_VM_POOL_MAX_CONCURRENT_BRINGUPS",
    // Read by `vm.rs`'s admission gate; the first was historically missing
    // here too, so tuning the pending-bring-up cap logged a spurious warning.
    "PG_VM_POOL_MAX_PENDING_BRINGUPS",
    "PG_VM_POOL_ADMISSION_WAIT_SECS",
    "PG_VM_POOL_ARCHIVE_VIA_GUEST",
    // Read lazily by the restore paths (vm.rs, imgarchive.rs).
    "PG_VM_POOL_RESTORE_FAST_LOAD",
    "PG_VM_POOL_RESTORE_GET_CONCURRENCY",
    // Cross-host logical replication (see `crate::replication`).
    "PG_VM_POOL_REPLICATION",
    "PG_VM_POOL_NODE_NAME",
    "PG_VM_POOL_PEERS_FILE",
    "PG_VM_POOL_REPLICATION_FILE",
    "PG_VM_POOL_ADVERTISE_PG_HOST",
    "PG_VM_POOL_ADVERTISE_PG_PORT",
    "PG_VM_POOL_REPL_SSLMODE",
    "PG_VM_POOL_REPL_ALLOW_INSECURE",
    "PG_VM_POOL_REPL_PEER_TIMEOUT_SECS",
    "PG_VM_POOL_REPL_SETUP_SECS",
    "PG_VM_POOL_REPL_MONITOR_SECS",
    "PG_VM_POOL_REPL_SLOT_STALE_SECS",
    "PG_VM_POOL_REPL_LAG_WARN_BYTES",
    "PG_VM_POOL_REPL_FIX_SEQUENCES",
];

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        for (key, _) in std::env::vars() {
            if key.starts_with("PG_VM_POOL_") && !KNOWN_VARS.contains(&key.as_str()) {
                tracing::warn!(
                    "ignoring unknown env var {key} — not a pooler setting \
                     (check the name against the README's config table)"
                );
            }
        }

        let listen =
            std::env::var("PG_VM_POOL_LISTEN").unwrap_or_else(|_| "127.0.0.1:6432".to_string());
        let listen_addr: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid PG_VM_POOL_LISTEN {listen:?}: {e}"))?;

        let image = std::env::var("PG_VM_POOL_IMAGE").unwrap_or_else(|_| "pg".to_string());
        let size_class = match std::env::var("PG_VM_POOL_SIZE_CLASS") {
            Ok(v) => parse_size_class(&v)?,
            Err(_) => SandboxSize::Micro,
        };
        let pg_user = std::env::var("PG_VM_POOL_USER").unwrap_or_else(|_| "postgres".to_string());
        // Optional; unset means no password (trust auth). An empty value is
        // treated as unset so `PG_VM_POOL_PASSWORD=` doesn't force an empty
        // password.
        let pg_password = std::env::var("PG_VM_POOL_PASSWORD")
            .ok()
            .filter(|p| !p.is_empty());
        // Idle timeout in seconds; default 15 min, `0` disables reaping.
        let idle_timeout = match std::env::var("PG_VM_POOL_IDLE_TIMEOUT_SECS") {
            Ok(v) => match v.parse::<u64>() {
                Ok(0) => None,
                Ok(secs) => Some(Duration::from_secs(secs)),
                Err(_) => Some(Duration::from_secs(900)),
            },
            Err(_) => Some(Duration::from_secs(900)),
        };
        // The short timeout for cheap-to-restart VMs; `0` disables the
        // two-speed reaper. Clamped to `idle_timeout` so it can only ever pull
        // a stop *earlier* than the operator's own setting, never push it out.
        let idle_timeout_fast = match std::env::var("PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS") {
            Ok(v) => match v.parse::<u64>() {
                Ok(0) => None,
                Ok(secs) => Some(Duration::from_secs(secs)),
                Err(_) => Some(DEFAULT_IDLE_TIMEOUT_FAST),
            },
            Err(_) => Some(DEFAULT_IDLE_TIMEOUT_FAST),
        }
        .map(|fast| match idle_timeout {
            Some(normal) => fast.min(normal),
            None => fast,
        });
        let idle_drain_window = match std::env::var("PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS") {
            Ok(v) => match v.parse::<u64>() {
                Ok(0) => None,
                Ok(secs) => Some(Duration::from_secs(secs)),
                Err(_) => Some(DEFAULT_IDLE_DRAIN_WINDOW),
            },
            Err(_) => Some(DEFAULT_IDLE_DRAIN_WINDOW),
        };
        let fast_bringup = std::env::var("PG_VM_POOL_FAST_BRINGUP_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_FAST_BRINGUP);
        let ready_secs = std::env::var("PG_VM_POOL_READY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300u64);
        let connect_secs = std::env::var("PG_VM_POOL_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30u64);
        let admit_secs = std::env::var("PG_VM_POOL_ADMIT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30u64);
        // Default 2 minutes, matching what Platform's RDS-backed databases
        // give every session; `0` disables. A malformed value is a startup
        // error rather than a silent fallback: this guards against runaway
        // queries, so a typo must not quietly mean "no guard".
        let client_statement_timeout =
            match std::env::var("PG_VM_POOL_CLIENT_STATEMENT_TIMEOUT_SECS") {
                Ok(v) => match v.trim().parse::<u64>() {
                    Ok(0) => None,
                    Ok(secs) => Some(Duration::from_secs(secs)),
                    Err(_) => anyhow::bail!(
                        "invalid PG_VM_POOL_CLIENT_STATEMENT_TIMEOUT_SECS {v:?}: \
                         expected whole seconds (0 disables)"
                    ),
                },
                Err(_) => Some(DEFAULT_CLIENT_STATEMENT_TIMEOUT),
            };
        let data_disk_gb = std::env::var("PG_VM_POOL_DATA_DISK_GB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2u32);
        // Default on; only "0"/"false"/"no" (case-insensitive) disables it.
        let direct_connect = match std::env::var("PG_VM_POOL_DIRECT_CONNECT") {
            Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"),
            Err(_) => true,
        };
        // Persistent schema→VM map; defaults under the heyo data dir.
        let state_file = std::env::var("PG_VM_POOL_STATE_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".heyo/pg-vm-pool/registry.tsv")
            });
        // Dedicated-database credentials live beside the state file unless
        // pointed elsewhere — same directory, same lifecycle as the registry
        // they key into.
        let dedicated_file = std::env::var("PG_VM_POOL_DEDICATED_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                state_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("dedicated.tsv")
            });
        // Peer and replication records live beside the state file too — same
        // directory, same lifecycle as the registry they key into.
        let sibling = |var: &str, name: &str| -> PathBuf {
            std::env::var(var)
                .ok()
                .filter(|p| !p.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    state_file
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .join(name)
                })
        };
        let peers_file = sibling("PG_VM_POOL_PEERS_FILE", "peers.tsv");
        let replication_file = sibling("PG_VM_POOL_REPLICATION_FILE", "replication.tsv");
        // Daily-partitioned event metrics live beside the state file unless
        // pointed elsewhere.
        let metrics_dir = std::env::var("PG_VM_POOL_METRICS_DIR")
            .ok()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                state_file
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("metrics")
            });
        // TLS cert/key PEM paths; empty treated as unset (like PASSWORD above).
        // Setting only one of the pair is a configuration mistake — fail fast
        // rather than silently serving plaintext.
        let tls_cert = std::env::var("PG_VM_POOL_TLS_CERT")
            .ok()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        let tls_key = std::env::var("PG_VM_POOL_TLS_KEY")
            .ok()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        if tls_cert.is_some() != tls_key.is_some() {
            anyhow::bail!(
                "PG_VM_POOL_TLS_CERT and PG_VM_POOL_TLS_KEY must be set together (or neither)"
            );
        }
        // Comma-separated schema names; blanks/whitespace ignored.
        let keepalive_schemas = std::env::var("PG_VM_POOL_KEEPALIVE_SCHEMAS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let dashboard = DashboardConfig::from_env()?;
        let replication = ReplicationConfig::from_env(listen_addr)?;
        // Acting as a primary means a peer's guests dial this listener, so it
        // has to be reachable and it has to be encrypted — the replication
        // login's password crosses that hop. Both are warnings rather than
        // errors: a node can legitimately run as replica-only, where neither
        // applies, and that is not knowable until a pairing is attempted.
        if let Some(r) = replication.as_ref() {
            if r.advertise_host.is_none() {
                tracing::info!(
                    "replication enabled without PG_VM_POOL_ADVERTISE_PG_HOST — this node \
                     can host replicas but cannot be a primary (a peer's guests would have \
                     no address to dial)"
                );
            }
            if tls_cert.is_none() && !r.allow_insecure {
                tracing::warn!(
                    "replication is enabled but TLS is not (PG_VM_POOL_TLS_CERT/KEY) — a \
                     replica's connection carries its password in cleartext, so acting as a \
                     primary will be refused; set the cert pair or \
                     PG_VM_POOL_REPL_ALLOW_INSECURE=1"
                );
            }
            if listen_addr.ip().is_loopback() && r.advertise_host.is_some() {
                tracing::warn!(
                    "replication advertises {}:{} but PG_VM_POOL_LISTEN is loopback ({}) — \
                     a peer's guests cannot reach it; bind 0.0.0.0",
                    r.advertise_host.as_deref().unwrap_or(""),
                    r.advertise_port,
                    listen_addr
                );
            }
        }
        let archive = ArchiveConfig::from_env()?;
        // Pressure eviction archives to S3, so it's meaningless without the
        // tier — a set path with the tier off is a config mistake, fail fast.
        if archive.is_none()
            && std::env::var("PG_VM_POOL_PRESSURE_PATH")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        {
            anyhow::bail!(
                "PG_VM_POOL_PRESSURE_PATH is set but the S3 eviction tier is not \
                 configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*) — \
                 disk-pressure eviction archives to S3"
            );
        }
        let reclaim = ReclaimConfig::from_env();
        let warm_spares = std::env::var("PG_VM_POOL_WARM_SPARES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        // Zero without a spare pool: the chilled shelf is maintained by the
        // replenisher, so with no replenisher the knob would only promise
        // vehicles nothing ever builds.
        let chilled_vehicles = if warm_spares == 0 {
            0
        } else {
            std::env::var("PG_VM_POOL_CHILLED_VEHICLES")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(2)
        };
        let offload_workers = match std::env::var("PG_VM_POOL_OFFLOAD_WORKERS") {
            Ok(v) => match v.trim().parse::<usize>() {
                Ok(n) => n.clamp(1, 16),
                Err(_) => anyhow::bail!("invalid PG_VM_POOL_OFFLOAD_WORKERS {v:?}: expected 1-16"),
            },
            Err(_) => 1,
        };
        let offload_load_max = match std::env::var("PG_VM_POOL_OFFLOAD_LOAD_MAX") {
            Ok(v) => match v.trim().parse::<f64>() {
                Ok(f) if f > 0.0 => f,
                _ => anyhow::bail!("invalid PG_VM_POOL_OFFLOAD_LOAD_MAX {v:?}: expected > 0"),
            },
            Err(_) => 0.75,
        };
        // `0` is the explicit "never override the client gate" opt-out, not a
        // zero-second holdoff — a holdoff of 0 would dispatch through every
        // waiting client, which is the one thing the gate exists to prevent.
        let offload_max_holdoff = match std::env::var("PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) => None,
                Ok(n) => Some(Duration::from_secs(n)),
                Err(_) => anyhow::bail!(
                    "invalid PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS {v:?}: expected whole seconds \
                     (0 disables)"
                ),
            },
            Err(_) => Some(Duration::from_secs(300)),
        };
        let freeze = FreezeConfig::from_env()?;
        // Explicit run dir, else reuse the pressure path (same directory: the
        // heyvmd run dir holding every VM's sb-<id>/). `None` means kill
        // verification is skipped, never that anything breaks.
        let run_dir = std::env::var("PG_VM_POOL_RUN_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                archive
                    .as_ref()
                    .and_then(|a| a.pressure.as_ref())
                    .map(|p| p.path.clone())
            });
        // Orphan-disk sweep interval; needs the run dir to locate sb-<id>/ dirs.
        let mut orphan_sweep = std::env::var("PG_VM_POOL_ORPHAN_SWEEP_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs);
        if orphan_sweep.is_some() && run_dir.is_none() {
            tracing::warn!(
                "PG_VM_POOL_ORPHAN_SWEEP_SECS is set but no run dir is known \
                 (set PG_VM_POOL_RUN_DIR) — the orphan-disk sweep is disabled"
            );
            orphan_sweep = None;
        }
        // Image archive is a mode of the S3 tier and needs the run dir to
        // find `sb-<id>/data.ext4` — half-configured, it stays off loudly.
        let mut image_archive = ImageArchiveConfig::from_env(&state_file);
        if image_archive.is_some() {
            if archive.is_none() {
                tracing::warn!(
                    "PG_VM_POOL_IMAGE_ARCHIVE is set but the S3 eviction tier is not \
                     configured (set PG_VM_POOL_ARCHIVE_AFTER_SECS + PG_VM_POOL_S3_*) — \
                     image archiving is disabled"
                );
                image_archive = None;
            } else if run_dir.is_none() {
                tracing::warn!(
                    "PG_VM_POOL_IMAGE_ARCHIVE is set but no run dir is known \
                     (set PG_VM_POOL_RUN_DIR) — image archiving is disabled"
                );
                image_archive = None;
            }
        }
        if let (Some(f), Some(a)) = (&freeze, &archive)
            && f.freeze_after >= a.archive_after
        {
            tracing::warn!(
                "PG_VM_POOL_FREEZE_AFTER_SECS ({}s) >= PG_VM_POOL_ARCHIVE_AFTER_SECS ({}s): \
                 schemas will be archived to S3 before they ever freeze locally, so the \
                 frozen tier will not fire",
                f.freeze_after.as_secs(),
                a.archive_after.as_secs()
            );
        }
        // Compacting images a stopped VM's disk in place from the run dir, so
        // like the image archive it is inert without one.
        let mut compact = CompactConfig::from_env(&state_file)?;
        if compact.is_some() && run_dir.is_none() {
            tracing::warn!(
                "PG_VM_POOL_COMPACT_AFTER_SECS is set but no run dir is known \
                 (set PG_VM_POOL_RUN_DIR) — the compacted tier is disabled"
            );
            compact = None;
        }
        if let (Some(c), Some(f)) = (&compact, &freeze)
            && f.freeze_after <= c.compact_after
        {
            tracing::warn!(
                "PG_VM_POOL_FREEZE_AFTER_SECS ({}s) <= PG_VM_POOL_COMPACT_AFTER_SECS ({}s): \
                 the freeze sweep (which boots each VM to pg_dump it) will win the race and \
                 the cheaper compacted tier will rarely fire — prefer compacting first",
                f.freeze_after.as_secs(),
                c.compact_after.as_secs()
            );
        }

        Ok(Self {
            listen_addr,
            image,
            size_class,
            pg_user,
            pg_password,
            idle_timeout,
            idle_timeout_fast,
            fast_bringup,
            idle_drain_window,
            ready_timeout: Duration::from_secs(ready_secs),
            connect_timeout: Duration::from_secs(connect_secs),
            admit_timeout: Duration::from_secs(admit_secs),
            client_statement_timeout,
            data_disk_gb,
            keepalive_schemas,
            direct_connect,
            state_file,
            dedicated_file,
            peers_file,
            replication_file,
            replication,
            metrics_dir,
            disk_grow: DiskGrowConfig::from_env()?,
            tls_cert,
            tls_key,
            dashboard,
            archive,
            image_archive,
            freeze,
            dump_net: DumpNetConfig::from_env()?,
            compact,
            warm_spares,
            chilled_vehicles,
            reclaim,
            run_dir,
            orphan_sweep,
            offload_workers,
            offload_load_max,
            offload_max_holdoff,
        })
    }
}

impl DashboardConfig {
    /// Build the dashboard config from the environment. Returns `Ok(None)` when
    /// `PG_VM_POOL_DASHBOARD_LISTEN` is unset (dashboard disabled). Errors on an
    /// unparseable listen address or a half-set basic-auth credential.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        // Empty string treated as unset, matching the PASSWORD/TLS handling above.
        let Some(listen) = std::env::var("PG_VM_POOL_DASHBOARD_LISTEN")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let listen: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid PG_VM_POOL_DASHBOARD_LISTEN {listen:?}: {e}"))?;

        let user = std::env::var("PG_VM_POOL_DASHBOARD_USER")
            .ok()
            .filter(|s| !s.is_empty());
        let password = std::env::var("PG_VM_POOL_DASHBOARD_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());
        // Half-set credentials are a config mistake: fail fast rather than
        // silently serve unauthenticated (mirrors the TLS cert/key pairing rule).
        let basic_auth = match (user, password) {
            (Some(u), Some(p)) => Some((u, p)),
            (None, None) => None,
            _ => anyhow::bail!(
                "PG_VM_POOL_DASHBOARD_USER and PG_VM_POOL_DASHBOARD_PASSWORD must be \
                 set together (or neither)"
            ),
        };

        let pooler_log = std::env::var("PG_VM_POOL_POOLER_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/log/pg-vm-pool/pg-vm-pool.log"));
        let heyvmd_log = std::env::var("PG_VM_POOL_HEYVMD_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/log/heyvmd/heyvmd.log"));
        let log_lines = std::env::var("PG_VM_POOL_DASHBOARD_LOG_LINES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200usize);
        let alerts_file = std::env::var("PG_VM_POOL_DASHBOARD_ALERTS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".heyo/pg-vm-pool/alerts.tsv")
            });
        let alert_interval = std::env::var("PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or_else(|| std::time::Duration::from_secs(60));

        let fleet_name = std::env::var("PG_VM_POOL_DASHBOARD_FLEET_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "local".to_string());
        let fleet = parse_fleet(
            &std::env::var("PG_VM_POOL_DASHBOARD_FLEET").unwrap_or_default(),
            &fleet_name,
            basic_auth.as_ref(),
        )?;
        let fleet_timeout = std::env::var("PG_VM_POOL_DASHBOARD_FLEET_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s > 0)
            .map(std::time::Duration::from_secs)
            .unwrap_or_else(|| std::time::Duration::from_secs(5));

        Ok(Some(Self {
            listen,
            basic_auth,
            pooler_log,
            heyvmd_log,
            log_lines,
            alerts_file,
            alert_interval,
            fleet,
            fleet_name,
            fleet_timeout,
        }))
    }
}

impl ArchiveConfig {
    /// Build the S3 eviction config from the environment. `Ok(None)` when
    /// `PG_VM_POOL_ARCHIVE_AFTER_SECS` is unset or `0` (tier disabled). When the
    /// tier is on, the bucket and both credentials are required — a partial
    /// config is a mistake, so it fails fast rather than silently never
    /// archiving. Credentials fall back to the standard `AWS_ACCESS_KEY_ID` /
    /// `AWS_SECRET_ACCESS_KEY` when the namespaced vars are unset.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let archive_after = match std::env::var("PG_VM_POOL_ARCHIVE_AFTER_SECS") {
            Ok(v) => match v.trim().parse::<u64>() {
                Ok(0) | Err(_) => return Ok(None),
                Ok(secs) => Duration::from_secs(secs),
            },
            Err(_) => return Ok(None),
        };
        let sweep_interval = std::env::var("PG_VM_POOL_ARCHIVE_SWEEP_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(3600));

        let nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
        let Some(bucket) = nonempty("PG_VM_POOL_S3_BUCKET") else {
            anyhow::bail!(
                "PG_VM_POOL_ARCHIVE_AFTER_SECS is set but PG_VM_POOL_S3_BUCKET is not — \
                 the S3 eviction tier needs a bucket"
            );
        };
        let access_key_id = nonempty("PG_VM_POOL_S3_ACCESS_KEY_ID")
            .or_else(|| nonempty("AWS_ACCESS_KEY_ID"));
        let secret_access_key = nonempty("PG_VM_POOL_S3_SECRET_ACCESS_KEY")
            .or_else(|| nonempty("AWS_SECRET_ACCESS_KEY"));
        let (Some(access_key_id), Some(secret_access_key)) = (access_key_id, secret_access_key)
        else {
            anyhow::bail!(
                "PG_VM_POOL_ARCHIVE_AFTER_SECS is set but S3 credentials are missing — \
                 set PG_VM_POOL_S3_ACCESS_KEY_ID/PG_VM_POOL_S3_SECRET_ACCESS_KEY (or the \
                 standard AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
            );
        };
        let region = nonempty("PG_VM_POOL_S3_REGION").unwrap_or_else(|| "us-east-1".to_string());
        let prefix = std::env::var("PG_VM_POOL_S3_PREFIX")
            .unwrap_or_else(|_| crate::s3::DEFAULT_PREFIX.to_string());
        let legacy_prefix = crate::s3::legacy_prefix_for(
            &prefix,
            std::env::var("PG_VM_POOL_S3_LEGACY_PREFIX").ok(),
        );
        let endpoint = nonempty("PG_VM_POOL_S3_ENDPOINT");

        Ok(Some(Self {
            archive_after,
            sweep_interval,
            pressure: PressureConfig::from_env()?,
            s3: crate::s3::S3Config {
                bucket,
                prefix,
                legacy_prefix,
                region,
                // Filled in on the first HEAD if S3 says the bucket lives
                // somewhere other than `region`.
                discovered_region: Default::default(),
                endpoint,
                access_key_id,
                secret_access_key,
            },
        }))
    }
}

/// Case-insensitive, matching heyo's own CLI parsing convention.
pub(crate) fn parse_size_class(v: &str) -> anyhow::Result<SandboxSize> {
    match v.trim().to_ascii_lowercase().as_str() {
        "micro" => Ok(SandboxSize::Micro),
        "mini" => Ok(SandboxSize::Mini),
        "small" => Ok(SandboxSize::Small),
        "medium" => Ok(SandboxSize::Medium),
        "large" => Ok(SandboxSize::Large),
        other => anyhow::bail!(
            "invalid PG_VM_POOL_SIZE_CLASS {other:?}: expected one of micro, mini, small, medium, large"
        ),
    }
}

#[cfg(test)]
mod fleet_tests {
    use super::*;

    #[test]
    fn parses_entries_strips_credentials_and_skips_self() {
        let own = ("admin".to_string(), "shared".to_string());
        let fleet = parse_fleet(
            " mia1=http://10.0.0.1:34199/ , mia2=http://10.0.0.2:34199,\
             mia3=https://ops:p%40ss%3Aw@mia3.pool.example",
            "mia2",
            Some(&own),
        )
        .unwrap();
        assert_eq!(
            fleet.len(),
            2,
            "mia2 is this instance and is read in-process"
        );
        assert_eq!(fleet[0].name, "mia1");
        assert_eq!(fleet[0].base_url, "http://10.0.0.1:34199");
        assert_eq!(
            fleet[0].basic_auth,
            Some(own.clone()),
            "no userinfo: our own login"
        );
        assert_eq!(fleet[1].base_url, "https://mia3.pool.example");
        assert_eq!(
            fleet[1].basic_auth,
            Some(("ops".to_string(), "p@ss:w".to_string())),
            "userinfo wins, percent-decoded"
        );
        assert!(
            !format!("{fleet:?}").contains("p@ss"),
            "Debug must never print a password"
        );
    }

    #[test]
    fn empty_spec_is_an_empty_fleet() {
        assert!(parse_fleet("", "local", None).unwrap().is_empty());
        assert!(parse_fleet(" , ", "local", None).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_entries_without_echoing_passwords() {
        for bad in [
            "mia1",
            "=http://h",
            "mia 1=http://h",
            "mia1=ftp://h",
            "mia1=not a url",
            "mia1=http://h,mia1=http://g",
            "mia1=http://user@h",
        ] {
            assert!(
                parse_fleet(bad, "local", None).is_err(),
                "{bad:?} should be rejected"
            );
        }
        let err = parse_fleet("mia1 https://u:secret@h", "local", None)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("secret"), "{err}");
    }
}
