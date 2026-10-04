# pg-fc

This repo has two parts that fit together: a **Firecracker build** that
produces a rootfs image booting straight into Postgres, and **pg-vm-pool**, a
connection pooler that runs many of those microVMs behind a single Postgres
endpoint — one VM per schema, created and stopped/restarted on demand. The
Firecracker image is the unit the pooler manages; the pooler is what a real
client actually connects to.

## Monorepo import

Imported from [Heyo-Computer/pg-fc](https://github.com/Heyo-Computer/pg-fc)
at [3168714](https://github.com/Heyo-Computer/pg-fc/commit/3168714ec1c7be2e3e702cb5b062d119cfb39be1)
using `git subtree add --prefix=pg-fc` without `--squash`. All 100 source
commits retain their original IDs, authors, and parent relationships. Before
the import, their file paths are repository-relative (for example `src/vm.rs`,
not `pg-fc/src/vm.rs`). To inspect that history:

```sh
git log 3168714ec1c7be2e3e702cb5b062d119cfb39be1 -- src/vm.rs
```

Merge this import with a **merge commit**, not a squash/rebase or a patch-only
submission, to retain the source history on the monorepo's main branch.
The import does not deploy the pooler, change VM runtimes, or migrate databases.
The accidentally tracked source registry is removed from the imported working
tree; runtime state must come from the configured state directory, never Git.

Unless otherwise noted, commands below run from `pg-fc/`. From the monorepo
root, build with `cargo build --locked --manifest-path pg-fc/Cargo.toml` and
test with `cargo test --locked --manifest-path pg-fc/Cargo.toml`. Linux/KVM is
required for VM integration tests and image builds. Supervisor configurations
are examples with host-specific paths; adapt them before use.

## Prerequisites

Linux only — Firecracker needs KVM, so there's no macOS host support.

**To build the Postgres rootfs image** (`build-rootfs.sh`):

| dependency | why |
|---|---|
| Docker | builds the image from `Dockerfile` before it's flattened |
| `e2fsprogs` (`mkfs.ext4`) | formats the output image |
| root/`sudo` | needed to loopback-mount the image while the container fs is exported into it |

**To run `pg-vm-pool` and boot the VMs it manages:**

| dependency | why |
|---|---|
| Rust (edition 2024 toolchain) | builds `pg-vm-pool` (`cargo build --release`) |
| Firecracker + KVM access (`/dev/kvm`, user in the `kvm` group) | actually boots each per-schema microVM |
| `heyvm` / `heyvmd` (from the sibling `heyo` project) | the VM control plane: `heyvmd` (or `heyvm --api --port 34099`) serves the local sandbox HTTP API pg-vm-pool drives, and the `heyvm` CLI builds the `pg` image (`heyvm mvm build`) |
| `heyo-sdk` crate, `>= 0.1.5` | Rust client for that API; pulled automatically by `cargo build` from crates.io, already pinned in `Cargo.toml` — no separate install needed |

### Host service on systemd

`deploy/pg-fc@.service` runs `/usr/local/bin/pg-vm-pool` using
`/etc/pg-fc/<node>.env`, `/etc/pg-fc/<node>.secrets.env`, and working directory
`/var/lib/pg-fc-<node>`. Create these paths before enabling the instance. Set
`PG_VM_POOL_STATE_FILE` explicitly inside that state directory; the working
directory alone does not override the default registry path. Keep the secrets
file mode `0600`, populated from your secret manager, including `HEYO_API_KEY`
when the host-local heyvm API requires authentication.

Install the unit under `/etc/systemd/system/` and validate it with
`systemd-analyze verify` before reloading systemd and enabling the instance.
It does not install heyvm, provision an image, expose ports, or establish
replication. Leave automatic eviction, orphan sweeping, and disk reclamation
disabled on a shared host until resource ownership is configured.

## Postgres VM

A Firecracker rootfs that boots straight into Postgres, with the data directory
on a separate volume mounted at `/workspace`.

### Files

| file | purpose |
|------|---------|
| `Dockerfile` | Debian + Postgres 16 image; ships `init.sh` as `/init.sh` |
| `Dockerfile.pg18` | Same image built with Postgres 18 (`heyvm mvm build -f Dockerfile.pg18 --name pg18`); a data volume initdb'd by one major can't be opened by the other |
| `init.sh` | PID 1 inside the microVM: mounts pseudo-fs + data volume, init's the cluster, exec's postgres |
| `build-rootfs.sh` | Builds the image and flattens it into a bootable ext4 rootfs |

### Design

Firecracker boots a kernel + a flat rootfs and runs `init=` as PID 1 — there's
no systemd. `init.sh` does the minimal init work and then `exec`s `postgres` so
it inherits PID 1 and gets clean SIGTERM shutdown.

The OS rootfs stays disposable; **all database state lives on `/workspace`**,
which is a second Firecracker drive (`/dev/vdb` by default). On first boot the
volume is formatted ext4 and the cluster is `initdb`'d into
`/workspace/pgdata`; subsequent boots just mount and start.

Both image recipes include `en_US.UTF-8`, so existing clusters initialized
with that locale remain readable after a cold boot. Running `localedef` only
inside a guest is not a durable repair: Firecracker recreates its disposable
rootfs from the catalog image when it boots again. Preserve the PostgreSQL
major version and the separate data disk when updating a database's rootfs.

### Build

`build-rootfs.sh` needs Linux (mkfs.ext4 + loopback mount):

```sh
./build-rootfs.sh pg-rootfs.ext4 2G
```

### Boot

```sh
firecracker --api-sock /tmp/fc.sock   # then configure via the API, or use a config:
```

Key settings:
- `boot-source.boot_args`: include `init=/sbin/init.sh console=ttyS0 reboot=k panic=1`
- `drives`: `vda` = `pg-rootfs.ext4` (root), `vdb` = your persistent data disk
- override the data device with the kernel arg `pgdata_dev=/dev/vdc` if needed

Postgres listens on `0.0.0.0:5432`. Reach it over the VM's tap interface.

## pg-vm-pool (per-schema pooler)

This repo also contains `pg-vm-pool` (`src/`), a connection pooler that fronts
many of these microVMs behind a single Postgres endpoint — **one VM per
schema**. The database name in the client's connection string selects the
schema; the pooler lazily creates/restarts the `pg-<schema>` VM, opens a raw-TCP
iroh tunnel to its Postgres, and splices the connection through.

### Using the pooler

Prereqs: a running local heyvmd (`heyvm --api --port 34099`) with the
`POST /sandboxes/:id/tcp-tunnel` endpoint, `heyo-sdk` ≥ 0.1.5, and the `pg`
image built (`heyvm mvm build --local-only -f Dockerfile --name pg`).

```sh
cargo build --release
target/release/pg-vm-pool       # listens on 127.0.0.1:6432 (PG_VM_POOL_LISTEN)

# The dbname selects (and lazily creates) the VM — one per schema:
psql "host=127.0.0.1 port=6432 user=postgres dbname=tenant1"   # -> VM pg-tenant1
psql "host=127.0.0.1 port=6432 user=postgres dbname=tenant2"   # -> VM pg-tenant2
```

That lazy-create-per-name behavior is the default contract. For credentials you
hand to an application or a customer, provision a **dedicated database**
instead: its own role and password, pinned to exactly one database, unable to
create any more VMs. See "Dedicated databases" below.

First connect to a new schema boots a VM (~2s); reconnects reuse or restart it.
If Postgres dies while its VM stays up (OOM kill, segfault — the VM's PID 1 is
a shell, so the sandbox still reports running), the pooler notices on the next
connect: a short probe distinguishes a dead postmaster (silent port) from one
that's alive but recovering (answers `57P03` during WAL replay), and only the
former triggers an automatic stop/start of the VM — a fresh boot re-runs
`init.sh`, which relaunches Postgres.
Each schema's data lives on its VM's persistent disk and survives stops,
restarts, and idle reaping. Before an idle stop the pooler issues a
`CHECKPOINT` over its warm connection, so the unclean VM kill loses no
acknowledged commits (the VMs run `synchronous_commit=off`) and the next boot
skips WAL replay entirely. The schema→VM binding is persisted in
`PG_VM_POOL_STATE_FILE` (default `~/.heyo/pg-vm-pool/registry.tsv`) so it also
survives pooler restarts.

The pooler splices 1:1, so it admits at most `max_connections` minus the
guest's reserved superuser slots and its own housekeeping pool; past that,
clients queue at the pooler for `PG_VM_POOL_ADMIT_TIMEOUT_SECS` rather than
being refused by Postgres with `FATAL: too many clients already`. Because a
slot is held for the life of the splice, both legs run TCP keepalive (~60s
idle, then 3 probes 10s apart) and, on Linux, `TCP_USER_TIMEOUT`; the guest
probes back with `tcp_keepalives_*`. Without that, a client that vanishes
without a FIN — a SIGKILLed pod, a preempted node, a NAT or load balancer
dropping an idle flow — leaves a socket the kernel never times out, so its slot
is never released. That leak is permanent on a keep-alive schema, whose entry
(and its slot semaphore) no eviction tier ever rebuilds. The dashboard's
per-VM `client slots` reads `0 / N — clients queueing` when a VM is saturated.

Connect as `user=postgres`; the VM image's `trust` host auth needs no password
(see the auth note in `init.sh`). `PG_VM_POOL_PASSWORD` does double duty:

- it's what the pooler itself uses for its readiness probe and per-schema
  bootstrap connection, if a VM's Postgres requires password auth (scram/md5)
  instead of `trust`;
- and, separately, if set it's also the password the pooler **requires from
  clients** (a plain `AuthenticationCleartextPassword` challenge) before it
  proxies them anywhere — see "Client auth" below. Unset means no client auth
  gate at all: fine on a loopback-only `PG_VM_POOL_LISTEN`, not once it's
  reachable from elsewhere.

Config via env (all optional):

| var | default | meaning |
|-----|---------|---------|
| `PG_VM_POOL_LISTEN` | `127.0.0.1:6432` | client listen address |
| `PG_VM_POOL_IMAGE` | `pg` | Firecracker image per schema |
| `PG_VM_POOL_DAEMON_URL` | `http://127.0.0.1:34099` | base URL of the heyvmd daemon every VM operation addresses. Read once at first use. Set it when the daemon listens on a non-default port; the cold-start load harness (`src/loadtest.rs`) also uses it to aim the pooler at an in-process daemon stub |
| `PG_VM_POOL_SIZE_CLASS` | `micro` | VM resource tier for every schema's VM: `micro` (0.25 CPU, 512MB), `mini` (0.5 CPU, 1GB), `small` (1 CPU, 2GB), `medium` (2 CPU, 4GB), `large` (4 CPU, 8GB) |
| `PG_VM_POOL_USER` / `PG_VM_POOL_PASSWORD` | `postgres` / unset | probe+bootstrap credentials, and (if set) the required client password |
| `PG_VM_POOL_IDLE_TIMEOUT_SECS` | `900` | stop a VM after this long with no connections; `0` disables. Applies to VMs that were *expensive* to bring up — see `PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS` for the rest. The effective timeout is jittered ±15% per schema, and how many VMs may actually stop per pass (oldest-idle first, 8 at a time) is bounded by `PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS`, so a cohort that went idle together drains as a ramp rather than mass-stopping into a reclaim pass + synchronized cold-start storm — see "Draining as a ramp" |
| `PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS` | `60` | the *short* idle timeout, applied to a VM the pooler measured as cheap to bring back (see below); `0` disables the two-speed reaper. Clamped to `PG_VM_POOL_IDLE_TIMEOUT_SECS` — it can only pull a stop earlier, never push it out — see "Two-speed idle reaping" |
| `PG_VM_POOL_FAST_BRINGUP_SECS` | `5` | how fast a bring-up must have been for its VM to be reaped on the short timeout. Measured per entry, not assumed from whether the VM already existed, so a loaded host where restarts have gone slow falls back to the long timeout on its own |
| `PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS` | `600` | the shortest time in which the reaper may stop the **whole** live fleet. Bounds the rate of change so a synchronized expiry ramps down instead of falling off a cliff; `0` disables the limit. Applies to the untracked reaper too — see "Draining as a ramp" |
| `PG_VM_POOL_KEEPALIVE_SCHEMAS` | none | comma-separated schemas exempt from idle reaping |
| `PG_VM_POOL_DATA_DISK_GB` | `2` | persistent per-schema disk size — a *cap*, not an upfront allocation: the guest formats a small (2GB) filesystem inside it and grows it online as the database grows (see "Reclaiming disk slack") |
| `PG_VM_POOL_READY_TIMEOUT_SECS` | `300` | max wait for VM+Postgres readiness |
| `PG_VM_POOL_DISK_GROW_PCT` | unset (off) | guest-filesystem used% at or above which a schema's data **device** is grown (doubled, offline). Setting it is the on/off switch for device growth — see "Growing the device" |
| `PG_VM_POOL_DISK_GROW_URGENT_PCT` | `95` | used% at or above which a **warm** VM's device is grown without waiting for it to go idle — online under the running VM when heyvmd has the online resize route, otherwise stop, resize, and let the next connect boot it, dropping the sessions it had. Once every host's heyvmd has the route, 70–80 grows early at no cost. Must be >= `PG_VM_POOL_DISK_GROW_PCT`; `0` disables the online path. Without it a schema whose write load never pauses can never grow — see "Growing the device" |
| `PG_VM_POOL_DISK_MAX_GB` | `100` | ceiling device growth never passes (the daemon itself caps at 250) |
| `PG_VM_POOL_ADMIT_TIMEOUT_SECS` | `30` | how long a client waits for a free connection slot on its schema's VM before the pooler errors it; `0` fails immediately when full |
| `PG_VM_POOL_CLIENT_STATEMENT_TIMEOUT_SECS` | `120` | session-default `statement_timeout` for client sessions, injected into the startup packet the pooler replays to the guest (as `options=-c statement_timeout=…`, ahead of any `options` the client sent, so the client's own settings still win). Replication logins are exempt, and the pooler's own maintenance connections never pass through it. Clients may still `SET statement_timeout` per session; `RESET` returns to this value. `0` disables |
| `PG_VM_POOL_MAX_CONCURRENT_BRINGUPS` | `3` | max VM deploys/boots in flight against heyvmd; the excess queues FIFO in the pooler (an unbounded burst can wedge the daemon, whose watchdog restart then kills every running VM); `0` disables |
| `PG_VM_POOL_MAX_PENDING_BRINGUPS` | `16` | max whole bring-ups (deploy through ready/restore) in flight at once; the excess queues FIFO at the pooler's front door; `0` disables |
| `PG_VM_POOL_ADMISSION_WAIT_SECS` | `15` | how long a client's bring-up may wait in that queue before it is shed with FATAL `53300`. Nothing is built for a shed bring-up and it doesn't count toward the schema's bring-up circuit breaker. Just past the Platform's 12s create budget, so no VM is built for a client that has already given up; `0` waits forever |
| `PG_VM_POOL_CONNECT_TIMEOUT_SECS` | `30` | iroh tunnel handshake cap |
| `PG_VM_POOL_DIRECT_CONNECT` | on | dial guest IP directly; `0` forces the tunnel |
| `PG_VM_POOL_STATE_FILE` | `~/.heyo/pg-vm-pool/registry.tsv` | persisted schema→VM map |
| `PG_VM_POOL_DEDICATED_FILE` | `<state dir>/dedicated.tsv` | persisted dedicated-database credentials (database → role + password). Written `0600` — it holds cleartext passwords. See "Dedicated databases" |
| `PG_VM_POOL_TLS_CERT` / `PG_VM_POOL_TLS_KEY` | unset (TLS off) | PEM cert chain + key; see TLS below |
| `PG_VM_POOL_DASHBOARD_LISTEN` | unset (dashboard off) | HTTP listen address for the admin dashboard; setting it enables the dashboard — see Dashboard below |
| `PG_VM_POOL_DASHBOARD_USER` / `PG_VM_POOL_DASHBOARD_PASSWORD` | unset (no auth) | HTTP Basic auth credentials for the dashboard (must be set together) |
| `PG_VM_POOL_POOLER_LOG` | `/var/log/pg-vm-pool/pg-vm-pool.log` | pooler log file the dashboard tails |
| `PG_VM_POOL_HEYVMD_LOG` | `/var/log/heyvmd/heyvmd.log` | heyvmd log file the dashboard tails |
| `PG_VM_POOL_DASHBOARD_LOG_LINES` | `200` | how many trailing lines the dashboard shows per log |
| `PG_VM_POOL_DASHBOARD_ALERTS_FILE` | `~/.heyo/pg-vm-pool/alerts.tsv` | where the monitoring page's webhook alert rules persist |
| `PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS` | `60` | how often the alert evaluator samples host metrics and fires crossed alerts |
| `PG_VM_POOL_ARCHIVE_AFTER_SECS` | `0` (off) | S3 eviction: offload a schema untouched this long to S3 and kill its VM; e.g. `604800` = 1 week — see "S3 eviction tier" |
| `PG_VM_POOL_ARCHIVE_SWEEP_SECS` | `3600` | how long the offload pacer waits before re-scanning **after a scan that found nothing** (clamped to 5–60s). It no longer paces the work itself — see "Offload pacer" |
| `PG_VM_POOL_OFFLOAD_WORKERS` | `1` | how many offload jobs the pacer may run concurrently (1–16). `1` keeps the classic one-schema-at-a-time pacing; higher values let no-boot jobs (compact/promote) overlap on a backlogged host. At most ONE in-flight job may boot a VM regardless, and jobs beyond the first are dispatched only under `PG_VM_POOL_OFFLOAD_LOAD_MAX` — see "Offload pacer" |
| `PG_VM_POOL_OFFLOAD_LOAD_MAX` | `0.75` | normalized host load (1-min loadavg / cores; on Linux this includes tasks blocked on disk I/O) at or above which the pacer stops adding jobs beyond the first — aggressive with headroom, single file without |
| `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` | `300` | how long queued client bring-ups **or a running reclaim pass** may hold the pacer off before it dispatches anyway — single-file, no-boot kinds only. Bounds the sawtooth on a host whose bring-up queue is never empty and whose reaper keeps re-triggering reclaim; `0` yields indefinitely — see "Offload pacer" |
| `PG_VM_POOL_S3_BUCKET` | unset | S3 bucket for dumps (required when eviction is on) |
| `PG_VM_POOL_S3_PREFIX` | `pg-vm-pool/` | key prefix; the objects per schema are `{prefix}{schema}.dump` and `{prefix}{schema}.img.zst`. Joined as plain text, so end it with `/`. Every upload and delete uses it. Give each host its own (e.g. `pg-vm-pool/<host>/`) so hosts sharing a bucket can't overwrite each other's archives |
| `PG_VM_POOL_S3_LEGACY_PREFIX` | `pg-vm-pool/` when `PG_VM_POOL_S3_PREFIX` differs, else unset | read-only fallback for restores: consulted only when both of a schema's keys under `PG_VM_POOL_S3_PREFIX` are known absent (a failed HEAD or a torn object keeps the restore on the write prefix), so changing the prefix on a host with existing archives doesn't strand them. Nothing is ever written or deleted under it. Set it empty to disable the fallback |
| `PG_VM_POOL_S3_REGION` | `us-east-1` | region for SigV4 signing |
| `PG_VM_POOL_S3_ENDPOINT` | unset (AWS) | custom endpoint for an S3-compatible store (MinIO/R2); path-style addressing |
| `PG_VM_POOL_S3_ACCESS_KEY_ID` / `PG_VM_POOL_S3_SECRET_ACCESS_KEY` | unset | S3 credentials (fall back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) |
| `PG_VM_POOL_RESTORE_FAST_LOAD` | on | dump restores (S3 and local) load with `fsync` and `full_page_writes` off — via a tmpfs `/run/pg-fc-restore.conf` that `init.sh` includes last — then put them back, `CHECKPOINT` and `sync` before the database is served. Safe because a failed restore's VM is destroyed. `0` loads with normal durability. On a one-vCPU guest the dump is also streamed straight into a single-transaction `pg_restore` (falling back to download-then-restore if that fails) |
| `PG_VM_POOL_IMAGE_ARCHIVE` | unset (off) | `1` enables the image-level archive fallback: when a schema's dump-based archive fails (its Postgres won't boot or won't dump), its stopped VM's raw `data.ext4` is trimmed, zstd-compressed, and uploaded to S3 as `{prefix}{schema}.img.zst` instead — no boot needed; restore boots a fresh VM directly on the downloaded image. Also adds a per-VM "archive disk image" dashboard action. Requires the S3 tier and `PG_VM_POOL_RUN_DIR`, plus `zstd` (and ideally `e2fsck`/`debugfs`) on the host. Note an image preserves the pgdata version, so restoring needs a rootfs with a matching Postgres major |
| `PG_VM_POOL_IMAGE_SPOOL_DIR` | `<state dir>/spool` | where the compressed image is staged (and integrity-checked) before upload; needs roughly the disk's allocated size free |
| `PG_VM_POOL_RESTORE_GET_CONCURRENCY` | `8` | ranged GETs an S3 image restore keeps in flight (1–32). The download is split into 8MiB parts, reassembled in order and decompressed by one `zstd -d` as it arrives, so the compressed image never lands on disk; `1` is a single stream |
| `PG_VM_POOL_FREEZE_AFTER_SECS` | `0` (off) | local freeze tier: dump a schema idle this long to a local file and delete its VM — see "Local freeze tier" |
| `PG_VM_POOL_FREEZE_SWEEP_SECS` | `900` | idle re-scan interval, as `ARCHIVE_SWEEP_SECS` (the shortest of the configured `*_SWEEP_SECS` wins) |
| `PG_VM_POOL_DUMP_DIR` | `~/.heyo/pg-vm-pool/dumps` | where local dump files live |
| `PG_VM_POOL_DUMP_LISTEN` | `0.0.0.0:6433` | local dump server bind; guests reach it at their default gateway, access is token-gated |
| `PG_VM_POOL_WARM_SPARES` | `0` (off) | keep N pre-booted, initdb-complete spare VMs (`spare-pg-*`) for cold bring-ups to claim — an S3 restore skips create+boot+initdb and goes straight to download+load; capped at 16, each parked spare holds its size class's RAM |
| `PG_VM_POOL_CHILLED_VEHICLES` | `2` (0 when the pool is off) | of those spares, keep N parked **stopped** as image-restore vehicles — a thaw overwrites its vehicle's disk, so it wants a stopped VM and a chilled one saves it the stop plus the disk-release wait (~4.8s of a ~6.9s thaw). Stopped VMs hold no RAM, so these cost a thin disk each, not memory |
| `PG_VM_POOL_PRESSURE_PATH` | unset (off) | filesystem to watch (the heyvmd run dir); setting it enables emergency disk-pressure eviction — see "S3 eviction tier" |
| `PG_VM_POOL_PRESSURE_HIGH_PCT` / `PG_VM_POOL_PRESSURE_LOW_PCT` | `85` / `75` | start emergency-archiving oldest-idle schemas at/above high; stop below low |
| `PG_VM_POOL_PRESSURE_CHECK_SECS` | `60` | how often the pressure watchdog reads disk usage |
| `PG_VM_POOL_RECLAIM_CMD` | unset (off) | shell command that offline-trims stopped VMs' disks (normally `sudo -n .../reclaim-disks.sh <run-dir>`); setting it enables automatic disk reclamation — see "Reclaiming disk slack" |
| `PG_VM_POOL_RECLAIM_INTERVAL_SECS` | `3600` | how often the periodic reclaim run fires. Extra runs fire 30s after an idle reap that stopped anything, but at most one per 5 minutes: the reaper stops VMs often enough that an unthrottled trigger would keep `e2fsck` running continuously — burning client I/O and, because a running pass defers the offload pacer, starving the ladder. The dashboard's "reclaim now" is never throttled |
| `PG_VM_POOL_RUN_DIR` | falls back to `PG_VM_POOL_PRESSURE_PATH` | the heyvmd run dir (holds each VM's `sb-<id>/`). Used to verify a killed VM's disk directory is actually gone after archive/freeze, and to locate orphaned directories for the sweep below. When a kill leaves the directory behind (stranding the disk) the pooler logs it loudly instead of reporting "disk reclaimed". Unset ⇒ that removal is left unverified and the orphan sweep is disabled |
| `PG_VM_POOL_ORPHAN_SWEEP_SECS` | unset (off) | how often to sweep the run dir for **orphaned** disk directories — an `sb-<id>/` heyvmd has forgotten (a kill it acked but didn't act on). Requires `PG_VM_POOL_RUN_DIR`. Deletes only directories the daemon confirms gone (per-id 404) that are also not held open and belong to an offloaded/unreferenced schema; a `live` schema whose VM vanished is logged as a data-loss orphan and never deleted. When a pass hits its per-pass cap (100 deletions) with a backlog remaining, it re-arms after ~20s instead of waiting the whole interval — but only while no client bring-up is queued — so a large backlog drains in minutes without ever growing the per-pass blast radius — see "Reclaiming disk slack" |

Postgres inside each VM **tunes itself to the VM's resources at every boot**:
`init.sh` reads live RAM/vCPUs/disk and regenerates
`$PGDATA/heyvm-tuning.conf` (`shared_buffers` = ¼ RAM, `work_mem`,
`maintenance_work_mem`, WAL sizing from the data disk, parallel workers from
vCPUs), so one image serves every size class and a VM that changes size class
picks up correct values on its next start. The profile is single-tenant and
ingest-friendly: `wal_level=minimal` + `wal_compression=lz4` (no per-VM
replicas), `synchronous_commit=off` (commits already ride WAL crash recovery
— the pooler stop-kills VMs), SSD plan costs, JIT off. Manual overrides go in
`postgresql.conf`, which is read after the include and therefore wins.

The image also hardens against ingest memory spikes (the classic "big upload
OOM-kills Postgres inside a live VM" failure): `init.sh` creates a swapfile on
the data disk (sized to RAM, capped at 2GB / an eighth of the disk) as an
emergency spillway, switches to strict overcommit (`vm.overcommit_memory=2`,
per the Postgres docs) so an oversized allocation fails just that one query
with a clean `out of memory` instead of summoning the OOM killer, and shields
the postmaster (`oom_score_adj -900`, with `PG_OOM_ADJUST_FILE` resetting
backends to 0) so if the killer runs anyway it takes a recoverable backend,
not the whole cluster. `temp_file_limit` (¼ disk) keeps a runaway sort's
spill files from filling the disk — disk-full is a cluster-wide PANIC, the
limit is a one-query error.

**Direct connect (default):** when the pooler shares the host with the VMs (the
local-daemon deployment), it dials each VM's Postgres directly at its `guest_ip`
over the host tap and skips the iroh tunnel entirely — no relay dependency,
lower latency, faster bring-up. It falls back to a tunnel automatically if the
daemon reports no `guest_ip`. Set `PG_VM_POOL_DIRECT_CONNECT=0` to force the
tunnel path (e.g. if the pooler ever runs on a different machine than the VMs).

### Two-speed idle reaping

The idle timeout is a bet on the *next* bring-up: keeping a VM warm buys the
next client whatever bringing it back would have cost. Those costs are not
remotely alike. A schema whose VM still exists on disk comes back with a daemon
`start()` and a Postgres restart — a fraction of a second on a healthy host —
while a schema being built from scratch pays create + boot + `initdb`, tens of
seconds. One timeout for both prices the cheap case like the expensive one, and
the fleet fills up with running VMs nobody is using: RAM held, and disks neither
the reclaim pass nor the offload ladder can touch, because both need the VM
stopped.

So the reaper runs two timeouts. Every entry records what its own bring-up
actually cost — everything after the admission queue, which measures how many
other clients arrived at once rather than anything about this VM — and is
reaped on `PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS` (default 60) if that was at or
under `PG_VM_POOL_FAST_BRINGUP_SECS` (default 5), on the full
`PG_VM_POOL_IDLE_TIMEOUT_SECS` otherwise. In practice a schema's first connect
creates its VM and earns the long hold; every reconnect after that is a restart
and gets the short one.

**Why measured rather than "was this VM already on disk".** The number that
matters is what the host can do *right now*. When heyvmd is saturated, a
restart that is normally 200ms takes seconds — and that is exactly the moment a
short timeout does damage, feeding stop/start work to a daemon already behind.
Bring-ups that slow down fail the threshold on their own, so the reaper eases
off under load with no load signal to calibrate and no extra knob. Set
`PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS=0` for the old single-timeout behavior.

The reaper is paced off the shortest budget in play, stops up to 8 VMs
concurrently (a stop is almost all waiting — a guest `df`, a `CHECKPOINT`, the
daemon's stop — so serially a full pass cost the sum of every victim's worst
case and ran longer than the tick that scheduled it), and bounds each stop at
30s so one wedged VM cannot park the pass. How many it may stop per pass is
governed by `PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS` — see "Draining as a ramp".

### Draining as a ramp (`PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS`)

Idle reaping is **deadline-driven**, and real workloads arrive in bursts — so
they go idle in bursts, and every VM in the burst comes due within seconds of
the others. The per-schema jitter spreads a cohort's deadlines by only ±15%,
which on a 60s budget is a window of about eighteen seconds. What the reaper
does with that backlog is what decides whether the fleet ramps down or falls
off a cliff.

A flat per-pass cap does not decide it. Any cohort larger than the cap keeps
the reaper saturated at cap-per-tick regardless of how the deadlines spread —
so widening the jitter cannot fix a mass expiry, and only bounding the *rate*
can. Concretely, simulating a 600-VM cohort going idle together:

| drain policy | time to drain | peak | median |
|---|---|---|---|
| flat cap, run flat out | 384 s | 120/min | 120/min |
| flat cap, one pass per tick | 504 s | 96/min | 72/min |
| **rate-limited (this)** | 774 s | 60/min | 45/min |

The rate limit is `live_schemas × tick / window` VMs per pass: at most one
window's worth of the fleet per window, i.e. a straight line of known gradient
however synchronized the expiry. It is sized off the **live-tier schema count**
rather than the warm or running count on purpose — stopping a VM does not
change its tier, so the divisor holds still for the length of a drain and the
slope stays constant. Sizing it off the running count instead makes the
allowance shrink as the drain proceeds, decaying into a long tail: the last VMs
of a 600-VM cohort would wait half an hour past a 60s budget.

Two clamps bound it. A floor (4/pass) keeps a small fleet from smoothing
something that was never going to be a swing; a ceiling (24/pass, 8 stopped
concurrently) is the daemon's protection and binds on a fleet big enough to ask
for more, which simply means the drain takes longer than the window:

| live schemas | rate | whole fleet drains in |
|---|---|---|
| 50 | 16/min | 3.1 min |
| 300 | 32/min | 9.4 min |
| 600 | 60/min | 10.0 min |
| 2000 | 96/min (capped) | 20.8 min |
| 5000 | 96/min (capped) | 52.1 min |

The same limit governs the **untracked reaper**, which needs it more sharply:
after a pooler restart the warm map starts empty, so every running VM is
untracked by definition and its population is the entire fleet at once.
Uncapped, that made every deploy stop the whole fleet about two passes (~2.5
min) later.

**The trade is explicit.** In a large synchronized expiry a VM stops well after
its own idle budget — bounded by the window, and bought in exchange for a fleet
that does not swing. The monitoring page's **"past idle budget"** tile is how
you watch it: some backlog during a drain is the ramp working, but a number
that never returns to zero means VMs are going idle faster than the window lets
the reaper stop them, and the window (or the 24/pass ceiling) is too slow for
the workload.

### Offload pacer

The three offload tiers below (compact, freeze, S3) don't have three timers.
They share one **pacer**: a dispatcher that wakes every second, asks whether
the host is quiet, and if it is, dispatches *one* schema's worth of work — then
re-asks. The tiers only decide what is eligible; the pacer decides when. Up to
`PG_VM_POOL_OFFLOAD_WORKERS` jobs may be in flight at once (default 1 — the
classic strictly-serial pacing).

This replaced three periodic batch sweeps, and the reason is worth stating.
Each sweep woke on its own interval regardless of what the host was doing, then
ran every candidate it found back to back — each one a VM boot plus a `pg_dump`
plus an upload, minutes apiece, holding a bring-up slot and the shared sweep
lock throughout. On a fleet with a real backlog that is a multi-hour block of
self-inflicted load landing at an arbitrary moment: as likely to be during a
reconnect storm, or while the warm pool is rebuilding, as at 4am. The pacer does
the same total work with the same thresholds, spread thin and yielding to
anything a person is waiting on.

Before dispatching every job it checks, and defers while any of these hold
(in-flight jobs always run to completion — deferral only pauses NEW work):

- a client bring-up is queued (waiting for an admission or bring-up slot);
- a disk-reclaim pass is running (an offload may want the disk the pass is on
  and make it yield — losing its progress for work nobody is waiting on);
- all `PG_VM_POOL_OFFLOAD_WORKERS` slots are taken.

Deferring on a reclaim pass is a *progress* choice, not a safety one. The
compact and image-archive jobs `e2fsck -E discard` and read a stopped VM's
`data.ext4` exactly as the script does, so they take the same per-disk
exclusion a VM boot takes — but non-preemptively: they look, and if the pass
holds that disk they skip the schema and pick it up on a later scan. A boot has
a client behind it and is entitled to make a pass yield; an offload job has
nobody waiting and is not.

**One bound on the yielding.** "Wait for quiet" is not the same promise as
"eventually run", and on a busy host the difference shows up as a sawtooth:
once enough schemas are offloaded every cold connect is a thaw, the bring-up
queue is never empty for a whole tick, and the pacer dispatches *nothing* for
hours while the disk climbs toward the pressure high-water mark — then the
whole backlog drains in one burst the moment the host finally goes quiet. A
reclaim pass does the same thing and does it harder: a pass may run for up to
half an hour and another is triggered after every idle reap, so on a churning
host "later" is very nearly never.

So after `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` (default 300) of *continuous*
backpressure — client or reclaim, counted on one clock, because they alternate
and a clock that reset on the changeover would never reach the limit at all —
the pacer dispatches anyway: one job at a time, no-boot kinds only (compact /
image-archive / promote — those take no bring-up slot, so nothing a client is
queued for moves behind them), and it keeps trickling for as long as the host
stays busy. A running **sweep** is the one deferral no holdoff overrides: it
drains through this same picker and already holds per-schema claims, so forcing
past it would only double-dispatch. Set the var to `0` to restore the strict
yield-to-everything behavior. Forced dispatches log at `info` with how long the
pacer had been held off and by what — the deferral itself only logs at `debug`,
which is what made this starvation invisible.

With workers > 1, three brakes keep the extra concurrency from outbidding
clients: every job **beyond the first** is dispatched only while normalized
host load (1-min loadavg / cores — which on Linux counts tasks blocked on disk
I/O, so it backs off under disk saturation too) is below
`PG_VM_POOL_OFFLOAD_LOAD_MAX`; at most ONE in-flight job may boot a VM
(archive/freeze share the FIFO bring-up gate with waiting clients); and the
offload path's `zstd`/`e2fsck` children run at `nice` 19 with best-effort-low
I/O priority, with the zstd thread count split across workers instead of every
job taking `-T0`. Per-schema exclusivity is unchanged — the `archiving` claim
each job takes also excludes it from concurrent picks, so workers, the
pressure pass, and dashboard buttons never collide on a schema (a lost claim
race is journaled as a skip, not a failure). Side effect worth knowing: a
dashboard-button offload no longer pauses the pacer host-wide — it only makes
that one schema unpickable.

When several schemas are eligible it takes the cheapest-and-most-valuable job
first — promote a local file to S3 (an upload, no VM), then compact (no boot),
then archive, then freeze — breaking ties toward the coldest schema. Scanning
only happens when the pacer is about to act, so a tick on a busy host or during
a job is a couple of atomic loads; a scan that finds nothing defers the next one
by the shortest configured `*_SWEEP_SECS` (clamped to 5–60s), which is all those
vars now mean.

Two things deliberately stay batch: **disk-pressure eviction**, which is an
emergency and overrides both the thresholds and this politeness, and the
dashboard's **"sweep now"** button, which is an operator saying "I want the disk
back now" (the pacer stands down while it runs).

### Warm spare pool (`PG_VM_POOL_WARM_SPARES`)

A cold bring-up pays create + boot + `initdb` before it can serve anything, and
that work is identical for every schema — so it can be done ahead of time. With
`PG_VM_POOL_WARM_SPARES=N` (max 16) a background replenisher keeps N pre-booted
`spare-pg-*` VMs with an empty cluster ready; a bring-up that needs a brand-new
VM (first connect, or a restore whose VM was killed) **claims** one and goes
straight to creating the schema database. A claimed spare keeps its name — the
registry's `schema → sandbox-id` binding is what owns it, as for every VM.

Two properties matter for it to actually be faster than a cold create:

- **Claiming never lists.** `GET /deployed-sandboxes` is heyvmd's most expensive
  and most lock-contended call (it drains its whole handle map under a write
  lock); on a host with thousands of sandboxes it is seconds. The replenisher
  lists on its own cadence and publishes the ids it verified; a claim pops one
  from that shelf and spends a single by-id lookup confirming it is still there.
  An empty shelf answers "cold-create" immediately rather than paying for a
  listing to discover it has nothing.
- **A spare counts only when its Postgres answers.** heyvmd reports a VM running
  as soon as the guest signals ready, which is not the same as a healthy
  postmaster; a half-failed boot leaves a "running" spare that poisons the first
  claim that takes it while the pool reports itself full. Every pass TCP-probes
  each free spare's 5432, and a spare unreachable for 5 minutes is deleted and
  rebuilt (capped per pass — when *every* spare probes sick the cause is usually
  the host or the daemon, and deleting the whole pool at once is just another
  create burst).

Passes build the deficit a few VMs at a time rather than one at a time (an empty
pool with a target of a dozen must not take a dozen sequential boots to fill),
one failed build no longer cancels the rest of the pass, and a claim or a failed
claim wakes the replenisher immediately instead of leaving the pool short until
its next tick. Stranded *stopped* spares — the residue of a daemon restart — are
restarted in preference to creating new ones, and are only counted once they are
genuinely up.

#### Chilled vehicles (`PG_VM_POOL_CHILLED_VEHICLES`)

An **image** restore does not want a running VM. It overwrites its vehicle's
data disk with the archived filesystem and boots on that, so every bit of the
boot and `initdb` a warm spare paid for is discarded — and handing it a running
spare means stopping that VM first and waiting for Firecracker to release the
disk file before the swap can start. Measured on a production host, that
stop-and-wait was **~4.8s of a ~6.9s thaw**, against ~2.8s of actual work
(decompress + one boot).

So `PG_VM_POOL_CHILLED_VEHICLES` of the spares are parked **stopped**, already
in the state a restore wants. A thaw claims one, writes the disk, and starts
the VM once. They are chilled by the replenisher, off any client's critical
path, and only ever from spares whose Postgres answered while running — a
vehicle that never booted would also have no readable `PG_VERSION` for the
major-compatibility gate to check the archive against. Stopped VMs hold no RAM,
so the vehicle shelf does not compete with the warm one for memory; it costs a
thin data disk each.

Three properties keep the two shelves from fighting:

- **The replenish plan can't see them.** A chilled vehicle is stopped, unbound
  and unclaimed — exactly the shape the plan restarts as deficit or deletes as
  surplus. They are exempt from both, or the pool would spend every pass
  undoing its own vehicles.
- **Chilling shrinks the warm shelf, and the next pass refills it.** The pool
  settles at `WARM_SPARES` running plus `CHILLED_VEHICLES` stopped. Nothing is
  chilled while clients are queued for bring-ups, for the same reason nothing
  is built then.
- **The disk-release check still runs.** Skipping the *stop* is safe on the
  pool's promise; skipping the check that nothing holds the disk open is not,
  and it costs one fd scan when the disk is already free.

With the shelf empty a restore falls back to the old path — claim a running
spare, stop it — which is correct, just slower. The dashboard reports vehicle
depth next to warm-spare depth; zero chilled is the image-restore equivalent of
zero warm spares.

### Local freeze tier

Between "idle-stopped VM" (full filesystem image on disk) and "archived to S3"
(off-host, slow to restore) sits the **frozen** tier: a schema idle for
`PG_VM_POOL_FREEZE_AFTER_SECS` is dumped to a local file
(`PG_VM_POOL_DUMP_DIR/<schema>.dump`) and its **VM is deleted**. A cold schema
then costs dump-file bytes (~1–5MB for a typical workbook) instead of a
filesystem image (~200MB+ floor) — roughly an order of magnitude more cold
schemas per host disk. The next client connect restores it: with
`PG_VM_POOL_WARM_SPARES` set it claims a pre-booted spare and goes straight to
download + parallel `pg_restore` (seconds for small workbooks).

The dump bytes move exactly like the S3 tier's — the guest streams
`pg_dump`/`pg_restore` through `curl` — but against a tiny token-gated HTTP
server the pooler runs on the host (`PG_VM_POOL_DUMP_LISTEN`), reached in-guest
at the VM's default gateway. Every guard from the S3 pipeline applies: the VM
is only killed after the server has fully received, fsync'd, and renamed the
dump (size-checked); the tier flip is durable before the kill; restores are
idempotent (`--clean --if-exists`).

The tiers ladder: after `PG_VM_POOL_ARCHIVE_AFTER_SECS`, a *frozen* schema's
dump is **promoted to S3 by the pooler itself** — a file upload, no VM bring-up
at all — and the local file is deleted. `frozen` schemas appear in the
dashboard with a "frozen (local)" badge and a `frozen` state filter.

### Local compacted tier

The **compacted** tier solves the same problem as freezing — a stopped
schema's full ext4 image squatting on host disk — without ever booting the
VM: a schema whose VM has sat stopped for `PG_VM_POOL_COMPACT_AFTER_SECS` has
its data disk trimmed (`e2fsck -fp -E discard`, the reclaim pipeline) and
zstd-compressed into `PG_VM_POOL_COMPACT_DIR/<schema>.img.zst`, verified
(`zstd -t` + the ext4 magic, atomic rename), and its **VM + disk deleted**.
Measured on a real pool disk: a 183MB-allocated idle disk became a 7MB image
(~26x) in under 3 seconds. Thawing decompresses the image onto a fresh VM's
disk (sparse) and boots on the real data — no `pg_restore`, no index
rebuilds; the crash-recovery path a normal VM restart takes.

**Restores are sized to the schema, not to the default.** The dump tiers
(frozen, and the S3 dump archive) delete the VM they came from, and a dump
carries no trace of the device it came off — so the pooler notes that device's
size in the registry (a fifth `disk_gb` column, written at idle-stop and again
just before a dump-offload kills the VM) and builds the restore's VM at that
size, floored at `PG_VM_POOL_DATA_DISK_GB` and capped at the daemon's 250GiB.
A restore that needs more than a warm spare has skips the pool and pays a
create; spares are minted at the default size before anyone knows which schema
will claim one. Without this a schema whose device had grown comes back into
the *starting* size — device growth is offline-only, so `pg_restore` cannot
grow its way out — fills it, and leaves a half-loaded cluster behind
`No space left on device`. Image restores are unaffected: they swap the
archived disk in, so it arrives at whatever size it was archived at. Rows
written before this column existed read as "unknown" and take the default.

Freeze vs. compact: a dump is smaller than an image and version-independent,
but freezing must boot each candidate to `pg_dump` it, and thawing pays a
full restore. Compacting is a few seconds of host CPU each way. With both
enabled, whichever threshold fires first wins (the config warns if freeze
would always beat compact); the shipped supervisor conf prefers compact and
leaves freeze off. Needs `PG_VM_POOL_RUN_DIR` and `zstd`.

Same ladder as frozen: past `PG_VM_POOL_ARCHIVE_AFTER_SECS` a compacted
schema's image is promoted to S3 as `{schema}.img.zst` — the image-archive
format, uploaded as-is with no recompression, any stale dump object deleted so
it can't shadow the newer image — and the local file is removed.

### S3 eviction tier

The idle reaper (`PG_VM_POOL_IDLE_TIMEOUT_SECS`) only **stops** an idle VM — its
data disk still occupies host storage forever. On a host accumulating thousands
of rarely-touched workbooks, disk is the binding constraint. The **eviction
tier** is a second, slower reclamation stage: any non-keepalive schema untouched
for a long window (e.g. a week) has its database dumped to S3 and its VM
**killed** — freeing the disk. The next client connection restores the dump into
a fresh VM transparently. When it happens is the offload pacer's call (below).

Enable it by setting `PG_VM_POOL_ARCHIVE_AFTER_SECS` to a positive number and
providing an S3 bucket + credentials (the pooler fails fast at startup if the
threshold is set but the bucket/credentials are missing):

```
PG_VM_POOL_ARCHIVE_AFTER_SECS=604800        # 1 week
PG_VM_POOL_S3_BUCKET=my-pg-vm-pool-dumps
PG_VM_POOL_S3_REGION=us-west-2
PG_VM_POOL_S3_ACCESS_KEY_ID=...
PG_VM_POOL_S3_SECRET_ACCESS_KEY=...
# optional, for MinIO/R2/other S3-compatible stores:
# PG_VM_POOL_S3_ENDPOINT=https://minio.internal:9000
```

How it moves the data: the pooler never handles dump bytes itself. It generates
a short-lived **SigV4 presigned URL** and the guest VM streams straight to/from
S3 with its own `pg_dump`/`pg_restore` + `curl` (`pg_dump -Fc | curl -T` on the
way out, `curl | pg_restore` on the way back). The dump bytes never transit the
pooler and the S3 secret key never leaves it. This requires the guest VMs to
have outbound network egress to the S3 endpoint. Each schema maps to one object,
`s3://{bucket}/{prefix}{schema}.dump`; a single `PUT` caps at 5 GB, which is
ample for one-workbook databases.

**Empty databases are never uploaded.** A schema's key is stable and shared, so
an upload replaces whatever is already at it — and a cluster with no user
relations is worth nothing in a bucket: restoring one leaves a client exactly
where a fresh create would. Every path that writes to S3 refuses such a cluster
first. The image paths read the stopped disk's `base/` directory offline (a
database is copied from `template1` and only grows, so a user database no
larger than template1 has no relations of its own); the dump paths ask the
running Postgres. Compaction and local freezing still run — the bytes stay on
the host, the registry row keeps its tier, and the pooler journals
`kept local — its database holds no user data`. An unreadable disk or an
unreachable database is never treated as empty.

**Disk-pressure eviction (emergency tier):** the threshold-driven pacer can't
help when load outruns it — a filesystem that hits `No space left on device`
takes everything down at once (VM creates fail, Postgres PANICs, even the
rescue dumps fail). Set `PG_VM_POOL_PRESSURE_PATH` to the filesystem holding the
VM disks and a watchdog checks usage every `PG_VM_POOL_PRESSURE_CHECK_SECS`: at
or above `PG_VM_POOL_PRESSURE_HIGH_PCT` it offloads schemas through the same
worker pool as the pacer (up to `PG_VM_POOL_OFFLOAD_WORKERS` concurrent jobs, at
most one of which may boot a VM; no host-load gate — this is an emergency),
re-reading usage between dispatches, until below `PG_VM_POOL_PRESSURE_LOW_PCT`.

The monitoring page also carries a manual **"offload idle > TTL now"** control:
enter an idle TTL in seconds and every schema whose disk has been untouched
longer than that is offloaded through the same parallel drain loop — pressure-
mode ranking (no-boot kinds first: compact / image-archive / promote), disk
usage ignored, the whole backlog run dry. It's the operator override for "the
threshold is 30 minutes but the backlog is growing — drain everything idle over
X right now".

It picks jobs the same way the pacer does, with two changes that matter when
the disk is nearly full:

- **The idle thresholds are ignored.** Every schema without live sessions is a
  candidate, coldest first — under pressure, least-recently-used is the whole
  policy. (The *tiers* still have to be configured: pressure overrides how old
  data must be, never the operator's choice of where it may go.)
- **It will not boot a VM while any no-boot option remains.** Compaction and the
  image archive both work on a stopped disk — trim, compress, delete the VM —
  in seconds of CPU, and compaction alone frees ~96% of a schema's footprint.
  The boot-and-dump path is ranked last because on a nearly-full host it is both
  the slowest option and the likeliest to fail: booting a VM needs a ~200MB
  rootfs clone the disk may not have room for, which is exactly the failure that
  turns "nearly full" into "wedged". Freezing is dropped entirely here — it
  costs a boot *and* leaves the bytes on the host.

Keepalive schemas and schemas with live sessions are never touched, it shares
the sweep's single-flight lock (and the routine pacer stands down while it
runs), and it aborts after 3 consecutive failures — an unhealthy environment
shouldn't be ground through. If every candidate is exhausted while still above
the low-water mark it says so loudly; at that point the remaining usage is
running VMs or non-VM data.

One thing to check before relying on it: `PG_VM_POOL_COMPACT_DIR` defaults to
`<state dir>/compact`, which on most hosts is **not** the filesystem being
watched. That is usually what you want (compaction then moves bytes off the
full array), but the destination needs room for roughly 4% of what it drains —
~40GB for a 5000-schema fleet. Point it at the array explicitly if the state
dir lives on a small root filesystem.

Archived schemas show up in the dashboard with an **"archived (S3)"** status
(filterable via the `archived` state pill) even though no VM backs them, and any
idle running schema VM has a **reap → S3** button on its detail page to offload
it on demand. `PG_VM_POOL_KEEPALIVE_SCHEMAS` are exempt from eviction, same as
from idle reaping.

### Reclaiming disk slack (`reclaim-disks.sh`)

A VM's data disk (`data.ext4`) is a **sparse** file provisioned at
`PG_VM_POOL_DATA_DISK_GB`. When Postgres frees blocks inside the guest — recycled
WAL, vacuumed heap, dropped temp/tables, a reinitialised cluster — ext4 marks
them free, but with no TRIM/discard reaching the host those blocks are never
punched out of the backing file. A disk therefore ratchets toward its full
provisioned size and never shrinks, even when the live database is tiny (a 1 GB
database routinely pins tens of GB on disk after a transient bulk load).

**Thin provisioning (first line of defense):** the image formats only a small
(2GB, `pgdata_init_mb` cmdline override) filesystem inside the provisioned
device on first boot, and a watcher in the guest grows it online with
`resize2fs` — doubling up to the device cap — whenever free space drops below
1GB (or ⅛ of the fs). Since ext4 never touches blocks past its own end, the
host allocation can never ratchet past the *current filesystem* size: the
provisioned max is a cap, not the de-facto footprint. The disk-derived Postgres
knobs (`max_wal_size`, `temp_file_limit`, swap sizing) key off the live
filesystem size and are recomputed + reloaded on each growth step.

The watcher never exits. Once the filesystem spans the device it logs
`[grow] filesystem spans $DATA_DEV; idling until it changes` and re-checks
once a minute, re-reading the device size each time. When the host grows the
device under the running VM (heyvmd's online resize runs `resize2fs` in the
guest itself), the watcher sees a filesystem it didn't grow, logs
`[grow] filesystem is now …MB (grown outside this watcher); retuning`, and
recomputes + reloads the same knobs — within a minute of the grow. If the
device grew but the filesystem didn't, its normal growth path takes over.
Guests booted from an image older than this keep the old watcher, which exits
at the first span; they still get the space from an online grow, but keep
their boot-time knobs until the next restart.

**Growing the device (second line of defense).** Once the guest watcher has
grown the *filesystem* to span the device, the **device** is the binding
constraint, and only the host can grow it. That
is what `PG_VM_POOL_DISK_GROW_PCT` enables, and it has two triggers because one
is not enough:

- **At idle-stop** (`PG_VM_POOL_DISK_GROW_PCT`, e.g. 85). The reaper is
  stopping the VM anyway, so the offline resize is free: no client is
  disturbed. This handles every schema that goes quiet.
- **While warm** (`PG_VM_POOL_DISK_GROW_URGENT_PCT`, default 95). The pooler
  asks heyvmd to grow the device *online* (`POST /sandboxes/{id}/resize-online`):
  heyvmd extends the disk under the running VM, grows the guest filesystem and
  verifies both, and no session is dropped. When that is unavailable — an
  older heyvmd without the route (404), a VM that is not running (409), or a
  failure partway (5xx) — it falls back to stopping the VM *itself*, resizing
  offline, and leaving it for the next connect to boot, dropping whatever
  sessions it had.

The second trigger exists because the first one cannot reach the schemas that
need it most. Growing a device is offline-only (the daemon fscks and cold-boots
the disk to do it), so for a long time the only trigger was an idle stop — and
a schema under continuous write load never goes idle. It would fill its
filesystem, the guest watcher would grow that to span the device and retire,
and then Postgres would start failing writes with `No space left on device`
and *stay* that way until its traffic happened to pause for a whole
`PG_VM_POOL_IDLE_TIMEOUT_SECS`. The busiest schemas were precisely the ones
that could not grow.

Hence the higher default threshold on the warm path: the free idle-stop grow
keeps handling everything that does go idle, and the offline fallback only
fires on what it misses — a filesystem genuinely at the wall. It samples the
warm set once a minute, does at most 4 *offline* grows per pass (each costs a
schema its live sessions, so a busy pass trickles rather than restarting
everything at once; online grows are not capped), and backs off per-schema on
failure. The offline fallback claims the schema the same way an offload does,
so clients arriving mid-resize queue at the pooler instead of racing the
stop/start, and it logs the stop at `warn` with the session count. Once every
host's heyvmd serves the online route, the threshold can come down to 70–80.

When a full filesystem already spans a device at `PG_VM_POOL_DISK_MAX_GB`,
growth has nothing left to give: that is logged at **error** level (and to the
events journal) naming the cap, because the alternative — declining to act and
saying nothing — reads as a healthy pooler while the database fails every
write. Raise `PG_VM_POOL_DISK_MAX_GB`, or move the schema off the pool.

Eviction reclaims the whole disk once a schema is *long* idle; `reclaim-disks.sh`
reclaims the **slack** from disks whose VMs are merely stopped, without deleting
anything. For every `data.ext4` whose VM is not currently running it recovers
the journal (`e2fsck -fp`) and then punches all free blocks and unused
inode-table blocks straight out of the backing file (`e2fsck -fp -E discard` —
file-level hole punch, no loop device or mount, which keeps working on hosts
where loop-device discard doesn't). Disks a live Firecracker still has open are
skipped (writing to those would corrupt them), and skips name the holding
process. `PRUNE_SWAP=1` additionally deletes each stopped VM's swapfile (dead
weight — swap never survives a boot, and init.sh recreates it right-sized):

```
sudo DRY_RUN=1 ./reclaim-disks.sh ~/.heyo/run   # list candidates, change nothing
sudo ./reclaim-disks.sh ~/.heyo/run             # actually reclaim
sudo SHRINK=1 PRUNE_SWAP=1 ./reclaim-disks.sh ~/.heyo/run   # maximum reclaim (below)
```

**`SHRINK=1` — retro-fit thin provisioning onto legacy disks.** Disks formatted
before thin provisioning have a full-device filesystem, so even after a trim
their next growth ratchets straight back toward the provisioned max, and ~1GB
of full-device ext4 metadata stays allocated forever. With `SHRINK=1` the
script also *shrinks* each stopped VM's filesystem to `used × 1.25` (floored at
`MIN_FS_MB`, default 2048 to match the image's initial size) and hole-punches
the backing file past the new end. The guest's grow watcher re-extends the
filesystem online if the database later needs the space. Shrinking relocates
blocks, so it's slower than a plain trim and the script re-fscks each shrunk
filesystem before mounting it — run it once during a quiet window to convert
the existing fleet, then let the pooler's periodic (non-shrink) runs maintain
it.

This only reclaims *stopped* VMs; reclaiming a **live** VM's disk would need the
guest to issue discards (the image already mounts `/workspace` with `-o discard`)
**and** the Firecracker drive to pass them through to the backing file — which
Firecracker's virtio-blk does not (in-guest `fstrim` reports "the discard
operation is not supported"). Until that changes, offline trim is the only
reclaim path, so the pooler automates it.

**Automatic reclamation:** set `PG_VM_POOL_RECLAIM_CMD` and the pooler runs it
itself — every `PG_VM_POOL_RECLAIM_INTERVAL_SECS` (default hourly), **plus a run
~30 s after the idle reaper stops VMs**, so a just-reaped VM's slack returns
within a minute instead of waiting for a human or the next interval. That
trigger is rate-limited to one run per 5 minutes: with two-speed reaping the
reaper stops VMs often, and unthrottled the triggers chain into an `e2fsck`
sweep that never stops — which costs the clients I/O and, because a running pass
defers the offload pacer, starves the ladder that frees far more disk than a
trim does. The periodic run is the backstop, and the dashboard button is never
throttled. Runs are single-flighted and time-bounded (30 min), the output
summary lands in the pooler log, and the dashboard's monitoring page gets a
**"reclaim disk slack now"** button. The command needs root for loop-setup/mount, so a non-root pooler
invokes the script through a `NOPASSWD` sudoers entry:

```
# /etc/sudoers.d/pg-vm-pool-reclaim  (chmod 0440; adjust user + paths)
pooler ALL=(root) NOPASSWD: /opt/pg-vm-pool/reclaim-disks.sh /workbooks/heyvm/run --shrink --prune-swap
```

```
PG_VM_POOL_RECLAIM_CMD="sudo -n /opt/pg-vm-pool/reclaim-disks.sh /workbooks/heyvm/run --shrink --prune-swap"
PG_VM_POOL_RECLAIM_INTERVAL_SECS=3600
```

The flags exist as *arguments* (equivalent to the `SHRINK=1`/`PRUNE_SWAP=1` env
vars) because a pinned sudoers entry can match an exact argument list, while
env assignments are silently refused by `sudo -n` without a `SETENV` tag.
Including them in the periodic command is self-limiting: an already-thin
filesystem skips the shrink and a right-sized swapfile costs only its own
recreation on the next boot, so in steady state the pass degenerates to a plain
trim — but every legacy VM gets fully converted at its first idle stop.

Pin the script at a root-owned path (`chown root:root`, `chmod 0755`) so the
sudoers entry can't be repointed by editing a user-writable file, and pass the
run dir in the sudoers line exactly as in the command so `sudo -n` matches.

**Verify after any change to the script path, run dir, or flags** — sudoers
matches the argument list byte-for-byte, and a stale entry fails every
automated run without anything obviously breaking (the pooler just logs a
failed reclaim once an hour):

```
# as the pooler's user; prints the command if the entry matches, errors if not
sudo -n -l /opt/pg-vm-pool/reclaim-disks.sh /workbooks/heyvm/run --shrink --prune-swap
```

then confirm the next periodic run's summary line (`trimmed N disk(s),
reclaimed …`) appears in the pooler log. The two historical failure modes are
exactly this: env vars stripped by `sudo` (hence flags-as-arguments) and an
argument list that drifted from the sudoers pin after a run-dir change.

**Passes and boots are excluded per disk.** The script's in-use scan is a
snapshot taken at pass start, so a VM booted mid-pass would be invisible to it
and its filesystem could be fscked underneath the running guest. The hazard is
per-*disk* — a boot of VM A is only endangered by work on A's disk — so that is
how the exclusion is keyed. Both sides `flock` a file per sandbox,
`<run-dir>/.reclaim-locks/<id>.lock`: the pooler holds it across the VM's
`start()`, the script holds it across one disk's whole pipeline and skips any
disk it can't lock (`skip (a VM boot holds the disk lock)`). A boot of a VM the
pass isn't touching therefore costs nothing at all, and the pass keeps running
through cold starts and warm-spare restarts instead of losing its progress to
them.

A pass under per-disk locks also runs at `nice` 19 with best-effort-low I/O
priority (inherited through `sudo` by the `e2fsck` underneath), where one under
the global gate runs at full priority. The mode decides who the pass is
competing with: under the gate it is holding up every VM boot on the host, so
finishing fast *is* the client-facing priority; under locks it runs alongside
live traffic instead, and an fsck-and-trim sweep over every stopped disk at
normal I/O priority competes with heyvmd itself — saturate it far enough and its
watchdog restarts it, which drops every in-flight create and kills every running
VM (the `has been unknown to heyvmd` bring-up failure).

Because the permit is only held across `start()`, a VM that boots mid-pass ends
up holding its disk open while the pass-start in-use snapshot still predates it.
So the script asks that question twice: against the snapshot (free — it catches
everything already running), and then, for whatever survives, once *live while
holding the disk's lock*, which is the only moment the answer is guaranteed to
stay true (`skip (booted during this pass)`). Under the global gate the live
scan is skipped entirely — no VM can boot during a pass at all.

The pooler can't tell by inspection whether the script it invokes implements
this, so the script declares it: it writes `perdisk-1` into
`<run-dir>/.reclaim-locks/.protocol` at every pass start, and the pooler deletes
that marker before each run and re-reads it after the child exits. No marker
means an older script, and the pooler falls back to a global boot gate — one it
holds for the pass's whole duration, with every VM boot on the host taking the
read side. The latch is re-derived every pass, so rolling the script back
returns the pooler to the gate on that script's first run rather than leaving it
trusting a stale answer. The dashboard's "reclaim pass" tile says which scheme
is in force. `flock(1)` missing, or a `<run-dir>/.reclaim-locks` that isn't
writable by both the (root) script and the pooler, also means the gate — safe,
just slower.

**A pass yields to a waiting boot.** Under the gate, a pass on a large fleet is
minutes, not seconds, and a boot that simply waited it out would stall a client
cold start, a warm-spare restart or a thaw for exactly that long. Under per-disk
locks the same applies to a boot that collides with the pass on its own disk —
and the disk the pass is on is precisely the one that boot wants.

So a waiting boot asks the pass to stop: the pooler creates
`<run-dir>/.reclaim-stop`, the script yields at its next safe point — between
disks, at a stage boundary inside one, or by killing its own discard-stage
fsck (which only punches free blocks on a verified-clean filesystem, so
interruption is safe; a mid-way disk is simply re-trimmed next pass) — and
the gate is released *after* the child has actually exited. Where it stopped is
recorded in `<run-dir>/.reclaim-cursor` and the next run resumes after that
disk, so a host that yields often still walks the whole fleet. Deliberately
cooperative rather than a kill: the command runs under `sudo`, so the pooler can
only signal the shell it spawned while `sudo`'s root-owned `e2fsck` keeps
writing — handing the gate back then would cause exactly the corruption the gate
prevents. An older deployed script that knows neither the lock files nor the
stop file still works; boots just wait for the full pass, as before. (Redeploy
the script after upgrading if you want per-disk locks and yielding:
`install -D -m 0755 reclaim-disks.sh /home/sam/.heyo/bin/reclaim-disks.sh`.)

#### Stale rootfs copies (`prune-stale-rootfs.sh`)

Usually the largest single reclaimable item on a host, and the one nothing else
touches. heyvmd clones the base image into `<run-dir>/sb-<id>/rootfs.ext4` on
every **boot** and deletes it again on a clean **stop**; a copy sitting beside a
stopped VM's data disk is residue from a stop that never ran its cleanup — a
watchdog restart of the daemon, a SIGKILL, a host reboot. At ~190MB each that is
most of a terabyte on a fleet of a few thousand (measured: 1.05TB of 3.2TB used
on a 5600-sandbox host). `reclaim-disks.sh` only touches `data.ext4`, and the
orphan sweep only deletes directories heyvmd has *forgotten*, so these
accumulate indefinitely.

```
sudo ./prune-stale-rootfs.sh /mnt/md0/heyvm/run             # dry run: what and how much
sudo DELETE=1 ./prune-stale-rootfs.sh /mnt/md0/heyvm/run    # reclaim it
```

Nothing is orphaned: a rootfs copy holds no sandbox state (the schema's data is
`data.ext4`, the binding is the registry), and the next boot re-clones it from
the base image — the same thing heyvmd's own `stop` does. Guards: skips any file
a process holds open (device:inode, so a *running* VM's copy is never touched
even under jailer's chroot), skips anything younger than `MIN_AGE_MINS` (default
30) so a VM mid-boot can't be caught between clone and open, and only ever
matches `sb-*/rootfs.ext4` — never a base image, a data disk, or a
`snapshot/rootfs.ext4` checkpoint. The pooler's orphan sweep prunes these
continuously once running; the script is for draining an existing backlog now.

#### Orphaned disks (`PG_VM_POOL_ORPHAN_SWEEP_SECS`)

Slack reclamation trims a *live* schema's disk; it does nothing for a disk whose
VM is **gone**. When a schema is archived to S3 or frozen, the pooler kills its
VM to reclaim the whole `sb-<id>/` directory — but the kill is a
`DELETE /deployed-sandboxes/:id` the SDK treats as success on a 404, and heyvmd
has been observed to drop the sandbox record while leaving the directory on
disk. The VM count falls, the bytes don't, and nothing above reclaims them
(`reclaim-disks.sh` only trims live schemas' disks). Left alone this strands
hundreds of GB — a fleet can archive most of its schemas and barely move total
storage.

Two mechanisms address it. First, after every archive/freeze the pooler now
**verifies** the directory is actually gone (needs `PG_VM_POOL_RUN_DIR`) and
logs a loud warning with the path and size instead of a false "disk reclaimed"
when it isn't. Second, set `PG_VM_POOL_ORPHAN_SWEEP_SECS` to have the pooler
periodically **sweep and delete** the orphans itself:

```
PG_VM_POOL_RUN_DIR=/workbooks/heyvm/run
PG_VM_POOL_ORPHAN_SWEEP_SECS=3600
```

A directory is deleted only when every one of these holds, checked cheapest-first
so a live disk is ruled out before any daemon call or destructive action:

1. it's older than 30 min (not a VM mid-create, whose fresh dir the daemon may
   not report yet);
2. no process holds a file in it open — the same chroot-proof `device:inode`
   check `reclaim-disks.sh` uses (not a running VM);
3. heyvmd's **per-id** endpoint returns 404 — the daemon truly forgot it. The
   *list* endpoint is unreliable (it can omit stopped VMs and is truncated on a
   large fleet), so classification never uses it;
4. its schema is offloaded (`frozen`/`archived`, data safe elsewhere) or the id
   is unreferenced by any registry entry (dead).

Conditions 2–3 are re-checked against a fresh snapshot immediately before each
delete. A `live`-tier schema whose VM vanished is a **data-loss orphan** — its
disk is the only copy — so it is reported at error level and *never* deleted;
resolve those (restore, or mark archived/frozen) before they serve an empty DB.
Deletions are capped per pass and a flaking daemon aborts the sweep, so a "gone?"
ambiguity can never become a destructive action. Unlike slack reclamation this
needs no root — just delete permission on the run dir (the pooler runs as the
same user heyvmd creates the directories as); if jailer left root-owned files a
removal fails and is logged rather than silently half-done.

The same pass also **prunes leftover rootfs copies** from directories it keeps.
heyvmd clones the base image into `<run-dir>/sb-<id>/rootfs.ext4` on every boot
and deletes it again on a clean stop, so a copy sitting beside a *stopped* VM's
data disk is residue from an unclean one — a daemon restart, a watchdog kill, a
host reboot. On the pg image that is ~200 MB per VM and on a large fleet it is
the biggest reclaimable item in the run dir (measured at ~1 TB on a host with
~5 600 sandboxes). It is deleted only under the same in-use and age guards as a
directory, plus heyvmd reporting the VM **not running** — and the cost of being
wrong is one extra image clone on the next boot, since that boot rewrites the
file anyway.

At startup the pooler counts `sb-<id>/` directories under `PG_VM_POOL_RUN_DIR`
and warns if there are none. Every disk-reclaiming feature here resolves paths
under that directory and treats "nothing there" as "nothing to do", so a run dir
pointed at the wrong path (e.g. the default `~/.heyo/run` on a host whose daemon
actually runs out of a mounted array) disables all of them without a single
error line. Check `PG_VM_POOL_RECLAIM_CMD`'s argument at the same time.

### Managing with supervisord

`deploy/supervisor/pg-vm-pool.conf` runs the release binary under supervisord
and is the single place to manage the pooler's environment:

```sh
cargo build --release
sudo ln -s /home/sam/Projects/pg-fc/deploy/supervisor/pg-vm-pool.conf \
           /etc/supervisor/conf.d/pg-vm-pool.conf
sudo mkdir -p /var/log/pg-vm-pool
sudo supervisorctl reread && sudo supervisorctl update
sudo supervisorctl status pg-vm-pool          # start/stop/restart/tail work too
```

Edit the `environment=` block in the conf to change any `PG_VM_POOL_*` var,
then `supervisorctl reread && supervisorctl update pg-vm-pool` — note a plain
`restart` does **not** reload `environment=`; `update` does. Comma-containing
values (like `KEEPALIVE_SCHEMAS`) must be double-quoted. Logs land in
`/var/log/pg-vm-pool/pg-vm-pool.log`.

The shipped `environment=` block enables the full density stack — orphan
sweep, periodic reclaim (`--shrink --prune-swap`), the compacted tier (1h
idle → the stopped disk is trimmed + zstd'd into a local image ~5-25x
smaller, VM deleted; thaw is a decompress + boot), the S3 archive tier (24h
idle, plus the image-level fallback), and pressure eviction — so idle schemas
progressively leave the host instead of pinning ext4 images forever. It requires one-time host setup (deploy
`reclaim-disks.sh` to a stable path + a pinned sudoers entry, migrate any
repo-relative `registry.tsv`, fill in the `S3_*` placeholders); the checklist
lives in the header comment of `deploy/supervisor/pg-vm-pool.conf`. On a host
with a large stopped-VM backlog, enable reclaim first and the freeze/archive
timers second (sequencing notes ibid.).

### Client auth

The pooler has no client auth gate by default — any client that can reach
`PG_VM_POOL_LISTEN` is proxied straight through to a VM, whatever the VM's
Postgres itself would accept. Set `PG_VM_POOL_PASSWORD` to close that: the
pooler then answers each client's `StartupMessage` with an
`AuthenticationCleartextPassword` challenge and rejects (`28P01`, "password
authentication failed") anyone who doesn't send it back before ever dialing
the backend VM. This is deliberately a separate layer from backend auth — the
VM's own Postgres can (and by default does) stay on `trust`, since gating
access is now the pooler's job.

Because it's cleartext, the password crosses the network unencrypted unless
the connection is also TLS — required reading if `PG_VM_POOL_LISTEN` binds to
anything other than `127.0.0.1` (the pooler logs a startup warning in that
case). Set `PG_VM_POOL_TLS_CERT`/`KEY` alongside it; see TLS below.

### Dedicated databases

`PG_VM_POOL_PASSWORD` gates the whole namespace: any client holding it can mint
an unbounded number of VMs just by connecting with database names nobody has
used yet. That's the right contract for a trusted control plane, and the wrong
one for handing credentials to an application or a customer.

A **dedicated database** is the scoped alternative. An operator provisions
`(database, role, password)` up front, and that credential can open exactly one
database:

- it authenticates with **its own** password, never the shared one;
- asking for any other database name is refused (`42501`) rather than
  provisioned — so these credentials can never create a second VM;
- conversely a dedicated database is reachable **only** through its own role, so
  a shared-password client can't wander into it either.

Below the routing decision nothing is special: the database name is still the
schema key, so the VM is still `pg-<database>` and the idle reaper, the
frozen/compacted/archived tiers, disk growth and the orphan sweeps all treat it
like any other schema. Inside the VM the role is created `NOSUPERUSER
NOCREATEDB NOCREATEROLE` and owns its database — full control of its own data,
no path to anything else — and it is re-created on every bring-up, so a thaw or
an S3 restore (which rebuilds the cluster from a dump that carries no roles)
comes back with the role, its password, and the tenant's ownership intact.

Provision over the admin API, which lives on the **dashboard's** listener and
behind the same Basic auth (so `PG_VM_POOL_DASHBOARD_LISTEN` must be set):

```sh
# username defaults to the database name; password is generated if omitted
curl -u admin:secret -X POST http://127.0.0.1:8080/api/databases \
     -H 'content-type: application/json' -d '{"database":"acme"}'
# -> 201 {"database":"acme","username":"acme","password":"WyGF0n32yJJgdzQVYRi7rrlv",
#         "status":"provisioning","created_at":1787086289}

curl -u admin:secret http://127.0.0.1:8080/api/databases          # list (no passwords)
curl -u admin:secret -X DELETE http://127.0.0.1:8080/api/databases/acme   # revoke
```

The same operations are on the dashboard's **dedicated** page, including a form
that generates the password and shows it once.

The client then connects like any other Postgres endpoint, with its own
credentials:

```sh
psql "host=pooler.example.com port=6432 user=acme dbname=acme"   # PGPASSWORD=…
```

Notes:

- The password is returned exactly once, at provisioning. It is stored in
  cleartext in `PG_VM_POOL_DEDICATED_FILE` (mode `0600`, default
  `<state dir>/dedicated.tsv`) — that file is where to look if it's lost, and
  it's why the pooler's state directory should not be world-readable. Pair this
  with TLS for the same reason as `PG_VM_POOL_PASSWORD`: the challenge is
  cleartext on the wire.
- Names are strict — lowercase letters, digits and underscores, starting with a
  letter, ≤63 bytes — because the name becomes a Postgres identifier, a VM name,
  a dump/image filename and an S3 key. `pg_`/`spare` prefixes and Postgres'
  catalog databases are rejected.
- Provisioning a name the pooler has **already** backed as an ordinary schema is
  refused: that VM holds someone else's data.
- The VM is built by a background bring-up right after provisioning, so the
  first real client connection is usually warm; it isn't required to be — a
  client can connect immediately and just waits for the cold start.
- Revoking is **non-destructive**: it removes the credential only. The VM, its
  disk and its data are untouched, and the name drops back to ordinary schema
  routing — which is also how an operator gets at the data afterwards. Reclaim
  the storage with the existing reap/purge controls.

### Cross-host replication

A dedicated database on one pg-fc host can be replicated, continuously, to a
second pg-fc host. The flow is: provision the database on node A as usual, add
node B as a **peer**, then start replication from node A's `/replication` page.
Node B builds a VM for the same database, seeds it, and follows.

Upgrade the guest image as well as the host binary. The image must contain
the current `init.sh` support for `/workspace/heyvm-replication`; older images
can keep `wal_level=minimal` after pg-fc requests replication. Verify the
marker and locale survive a cold boot on a disposable data disk before
changing a service database.

```
node A (primary)                              node B (replica)
  pg-acme VM, wal_level=logical                 pg-acme VM
  PUBLICATION pgfc_pub_acme                     SUBSCRIPTION pgfc_sub_acme
  role acme_pgfcrepl (REPLICATION)                      │
             ▲                                          │
             └──── A's pooler :6432 ◄──── walreceiver ───┘
```

It is **logical** replication, not a physical standby, and that choice has
consequences worth reading before you rely on it — see "What it does not
carry" below.

The logical replica's walreceiver connects to node A's ordinary pooler listener like any other
client: the pooler challenges it for the replication login's password, the
`dbname` routes it to the right VM, and the raw StartupMessage (including
`replication=database`) is replayed upstream verbatim. So the only network
requirement is that node A's `PG_VM_POOL_LISTEN` is reachable from node B.

The listener also accepts **physical replication protocol** connections from
a registered replication login on an active or syncing primary pairing. In
this mode PostgreSQL ignores `dbname`, so the authenticated login selects its
bound database VM, regardless of the client's database parameter. Tenant and
shared credentials cannot request this mode. The bound VM's hard fence denies
it; a selective fence allows the replication login to reconnect. Upstream
PostgreSQL must also allow physical replication in `pg_hba.conf` (a `host all`
rule does not cover it). The original startup packet is forwarded unchanged.
Existing pairings remain logical until explicitly migrated. Physical candidate
preparation is a separate, authenticated operation; it does not promote or
replace a serving database.

#### Preparing a physical replacement

Upgrade the host binary on both peers and build the new guest image with the
**same PostgreSQL major as the source**. `physical.sh` must be installed as
`/usr/local/bin/pg-fc-physical`. Guest boot now refuses to initialize a database
when its persistent volume is missing, keeping only the management console up.
The release artifact includes checksummed guest build inputs alongside the
host binary. The guest requires the full `python3` package: `python3-minimal`
does not provide `ctypes`, used to parse credentials with libpq. Run
`python3 pg-fc/deploy/test_physical_seed.py` from the repository root to test
the production guest Dockerfile with PostgreSQL 18, including TTY status output
and retry after a helper exits unexpectedly.

On the existing logical primary, POST `/api/replication/<database>/physical-prepare`
with `{"generation":"<unique-lowercase-operation-id>"}`. Repeating that request
resumes the same operation. The source durably owns a separate physical slot
before creating it; the existing logical slot and serving databases remain
untouched. Both peers must advertise physical preparation support.

The peer creates a distinct `repl-seed-<generation>` VM, records its ownership,
and runs `pg_basebackup` under an exclusive guest lock. A durable plan inhibits
ordinary initialization until backup validation and activation succeed. Verify
progress with GET `/api/replication/<database>/physical` on the replica. The
`verified` phase requires the expected system identifier, recovery/read-only
mode, source sender and slot, database/role, and replay position. After guest
startup, verification waits within the setup deadline for streaming and replay
to become ready; command errors or malformed probe output still fail immediately.
It does not change the serving VM binding. Existing eu1 logical or libvirt
databases are not seed targets.

Errors retain ownership and lifecycle protection. If creation was attempted
but the daemon has no visible record yet, retries refuse a second create.
While candidates exist, destructive cleanup is conservatively blocked,
including pending-creation and orphan-disk cleanup. Logical promote/detach
cannot remove credentials or slots owned by an ongoing physical migration.
Preparation itself does not activate the candidate. A planned handoff is a
separate controller operation described below.

#### Recovering a lost preparation as a standby

When the logical pairing is already `failed` and both its logical slot and the
prior physical slot report `wal_status=lost`, POST
`/api/replication/<database>/physical-reseed` on the still-running writer with
`{"generation":"<new-unique-generation>","prior_generation":"<failed-generation>"}`.
This separately authorized operation checks the live primary identity,
`wal_level`, replication login, pairing identity, and lost slots. It archives
the previous source and candidate intents without deleting their slots, VMs,
or bound replica and then uses the normal `pg_basebackup` seed machinery. A
retry of the same generation resumes its exact candidate; it cannot create a
second candidate after an ambiguous create.

After the new candidate reaches `verified`, POST
`/api/replication/<database>/physical-standby-bind` on the writer with the same
generation. The source remains unfenced and writable. The destination persists
`standby-binding`, verifies the exact source identity and fresh source LSN,
waits for replay, CASes the old destination binding to the exact candidate,
clears the warm cache, reattaches by VM ID, and persists `standby`. Recovery
retries only a durable `standby-binding`; it never promotes it. The old logical
record remains `failed`, and all old VM ownership remains in journal history.
The standby serves locally in recovery/read-only mode and is not `activated` or
writer authority. A later handoff still requires the ordinary explicit source
grant and fence. This recovery path therefore makes no zero-downtime writer
failover claim.

#### Retiring a replaced bootstrap logical replica

For an initial physical preparation (`predecessor` absent), ordinary tenant
connections continue forwarding to the source writer before, during, and after
standby binding. The bound physical guest remains read-only; binding it does
not promote it. Both peers must advertise `physical_standby_writer_routing`
before a bootstrap standby bind is accepted. Upgrade both poolers first; do not
downgrade either to the legacy local-read-only routing while this binding is in
service. Reseeded standbys retain their existing local read-only behavior.

After binding and verifying the physical standby, POST on the source writer:

```text
/api/replication/<database>/retire-previous
{"generation":"<exact-generation>","previous_vm_id":"<old-logical-vm>","candidate_id":"<retained-physical-vm>"}
```

This is an explicit destructive operation for the previous bootstrap logical
replica only. It refuses a serving binding, any current or historical physical
source/candidate VM, and mismatched identities. It verifies the writer and a
streaming standby that has replayed a fresh source LSN, journals the previous
guest's creation timestamp and PostgreSQL system identifier, closes its tenant
database to new connections, and refuses deletion while clients, prepared
transactions, or other user databases remain. Existing clients are not killed.
It deletes only the named VM and confirms absence before recording completion.
Missing creation identity or uncertain daemon responses fail closed.

Retry the identical request after interruption; no background deletion starts
without this request. Completed VM retirement is never repeated. The source
then removes only the old, inactive logical slot. A still-active slot reports
incomplete cleanup and needs the same request retried. The physical slot,
shared replication login, and all ownership history remain intact. The logical
record remains compatibility metadata, not proof of physical-stream health.
`GET /api/replication/<database>/physical` exposes the retirement receipt.
Once a retirement is journaled, older poolers cannot read that new journal
field; binary rollback must retain support for it.

This does not retire an entire database or a former physical writer. For
consumer investigation, `GET /api/schemas/<database>/sessions` returns session
identities from the currently bound, already-warm VM, without SQL text or
credentials. An unavailable/cold VM is an error, never an empty-session proof.

#### Planned physical handoff

POST `/api/replication/<database>/physical-handoff` on the source with the
exact generation, candidate ID, source node/VM, system identifier, PostgreSQL
major, and an initially informational `barrier_lsn` (use `0/0`). Obtain the
identity fields from GET `/api/replication/<database>/physical` on the candidate
region; the response includes no replication credentials. The controller re-reads
the candidate from the trusted peer and durably authorizes that exact candidate
before fencing. It then fences and drains the exact source VM,
captures the authoritative flushed WAL barrier, then durably and irrevocably
grants only that peer/candidate/generation/barrier. Ordinary unfence is refused
once candidate authorization is saved, even before the grant. Request failure
or disconnection does not cancel an accepted handoff. A controller worker scans
every five seconds, including after restart, and retries authorized source
operations and destination `prepared` through `binding` operations. A merely
`verified` standby never promotes automatically. Completed source requests are
acknowledged durably and removed from the retry set, not from ownership history.

The destination independently reads that grant through the authenticated peer
API and persists its barrier before any guest transition. Subsequent retries
use that durable authorization even if the source is offline, and reject a
different barrier. It journals `prepared`, `promoting`, `promoted`, `binding`, and
`activated` around guest preparation/promotion, the fsynced expected-old to
candidate registry CAS, stale warm-entry removal, logical metadata retirement,
and explicit admission open. Until `activated`, ordinary client admission is
fail-closed. After activation, checkout attaches the exact candidate ID via the
no-DDL fenced attach path; a mismatched registry binding is refused. The old
logical VM remains owned and is not stopped, overwritten, or deleted.

This protocol is operator-driven planned handoff, not automatic failover.
For switch-back, call `physical-prepare` on the activated writer with a new
generation. Both peers must advertise `physical_successor`. The request links
the new operation to the preceding activation and source grant, retains the
replication credential, and seeds a fresh VM in the other region. It never
reuses or rewinds a former writer. Repeat `physical-handoff` after verification.
Current operations and immutable history are persisted together; an old VM's
grant permanently revokes that VM even after later switches. Stale requests
and queued seed workers cannot mutate a newer generation.

Physical sources own their durable fences independently of logical replication
metadata. Before handoff authorization, `unfence` invalidates the saved barrier
before reopening admission. After authorization the operation must finish; after
a grant reopening that source VM is permanently forbidden. An
ambiguous journal directory-sync failure stops the controller so restart reloads
disk state instead of continuing with stale in-memory authorization.

Cleanup, external secret DSNs, and regional/application routing remain outside
the controller operation.

#### Stable region-local SQL endpoints

For dedicated tenants participating in physical handoff, the regional pooler
routes new ordinary SQL connections to the authorized writer. A verified initial
physical preparation routes to its source; an irrevocable source grant routes
to its exact activated destination. The old guest remains revoked even though
its region's frontend can forward to the new writer. Incomplete handoffs, stale
bindings, mismatched identities, and unavailable peers fail closed.

Forwarding uses a one-hop HTTP/1.1 upgrade on the peer dashboard API with
certificate-verified HTTPS, no redirects, and the existing full-trust dashboard
Basic credentials. These credentials are full administrative access, not an
isolated SQL permission. The receiving endpoint validates tenant and ownership
and can only attach a local writer; it never forwards again. Replication and
maintenance connections are excluded. Sessions remain pinned to one backend;
disconnects never cause SQL or transactions to be replayed. Applications must
reconnect after a handoff, but can retain their region-local connection URL.
This does not move applications, elect a writer during a partition, or implement
regional maintenance orchestration. Prepare both peers before adopting these URLs.

#### Guest promoted-but-fenced transition

`pg-fc-physical` provides a deliberately narrower primitive for an authenticated
controller that has already fenced the source. It is **not standalone failover**:
the helper does not authorize or fence a source, change a serving binding,
admit tenants, route traffic, or rejoin the old primary. The controller supplies
the final source WAL barrier and must not commit serving ownership until the
guest reports `promoted-but-fenced`.

The controller invokes two durable boundaries, with the same environment on
every retry:

```sh
PG_FC_GENERATION=generation-1 PG_FC_SYSTEM_IDENTIFIER=... PG_FC_PG_MAJOR=18 PG_FC_TENANT_DATABASE=tenant_db PG_FC_BARRIER_LSN=0/ABC PG_FC_ADMIN_ROLE=postgres PG_FC_ADMIN_PASSWORD=... /usr/local/bin/pg-fc-physical prepare-promotion
PG_FC_GENERATION=generation-1 PG_FC_SYSTEM_IDENTIFIER=... PG_FC_PG_MAJOR=18 PG_FC_TENANT_DATABASE=tenant_db PG_FC_BARRIER_LSN=0/ABC PG_FC_ADMIN_ROLE=postgres PG_FC_ADMIN_PASSWORD=... /usr/local/bin/pg-fc-physical promote
```

`prepare-promotion` validates the values against the durable seed plan and
cluster, requires the exact database to exist with `ALLOW_CONNECTIONS false`,
and requires a recovering standby whose replay LSN is at or beyond the barrier.
It then atomically writes mode-0600
`/workspace/pg-fc-physical/promotion.json` with the generation, system ID,
PostgreSQL major, database, barrier and phase `prepared`. The password is read
only from the environment and is never included in the operation record,
status, command output, or retained error log.

`promote` changes the record to `promoting` before calling `pg_promote`. It then
verifies recovery ended, identity is unchanged, and tenant admission is still
closed; finally it changes only `PG_FC_ADMIN_ROLE`'s password (the role must
already be a superuser) and records `promoted-but-fenced`. PostgreSQL identifier
and password quoting are performed by PostgreSQL rather than shell SQL
interpolation. Tenant and replication roles are not modified. There is no
guest command to reopen admission.

Both commands and `seed` serialize on `seed.lock`. Once any promotion record
exists, seeding refuses permanently. A retry at `prepared` repeats preflight; a
retry at `promoting` distinguishes recovery from an already-promoted primary,
then resumes credential reconciliation and acknowledgment. A restart with a
valid promotion record remains in physical boot mode: `prepared` still requires
`standby.signal`, while `promoting` and `promoted-but-fenced` accept the same
identity after promotion removed it. Missing, corrupt, extra-field, or
plan-mismatched metadata inhibits PostgreSQL boot and cannot fall through to
ordinary initialization. The durable seed plan and persistent root marker are
retained throughout.

#### Setting it up

On **both** nodes:

```
PG_VM_POOL_REPLICATION=1
PG_VM_POOL_NODE_NAME=node-a              # must differ between the two
PG_VM_POOL_DASHBOARD_LISTEN=0.0.0.0:34199   # the peer drives this
PG_VM_POOL_DASHBOARD_USER=admin
PG_VM_POOL_DASHBOARD_PASSWORD=...
```

On whichever node will be a **primary**, additionally:

```
PG_VM_POOL_LISTEN=0.0.0.0:6432           # the replica's guest dials this
PG_VM_POOL_ADVERTISE_PG_HOST=203.0.113.10   # what a PEER's guest dials to reach it
PG_VM_POOL_TLS_CERT=/path/fullchain.pem     # required: the login crosses the network
PG_VM_POOL_TLS_KEY=/path/privkey.pem
```

`PG_VM_POOL_ADVERTISE_PG_HOST` is deliberately separate from
`PG_VM_POOL_LISTEN`: the listener is usually `0.0.0.0`, which means nothing to
another host. It is resolved to an IPv4 address **on the host** before it ever
reaches a guest, because the microVMs ship with an empty `/etc/resolv.conf` —
the same reason the S3 path pins IPs with `curl --resolve`.

The resolved address is set as both libpq `host` and `hostaddr`, so an inherited
guest `PGHOST` cannot override the TLS server name. Role changes persist a
boot marker and apply the WAL, sender, and slot settings on an in-guest
Postgres restart; restart failures are reported rather than hidden.

Initial schema copy preserves table ownership and privileges. The tenant login
is mirrored before copying, and the publisher's replication role is created as
a non-login ACL grantee. Additional roles referenced by the source schema must
already exist on the replica or the transactional schema copy fails.
Both guest image recipes include HypoPG so schemas using that extension can be
restored. Other extensions must be installed in the replica image before copying;
schema copy does not silently omit an unavailable extension.

Then, on node A's dashboard: add node B under **peers** (its dashboard URL and
Basic credentials, plus the host and port a guest on node A would dial to reach
node B's pooler), pick the database and the peer, and press **start
replicating**. Or over the API:

```sh
curl -u admin:secret -X POST http://127.0.0.1:34199/api/peers \
     -H 'content-type: application/json' \
     -d '{"name":"node_b","base_url":"https://b.example:34199","user":"admin",
          "password":"...","pg_host":"198.51.100.20","pg_port":6432}'

curl -u admin:secret -X POST http://127.0.0.1:34199/api/replication \
     -H 'content-type: application/json' -d '{"database":"acme","peer":"node_b"}'

curl -u admin:secret http://127.0.0.1:34199/api/replication/acme   # state + lag
```

For an operator-coordinated planned switchover, node A also exposes a bounded
source-admission fence (all routes are protected by the same dashboard Basic
authentication):

```sh
curl -u admin:secret -X POST http://127.0.0.1:34199/api/replication/acme/fence
curl -u admin:secret -X POST http://127.0.0.1:34199/api/replication/acme/fence-selective
curl -u admin:secret http://127.0.0.1:34199/api/replication/acme
curl -u admin:secret -X POST http://127.0.0.1:34199/api/replication/acme/unfence
```

`fence` is valid only on a replication primary. It durably records intent,
then uses that VM's private `postgres` maintenance connection to commit
`ALTER DATABASE acme ALLOW_CONNECTIONS false` with `synchronous_commit=on`.
ALTER does not lock out already-admitted startup processes. After its commit,
pg-fc explicitly waits for target database-object lock holders to finish startup,
then freshly classifies and terminates application sessions and waits for their
actual exit. It rejects prepared transactions before and after drain and unknown
database workers, preserving only the walsender positively identified by this
pairing's slot. It then captures one fixed `pg_current_wal_insert_lsn()`, runs
`CHECKPOINT`, and verifies `pg_current_wal_flush_lsn()` reached that barrier.
The successful JSON response contains `database`, `vm_id`, `barrier_lsn`, and
the full replication `record`; GET exposes durable fence phase/error/barrier
under `record.fence` after a restart as well.

Any failure leaves the durable fence in phase `error`; it never auto-unfences.
Because PostgreSQL's database fence is intentionally nonselective, logical
replication may disconnect and cannot reconnect while fenced. That is an
abort/unfence/retry condition, not permission to reopen the source for
catch-up. `unfence` durably invalidates any ready barrier, explicitly restores
`ALLOW_CONNECTIONS true` through the maintenance database with synchronous
commit, then clears the durable intent.
Neither endpoint promotes a replica, drops replication objects, or authorizes
target writes. The barrier is local source durability evidence only; a later
coordinator must prove the replica applied that exact LSN before handoff.

`fence-selective` is the explicit reversible-handoff variant for dedicated,
unprivileged tenants. The ordinary `fence` remains the hard default, and a hard
fence must be explicitly unfenced before selective mode can be requested.
Selective mode durably records its mode and bound VM, sets the database owner
`NOLOGIN`, revokes database `CONNECT` from both `PUBLIC` and the owner, and
grants it only to the pairing's exact replication role. The frontend continues
to authenticate that role with its replication password and bind it to this
database; all tenant routes are rejected. Before changing admission, pg-fc
rejects alternative LOGIN roles, including inherited/`SET ROLE` ownership,
and privileged tenant roles. Only the controller, tenant owner, and exact
replication login may be login roles in this dedicated cluster. Existing tenant
sessions in other databases are terminated too. Sessions/startups are drained with the same worker,
prepared-transaction, fixed-barrier, checkpoint, and flush checks as the hard
fence while one private controller connection remains attached.

After drain, the controller reads every schema-qualified sequence's actual
`last_value` and `is_called`, plus type/start/min/max/increment/cycle/cache
definition, directly from the sequence and catalogs. It persists that snapshot
with the fixed barrier and VM identity in `record.fence.sequences`; values are
never inferred from table maxima. A ready retry returns the same durable
snapshot/barrier. Controller/Postgres restart recovery reattaches only the
bound VM through the maintenance path and does not run ordinary role DDL, so it
cannot restore tenant `LOGIN`. `unfence` restores owner `LOGIN` and owner
`CONNECT` before clearing durable intent. It does not regrant `PUBLIC` access.
This endpoint deliberately stops at the callable source boundary: it does not
prove target replay, apply sequences, promote, or establish reverse pairing.

Run the PostgreSQL protocol regressions against a disposable PostgreSQL 18
server with `wal_level=logical`, `max_prepared_transactions > 0`, and
`synchronous_commit=off`. Install `pg_recvlogical` for the sender test. The
controller-recovery test uses the mock daemon's fixed guest port, so run the
disposable server on `127.0.0.1:5432` to include it:

```sh
PG_FC_FENCE_TEST_URL=postgres://postgres:password@127.0.0.1:5432/postgres cargo test --locked --manifest-path pg-fc/Cargo.toml postgres_fence -- --ignored --nocapture
```

Selective-fence regressions require an otherwise isolated cluster and run
serially. The restart test requires a disposable Docker container whose name
starts with `heyo-pg-fence-`, using disk-backed PostgreSQL storage, not tmpfs:

```sh
PG_FC_FENCE_TEST_URL=postgres://postgres:password@127.0.0.1:55440/postgres PG_FC_FENCE_RESTART_CONTAINER=heyo-pg-fence-durable-restart cargo test --locked --manifest-path pg-fc/Cargo.toml postgres_selective -- --ignored --test-threads=1
```

What that does, in order — each step durable before the thing it describes
exists, so a crash leaves a retryable row rather than an object nothing names:

1. records the pairing, then switches node A's `pg-acme` VM to
   `wal_level = logical`. That needs a Postgres restart, which is cheap here
   because Postgres is not PID 1 on this image — `pg_ctl restart` bounces the
   database without touching the VM or its disk;
2. creates a `REPLICATION` login, `acme_pgfcrepl`, **separate from the
   tenant's own role** (a `REPLICATION` role can create logical slots, and an
   orphaned slot pins WAL until the disk fills — that must stay outside what a
   leaked tenant password can reach);
3. creates `PUBLICATION pgfc_pub_acme FOR ALL TABLES`, and warns about any
   table with no primary key and no `REPLICA IDENTITY`;
4. asks node B to build the replica. Node B mirrors the *tenant's* credential
   too, so the same connection string works against either node after a
   promote — which is what makes failover a DNS change;
5. node B copies the schema from node A (a detached in-guest
   `pg_dump --schema-only | psql`) and then `CREATE SUBSCRIPTION`, whose
   `create_slot = true` is what actually creates the slot on node A. Until
   that moment node A holds nothing that pins WAL, so a setup that dies
   halfway leaves no disk hazard.

The `/replication` page then shows each pairing's state and, for a primary, how
much WAL its slot is holding.

#### Promoting

**promote** on node B disables and drops the subscription, then re-seeds every
column-owned sequence from the data that arrived (logical replication carries no
sequence values, so without this the first insert after a promote collides).
The database is then an ordinary dedicated database on node B, reachable with
the credentials it already had.

The drop is ordered `DISABLE` → `SET (slot_name = NONE)` → `DROP SUBSCRIPTION`
specifically so it works when node A is **gone**: without the middle statement
`DROP SUBSCRIPTION` tries to drop the slot on the primary and hangs, which is
exactly the failover case.

**detach** on node A drops the publication, the replication login and the slot.
Dropping the slot is the step that must not be skipped.

#### What it does not carry

Logical replication is not a byte-for-byte standby. All of these are real:

- **DDL is not replicated.** A `FOR ALL TABLES` publication picks up new tables
  automatically, but the table must also be created on the replica and pulled
  in with the **refresh** button (`ALTER SUBSCRIPTION … REFRESH PUBLICATION`).
  Column changes must be applied on both nodes by hand. Schema migrations are a
  two-node operation.
- **Sequence values are not replicated.** Promote re-seeds them; an unplanned
  failover does not.
- **A table with no primary key** needs `REPLICA IDENTITY FULL`, or its
  `UPDATE`s and `DELETE`s error at the publisher. Setup warns; it cannot choose
  an identity on the tenant's behalf.
- **Large objects are not replicated.**

#### The hazard: WAL retention

This is the one to understand before turning it on. A replication slot pins WAL
on the primary until its subscriber consumes it. A subscriber that goes away
leaves an *inactive* slot pinning WAL **forever**, and on these VMs a full data
disk is a cluster-wide PANIC with no way back in — even booting to fix it needs
disk.

Three things guard it, in order of who acts:

1. `max_slot_wal_keep_size` in the guest (sized from the live filesystem, the
   same `disk/8` budget as `max_wal_size`). Postgres invalidates the slot
   rather than filling the disk. That forces a re-seed of the replica, which is
   strictly the better failure: lose the replica, keep the primary.
2. The monitor warns first — once per outage, on the events page and in the
   log — when a slot has had no subscriber for
   `PG_VM_POOL_REPL_SLOT_STALE_SECS` or is holding more than
   `PG_VM_POOL_REPL_LAG_WARN_BYTES`.
3. A replicating VM is never stopped in the first place (below).

If a replica is gone for good, **detach the pairing**. Do not just delete it.

#### Interaction with the storage tiers

A database in a live pairing is **pinned**: it is excluded from idle stopping,
compaction, freezing, S3 archiving, purging, disk-pressure eviction and the
dashboard's per-VM stop/reboot/reap buttons, on both nodes. Stopping a primary
drops its walsender and leaves an inactive slot; stopping a replica stops it
consuming, so the primary's slot backs up instead. Both are recoverable only by
a full re-seed.

The practical cost: **a replicated database holds RAM and disk on both hosts,
permanently**. It never ages out. Pinned VMs are also warmed at pooler startup,
before the untracked-VM reaper's first pass could stop them.

A failed pairing releases its live-VM pin, but retains its PostgreSQL replication
settings on subsequent bring-up. Failure does not remove slots or subscriptions;
downgrading a primary to minimal WAL while a logical slot remains prevents
PostgreSQL from starting. Retaining these settings does not mark replication
healthy or retry it. Detach or promote through the replication API to remove
the pairing's database objects before reverting to ordinary settings.

#### Configuration

| var | default | meaning |
|-----|---------|---------|
| `PG_VM_POOL_REPLICATION` | off | `1` enables the feature, its dashboard page and its routes. Turning it **off** does not un-pin existing pairings — those records still protect their VMs |
| `PG_VM_POOL_NODE_NAME` | hostname | this node's name in a pairing; must differ from the peer's (self-peering is refused) and is embedded in slot names |
| `PG_VM_POOL_PEERS_FILE` | `<state dir>/peers.tsv` | peer records. Mode `0600` — it holds another node's admin password |
| `PG_VM_POOL_REPLICATION_FILE` | `<state dir>/replication.tsv` | pairings. Mode `0600` — it holds the replication login's password |
| `PG_VM_POOL_ADVERTISE_PG_HOST` | unset | host/IP a **peer's guests** dial to reach this node's pooler. Required to act as a primary |
| `PG_VM_POOL_ADVERTISE_PG_PORT` | `PG_VM_POOL_LISTEN`'s port | ditto |
| `PG_VM_POOL_REPL_SSLMODE` | `require` | libpq sslmode for the replication link. `require` encrypts but does not authenticate the server — `verify-full` cannot work against a bare IP |
| `PG_VM_POOL_REPL_ALLOW_INSECURE` | off | permit a weaker sslmode, and permit acting as a primary with no TLS. Lab only: the login's password crosses the network on this link |
| `PG_VM_POOL_REPL_PEER_TIMEOUT_SECS` | `20` | bound on any call to a peer's API |
| `PG_VM_POOL_REPL_SETUP_SECS` | `3600` | bound on the in-guest schema copy |
| `PG_VM_POOL_REPL_MONITOR_SECS` | `60` | how often lag and slot health are sampled; `0` disables (the page then shows nothing) |
| `PG_VM_POOL_REPL_SLOT_STALE_SECS` | `3600` | warn once when a slot has had no subscriber this long |
| `PG_VM_POOL_REPL_LAG_WARN_BYTES` | `268435456` | warn once when an inactive slot holds more than this |
| `PG_VM_POOL_REPL_FIX_SEQUENCES` | on | re-seed column-owned sequences during a promote |

#### Security notes

- **Peering is a full trust relationship.** `peers.tsv` holds the peer's
  dashboard Basic password, and that credential can already stop and resize
  every VM on the peer. There is no narrower peer token, for the same reason
  the admin API has none: a second secret to rotate would buy no isolation.
- **The replication login's password reaches further than a tenant's.** It
  lives in `replication.tsv` on both nodes (`0600`), in
  `pg_subscription.subconninfo` on the replica (superuser-readable), and in the
  replica guest's `PGPASSWORD` during the schema copy. It never lands in a file
  on the guest's disk or in any argv, and it is per-database and independently
  revocable — but it is a durable credential, not a short-lived one.
- **TLS terminates at the pooler.** The pooler→VM hop stays plaintext over the
  host-local tap, which is the same boundary every other client has.
- **No automatic failover**, no automatic fencing, no quorum. The
  fence routes described above are operator-driven. The replica is writable
  throughout, so writing to it before a promote is invisible to the primary and
  will conflict. Promoting is an operator's decision.

### TLS

TLS is **off by default** and fully optional: without it the pooler answers the
Postgres `SSLRequest` with `N` and clients proceed in plaintext exactly as
before (`sslmode=prefer` falls back silently; `sslmode=disable` is unaffected).

To enable, point the pooler at a PEM cert chain + private key:

```sh
PG_VM_POOL_TLS_CERT=/path/fullchain.pem \
PG_VM_POOL_TLS_KEY=/path/privkey.pem \
target/release/pg-vm-pool
```

Both must be set together (setting only one is a startup error). With TLS on,
clients that ask get an encrypted session (`sslmode=require` works) and
plaintext clients are **still accepted** — nothing breaks for existing local
consumers. TLS terminates at the pooler; the pooler→VM hop stays plaintext over
the host-local tap.

The cert files are **hot-reloaded**: the pooler stats them before each
handshake and rebuilds its acceptor when they change, so an external renewer
can rotate certs with no pooler restart.

When host-local Traefik owns the certificate, `deploy/sync-traefik-cert.py`
exports the exact hostname's certificate and key from its ACME JSON store.
It validates expiry, hostname, and matching public keys with OpenSSL before
atomically switching a `current` symlink to a protected certificate generation:

```sh
python3 deploy/sync-traefik-cert.py /path/acme.json pg.example.com /etc/pg-fc/tls
```

Point `PG_VM_POOL_TLS_CERT` at `/etc/pg-fc/tls/current/cert.pem` and
`PG_VM_POOL_TLS_KEY` at `/etc/pg-fc/tls/current/key.pem`. Run the exporter
periodically or after certificate renewal. Unchanged material is a no-op;
invalid material leaves the existing certificate in place. The pooler
hot-reloads the exported files without a restart.
The exporter does not modify Traefik's ACME store or request certificates.

With Let's Encrypt/certbot:

```sh
# one-time issuance (needs public DNS -> this host, port 80 free for the challenge)
sudo certbot certonly --standalone -d pg.example.com

# deploy hook: copy renewed certs somewhere the pooler user can read
sudo tee /etc/letsencrypt/renewal-hooks/deploy/pg-vm-pool.sh >/dev/null <<'EOF'
#!/bin/sh
d=/home/sam/.heyo/pg-vm-pool/tls
mkdir -p "$d"
install -o sam -g sam -m 600 "$RENEWED_LINEAGE/fullchain.pem" "$d/fullchain.pem"
install -o sam -g sam -m 600 "$RENEWED_LINEAGE/privkey.pem"  "$d/privkey.pem"
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/pg-vm-pool.sh
# run the copy once by hand after the first issuance, then renewals are automatic
```

Then set `PG_VM_POOL_TLS_CERT`/`KEY` to those copies (see the commented lines
in the supervisor conf). For clients beyond localhost also set
`PG_VM_POOL_LISTEN=0.0.0.0:6432`, open the firewall, and have clients dial the
certificate's hostname (`sslmode=verify-full host=pg.example.com`).

### Dashboard

An optional server-side-rendered admin dashboard runs **inside the pooler
process** (a background task sharing the live registry), so it can show the
pooler's in-memory session counts alongside the daemon's VM inventory. It's
**off by default** and enabled purely by setting a listen address:

```sh
PG_VM_POOL_DASHBOARD_LISTEN=127.0.0.1:8080 \
PG_VM_POOL_DASHBOARD_USER=admin \
PG_VM_POOL_DASHBOARD_PASSWORD=secret \
target/release/pg-vm-pool
```

What it gives you (browse to the listen address):

- **VM/session overview** (`/`) — every heyvmd sandbox, with power state,
  allocated size (vCPU/RAM), uptime, and live pooler sessions. Pooler-managed
  `pg-<schema>` VMs are grouped first and link to a detail page.
- **Monitoring** (`/monitoring`) — whole-**host** health: total CPU % and
  memory % (from heyvmd's own `/system/usage` sampler) and **disk saturation**
  per host filesystem (read directly on the host with `df`, since the pooler
  runs alongside heyvmd), each shown as a color-banded meter. Below that,
  pooler-fleet aggregates (running VMs, warm/queueing, live sessions, allocated
  vCPU/RAM, guest CPU) rolled up from the same inventory the overview uses —
  still no guest access. Then per-hour activity charts, and beside the "VMs
  created" chart the **create-latency percentiles** (below). This page also
  configures **webhook alerts** (below).
- **Detail page** — full daemon config (size class + resources, image, region,
  guest IP, TTL, status) plus live **database size and backend count**, read
  over the pooler's own warm Postgres connection (a normal query, not a guest
  command).
- **Dedicated databases** (`/dedicated`) — provision a database with its own
  role and password (a credential that can never create a second VM), list what
  is provisioned, and revoke. The same operations are available as JSON at
  `/api/databases` on this listener, behind the same Basic auth — see
  "Dedicated databases" above.
- **Replication** (`/replication`) — cross-host logical replication: trusted
  peer nodes, every pairing this node is part of with its state and lag, and
  the controls to start one, refresh it, promote a replica or detach. Same
  operations as JSON at `/api/replication` and `/api/peers` — see
  "Cross-host replication" above.
- **JSON admin API** (`/api/…`) — everything above, for programs (app-lb's
  pg-fc plugin reads it). See "JSON admin API" below.
- **Logs** — tail the pooler log (`/logs/pooler`), the heyvmd log
  (`/logs/heyvmd`), and any VM's in-guest Postgres log (`/logs/vm/<id>`).
- **Controls** — stop / start / reboot / resize any VM from its detail page.
  Note that a pooler-managed VM stopped here auto-restarts on the next client
  connection, and a resize takes effect on the VM's next boot.

The browsable pages (index + detail) perform **no in-guest command execution** —
they read only the daemon inventory and the pooler's own PG pool, so viewing or
refreshing a VM never disturbs it. The one exception is the per-VM Postgres log
page (`/logs/vm/<id>`), which runs `tail` inside the guest and is therefore a
deliberate, explicitly-navigated action rather than part of the detail view.
Every daemon and guest call is timeout-bounded, so one wedged VM can't hang a
page. Access is gated by HTTP **Basic auth** when
`PG_VM_POOL_DASHBOARD_USER`/`PASSWORD` are set (they must be set together, or
startup fails). The dashboard can stop and resize **every** VM on the host, so
prefer a loopback/private `PG_VM_POOL_DASHBOARD_LISTEN`; binding it to a
non-loopback address without Basic auth logs a startup warning. The two log
paths default to the supervisord locations above and are overridable with
`PG_VM_POOL_POOLER_LOG` / `PG_VM_POOL_HEYVMD_LOG`.

#### VM create latency (p50 / p95 / p99)

Next to the "VMs created" chart the monitoring page reports how long a create
actually took over the same trailing 24 hours: p50, p95, p99, the slowest
sample, and — as prominently — how many creates those came from. Sample count
is part of the reading, not a footnote: a p99 over four creates is the slowest
of four creates, and the tile says "too few samples" below the threshold where
nearest-rank can separate that percentile from the maximum (20 samples for p95,
100 for p99).

What is measured is the daemon accepting the deploy through the VM reporting
ready. Two deliberate exclusions:

- **The wait for a bring-up slot.** That measures how many creates are already
  in flight (`PG_VM_POOL_MAX_CONCURRENT_BRINGUPS`), so folding it in would make
  the percentiles a function of concurrency rather than of how fast heyvmd
  builds a VM. Queue depth already has its own tile ("bring-ups queued").
- **Failed creates.** A create that times out is bounded by
  `PG_VM_POOL_READY_TIMEOUT_SECS`, not by the daemon's speed, so counting it
  would drag every percentile toward that ceiling and hide what a working
  create costs. Successes only, paired 1:1 with the chart above.

Percentiles are **nearest-rank**, so every figure shown is a create that
actually happened rather than an interpolated value no create ever took.

Samples land in `timings-YYYY-MM-DD.tsv` under the metrics dir — a third
partitioned series alongside `events-*.tsv` and `journal-*.tsv`, same daily
rotation and same retention — and are reloaded at startup, so the percentiles
survive a pooler restart. They are kept in their own files rather than as an
extra column on the event lines so the event format is unchanged: roll back to
an older binary and it still reads its charts, simply ignoring the timing
files. The same numbers are also in the pooler log, one line per create
(`created VM pg-<schema> in …`).

#### Restore latency (time to a serving Postgres)

Under the two restore charts the monitoring page reports, over the same
trailing 24 hours, how long a restore took to reach a Postgres serving the
client — one row per source, because the four have nothing in common to
average:

| source | what it does |
| --- | --- |
| S3 disk image | download `{prefix}{schema}.img.zst`, decompress, swap the disk under a vehicle VM, boot on it |
| S3 dump | bring a VM up, `CREATE DATABASE`, then the guest's `curl \| pg_restore` |
| local image (compacted) | the S3 image path minus the download |
| local dump (frozen) | the S3 dump path minus the download |

Read the two image rows against each other: everything after the download is
identical work, so the gap between them is what fetching from the bucket costs.
The note under the table splits an image restore further, into the download and
everything after it (decompress, `e2fsck`, disk swap, boot) — which is the
reading that separates "the bucket is slow" from "this host is busy", and points
at what to tune: the bucket's throughput on one side, or the run-dir filesystem
(the decompress and the in-place copy are disk-bound) and the spare pool that
supplies the vehicle on the other. For that last one, check **chilled-vehicle
depth** before anything else: an adopt figure several seconds above the work it
describes usually means the shelf was empty and every restore in the window
paid to stop a running spare and wait out its disk release.

Bounded exactly as the create figures are: the admission wait is excluded (it
measures how many other clients arrived at once, not what this restore costs),
only restores that finished are counted, and percentiles are nearest-rank, so
every figure is a restore someone actually waited through. A source with no
restores in the window shows dashes rather than zeros, and a window too thin to
support a percentile marks it rather than printing the maximum three times.
Samples share the `timings-*.tsv` partitions with the create figures, so they
survive a restart the same way; the download phase is recorded even when the
restore that follows it fails, since the bytes still moved.

#### Webhook alerts

The monitoring page can watch the basic host metrics and POST a webhook when one
crosses a threshold. Add a rule (metric = host CPU %, host memory %, disk
saturation %, or the daemon health check; a threshold; and a URL) from the
page's **alerts** panel. Rules are edited in place (change the metric,
threshold, or URL and save) and can be **paused** — a paused rule keeps its
config but is skipped by the evaluator until resumed (resuming re-triggers if
the metric is still over). A background task samples the same host metrics every
`PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS` (default 60) and, on a crossing,
`POST`s a small JSON body to the URL — **once** on the rising edge
(`"state":"triggered"`) and once when it falls back (`"state":"resolved"`), not
every interval while it stays over. The disk rule watches the fullest host
filesystem. Example body:

```json
{"source":"pg-vm-pool","host":"pool-1","rule_id":"q7m2…","metric":"disk",
 "state":"triggered","threshold_pct":90.0,"value_pct":93.4,"detail":"/"}
```

The **daemon health check** metric is the odd one out: each tick the evaluator
probes heyvmd's `GET /health` (5s bound), and the rule's threshold counts
**consecutive failed probes** rather than a percentage — a threshold of 3 means
"webhook me once the daemon has been silent for 3 straight intervals". That's
the same signal the supervisor watchdog keys on, so set the alert threshold
below the watchdog's restart threshold to get warned before a (VM-killing)
daemon restart; `detail` carries the probe error and the payload keeps the
`_pct` keys for wire compatibility.

Delivery shells out to `curl` (no extra HTTP dependency); a failed or slow
endpoint is logged and never blocks the pooler. Rules persist to
`PG_VM_POOL_DASHBOARD_ALERTS_FILE` (default `~/.heyo/pg-vm-pool/alerts.tsv`, a
sibling of the schema registry) and survive restarts — including the paused
flag; the firing state is in-memory, so a restart re-evaluates cleanly rather
than replaying a stale edge.

### JSON admin API

The dashboard listener also serves a JSON API with the same reads and
actions as the pages, behind the same Basic auth. It is keyed by **schema**
(the database name clients connect with) rather than sandbox id, because a
schema outlives its VMs: an offload deletes the VM and a restore creates a
new one. The wire types live in the `pg-fc-api` crate (`api/`), which
app-lb's pg-fc plugin depends on too, so the two sides cannot drift.

| Route | What it does |
|---|---|
| `GET /api/health` | Version, uptime, listen address, warm/known schema counts, configured tiers. In-memory only. |
| `GET /api/schemas[?tier=&q=]` | Every schema on every tier (`live`, `compacted`, `frozen`, `archived`, `pending`; `warm` filters to checked-in VMs), with sessions, slots and idle time when warm. |
| `GET /api/schemas/{schema}` | One schema, plus live `db_size_bytes`/`backends` when warm. |
| `POST /api/schemas/{schema}/{start,stop,reboot,resize,reap,restore,archive-image}` | The VM page's buttons. `resize` takes `{"size_class":"small"}`. Returns 409 for a pinned schema, or for a power action on an offloaded one. The long actions answer 202 and report in `/api/events`. |
| `GET /api/host` | Host CPU/memory, disks, spare shelf, and schema counts by tier. |
| `GET /api/events[?limit=&since=]` | The events journal, newest first. |
| `GET /api/logs/{pooler,heyvmd}[?lines=]` and `GET /api/logs/schema/{schema}` | Log tails as JSON lines. The schema log is read from inside the VM. |
| `POST /api/maintenance/{sweep,ttl-sweep,reclaim,stop-idle,purge}` | The monitoring page's buttons. `ttl-sweep` takes `{"ttl_secs":N}`. |
| `GET /api/config`, `PUT /api/config` | Runtime configuration (below). |

#### Runtime configuration

A few knobs can change without a restart, which would drop every client
session on the host:

- `idle_timeout_secs`, `idle_timeout_fast_secs` (`0` turns the short timeout off)
- `warm_spares`
- `compact_after_secs`, `freeze_after_secs`, `archive_after_secs`

`PUT /api/config` takes any subset of them; absent fields are left unchanged.
The loops that use these knobs re-read them on every pass. Overrides are saved
to `runtime-config.json` beside the registry file and applied over the
environment at boot, so they survive a restart.

`GET` reports each knob's effective value and where it came from (`override`,
`env` or `default`). It also lists the env-only settings as read-only.

A knob can only change if its subsystem was on at boot. For example, if
`PG_VM_POOL_ARCHIVE_AFTER_SECS` was unset, the S3 tier has no loop and no
credentials, so `archive_after_secs` is refused with a 400 until you set the
variable and restart.

```sh
curl -u admin:secret http://127.0.0.1:8080/api/config
curl -u admin:secret -X PUT http://127.0.0.1:8080/api/config \
  -H 'content-type: application/json' -d '{"idle_timeout_secs": 300}'
```

### Testing

`examples/e2e.rs` and `examples/e2e_concurrent.rs` are end-to-end tests that
exercise the full stack through a real client connection — not mocks: pooler
routing, daemon VM create/stop/restart, and per-VM persistent disks.

- `e2e.rs` drives one schema through several stop/restart cycles and
  hard-asserts each restart actually comes back healthy (the `/dev/vdb` data
  drive is still attached, and the guest's Postgres port is reachable) before
  checking the rows written earlier survived.
- `e2e_concurrent.rs` runs that same create/write/stop/restart/verify cycle for
  several schemas (default 5) **at the same time**, each with distinct data,
  to prove concurrent VMs don't cross-wire and the pooler restarts them all in
  parallel.

- `e2e_replication.rs` needs **two** nodes, because the thing under test is
  the pairing between them: it provisions a dedicated database on node A,
  starts replication to node B, and asserts the initial copy, streaming, the
  promote (including the sequence re-seed) and that detach leaves no
  replication slot behind. It also asserts what replication does *not* do —
  a column added on A must not appear on B — so the documented DDL limitation
  cannot quietly change under the README.

Prereqs: a running pooler (`target/release/pg-vm-pool`, default
`127.0.0.1:6432`) and a running local heyvmd daemon. Then:

```sh
cargo run --release --example e2e
cargo run --release --example e2e_concurrent

# two nodes, both with replication enabled and their dashboards reachable
A_DASH=https://a.example:34199 A_USER=admin A_PASS=... A_PG=a.example:6432 \
B_DASH=https://b.example:34199 B_USER=admin B_PASS=... B_PG=b.example:6432 \
PEER_PG_HOST=198.51.100.20 \
    cargo run --release --example e2e_replication
```

Useful env vars: `E2E_ROWS`, `E2E_CYCLES` (e2e.rs), `E2E_VMS` (e2e_concurrent.rs),
`E2E_STOP_MODE=cli|sdk` (`cli` reproduces a manual/out-of-band stop via
`heyvm stop`, the default and the path that catches the restart-silently-no-ops
bug; `sdk` is the cooperative stop path), and `E2E_KEEP=1` to keep the test
VM(s) around instead of deleting them at the end. See the doc comments at the
top of each file for the full list.

### Cold-start load harness (`src/loadtest.rs`)

The e2e examples prove the stack is *correct*; this one measures what it costs
as the host fills up. A fresh host serves a new schema in about a second; a
host tracking thousands of sandboxes takes far longer, with the daemon showing
no sign of the request for most of it and host CPU under 20%. That is latency
scaling with *inventory* rather than with load, and it cannot be reproduced
against a real daemon without first creating thousands of real VMs.

So the harness stands up an in-process heyvmd stub holding a synthetic fleet of
any size and points the whole pooler at it with `PG_VM_POOL_DAEMON_URL`. Every
path under test is the real one — the same `resolve_sandbox`, store, and gates
— but the daemon's own VM-building cost is zero, so whatever latency remains is
the pooler's own bookkeeping. The stub also counts every request and byte it
serves, which is the direct measure of how much daemon work one new VM costs
and whether that cost depends on how many VMs already exist.

```sh
cargo test --release loadtest -- --ignored --nocapture --test-threads=1
```

- `cold_start_cost_versus_fleet_size` holds concurrency fixed and varies the
  fleet, for both a never-seen schema and one already bound to a VM in the
  store. The two curves separate the find-by-name path from the reattach path.
- `cold_start_cost_versus_concurrency` is the control: fixed fleet, varying
  arrival rate.
- `one_cold_start_must_not_cost_the_whole_inventory` is the regression guard
  for keeping the cold path O(1) in fleet size. It runs in the normal suite
  (it was the acceptance criterion for the by-name work below, and holds now).

The harness's own self-checks (that the stub really is the daemon the pooler
talks to, and that the counters count) run in the normal suite.

### The by-name cold path and the inventory cache

Resolving a schema the pooler has never served used to pull the ENTIRE
`GET /deployed-sandboxes` inventory just to find its VM by name — ~1MB per
cold start at a fleet of 5000, serialized behind a busy daemon (the measured
production shape: p95 ≈ 25s at 32 concurrent bring-ups). Two pieces replaced
that:

- **By-name daemon lookup** (`vm::find_by_name_with_retry`): the cold path
  asks `GET /deployed-sandboxes?name=<exact>` — a current heyvmd answers off
  its name index with at most one entry. An old daemon ignores the query and
  returns the full list; the exact match is picked client-side either way, so
  no version negotiation is needed and either side can ship first.
- **Positive-only name→id cache** (`src/inventory.rs`): warmed by every
  listing the pooler pays for anywhere and written through on create/claim/
  kill. A hit skips daemon traffic entirely (verified by id — stale entries
  self-evict); a *miss* always goes to the authoritative by-name lookup before
  any create, because heyvmd does not enforce name uniqueness and a duplicate
  VM would mean a fresh empty data disk under a schema that has data. If the
  daemon is unreachable the bring-up fails, as it always has — it never
  creates blind.
