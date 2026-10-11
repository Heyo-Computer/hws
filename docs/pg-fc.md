# pg-fc: Postgres on microVMs

pg-fc runs one Firecracker microVM per Postgres database behind a single pooler endpoint on `:6432`, stopping idle databases and moving cold ones to cheaper storage tiers until the next client connects.

## What it is

pg-fc has two parts:

| Part | What it does |
|---|---|
| Postgres guest image (`Dockerfile`, `Dockerfile.pg18`, `init.sh`) | A Debian rootfs that boots straight into Postgres. All database state lives on a separate data disk mounted at `/workspace`. |
| `pg-vm-pool` (`src/`) | A Postgres wire-protocol pooler. The database name in a client's connection string selects a *schema*; the pooler finds, restarts or creates the VM `pg-<schema>` and splices the connection through to it. |

The pooler drives VMs through the local heyvm daemon (`heyvmd`) HTTP API, the same one [app-lb](app-lb.md) uses. It also serves an optional admin dashboard and JSON API. app-lb's `pgfc` plugin reads that API (see [app-lb](app-lb.md) and the [plugin reference](../app-lb/README.md#pg-fc-databases-pgfc)).

```text
client ──► pg-vm-pool :6432 ──► pg-<schema> VM :5432   (one VM per database)
                │                    │
                │                    └── /workspace data disk (per schema)
                ├── heyvmd API :34099 (create / start / stop / resize VMs)
                └── dashboard + JSON API (optional, PG_VM_POOL_DASHBOARD_LISTEN)
```

The lifecycle of one schema:

| Tier | Where the data is | What a connect costs |
|---|---|---|
| warm | running VM | nothing, the pooler splices immediately |
| stopped (`live`) | stopped VM's `data.ext4` | a daemon `start()` and Postgres startup |
| `compacted` | trimmed, zstd-compressed disk image in `PG_VM_POOL_COMPACT_DIR` | decompress onto a fresh VM disk, then boot |
| `frozen` | `pg_dump` file in `PG_VM_POOL_DUMP_DIR` | fresh VM plus `pg_restore` |
| `archived` | S3 object (`.img.zst` image or `.dump`) | download, then as above |

Every tier except warm is opt-in. With no tier variables set, pg-fc only stops idle VMs.

## Requirements

Linux with KVM only.

| To... | You need |
|---|---|
| Build the guest image | Docker, `e2fsprogs`, root (`build-rootfs.sh` loop-mounts the image), or `heyvm mvm build` |
| Run the pooler | Rust toolchain (edition 2024), Firecracker with `/dev/kvm` access, a running `heyvmd` (or `heyvm --api --port 34099`) |
| Use the compacted or image-archive tiers | `zstd`, and ideally `e2fsck` and `debugfs`, on the host |
| Use the S3 tier | An S3 or S3-compatible bucket, and guest egress to it |

## Build

### Guest image

The pooler boots VMs from the heyvm image named by `PG_VM_POOL_IMAGE` (default `pg`). Build it with heyvm:

```sh
cd pg-fc
heyvm mvm build --local-only -f Dockerfile.pg18 --name pg
```

`Dockerfile` defaults to PostgreSQL 16 (`ARG PG_MAJOR=16`). `Dockerfile.pg18` builds PostgreSQL 18. Pick one major for every host that shares an S3 bucket: a data directory initialized by one major can't be opened by the other, so a host running a different major can't restore the other hosts' archives. See [the major-mismatch runbook](../pg-fc/docs/runbook-pg-major-mismatch.md).

To build a raw ext4 rootfs for use without heyvm:

```sh
PG_MAJOR=18 ./build-rootfs.sh pg-rootfs.ext4 2G
```

`build-rootfs.sh` defaults to PostgreSQL 18 and checks that the requested major's `postgres` binary is present in the output.

### Pooler

```sh
cargo build --release --locked --manifest-path pg-fc/Cargo.toml
# binary: pg-fc/target/release/pg-vm-pool
```

The binary takes no flags. Configure it with environment variables. Log verbosity uses `RUST_LOG` (default `info,pg_vm_pool=info`). Unknown `PG_VM_POOL_*` variables log a warning at startup.

## How the guest behaves

- `init.sh` is PID 1. It mounts the data disk (`/dev/vdb`; override with the kernel arg `pgdata_dev=`), formats it on first boot, runs `initdb` into `/workspace/pgdata`, and starts Postgres on `0.0.0.0:5432`.
- The data disk is thin-provisioned. The guest formats a small filesystem (2 GB, kernel arg `pgdata_init_mb=` overrides) and grows it online with `resize2fs` as the database grows, up to the device size.
- Postgres settings are regenerated at every boot from the VM's actual RAM, vCPUs and disk into `$PGDATA/heyvm-tuning.conf`. Put manual overrides in `postgresql.conf`, which is read after it and wins.
- The profile is single-tenant: `wal_level=minimal` (unless replication is on), `synchronous_commit=off`, strict memory overcommit, a swapfile on the data disk, and `temp_file_limit` at a quarter of the disk. The pooler runs `CHECKPOINT` before every idle stop, so a stop does not lose acknowledged commits.
- Guest auth is `trust`. Access control is the pooler's job (see [Client authentication](#client-authentication)).
- The rootfs is recreated from the image on every boot. Anything changed only inside a running guest's rootfs does not survive a restart.

## Running the pooler

With `heyvmd` running and the `pg` image built:

```sh
target/release/pg-vm-pool        # listens on 127.0.0.1:6432

# The dbname selects the VM, creating it on first use:
psql "host=127.0.0.1 port=6432 user=postgres dbname=tenant1"   # -> VM pg-tenant1
psql "host=127.0.0.1 port=6432 user=postgres dbname=tenant2"   # -> VM pg-tenant2
```

The schema-to-VM binding is stored in `PG_VM_POOL_STATE_FILE` (default `~/.heyo/pg-vm-pool/registry.tsv`). This file is the only link between a schema and its VM and disk. If you lose it, every existing schema looks brand new. Back it up, and never run two poolers against the same state directory.

Connection behaviour:

- A connection holds one Postgres backend slot for its whole life. When a VM is full, new clients wait at the pooler for `PG_VM_POOL_ADMIT_TIMEOUT_SECS` instead of getting `too many clients`.
- Both legs of every splice use TCP keepalive (and `TCP_USER_TIMEOUT` on Linux), so a client that vanishes without a FIN releases its slot.
- If Postgres has died inside a VM that still reports running, the next connect detects it and restarts the VM. A Postgres that is recovering (`57P03`) is left alone.
- By default the pooler dials each VM's guest IP directly over the host tap (`PG_VM_POOL_DIRECT_CONNECT`). It falls back to an iroh tunnel if the daemon reports no guest IP.

### As a systemd service

`deploy/pg-fc@.service` is a templated unit:

| Path | Purpose |
|---|---|
| `/usr/local/bin/pg-vm-pool` | the binary |
| `/etc/pg-fc/<node>.env` | non-secret `PG_VM_POOL_*` settings (the unit won't start without it) |
| `/etc/pg-fc/<node>.secrets.env` | secrets, mode `0600` (S3 keys, dashboard password, `HEYO_API_KEY` if heyvmd requires auth) |
| `/var/lib/pg-fc-<node>` | working directory |

Set `PG_VM_POOL_STATE_FILE` explicitly inside the state directory. The working directory alone does not move the registry, which otherwise defaults under `$HOME`.

```sh
sudo install -m 0644 pg-fc/deploy/pg-fc@.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/pg-fc@.service
sudo systemctl daemon-reload
sudo systemctl enable --now pg-fc@node-a
```

The unit does not install heyvm, build the image, open ports or set up replication. On a shared host, leave eviction, orphan sweeping and disk reclamation off until you have decided which process owns which disks.

### As a supervisord program

`deploy/supervisor/pg-vm-pool.conf` is an example program with the full density stack enabled (orphan sweep, periodic reclaim, compacted tier, S3 archive tier, pressure eviction). Its header comment lists the one-time host setup it needs. Paths in it are host-specific, so adapt them before you use it.

Change settings by editing `environment=` and running `supervisorctl reread && supervisorctl update pg-vm-pool`. A plain `restart` does not reload `environment=`. Double-quote values that contain commas.

`deploy/provision-pooler-host.sh` builds a bare Ubuntu machine into a pooler host (storage, heyvm, image, sudoers pin, supervisor). It is idempotent. Its only destructive step, RAID creation, requires `RAID_CREATE=yes` and refuses non-blank devices. It does not configure a firewall.

## Upgrading

Upgrading the pooler binary is **stop, replace, start**. Never start a second copy alongside the running one: two poolers over one state directory both act on the same registry and VMs, and neither knows about the other's sessions.

1. Build or download the new `pg-vm-pool` and check its digest.
2. Stop the service (`systemctl stop pg-fc@<node>` or `supervisorctl stop pg-vm-pool`) and confirm the old PID has exited.
3. Replace the binary in place atomically (write a temporary file, then rename it).
4. Start the service and verify: the running `/proc/<pid>/exe` has the new digest, the registry path it uses is unchanged, and a `SELECT 1` through `:6432` succeeds.
5. If verification fails, stop it, restore the previous binary, start it and verify again.

`deploy/replace_pooler.py` automates exactly this sequence with a journaled receipt and automatic rollback. `deploy/rollout_poolers.py` runs it across several hosts as app-lb update jobs, preflighting every target before replacing any. Clients connected during the upgrade are disconnected. VMs keep running and are re-adopted when the pooler starts.

Upgrade the **guest image** separately, and keep the same PostgreSQL major. Replication features need the current `init.sh`. Test the new image on a disposable data disk before pointing a serving pooler at it.

## Configuration

Every variable is optional. Values are read at startup. A few can also be changed at runtime (see [Runtime configuration](#runtime-configuration)).

### Core

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_LISTEN` | `127.0.0.1:6432` | Client listen address. |
| `PG_VM_POOL_IMAGE` | `pg` | heyvm image for every schema VM. |
| `PG_VM_POOL_SIZE_CLASS` | `micro` | VM size: `micro` (0.25 CPU, 512 MB), `mini` (0.5, 1 GB), `small` (1, 2 GB), `medium` (2, 4 GB), `large` (4, 8 GB). |
| `PG_VM_POOL_DAEMON_URL` | `http://127.0.0.1:34099` | heyvmd API base URL. |
| `PG_VM_POOL_DAEMON_API_KEY` | `HEYO_API_KEY` | Bearer for a daemon that requires one (`heyvm --api` with a key). Sent on every daemon call, including resize, the create gate and create-on-image. |
| `PG_VM_POOL_USER` | `postgres` | Role the pooler uses for probes and bootstrap. |
| `PG_VM_POOL_PASSWORD` | unset | Password for that role, and the password the pooler **requires from clients** when set. Unset means no client auth. |
| `PG_VM_POOL_STATE_FILE` | `~/.heyo/pg-vm-pool/registry.tsv` | Schema-to-VM registry. Its directory is the "state dir" below. |
| `PG_VM_POOL_DEDICATED_FILE` | `<state dir>/dedicated.tsv` | Dedicated database credentials, stored in cleartext, mode `0600`. |
| `PG_VM_POOL_METRICS_DIR` | `<state dir>/metrics` | Daily event, journal and timing files that feed the dashboard charts. |
| `PG_VM_POOL_DATA_DISK_GB` | `2` | Per-schema data device size in GB for a new VM. |
| `PG_VM_POOL_DIRECT_CONNECT` | on | Dial the guest IP directly. `0`, `false` or `no` forces the tunnel. |
| `PG_VM_POOL_KEEPALIVE_SCHEMAS` | none | Comma-separated schemas that are never idle-stopped or offloaded. |

### Timeouts and admission

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_READY_TIMEOUT_SECS` | `300` | Maximum wait for a VM and its Postgres to become ready. |
| `PG_VM_POOL_CONNECT_TIMEOUT_SECS` | `30` | Tunnel handshake limit. |
| `PG_VM_POOL_ADMIT_TIMEOUT_SECS` | `30` | How long a client waits for a free backend slot on a full VM. `0` fails immediately. |
| `PG_VM_POOL_MAX_CONCURRENT_BRINGUPS` | `3` | Maximum VM creates or boots in flight against heyvmd. `0` disables the limit. |
| `PG_VM_POOL_MAX_PENDING_BRINGUPS` | `16` | Maximum whole bring-ups (create through ready or restore) in flight. Excess requests queue FIFO. `0` disables the limit. |
| `PG_VM_POOL_ADMISSION_WAIT_SECS` | `15` | How long a bring-up may wait in that queue before the client is refused with `53300`. `0` waits forever. |

### Idle reaping

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_IDLE_TIMEOUT_SECS` | `900` | Stop a VM after this long with no connections. `0` disables. Jittered ±15% per schema. |
| `PG_VM_POOL_IDLE_TIMEOUT_FAST_SECS` | `60` | Shorter timeout for VMs whose last bring-up was fast. Clamped to the long timeout. `0` disables the two-speed reaper. |
| `PG_VM_POOL_FAST_BRINGUP_SECS` | `5` | A bring-up at or under this many seconds counts as fast. |
| `PG_VM_POOL_IDLE_DRAIN_WINDOW_SECS` | `600` | Shortest time in which the reaper may stop the whole live fleet. Rate-limits mass expiry. `0` disables the limit. |

A schema's first connect creates its VM and gets the long timeout. Later reconnects are cheap restarts and get the short one. When the host is slow, restarts stop being "fast", so the reaper backs off on its own.

### Disk growth

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_DISK_GROW_PCT` | unset (off) | Guest filesystem use (1–99) at which a schema's data device is doubled at idle stop. Setting it turns device growth on. |
| `PG_VM_POOL_DISK_GROW_URGENT_PCT` | `95` | Use at which a *running* VM's device is grown, online if heyvmd supports it and otherwise by stopping the VM. Must be at least `DISK_GROW_PCT`. |
| `PG_VM_POOL_DISK_MAX_GB` | `100` | Growth ceiling (1–250). A full filesystem at this size is logged at error level. |

### Warm spares

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_WARM_SPARES` | `0` | Keep this many pre-booted, `initdb`-complete `spare-pg-*` VMs for cold bring-ups to claim. Each one holds its size class's RAM. |
| `PG_VM_POOL_CHILLED_VEHICLES` | `2` (`0` with no spares) | How many of those spares to park stopped, ready for image restores. Stopped VMs hold disk, not RAM. |

### Offload tiers

The compacted, frozen and S3 tiers share one pacer. It dispatches one job at a time while the host is quiet and yields to queued client bring-ups and reclaim passes.

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_COMPACT_AFTER_SECS` | unset (off) | Compact a schema whose VM has been stopped this long: trim, zstd the disk image, delete the VM. Needs `PG_VM_POOL_RUN_DIR` and `zstd`. |
| `PG_VM_POOL_COMPACT_DIR` | `<state dir>/compact` | Where compacted images live. Needs about 4% of what it drains. |
| `PG_VM_POOL_COMPACT_SWEEP_SECS` | `900` | Re-scan interval after an empty scan. |
| `PG_VM_POOL_FREEZE_AFTER_SECS` | unset (off) | `pg_dump` a schema idle this long to a local file and delete its VM. |
| `PG_VM_POOL_FREEZE_SWEEP_SECS` | `900` | Re-scan interval after an empty scan. |
| `PG_VM_POOL_DUMP_DIR` | `~/.heyo/pg-vm-pool/dumps` | Local dump files. |
| `PG_VM_POOL_DUMP_LISTEN` | `0.0.0.0:6433` | Token-gated dump server that guests reach at their default gateway. |
| `PG_VM_POOL_ARCHIVE_AFTER_SECS` | unset (off) | Move a schema idle this long to S3. Local compacted or frozen files are promoted with no VM boot. Requires the bucket and credentials below, or startup fails. |
| `PG_VM_POOL_ARCHIVE_SWEEP_SECS` | `3600` | Re-scan interval after an empty scan. The shortest configured `*_SWEEP_SECS` is used, clamped to 5–60 s. |
| `PG_VM_POOL_IMAGE_ARCHIVE` | off | `1` uploads a stopped VM's compressed disk image (`.img.zst`) when a dump fails, with no boot needed. Needs the S3 tier and `PG_VM_POOL_RUN_DIR`. |
| `PG_VM_POOL_IMAGE_SPOOL_DIR` | `<state dir>/spool` | Staging area for image uploads. |
| `PG_VM_POOL_OFFLOAD_WORKERS` | `1` | Concurrent offload jobs (1–16). At most one may boot a VM. |
| `PG_VM_POOL_OFFLOAD_LOAD_MAX` | `0.75` | Normalized 1-minute load above which the pacer adds no job beyond the first. |
| `PG_VM_POOL_OFFLOAD_MAX_HOLDOFF_SECS` | `300` | After this long of continuous backpressure, dispatch no-boot jobs anyway. `0` yields indefinitely. |

S3 settings:

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_S3_BUCKET` | unset | Bucket. Required when the S3 tier is on. |
| `PG_VM_POOL_S3_PREFIX` | `pg-vm-pool/` | Key prefix. Objects are `{prefix}{schema}.dump` and `{prefix}{schema}.img.zst`. End it with `/`, and give each host its own prefix. |
| `PG_VM_POOL_S3_LEGACY_PREFIX` | `pg-vm-pool/` when the prefix differs | Read-only fallback prefix for restores. Set it empty to disable. |
| `PG_VM_POOL_S3_REGION` | `us-east-1` | SigV4 region. |
| `PG_VM_POOL_S3_ENDPOINT` | unset (AWS) | S3-compatible endpoint (MinIO, R2). Uses path-style addressing. |
| `PG_VM_POOL_S3_ACCESS_KEY_ID`, `PG_VM_POOL_S3_SECRET_ACCESS_KEY` | unset | Credentials. Fall back to `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. |

The guest streams dump bytes to and from S3 with presigned URLs, so the secret key never leaves the pooler. Empty databases (no user relations) are never uploaded.

### Disk pressure, reclaim and orphans

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_RUN_DIR` | falls back to `PG_VM_POOL_PRESSURE_PATH` | heyvmd's run directory (holds `sb-<id>/`). Required by compaction, image archive and the orphan sweep. |
| `PG_VM_POOL_PRESSURE_PATH` | unset (off) | Filesystem to watch. Setting it enables emergency offload under disk pressure. Needs the S3 tier. |
| `PG_VM_POOL_PRESSURE_HIGH_PCT`, `PG_VM_POOL_PRESSURE_LOW_PCT` | `85`, `75` | Start offloading the coldest schemas at or above high, and stop below low. Low must be below high. |
| `PG_VM_POOL_PRESSURE_CHECK_SECS` | `60` | Pressure check interval. |
| `PG_VM_POOL_RECLAIM_CMD` | unset (off) | Shell command that trims stopped VMs' disks, normally `sudo -n /path/reclaim-disks.sh <run-dir> --shrink --prune-swap`. |
| `PG_VM_POOL_RECLAIM_INTERVAL_SECS` | `3600` | Periodic reclaim interval. An extra run also fires about 30 s after an idle reap, at most once per 5 minutes. |
| `PG_VM_POOL_ORPHAN_SWEEP_SECS` | unset (off) | Interval for deleting `sb-<id>/` directories that heyvmd has forgotten and no live schema owns. Needs `PG_VM_POOL_RUN_DIR`. |

At startup the pooler warns if `PG_VM_POOL_RUN_DIR` contains no `sb-<id>/` directories. A wrong run dir silently disables every disk-reclaiming feature, so check this warning first when disk use doesn't fall.

### TLS and dashboard

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_TLS_CERT`, `PG_VM_POOL_TLS_KEY` | unset (TLS off) | PEM chain and key. Set both or neither. Hot-reloaded when the files change. |
| `PG_VM_POOL_DASHBOARD_LISTEN` | unset (off) | Dashboard and JSON API address. Setting it enables them. |
| `PG_VM_POOL_DASHBOARD_USER`, `PG_VM_POOL_DASHBOARD_PASSWORD` | unset | HTTP Basic credentials. Set both or neither. |
| `PG_VM_POOL_POOLER_LOG` | `/var/log/pg-vm-pool/pg-vm-pool.log` | Pooler log that the dashboard tails. |
| `PG_VM_POOL_HEYVMD_LOG` | `/var/log/heyvmd/heyvmd.log` | heyvmd log that the dashboard tails. |
| `PG_VM_POOL_DASHBOARD_LOG_LINES` | `200` | Lines shown per log. |
| `PG_VM_POOL_DASHBOARD_ALERTS_FILE` | `~/.heyo/pg-vm-pool/alerts.tsv` | Webhook alert rules. |
| `PG_VM_POOL_DASHBOARD_ALERT_INTERVAL_SECS` | `60` | Alert evaluation interval. |

## Client authentication

With `PG_VM_POOL_PASSWORD` unset, anyone who can reach `PG_VM_POOL_LISTEN` is proxied to a VM, and any database name they send creates a new VM. That is only acceptable on loopback.

Set `PG_VM_POOL_PASSWORD` and the pooler sends each client an `AuthenticationCleartextPassword` challenge before dialing any VM. A wrong password gets `28P01`. Because the challenge is cleartext, enable TLS whenever the listener is not loopback. The pooler logs a warning if it isn't.

### TLS

With TLS off, the pooler answers `SSLRequest` with `N` and clients continue in plaintext. With TLS on, clients that request TLS get it, and plaintext clients are still accepted. TLS terminates at the pooler. The pooler-to-VM hop is plaintext over the host-local tap.

```sh
PG_VM_POOL_TLS_CERT=/etc/pg-fc/tls/current/cert.pem \
PG_VM_POOL_TLS_KEY=/etc/pg-fc/tls/current/key.pem \
target/release/pg-vm-pool
```

The cert files are re-read before each handshake when they change, so renewals need no restart. If Traefik on the same host owns the certificate, `deploy/sync-traefik-cert.py <acme.json> <hostname> <out-dir>` exports and validates it into `<out-dir>/current/`. Run it periodically.

### Dedicated databases

`PG_VM_POOL_PASSWORD` is a shared credential that can create unlimited databases. To hand a credential to an application or customer, provision a **dedicated database** instead. It has its own role and password, can open only its own database (other names get `42501`), and cannot create VMs.

Provisioning uses the dashboard listener, so `PG_VM_POOL_DASHBOARD_LISTEN` must be set:

```sh
# username defaults to the database name; password is generated if omitted
curl -u admin:$DASH_PASS -X POST http://127.0.0.1:34199/api/databases \
     -H 'content-type: application/json' -d '{"database":"acme"}'
# -> 201 {"database":"acme","username":"acme","password":"…","status":"provisioning",…}

curl -u admin:$DASH_PASS http://127.0.0.1:34199/api/databases              # list, no passwords
curl -u admin:$DASH_PASS -X DELETE http://127.0.0.1:34199/api/databases/acme  # revoke
```

The client then connects normally:

```sh
psql "host=pg.example.com port=6432 user=acme dbname=acme sslmode=require"
```

- The password is shown once. It is stored in cleartext in `PG_VM_POOL_DEDICATED_FILE`.
- Names must be lowercase letters, digits and underscores, start with a letter, and be at most 63 bytes. The `pg_` and `spare` prefixes and Postgres catalog names are rejected, as is any name already in use as an ordinary schema.
- The role is `NOSUPERUSER NOCREATEDB NOCREATEROLE`, owns its database, and is recreated on every bring-up, so it survives dump restores.
- Revoking removes only the credential. The VM and data remain, and the name reverts to ordinary schema routing.

## Client guidance

A pooler connection can take much longer than a normal Postgres connect, because the first byte may wait for a VM to be created, started or restored.

| Situation | Typical wait |
|---|---|
| Warm VM | immediate |
| Stopped VM | under a second to a few seconds |
| New schema, warm spare available | seconds |
| New schema, no spare | create, boot and `initdb`, which can take tens of seconds |
| Compacted or archived schema | download, decompress and boot, from seconds to minutes |
| Busy host | up to `PG_VM_POOL_READY_TIMEOUT_SECS` (300 s) |

Recommendations:

- **Set an explicit connect timeout** that is longer than your worst expected cold start (for example `connect_timeout=60` in libpq, or `connectionTimeoutMillis` in node-postgres). Some drivers, including node-postgres `Pool`, have **no** connect timeout by default, so a connect to a slow thaw hangs silently.
- **Don't tie liveness to the first database connect.** If your app blocks startup on the database and its platform health check (for example app-lb's) expires before a thaw finishes, the app boot-loops without logging anything useful. Start serving, then connect, or give the health check a window longer than a cold start.
- **Retry on these codes:**

| SQLSTATE | Meaning | Action |
|---|---|---|
| `57P03` | The pooler couldn't bring the database up (failed or held-off bring-up, no capacity), or Postgres is recovering | Retry with backoff. |
| `53300` | Shed: the bring-up queue stayed full past `PG_VM_POOL_ADMISSION_WAIT_SECS` | Retry with backoff. |
| `28P01` | Wrong password | Fix the credential. Don't retry. |
| `42501` | Credential isn't allowed to use this database name | Fix the database name or credential. |

- **Reconnect after idle.** A stopped VM drops its sessions. Use pool validation (`SELECT 1` on checkout) or short idle lifetimes rather than holding connections for hours.
- **Use keep-alive schemas for latency-critical databases.** Listing them in `PG_VM_POOL_KEEPALIVE_SCHEMAS` keeps them warm at the cost of their RAM.

## Cross-host replication

A dedicated database on one pg-fc node can be replicated continuously to a peer node. Both nodes need:

```text
PG_VM_POOL_REPLICATION=1
PG_VM_POOL_NODE_NAME=node-a                   # different on each node
PG_VM_POOL_DASHBOARD_LISTEN=0.0.0.0:34199     # the peer calls this API
PG_VM_POOL_DASHBOARD_USER=admin
PG_VM_POOL_DASHBOARD_PASSWORD=…
```

A node acting as primary also needs a reachable listener, an advertised address and TLS:

```text
PG_VM_POOL_LISTEN=0.0.0.0:6432
PG_VM_POOL_ADVERTISE_PG_HOST=203.0.113.10     # what the PEER's guests dial
PG_VM_POOL_TLS_CERT=/path/fullchain.pem
PG_VM_POOL_TLS_KEY=/path/privkey.pem
```

Then register the peer and start a pairing from the primary:

```sh
curl -u admin:$DASH_PASS -X POST http://127.0.0.1:34199/api/peers \
  -H 'content-type: application/json' \
  -d '{"name":"node_b","base_url":"https://b.example:34199","user":"admin",
       "password":"…","pg_host":"198.51.100.20","pg_port":6432}'

curl -u admin:$DASH_PASS -X POST http://127.0.0.1:34199/api/replication \
  -H 'content-type: application/json' -d '{"database":"acme","peer":"node_b"}'

curl -u admin:$DASH_PASS http://127.0.0.1:34199/api/replication/acme   # state and lag
```

The default mode is **logical** replication: a publication on the primary, and a subscription on the replica that connects through the primary's ordinary pooler listener using a separate `REPLICATION` login. Things to know:

- DDL, sequence values and large objects are not replicated. After a new table is created on both nodes, pick it up with `refresh`. Promote re-seeds sequences.
- Tables with no primary key need `REPLICA IDENTITY FULL`.
- A database in a live pairing is **pinned** on both nodes: it is never idle-stopped, compacted, frozen, archived or evicted. It costs RAM and disk on both hosts permanently.
- An abandoned slot retains WAL until `max_slot_wal_keep_size` invalidates it. If a replica is gone for good, **detach** the pairing. Don't just delete the record.
- Peering is full trust. Each node stores the other's dashboard admin password.
- There is no automatic failover. `promote` (on the replica) and `detach` (on the primary) are operator actions.

For planned switchovers, the API also offers durable source fences (`fence`, `fence-selective`, `unfence`) and a physical-replication handoff (`physical-prepare`, `physical`, `physical-handoff`, `physical-reseed`, `physical-standby-bind`). The guest side of the physical path is `/usr/local/bin/pg-fc-physical` (`physical.sh`). These are controller primitives with strict preconditions. Read the [replication section of the component README](../pg-fc/README.md#cross-host-replication) before using them.

| Variable | Default | Meaning |
|---|---|---|
| `PG_VM_POOL_REPLICATION` | off | `1` enables replication routes, the page and the monitor. |
| `PG_VM_POOL_NODE_NAME` | short hostname | Node name. Must differ from the peer's. |
| `PG_VM_POOL_PEERS_FILE` | `<state dir>/peers.tsv` | Peer records (mode `0600`, contains peer passwords). |
| `PG_VM_POOL_REPLICATION_FILE` | `<state dir>/replication.tsv` | Pairings (mode `0600`). |
| `PG_VM_POOL_ADVERTISE_PG_HOST` | unset | Address the peer's guests dial. Required to be a primary. |
| `PG_VM_POOL_ADVERTISE_PG_PORT` | the listen port | Port the peer's guests dial. |
| `PG_VM_POOL_REPL_SSLMODE` | `require` | libpq sslmode for the replication link. Weak modes need `ALLOW_INSECURE`. |
| `PG_VM_POOL_REPL_ALLOW_INSECURE` | off | Allow a weak sslmode, or a primary without TLS. For lab use only. |
| `PG_VM_POOL_REPL_PEER_TIMEOUT_SECS` | `20` | Limit on peer API calls. |
| `PG_VM_POOL_REPL_SETUP_SECS` | `3600` | Limit on the initial schema copy (minimum 60). |
| `PG_VM_POOL_REPL_MONITOR_SECS` | `60` | Lag and slot sampling interval. `0` disables. |
| `PG_VM_POOL_REPL_SLOT_STALE_SECS` | `3600` | Warn when a slot has had no subscriber for this long. |
| `PG_VM_POOL_REPL_LAG_WARN_BYTES` | `268435456` | Warn when an inactive slot holds more than this. |
| `PG_VM_POOL_REPL_FIX_SEQUENCES` | on | Re-seed sequences on promote. |

## Dashboard and JSON API

Set `PG_VM_POOL_DASHBOARD_LISTEN` (and credentials) to serve a server-rendered dashboard from inside the pooler process. The dashboard can stop, resize and delete every VM on the host. Keep it on loopback or a private address, and always set Basic auth.

| Page | Contents |
|---|---|
| `/` | Every heyvmd sandbox with power state, size, uptime and pooler sessions |
| `/vm/{id}` | One VM's config, database size and backend count, with start/stop/reboot/resize/reap/restore controls |
| `/monitoring` | Host CPU, memory and disk, fleet aggregates, hourly charts, create and restore latency percentiles, webhook alerts, maintenance buttons |
| `/archives` | Offloaded schemas, with restore |
| `/dedicated` | Dedicated database provisioning |
| `/replication` | Peers and pairings (when replication is on) |
| `/events` | Events journal |
| `/logs/pooler`, `/logs/heyvmd`, `/logs/vm/{id}` | Log tails. The per-VM log runs `tail` inside the guest. |

The JSON API sits on the same listener and uses the same auth. It is keyed by schema name, not sandbox id, because a schema outlives its VMs. Wire types are in the `pg-fc-api` crate (`pg-fc/api/`).

| Route | Purpose |
|---|---|
| `GET /api/health` | Version, uptime, listen address, schema counts, configured tiers |
| `GET /api/schemas[?tier=&q=]` | All schemas. `tier` is `live`, `compacted`, `frozen`, `archived`, `pending` or `warm`. |
| `GET /api/schemas/{schema}` | One schema, plus live size and backends when warm |
| `POST /api/schemas/{schema}/{action}` | `start`, `stop`, `reboot`, `resize` (body `{"size_class":"small"}`), `reap`, `restore`, `archive-image`. Returns 409 for pinned schemas. Long actions return 202. |
| `GET /api/host` | Host metrics, disks, spare shelf, counts by tier |
| `GET /api/events[?limit=&since=]` | Events journal, newest first |
| `GET /api/logs/{pooler,heyvmd}[?lines=]`, `GET /api/logs/schema/{schema}` | Log tails |
| `POST /api/maintenance/{op}` | `sweep`, `ttl-sweep` (body `{"ttl_secs":N}`), `reclaim`, `stop-idle`, `purge`. Returns 409 if a pass is already running. |
| `GET /api/config`, `PUT /api/config` | Runtime configuration |
| `GET/POST /api/databases`, `DELETE /api/databases/{database}` | Dedicated databases |
| `GET/POST /api/peers`, `DELETE /api/peers/{name}` | Replication peers |
| `GET/POST /api/replication`, `GET/DELETE /api/replication/{database}` | Pairings |
| `POST /api/replication/{database}/{promote,refresh,detach,fence,fence-selective,unfence}` | Pairing operations |

### Runtime configuration

These settings can change without a restart: `idle_timeout_secs`, `idle_timeout_fast_secs`, `warm_spares`, `compact_after_secs`, `freeze_after_secs` and `archive_after_secs`.

```sh
curl -u admin:$DASH_PASS http://127.0.0.1:34199/api/config
curl -u admin:$DASH_PASS -X PUT http://127.0.0.1:34199/api/config \
  -H 'content-type: application/json' -d '{"idle_timeout_secs": 300}'
```

Overrides persist to `runtime-config.json` next to the registry and apply over the environment at boot. `GET` shows each value's source (`override`, `env` or `default`). A tier that was off at boot can't be turned on this way: the request returns 400 until you set the environment variable and restart.

### Webhook alerts

From `/monitoring`, add rules on host CPU %, memory %, disk %, or the heyvmd health check (the threshold is consecutive failed probes). The evaluator POSTs JSON once when a rule triggers and once when it resolves:

```json
{"source":"pg-vm-pool","host":"pool-1","rule_id":"…","metric":"disk",
 "state":"triggered","threshold_pct":90.0,"value_pct":93.4,"detail":"/"}
```

## Common operations

### Reclaim disk space

Data disks are sparse files, but without discard passthrough they only grow. Four tools recover space, from least to most destructive:

| Tool | What it removes |
|---|---|
| `reclaim-disks.sh <run-dir> [--shrink] [--prune-swap] [--dry-run]` | Free blocks inside stopped VMs' `data.ext4` (`e2fsck -E discard`). Needs root. Skips disks a running VM holds. |
| `prune-stale-rootfs.sh <run-dir>` (`DELETE=1` to act) | Leftover `sb-*/rootfs.ext4` clones from unclean stops |
| `PG_VM_POOL_ORPHAN_SWEEP_SECS` | `sb-<id>/` directories heyvmd has forgotten, whose schema is offloaded or unreferenced |
| `cleanup-never-booted.sh` | Sandboxes whose data disk was never formatted |

To run reclaim from the pooler, pin the exact command in sudoers and set `PG_VM_POOL_RECLAIM_CMD` to the same string:

```text
# /etc/sudoers.d/pg-vm-pool  (0440)
pooler ALL=(root) NOPASSWD: /opt/pg-fc/reclaim-disks.sh /srv/heyvm/run --shrink --prune-swap
```

```text
PG_VM_POOL_RECLAIM_CMD="sudo -n /opt/pg-fc/reclaim-disks.sh /srv/heyvm/run --shrink --prune-swap"
```

Install the script at a root-owned path. Verify the pin as the pooler user with `sudo -n -l <exact command>`. sudoers compares arguments byte for byte, and a mismatch fails every run while only logging a failed reclaim once an hour.

### Recover a full disk

If the host disk is full, offloads that boot a VM make it worse. `emergency-drain.sh` stops the pooler and only runs steps that free space without first consuming any. `disk-audit.sh` is read-only and reconciles the run dir, heyvmd and the registry.

### Change VM size

Resize a schema from its dashboard page or with `POST /api/schemas/{schema}/resize`. The new size applies on the VM's next boot. `PG_VM_POOL_SIZE_CLASS` sets the size for new VMs only.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Client hangs on connect, then succeeds | Cold start or restore. Expected. Set a client connect timeout longer than it. |
| Client hangs forever | The driver has no connect timeout and the bring-up is slow or failing. Set one, then check `/api/events` and the pooler log. |
| `53300` from the pooler | Bring-up queue full. Raise `PG_VM_POOL_MAX_PENDING_BRINGUPS` only if heyvmd has headroom. Otherwise add spares or capacity. |
| `57P03` repeatedly | Bring-ups are failing. Check the pooler log for the heyvmd error (capacity, image missing, disk full). |
| Clients queue at a warm VM | Every backend slot is taken. The detail page shows `client slots 0 / N`. Close leaked connections, or resize the VM. |
| Disk use doesn't fall after offloads | `PG_VM_POOL_RUN_DIR` is wrong (check the startup warning), or kills left directories behind. Enable the orphan sweep. |
| Reclaim never runs | The sudoers pin doesn't match `PG_VM_POOL_RECLAIM_CMD`. Test with `sudo -n -l`. |
| Restore fails with an incompatible-version error | The archive's Postgres major differs from the host image's. See [the major-mismatch runbook](../pg-fc/docs/runbook-pg-major-mismatch.md). |
| `No space left on device` inside a busy schema | Device growth is off, or the device is at `PG_VM_POOL_DISK_MAX_GB`. Set `PG_VM_POOL_DISK_GROW_PCT` or raise the maximum. |
| Every schema looks new after a restart | The pooler started with a different `PG_VM_POOL_STATE_FILE` (often a changed `$HOME` or working directory). Point it back at the original registry. |
| Startup fails naming an S3 variable | `PG_VM_POOL_ARCHIVE_AFTER_SECS` is set without a bucket or credentials. |
| Replication slot WAL keeps growing | The subscriber is gone. Detach the pairing on the primary. |

## Testing

```sh
cargo test --locked --manifest-path pg-fc/Cargo.toml

# end-to-end against a running pooler and heyvmd (from pg-fc/)
cd pg-fc
cargo run --release --example e2e
cargo run --release --example e2e_concurrent

# cold-start cost against a synthetic fleet (in-process heyvmd stub)
cargo test --release loadtest -- --ignored --nocapture --test-threads=1
```

`examples/e2e_replication.rs` needs two nodes. See its header for the variables it reads.

## See also

- [app-lb](app-lb.md): the `pgfc` plugin surfaces this dashboard in app-lb
- [multi-region](multi-region.md)
- [Component README](../pg-fc/README.md): design notes on every tier, the offload pacer, reclaim locking and physical handoff
