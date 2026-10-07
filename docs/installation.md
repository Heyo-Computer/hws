# Installation

Stand up Heyo Web Services on a Linux host: install heyvm, then the HWS services in dependency order, wire them together, and register a first deployment.

HWS is a set of independent binaries. Each one is configured entirely by
environment variables, runs in the foreground, and ships a supervisord program
file. You can install them three ways:

| Method | Needs a credential | Use it when |
| --- | --- | --- |
| [`bootstrap-host.sh`](#bootstrap-a-fleet-host) | No (secrets are written to files first) | You are turning a fresh Debian/Ubuntu machine into an app-lb host in one step |
| [`install-apps.sh`](#install-published-releases) | No | You want the published release of one or more apps from `get.us2.heyo.work` |
| [`.ci/install.sh`](#install-from-your-own-artifact-store) | `ART_API_KEY` | You run your own CI and artifact store and install what it built |
| [Build from source](#build-from-source) | No | You are developing HWS or need a platform the releases do not cover |

Published releases are built for `linux-x86_64` only.

## What you are installing

| Component | Binaries | Default listeners | Depends on |
| --- | --- | --- | --- |
| heyvm | `heyvm`, `heyvmd` | heyvmd API `127.0.0.1:34099` (or a unix socket) | KVM, Firecracker, docker (for image builds) |
| [heyosecret](heyosecret.md) | `heyosecret` | `:4455` | PostgreSQL |
| [art](artifacts.md) (artifact store) | `art` | `127.0.0.1:8080` (`art serve`) | Local disk |
| [app-lb](app-lb.md) | `app-lb`, `heyctl` | proxy `0.0.0.0:6188`, TLS `0.0.0.0:6189`, admin `127.0.0.1:9090` | heyvmd; `art` on the same host for workspace/artifact features |
| [app-obs](app-obs.md) | `app-obs`, `app-obs-dump` | ingest `0.0.0.0:9500`, syslog `0.0.0.0:9514`, API `127.0.0.1:9600` | app-lb admin API |
| [ci](ci.md) | `ci` | `127.0.0.1:9500` | PostgreSQL, NATS JetStream, heyvm runner hosts |
| [pg-fc](pg-fc.md) (optional) | `pg-vm-pool` | `127.0.0.1:6432` | heyvmd on the same host |
| [queue](queue.md) (optional) | `queue` | `127.0.0.1:9700` | A NATS server with monitoring on `:8222` |
| [mcp](mcp.md) (optional) | Node.js app | set by `HEYO_MCP_HTTP_PORT` (stdio if unset) | app-lb, app-obs, ci, art APIs |

The defaults for app-obs ingest and ci both use port 9500. If you run both on
one host, move one of them (`APP_OBS_INGEST_ADDR` or `CI_LISTEN_ADDR`).

## Host requirements

- Linux x86_64 with `/dev/kvm` (bare metal, or a VM with nested virtualisation).
- Firecracker on `PATH`. `bootstrap-host.sh` installs `v1.16.1` by default.
- docker and `e2fsprogs` if the host builds guest images (any deployment with a
  `build` block, or `heyctl build`).
- `supervisor` if you want to use the shipped program files. Any process manager
  works; the `.conf` files show the environment each service needs.
- `curl`, `tar`, `sha256sum` for the installers.
- PostgreSQL reachable from heyosecret and ci. pg-fc can provide it.

## Recommended order

Install in this order. Each step depends only on the ones above it.

1. **heyvm** (`heyvmd`) — the microVM daemon every VM-backed service drives.
2. **heyosecret** — secrets store; other services and CI read credentials from it.
3. **art** — artifact store for guest images, release tarballs, and workspaces.
   app-lb also needs the `art` binary on its own host.
4. **app-lb** — load balancer, autoscaler, and control plane. From here on you
   register workloads with `heyctl`.
5. **app-obs** — logs, metrics, and alerts fed by app-lb.
6. **ci** — the CI orchestrator, if you want to build and release on HWS.
7. Optional: **pg-fc** (Postgres microVMs and pooler), **queue** (NATS
   dashboard), **mcp** (MCP server for agents).

heyosecret and art can themselves run as app-lb deployments once app-lb is up
(see `app-lb/examples/heyosecret.json` and `app-lb/examples/artifacts.json`).
The order above installs them directly on the host, which is simpler for a
first install.

## Bootstrap a fleet host

[`.ci/bootstrap-host.sh`](../.ci/bootstrap-host.sh) turns a fresh
Debian/Ubuntu host into an app-lb host: it installs packages and Firecracker,
installs `heyvm`, `app-lb` and `art` with `install-apps.sh`, writes supervisor
units for `heyvmd` and `app-lb`, starts them, and routes `admin.<domain>` to
the admin API. It creates no workload VMs.

Write the secrets first, mode `0600`, over a channel that does not record them:

```sh
sudo install -d -m0755 /etc/app-lb /etc/heyvm
sudo sh -c 'umask 077; printf "APP_LB_DASHBOARD_PASSWORD=%s\n" "<password>" > /etc/app-lb/env'
# optional: /etc/heyvm/env with heyvmd's environment (for example CLOUD_INTERNAL_API_KEY)
```

`/etc/app-lb/env` may also carry `APP_LB_OBS_TOKEN` and
`APP_LB_DAEMON_API_KEY`. If `/etc/heyvm/env` sets `CLOUD_INTERNAL_API_KEY`,
that value is heyvmd's operator key, and app-lb must present the same value as
`APP_LB_DAEMON_API_KEY`.

Then run, as root:

```sh
curl -fsSL https://get.us2.heyo.work/bootstrap-host.sh | sh -s -- \
    --id us4 --domain us4.example.com \
    --public-ip 203.0.113.4 --acme-email ops@example.com
```

| Flag | Required | Meaning |
| --- | --- | --- |
| `--id NAME` | yes | Short lowercase host name; becomes `APP_LB_NAME` |
| `--domain HOST` | yes | Base domain; sets `APP_LB_DEPLOY_BASE_DOMAIN` and the `admin.<domain>` route |
| `--public-ip IP` | yes | The host's public address (`APP_LB_PUBLIC_IPS`) |
| `--acme-email EMAIL` | yes | Let's Encrypt account contact (`APP_LB_ACME_EMAIL`) |
| `--acme-staging` | no | Use the Let's Encrypt staging directory |
| `--releases-url URL` | no | Manifest site. Default `https://get.us2.heyo.work` |

| Environment | Default | Meaning |
| --- | --- | --- |
| `RELEASES_URL` | `https://get.us2.heyo.work` | Same as `--releases-url` |
| `FIRECRACKER_VERSION` | `v1.16.1` | Firecracker release to install if the one on `PATH` differs |
| `DASHBOARD_USER` | `heyo` | `APP_LB_DASHBOARD_USER` |

What the host looks like afterwards:

- `heyvmd --api-port 34099` under supervisor, `MVM_DATA_DIR=/var/lib/heyvm`,
  logs in `/var/log/heyvmd/`.
- `app-lb` as root, proxy on `:80`, TLS on `:443`, admin on `127.0.0.1:9090`,
  state in `/var/lib/app-lb/app-lb-state.json`, ACME in `/var/lib/app-lb/acme`,
  `APP_LB_ART_BIN=/usr/local/bin/art`, images in
  `/var/lib/heyvm/images/firecracker`.
- A `local` heyctl context and an `app-lb-admin` deployment routing
  `admin.<domain>` to `127.0.0.1:9090`. ACME issues its certificate once DNS
  points at the host.

Re-running the script is safe: it upgrades binaries, keeps existing supervisor
units (new ones land beside them as `.conf.new`), and re-applies the admin
route.

## Install published releases

[`.ci/install-apps.sh`](../.ci/install-apps.sh) installs published releases
with no credential. It reads `<app>.json` manifests from the release site,
downloads the public blob each names, and verifies it.

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sh -s -- --list
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- heyvm app-lb art
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- --version app-lb=<ver> app-lb
```

Pass flags through a pipe with `sh -s --`, or `sh` treats them as its own.

HWS apps it installs: `app-lb`, `app-obs`, `ci`, `queue`, `art`, `heyosecret`,
and `heyvm`. The same manifests also list `cloud`, `auth` and `retail`, which
are built outside this repository and are not part of HWS.

| Option | Meaning |
| --- | --- |
| `--list` | Show what the manifests offer; install nothing |
| `--dry-run` | Download and verify; install nothing |
| `--version APP=VER` | Install `VER` of `APP` instead of the latest. Repeatable |
| `--supervisor` | Install shipped supervisor units. Default when `/etc/supervisor/conf.d` exists |
| `--no-units` | Install no process-manager units |
| `--restart` | Run `supervisorctl reread`/`update` and restart what was installed |

| Environment | Default | Meaning |
| --- | --- | --- |
| `RELEASES_URL` | `https://get.us2.heyo.work` | Where the manifests are |
| `STORE_URL` | the manifest's `store` | Override the artifact store to download from |
| `PREFIX` | `/usr/local` | Binaries go in `$PREFIX/bin` |
| `STATE_ROOT` | `/var/lib` | Migrations go in `$STATE_ROOT/<app>/migrations` |
| `OPT_ROOT` | `/opt/heyo` | Where `tree` apps are installed |
| `SITE_ROOT` | `/srv/heyo` | Where `site` apps are installed |
| `SUPERVISOR_DIR` | `/etc/supervisor/conf.d` | Where supervisor programs go |

What gets installed depends on the manifest's `kind`:

| Kind | Installs |
| --- | --- |
| `bin` | The named binaries into `$PREFIX/bin` (by rename, so a running binary is replaced safely), `migrations/` into `$STATE_ROOT/<app>/migrations`, and `<app>.conf` into `$SUPERVISOR_DIR` |
| `tarball` | `heyvm` and `heyvmd` from the release tarball inside the artifact |
| `tree` / `site` | The whole release under `<root>/<app>/releases/<version>`, with `current` repointed at it |

Every download is checked twice: the blob's sha256 must equal the digest it
was fetched by, then `sha256sum -c SHA256SUMS` runs over the unpacked files.
The script sends no `Authorization` header; the store rejects a presented
stale key even for a public blob.

It never overwrites an existing supervisor file. The shipped file is written
beside yours as `<app>.conf.new`, and you merge new settings by hand.

## Install from your own artifact store

[`.ci/install.sh`](../.ci/install.sh) installs the newest build of each app
from an `art serve` that your CI pushes to. It resolves tags, so it needs the
store's API key.

```sh
ART_URL=https://art.example.com ART_API_KEY=... sh .ci/install.sh
sh .ci/install.sh --list
sh .ci/install.sh --dry-run
sh .ci/install.sh app-lb
sh .ci/install.sh --ref ci-app-lb-<run>-release-app-lb app-lb   # roll back
PREFIX=~/.local SUPERVISOR_DIR= sh .ci/install.sh               # unprivileged, no units
```

| Option | Meaning |
| --- | --- |
| `--list` | Show what the store has, with each artifact's description |
| `--dry-run` | Resolve, download and verify; install nothing |
| `--restart` | `supervisorctl update` and restart each installed program |
| `--ref TAG` | Install this exact tag instead of the newest |
| `--prefix PATH` | Same as `PREFIX` |

| Environment | Default | Meaning |
| --- | --- | --- |
| `ART_URL` | (required) | Base URL of the `art serve` |
| `ART_API_KEY` | (required unless the store is open) | Bearer token for it |
| `PREFIX` | `/usr/local` | Binaries go in `$PREFIX/bin` |
| `STATE_ROOT` | `/var/lib` | Migrations go in `$STATE_ROOT/<app>/migrations` |
| `SUPERVISOR_DIR` | `/etc/supervisor/conf.d` | Set empty to skip supervisor files |
| `APPS` | `app-lb app-obs ci art` | Which apps to install when none are named |

Installable names: `app-lb`, `app-obs`, `ci`, `art`, `codegraph`, `queue`,
`heyosecret`, `pg-fc`. `queue` and `pg-fc` are deliberately not in the default
set: queue belongs only on the host that runs `nats-server`, and `pg-fc`
installs only the `pg-vm-pool` binary without configuring or restarting a
pooler.

CI tags each upload `ci-<workflow>-<run>-<job>-<name>`, for example
`ci-app-lb-<run>-release-app-lb`. The run id is fixed-width hex, so sorting
tags lexicographically sorts them chronologically; that is how the script
finds the newest build. See [ci](ci.md) and [artifacts](artifacts.md).

## Build from source

Every service has its own lockfile. Build with `--locked`:

```sh
cargo build --release --locked --manifest-path app-lb/Cargo.toml --workspace   # app-lb + heyctl
cargo build --release --locked --manifest-path app-obs/Cargo.toml               # app-obs + app-obs-dump
cargo build --release --locked --manifest-path artifacts/Cargo.toml             # art
cargo build --release --locked --manifest-path heyosecret/Cargo.toml
cargo build --release --locked --manifest-path ci/Cargo.toml
cargo build --release --locked --manifest-path queue/Cargo.toml
cargo build --release --locked --manifest-path pg-fc/Cargo.toml                 # pg-vm-pool
cargo build --release --locked --manifest-path orchestrator/Cargo.toml
```

Binaries land in `<crate>/target/release/` unless `CARGO_TARGET_DIR` is set.
Copy them into `/usr/local/bin`, and copy each crate's
`deploy/supervisor/*.conf` into `/etc/supervisor/conf.d/`.

System packages the builds need:

| Crate | Packages (Debian/Ubuntu) |
| --- | --- |
| app-lb | `build-essential cmake perl pkg-config` (OpenSSL and zlib-ng are compiled from source) |
| app-obs | `build-essential cmake pkg-config` |
| ci | `build-essential pkg-config libssl-dev` |
| codegraph | `build-essential` |

Without `--workspace`, the app-lb build produces only `app-lb`, not `heyctl`.
app-obs needs noticeably more memory to compile than the other crates; lower
`CARGO_BUILD_JOBS` if the build is OOM-killed.

The MCP server is Node.js:

```sh
cd mcp && npm ci && npm run build   # output in mcp/dist/
```

## Step by step

### 1. heyvm

heyvm is the Firecracker/KVM microVM runtime. Its CLI and daemon are documented
at [heyo.computer/docs](https://heyo.computer/docs/quickstart.html). Install
both binaries from the release manifests:

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- heyvm
```

Run `heyvmd` under a process manager with a fixed data directory. The unit
`bootstrap-host.sh` writes is a good template:

```ini
[program:heyvmd]
command=/bin/sh -c 'set -a; [ -f /etc/heyvm/env ] && . /etc/heyvm/env; set +a; exec /usr/local/bin/heyvmd --api-port 34099'
directory=/var/lib/heyvm
user=root
environment=
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME="/var/lib/heyvm",
    MVM_DATA_DIR="/var/lib/heyvm"
autostart=true
autorestart=true
stopsignal=TERM
stopwaitsecs=15
stopasgroup=true
killasgroup=true
redirect_stderr=true
stdout_logfile=/var/log/heyvmd/heyvmd.log
```

Check it answers (a 401 is fine when an operator key is set):

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:34099/deployed-sandboxes
```

heyvmd resolves image names under its own data directory. If app-lb builds or
pulls images, point both at the same directory: set `MVM_DATA_DIR` on both
processes and `APP_LB_IMAGES_DIR=<MVM_DATA_DIR>/images/firecracker` on app-lb,
or set `APP_LB_HEYVM_HOME` to heyvmd's home when app-lb can write it.

### 2. heyosecret

Create a PostgreSQL database and role, then install:

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- heyosecret
sudo useradd --system --no-create-home --shell /usr/sbin/nologin heyosecret
sudo install -d -o heyosecret -g heyosecret /var/lib/heyosecret /var/log/heyosecret
```

The installer puts migrations in `/var/lib/heyosecret/migrations`, which is
where the shipped unit's `HEYOSECRET_MIGRATIONS_DIR` points. Edit
`/etc/supervisor/conf.d/heyosecret.conf` and replace every `change-me`:

| Variable | Meaning |
| --- | --- |
| `HEYOSECRET_DATABASE_URL` | PostgreSQL URL |
| `HEYOSECRET_INTERNAL_API_KEY` | Machine API key |
| `HEYOSECRET_MASTER_KEY` | At least 32 bytes; derives the value-encryption key. Losing it loses every stored value |
| `HEYOSECRET_ADMIN_PASSWORD` | Dashboard password. Mutually exclusive with `HEYOSECRET_DASHBOARD_GATE=1` |

Instead of putting secrets in the unit, you can point
`HEYOSECRET_CONFIG_PATH` at a `0600` TOML file. See [heyosecret](heyosecret.md).

### 3. art

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- art
```

Every app-lb host needs the `art` binary, even if the store runs elsewhere:
app-lb runs it as a subprocess to restore and capture workspaces. Without it, a
deployment whose `vm.workspace.store` is a local path holds its pool at zero
replicas with `workspace restore pending: could not run art`.

To run a store, start `art serve` under your process manager:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ART_ROOT` | `~/.artifacts` | Store root |
| `ART_LISTEN` | `127.0.0.1:8080` | Listen address |
| `ART_API_KEY` | (unset: every route open) | Bearer / `X-Api-Key` secret. `/healthz` is always open |
| `ART_READ_ONLY` | off | Refuse every mutating route |
| `ART_ADMIN_USER` / `ART_ADMIN_PASSWORD` | `admin` / unset | Dashboard login. No password, no dashboard |
| `ART_DASHBOARD_GATE` | off | Trust identity forwarded by app-lb instead of a local login |

`art` ships no supervisor file. See [artifacts](artifacts.md) for running it
as an app-lb deployment instead.

### 4. app-lb

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- app-lb
sudo useradd --system --no-create-home --shell /usr/sbin/nologin app-lb
sudo install -d -o app-lb -g app-lb /var/lib/app-lb /var/log/app-lb
sudo install -d -m0700 -o app-lb -g app-lb /var/lib/app-lb/acme
```

This installs `app-lb` and `heyctl`. Edit `/etc/supervisor/conf.d/app-lb.conf`:

| Variable | Shipped value | Change it to |
| --- | --- | --- |
| `APP_LB_DASHBOARD_PASSWORD` | `change-me` | A real password. Required when `APP_LB_ADMIN_AUTH=1` |
| `APP_LB_PROXY_ADDR` | `0.0.0.0:6188` | `0.0.0.0:80` if app-lb is the public ingress |
| `APP_LB_ART_BIN` | (unset) | `/usr/local/bin/art` |
| `APP_LB_ACME_EMAIL` | (unset) | Your contact, to enable automatic certificates |
| `APP_LB_PROXY_TLS_ADDR` | (unset; default `0.0.0.0:6189`) | `0.0.0.0:443` with ACME |
| `APP_LB_DAEMON_API_KEY` | (unset) | heyvmd's operator key, if it has one |
| `APP_LB_OBS_URL` | (unset) | app-obs ingest base URL, once app-obs is up |

Binding `:80`/`:443` as a non-root user needs
`sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/app-lb`. ACME validates
HTTP-01 on port 80 only, so automatic certificates need the proxy on `:80`.
Test against Let's Encrypt staging first with
`APP_LB_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory`.

If the host builds images, add the service user to the `docker` group, give it
a real home directory (`sudo install -d -o app-lb -g app-lb /home/app-lb`), and
restart the program (not just `reread`) so it picks up the group.

Start it and log in:

```sh
sudo supervisorctl reread && sudo supervisorctl update
curl -s http://127.0.0.1:9090/healthz
heyctl login --server http://127.0.0.1:9090 --user admin --password-stdin --name local
heyctl status
```

The full configuration reference is in [app-lb](app-lb.md); sign-in options
are in [app-lb auth](app-lb-auth.md).

### 5. app-obs

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- app-obs
sudo useradd --system --no-create-home --shell /usr/sbin/nologin app-obs
sudo install -d -o app-obs -g app-obs /var/lib/app-obs /var/log/app-obs
```

The shipped unit sets `APP_OBS_DATA_DIR=/var/lib/app-obs/data` and
`APP_LB_URL=http://127.0.0.1:9090`. If app-lb's admin API requires auth, add
`APP_LB_USER` and `APP_LB_PASSWORD`. Set `APP_OBS_API_TOKEN` to gate the query
API, and `APP_OBS_INGEST_TOKEN` to gate ingest.

Then point app-lb at it and restart app-lb:

```ini
APP_LB_OBS_URL="http://127.0.0.1:9500",
APP_LB_OBS_TOKEN="<same value as APP_OBS_INGEST_TOKEN, if set>"
```

app-lb appends `/ingest` itself. Leave `stopwaitsecs` above 30 so app-obs can
flush buffered records on shutdown. See [app-obs](app-obs.md).

### 6. ci

ci needs PostgreSQL, a NATS server with JetStream, and heyvm runner hosts that
belong to a heyvm network.

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sudo sh -s -- ci
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ci
sudo install -d -o ci -g ci /var/lib/ci /var/lib/ci/logs /var/lib/ci/workspaces /var/lib/ci/artifacts
```

Replace every `REPLACE-ME` in `/etc/supervisor/conf.d/ci.conf`. ci refuses to
start without `CI_HEYO_API_KEY`, `CI_NETWORK`, `CI_DATABASE_URL`, and
`CI_WEBHOOK_SECRET` (at least 16 characters). Migrations are compiled into the
binary; leave `CI_MIGRATIONS_DIR` unset. Remember the port 9500 overlap with
app-obs. See [ci](ci.md).

### 7. Optional services

- **pg-fc** — `sudo sh .ci/install.sh pg-fc` (from your own store) or build
  from source. The pooler listens on `PG_VM_POOL_LISTEN` (default
  `127.0.0.1:6432`) and drives heyvmd on the same host. The repo ships
  `pg-fc/deploy/supervisor/pg-vm-pool.conf` and a systemd template
  `pg-fc/deploy/pg-fc@.service`. See [pg-fc](pg-fc.md).
- **queue** — install only on the host that runs `nats-server`. Defaults:
  `QUEUE_NATS_MONITOR_URL=http://127.0.0.1:8222`, `QUEUE_API_ADDR=127.0.0.1:9700`.
  See [queue](queue.md).
- **mcp** — build `mcp/` with npm and run `node dist/index.js`. Set
  `HEYO_MCP_HTTP_PORT` for HTTP mode; `mcp/deploy/supervisor/heyo-mcp.conf`
  lists the service URLs and tokens it reads. See [mcp](mcp.md).

## Shipped supervisor files

| File | Program | Runs as | Directories to create |
| --- | --- | --- | --- |
| `app-lb/deploy/supervisor/app-lb.conf` | `app-lb` | `app-lb` | `/var/lib/app-lb`, `/var/log/app-lb` |
| `app-obs/deploy/supervisor/app-obs.conf` | `app-obs` | `app-obs` | `/var/lib/app-obs`, `/var/log/app-obs` |
| `ci/deploy/supervisor/ci.conf` | `ci` | `ci` | `/var/lib/ci` |
| `heyosecret/deploy/supervisor/heyosecret.conf` | `heyosecret` | `heyosecret` | `/var/lib/heyosecret`, `/var/log/heyosecret` |
| `queue/deploy/supervisor/queue.conf` | `queue` | `queue` | `/var/lib/queue`, `/var/log/queue` |
| `pg-fc/deploy/supervisor/pg-vm-pool.conf` | `pg-vm-pool` | see file | see file |
| `pg-fc/deploy/supervisor/heyvmd.conf` | `heyvmd` | see file | see file |
| `mcp/deploy/supervisor/heyo-mcp.conf` | `heyo-mcp` | see file | `/var/log/heyo-mcp` |

All of them use `autorestart=unexpected` or `true` with bounded
`startretries`, so a startup misconfiguration ends in `FATAL` rather than a
crash loop. Read the reason with `supervisorctl tail <program> stderr`.

## Firewall and tap interfaces

app-lb reaches each guest at its guest IP over the host's tap interface. A host
firewall that rejects forwarded or tap traffic makes every VM look permanently
unhealthy. `ping` may still work, because ufw allows ICMP echo while rejecting
TCP, which shows up as `No route to host`. If health checks never go green,
check the firewall first:

```sh
sudo ufw status
sudo ufw allow in on tap-fc-+        # or scope to the guest subnet
```

Open to the internet only what should be public: app-lb's proxy ports. Keep
the app-lb admin API, heyvmd, art, heyosecret, and app-obs's query API on
loopback or a private network, and expose them through app-lb deployments with
auth when people need them.

## First deployment

With heyvmd and app-lb running and `heyctl` logged in, register a managed VM
deployment built from a git repository that contains a Dockerfile. The service
in the image must listen on the port you give and answer the health path.

```sh
heyctl create deployment hello \
  --host hello.example.com \
  --repo https://github.com/<you>/hello.git --ref main \
  --port 8080 --health-path / \
  --min 1 --max 2

heyctl build hello --wait --logs   # build the guest image and roll the pool onto it
heyctl rollout status hello        # wait for the pool to be at size and healthy
heyctl describe hello              # spec, pool, backends, traffic
```

`--dry-run` on `create deployment` prints the spec without sending it. For a
private repository, store a token first with `heyctl create secret` and pass
`--secret NAME[/KEY]`.

Send a request through the proxy:

```sh
curl -H 'Host: hello.example.com' http://127.0.0.1:6188/
```

Once DNS for `hello.example.com` points at the host and ACME is configured,
the same request works over HTTPS with a Let's Encrypt certificate.

The same deployment as a spec file, which you can keep in git and apply with
`heyctl apply -f hello.json`:

```json
{
  "id": "hello",
  "routes": [{ "host": "hello.example.com" }],
  "vm": { "driver": "firecracker", "image": "hello", "port": 8080, "size_class": "mini" },
  "build": { "repo": "https://github.com/<you>/hello.git", "ref": "main", "dockerfile": "Dockerfile" },
  "scaling": { "min_replicas": 1, "max_replicas": 2 },
  "health": { "path": "/", "timeout_secs": 2 }
}
```

`app-lb/examples/` has specs for static sites, agent sandboxes, artifact
pulls, and the HWS services themselves. The spec reference is in
[app-lb](app-lb.md); the CLI is in [heyctl](heyctl.md).

## heyctl on a workstation

To manage an app-lb from your own machine, install only `heyctl`:

```sh
curl -fsSL https://heyo.computer/heyctl/install.sh | sh
curl -fsSL https://heyo.computer/heyctl/install.sh | sh -s -- --prefix /usr/local
```

| Option / variable | Default | Meaning |
| --- | --- | --- |
| `--prefix PATH` / `HEYCTL_PREFIX` | `~/.local` | Install into `PATH/bin` |
| `--version VER` / `HEYCTL_VERSION` | manifest `latest` | Version to install |
| `--digest SHA256` / `HEYCTL_DIGEST` | | Install this exact blob; skip the manifest |
| `--list` | | Show available versions |
| `HEYCTL_BASE_URL` | `https://heyo.computer` | Site serving `heyctl/versions.json` |
| `HEYCTL_MANIFEST_URL` | | Full manifest URL; overrides `HEYCTL_BASE_URL` |
| `HEYCTL_STORE_URL` | manifest `store` | Artifact store base |

Then `heyctl login --server https://admin.<your-domain>`.

## Publishing your own releases

If you run your own CI and artifact store, publish keyless manifests for your
hosts with [`.ci/publish-releases.sh`](../.ci/publish-releases.sh):

```sh
ART_URL=https://art.example.com ART_API_KEY=... \
  sh .ci/publish-releases.sh --all --from-url https://get.example.com --push-tag releases-live
```

| Option | Meaning |
| --- | --- |
| `--all` / `app...` | Which apps to publish |
| `--out DIR` | Output directory. Default `./releases` |
| `--from-url URL` / `--from DIR` | Merge into existing manifests so pinned versions keep installing |
| `--ref APP=TAG` | Publish this exact build |
| `--keep N` | Keep at most N versions per app and platform |
| `--push-tag TAG` | Upload the directory to the store as one public bundle and move `TAG` to it |
| `--dry-run` | Resolve and verify; write nothing |

The output holds one `<app>.json` per app, `index.json`, and copies of
`install-apps.sh` and `bootstrap-host.sh`. Serve it with an app-lb `site`
deployment that follows the pushed tag (`app-lb/examples/releases-site.json`),
then `heyctl pull <deployment>` to make it live. Anonymous downloads also need
the store's gate to leave `/blobs/` public (`app-lb/examples/artifacts-gated.json`).

## Upgrades and rollback

- Re-run the installer. Binaries are replaced by rename, so running processes
  keep the old inode until restarted.
- Supervisor files are never overwritten. Diff `<app>.conf.new` against your
  file and merge new settings.
- Restart explicitly (`supervisorctl restart <app>`) or pass `--restart`.
- Roll back with `install-apps.sh --version APP=VER` or
  `.ci/install.sh --ref <tag> <app>`.
- `APP_LB_STATE_PATH` holds every registered deployment. Keep it on persistent
  disk and back it up.
- Run only one app-lb per heyvmd. Two app-lbs sharing a daemon each see the
  other's VMs as orphans. app-lb takes a host-wide instance lock by default
  (`APP_LB_INSTANCE_LOCK`; a path, or `off`), so a second instance refuses to
  start. Leave it on. `app-lb` with no arguments starts a full instance; only
  `--version` and `--help` are safe to run by hand on a live host.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `/dev/kvm is missing` | Enable virtualisation in firmware, or nested virtualisation on the hypervisor |
| app-lb `FATAL` right after start | `supervisorctl tail app-lb stderr`. Common causes: only one of `APP_LB_TLS_CERT`/`APP_LB_TLS_KEY`, `APP_LB_ADMIN_AUTH=1` with no password, or a listen address already in use |
| Pool stays at zero with `could not run art` | Set `APP_LB_ART_BIN=/usr/local/bin/art` and install `art` on the app-lb host |
| Build fails on the docker socket | Add the service user to `docker`, give it a home directory, restart the program |
| Build succeeds but the VM never boots | app-lb and heyvmd disagree on the image directory; share `MVM_DATA_DIR` and set `APP_LB_IMAGES_DIR` |
| VMs never go healthy | Firewall on the tap interfaces; the health path and port in the spec |
| `install-apps.sh`: store refused an anonymous download | The blob is not public, or a gate in front of the store requires login for `/blobs/` |
| `install.sh`: no builds found | `ART_URL`/`ART_API_KEY`, and that CI has published under `ci-<workflow>-...` tags |
| ci or app-obs fails to bind `:9500` | Both default to 9500; move one |
