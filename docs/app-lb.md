# app-lb

app-lb is the HWS load balancer, autoscaler and control plane: it routes HTTP traffic to pools of heyvm microVMs, fixed upstreams or static files, and manages those pools through an admin API and dashboard.

## What it is

app-lb is one Rust process built on [Pingora](https://github.com/cloudflare/pingora). It does three jobs:

- **Proxy.** It terminates HTTP and HTTPS and routes each request to a deployment by host and path.
- **Autoscaler.** It boots, health-checks, drains and reaps Firecracker or KVM microVMs through the local heyvm daemon (`heyvmd`), sized to the traffic each deployment is receiving.
- **Control plane.** It runs an admin HTTP API, a dashboard, a secret store, deploy jobs (image builds, artifact pulls, host updates), security monitoring with block rules, and disk management for the host.

You register a **deployment** over the admin API. A deployment is routing rules plus exactly one backend:

| Kind | Spec block | Backend |
| --- | --- | --- |
| Managed | `vm` | A pool of microVMs that app-lb boots and scales. |
| Static (`proxy_pass`) | `upstreams` | A fixed list of `host:port` or `https://` origins, load-balanced least-in-flight with failover. |
| Site | `site` | A directory on the app-lb host, served straight off disk. |

How it fits with the rest of HWS:

- [heyctl](heyctl.md) is the CLI and client library for the admin API.
- [app-lb-auth](app-lb-auth.md) covers the admin gate, app-tokens, Google and JWT sign-in, federated auth and namespaces.
- [artifacts](artifacts.md) is the store app-lb pulls rootfs images, site bundles, guest mounts and workspace snapshots from.
- [app-obs](app-obs.md) receives app-lb's access log, events, job output and security alerts, and polls `/metrics`.
- [orchestrator](orchestrator.md) can own a static deployment's upstream membership through discovery. [multi-region](multi-region.md) covers regional gateways.
- [heyosecret](heyosecret.md) is where canonical service credentials live. You then place them in app-lb's own secret store for deployments to reference.

### Process model

The foreground process owns all management state: the state lock, the admin API, discovery, autoscaling, ACME, authentication and request admission. It supervises one forwarding subprocess that owns the HTTP/TLS listeners and streams request and response bodies. The two talk over a Unix socket in a private directory. If the manager dies, the worker dies with it, and new requests depend on the manager being up. Restarting app-lb interrupts in-flight streams. It is not a hot takeover.

## Requirements

- Linux with KVM (`/dev/kvm`).
- A running `heyvmd`. app-lb routes directly to each sandbox's `guest_ip`, which the daemon only reports for tap-networked Firecracker and KVM sandboxes on the local host. One app-lb manages one daemon.
- To build from source: `cmake` (a Pingora dependency) and `libssl-dev` (the TLS listener uses OpenSSL for per-handshake certificate selection).
- Optional tools on the host, depending on which features you use: `heyvm` and Docker (image builds), `git` (git builds and site updates), `art` (local artifact stores and local workspace stores), `aws` (DNS-01 wildcard certificates, disk archives, S3 workspace stores), `tar`.
- Optional: Incus, for the `lxc` driver (system containers from OCI images).

## Install and run

```sh
cargo build --release --locked --manifest-path app-lb/Cargo.toml
./app-lb/target/release/app-lb
```

See [installation](installation.md) for release bundles. To run app-lb as a supervised service, use the supervisord program in [`app-lb/deploy/supervisor/app-lb.conf`](../app-lb/deploy/supervisor/app-lb.conf). It runs as an `app-lb` user from `/var/lib/app-lb`, pins `APP_LB_STATE_PATH` to an absolute path, sends `SIGTERM` for a graceful drain, and restarts on crashes. Change its placeholder dashboard password before you use it.

app-lb takes no arguments. You configure it with `APP_LB_*` environment variables.

| Invocation | Effect |
| --- | --- |
| `app-lb` | Run in the foreground. |
| `app-lb --version` (`-V`, `version`) | Print `app-lb <version> (<git sha>)` and exit. The SHA comes from `HEYO_BUILD_GIT_SHA` at build time, or `unknown`. |
| `app-lb --help` (`-h`, `help`) | Print usage and exit. |
| anything else | Refused with exit code 2. Nothing starts. |

`--forwarding-worker`, `--apply-host-update` and `--bootstrap-host-update` are internal entry points. You don't run them yourself.

**One instance per daemon.** At startup app-lb takes a host-wide lock at `/run/app-lb/instance.lock`. If `/run` is not writable, it uses the temp directory. A second instance refuses to start and names the process holding the lock. This matters because an app-lb that doesn't know about another instance's sandboxes treats them as orphans. Point `APP_LB_INSTANCE_LOCK` elsewhere only for instances that talk to different daemons.

Quick check once it is running:

```sh
curl localhost:9090/healthz                      # "ok", with an x-heyo-revision header
curl -XPOST localhost:9090/deployments -H 'content-type: application/json' -d '{
  "id": "demo",
  "routes": [{"host": "demo.local"}],
  "vm": {"driver": "firecracker", "image": "nginx", "port": 80},
  "scaling": {"min_replicas": 0, "max_replicas": 4}
}'
curl -H 'Host: demo.local' localhost:6188/
```

Every proxied response has an `x-vm-id` header naming the VM (or, for a static deployment, the upstream address) that served it.

## Configuration

All configuration comes from the environment. Boolean flags accept `1`/`true`/`yes`/`on`.

### Listeners, state and identity

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_PROXY_ADDR` | `0.0.0.0:6188` | Plain HTTP proxy listener. Set it to `0.0.0.0:80` when ACME is on. |
| `APP_LB_PROXY_TLS_ADDR` | `0.0.0.0:6189` | HTTPS listener. Bound only when ACME is on or a cert/key pair is set. |
| `APP_LB_ADMIN_ADDR` | `127.0.0.1:9090` | Admin API and dashboard listener. It is plain HTTP, so put TLS in front of it if it leaves localhost. |
| `APP_LB_STATE_PATH` | `app-lb-state.json` | Names the state location (see [Where state lives](#where-state-lives)). Use an absolute path. |
| `APP_LB_SECRETS_PATH` | `app-lb-secrets.json` | Secret store file, written `0600`. |
| `APP_LB_SECRET_KEY` | unset | Seals the secret file with AES-256-GCM. A 64-hex value is used directly, and anything else is hashed into a key. |
| `APP_LB_TOKENS_PATH` | `app-lb-tokens.json` | App-token store (hashes only), written `0600`. |
| `APP_LB_AUTH_KEY` | `app-lb-auth-key` | Session signing key, generated `0600` on first use. |
| `APP_LB_GUARD_PATH` | `app-lb-guard.json` | Persisted block/allow rules. |
| `APP_LB_INSTANCE_LOCK` | `/run/app-lb/instance.lock` | Single-instance lock path, or `off`. |
| `APP_LB_NAME` | `app-lb` | Name shown in the dashboard header. |
| `RUST_LOG` | `info,app_lb=debug` | Log filter. |

### heyvm daemon

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_DAEMON_URL` | auto | With this unset, app-lb uses a live Unix socket if one is discoverable (`HEYVM_SOCKET`, then `socket_path` in `~/.heyo/daemon.json`), and otherwise `http://127.0.0.1:34099`. An explicit value is always used as given. The chosen transport is logged at startup. |
| `APP_LB_DAEMON_API_KEY` | falls back to `HEYO_API_KEY` | Bearer credential for an authenticated daemon. |

### Admin gate and federated auth

These are summarized here. The details are in [app-lb-auth](app-lb-auth.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_DASHBOARD_PASSWORD` | unset | Enables HTTP Basic auth on the view tier (dashboard pages, `/metrics`, `/security`, and so on). |
| `APP_LB_DASHBOARD_USER` | `admin` | Basic auth username. |
| `APP_LB_DASHBOARD_AUTH` | `true` | Set `0` to leave the view tier open while the password still gates CRUD. Use this when your own sign-in fronts the dashboard. |
| `APP_LB_ADMIN_AUTH` | `false` | Extends the gate to the CRUD API. Startup fails if no password is set. |
| `APP_LB_AUTH_URL` | unset | Heyo auth service base URL. Enables federated bearer auth. Startup fails unless `APP_LB_ADMIN_AUTH=1`. |
| `APP_LB_AUTH_CACHE_SECS` | `60` | How long a resolved federated grant is cached. |
| `APP_LB_AUTH_TIMEOUT_SECS` | `5` | Timeout for one grant lookup. The gate fails closed. |
| `APP_LB_HOME_URL` | unset | Front-end URL linked from `/login` and from expired namespace sessions. |
| `APP_LB_ONBOARDING_MCP_URL` | unset | Hosted MCP endpoint the dashboard's "Get started" card tells namespace users to install (e.g. `https://mcp.us2.heyo.work/mcp`). Unset leaves that step out. |
| `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` | `7776000` (90 days) | Longest lifetime a namespace admin may mint a token for; also the default when they ask for none. |
| `APP_LB_PUBLIC_IMAGE_CATALOG_URL` | unset | Cloud base URL serving `/public-images/{name}/meta`. Used to resolve the "Get started" fastcar spec's image download and digest. |
| `APP_LB_ONBOARDING_FASTCAR_IMAGE` | `fastcar` | Catalog name of the image that spec deploys. |

### TLS and certificates

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_TLS_CERT` / `APP_LB_TLS_KEY` | unset | Static PEM pair. Set both or neither. With ACME on, this pair is the fallback certificate for any SNI without its own. |
| `APP_LB_ACME_EMAIL` | unset | Enables Let's Encrypt. app-lb issues a certificate for every exact `host` route and renews it 30 days before expiry. |
| `APP_LB_ACME_DIR` | `/var/lib/app-lb/acme` | Account key, certificates and backoff state. Should be `0700`. |
| `APP_LB_ACME_DIRECTORY` | Let's Encrypt production | ACME directory URL. Point it at staging while testing. |
| `APP_LB_ACME_WILDCARD` | unset | Comma-separated domains to cover with a wildcard over DNS-01 (`sb.example.com` also covers `*.sb.example.com`). |
| `APP_LB_ROUTE53_ZONE_ID` | unset | Route 53 zone for DNS-01 challenge records. |
| `APP_LB_AWS_BIN` | `aws` | AWS CLI, used for DNS-01, disk archives and S3 workspaces. |
| `APP_LB_PUBLIC_IPS` | unset | Comma-separated public IPs, reported by `GET /ingress` so clients can show the A/AAAA records to create. app-lb never writes DNS for routes. |
| `APP_LB_DEPLOY_BASE_DOMAIN` | first `APP_LB_ACME_WILDCARD` | Base domain for [hostless deployments](#hostless-deployments). |

HTTP-01 validation needs the proxy on port 80. To bind 80/443 as a non-root user, run `setcap 'cap_net_bind_service=+ep' /usr/local/bin/app-lb`. Let's Encrypt allows 50 new certificates per registered domain per week, so for a fleet of per-sandbox hostnames, use one wildcard plus one wildcard `A` record. A wildcard covers exactly one label. Failed issuance backs off per host (1 minute doubling to 6 hours), and the backoff persists across restarts.

### Builds, images, mounts and site updates

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_BUILD_DIR` | `/var/lib/app-lb/builds` | Git checkouts for image builds. |
| `APP_LB_HEYVM_BIN` | `heyvm` | CLI that runs `heyvm mvm build`. |
| `APP_LB_ART_BIN` | `art` | `art` CLI, used for local-path artifact stores (rootfs, site bundles, mounts, workspaces). Not used for `http(s)://` stores. |
| `APP_LB_GIT_BIN` | `git` | git binary. |
| `APP_LB_IMAGES_DIR` | `/var/lib/app-lb/images` | Scratch directory for pulled or built images before they are uploaded to the daemon. |
| `APP_LB_MOUNTS_DIR` | `/var/lib/app-lb/mounts` | Unpacked guest-mount trees. Must be writable by app-lb and readable by heyvmd. Checked at startup. |
| `APP_LB_MOUNT_TTL_SECS` | `86400` | How long a mount tree that no deployment names is kept. `0` keeps them indefinitely. |
| `APP_LB_UPDATE_SHELL` | `/bin/sh` | Shell used to run `update.commands`. |
| `APP_LB_BUILD_TIMEOUT_SECS` | `1800` | Time limit for one build step or update command. |
| `APP_LB_HEYVM_HOME` | unset | `HOME` for the `heyvm` and `art` child processes. |

### Disks and workspaces

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_DISKS_PATH` | `app-lb-disks.json` | Retention decisions (pins, notes, archive locations). |
| `APP_LB_DISK_TTL_SECS` | `604800` (7 days) | Age at which an unclaimed, unpinned disk is reclaimed. `0` turns expiry off. |
| `APP_LB_DISK_ORPHAN_TTL_SECS` | `900` | Age at which a disk the daemon has no record of is reclaimed. |
| `APP_LB_DISK_SWEEP_SECS` | `3600` | Interval between sweeps (minimum 60). |
| `APP_LB_DISK_ARCHIVE_BUCKET` | unset | S3 bucket for disk archives. Setting it enables archiving. |
| `APP_LB_DISK_ARCHIVE_PREFIX` | `app-lb/disks` | Key prefix in that bucket. |
| `APP_LB_DISK_ARCHIVE_ENDPOINT` | unset | `--endpoint-url` for an S3-compatible store. Also used by S3 workspace stores. |
| `APP_LB_DISK_ARCHIVE_ON_EXPIRE` | `false` | Archive a disk before the sweep reclaims it. |
| `APP_LB_DISK_ARCHIVE_TIMEOUT_SECS` | `7200` | Time limit for one archive. |
| `APP_LB_WORKSPACES_DIR` | `/var/lib/app-lb/workspaces` | Local workspace trees. |
| `APP_LB_WORKSPACE_TIMEOUT_SECS` | `3600` | Time limit for one workspace capture, push or restore. |
| `APP_LB_TAR_BIN` | `tar` | `tar` used for workspace captures and restores. |

### Discovery, fleet views and host updates

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_DISCOVERY_URL` | unset | Default Orchestrator base URL for [discovery](#discovery-and-regions). Must be set together with the token. |
| `APP_LB_DISCOVERY_TOKEN` | unset | Bearer credential for that Orchestrator. |
| `APP_LB_DISCOVERY_INTERVAL_SECS` | `5` | Poll interval. |
| `APP_LB_FLEET_FILE` | unset | JSON array of regional gateways for the dashboard's fleet view. When set, it overrides `/control-plane/config`. |
| `APP_LB_CONTROL_PLANE_FILE` | unset | JSON array of Orchestrator origins for `GET /services`. When set, it overrides `/control-plane/config`. |
| `APP_LB_HOST_UPDATE_CONFIG` | unset | Absolute path to the host-update mapping file. Enables [host executable rollouts](#host-executable-rollouts). |

### Log shipping and security monitoring

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_OBS_URL` | unset | app-obs address (`127.0.0.1:9500` works). Setting it enables shipping. |
| `APP_LB_OBS_TOKEN` | unset | Must match app-obs's `APP_OBS_INGEST_TOKEN`. |
| `APP_LB_OBS_HOST` | contents of `/etc/hostname` | Host name stamped on each batch. |
| `APP_LB_OBS_DEPLOYMENT` | `_lb` | app-obs deployment id for app-lb's own records. Give each host its own value when several share a collector. |
| `APP_LB_OBS_ACCESS_LOG` | `true` | Ship the per-request access log. |
| `APP_LB_OBS_EVENTS` | `true` | Ship app-lb's own events and deploy-job output. |
| `APP_LB_OBS_QUEUE_CAPACITY` | `8192` | Records buffered before new ones are dropped. |
| `APP_LB_OBS_BATCH` | `500` | Records per POST. |
| `APP_LB_OBS_FLUSH_SECS` | `2` | Maximum wait for a fuller batch. |
| `APP_LB_SIEM` | `true` | Security monitoring on or off. |
| `APP_LB_SIEM_QUEUE_CAPACITY` | `4096` | Observations queued for analysis. |
| `APP_LB_SIEM_ALERT_CAPACITY` | `512` | Alerts held in memory. |
| `APP_LB_SIEM_WINDOW_SECS` | `60` | Window for rate-based rules. |
| `APP_LB_SIEM_MAX_CLIENTS` | `16384` | Source addresses tracked at once. |
| `APP_LB_SIEM_AUTH_THRESHOLD` | `8` | Auth failures per window before an alert. |
| `APP_LB_SIEM_SCAN_THRESHOLD` | `30` | 4xx responses per window before a source reads as scanning. |
| `APP_LB_SIEM_RATE_THRESHOLD` | `600` | Requests per window before a source reads as a spike. |
| `APP_LB_SIEM_SUPPRESS_SECS` | `300` | Repeats within this period fold into the open alert. |
| `APP_LB_SIEM_MAX_ALERTS_PER_MIN` | `60` | Maximum number of new alerts per minute. |
| `APP_LB_SIEM_SCAN_QUERY` | `true` | Also scan the query string (it is never stored). |
| `APP_LB_SIEM_SHIP` | `true` | Ship alerts to app-obs. |
| `APP_LB_GUARD_ENFORCE` | `true` | Set `0` for a dry run: rules match and count hits but refuse nothing. |

### LXC driver (Incus)

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_LXC_ENABLED` | `true` | Allow `driver: lxc`. It also needs the Incus socket to be present. |
| `APP_LB_LXC_SOCKET` | `/var/lib/incus/unix.socket` | Incus API socket. |
| `APP_LB_LXC_PROJECT` | `default` | Incus project every request is scoped to. Run app-lb as a member of `incus`, not `incus-admin`. |
| `APP_LB_LXC_REMOTES` | `docker=https://docker.io` | `name=url,...` OCI registries an image may name. Replaces the default list. |
| `APP_LB_LXC_DEFAULT_REMOTE` | `docker` | Remote used when an image has no `remote:` prefix. |
| `APP_LB_LXC_PROFILES` | Incus default | Comma-separated profiles for every container. |
| `APP_LB_LXC_NETWORK_NIC` | first non-`lo` with IPv4 | Interface to read the container address from. |

### Where state lives

Everything relative to `APP_LB_STATE_PATH` sits beside it. With the default name:

| Path | Contents |
| --- | --- |
| `app-lb-state.d/<id>.json` | One file per deployment: spec plus runtime state (suspended VMs, drains, rollout records). |
| `app-lb-state.views.json` | Fleet and control-plane view bindings set through `/control-plane/config`. |
| `app-lb-workflows.d/`, `app-lb-namespaces.d/`, `app-lb-plugins.d/` | CI workflow objects, declared namespaces, plugin configs. |
| `app-lb-state.d/retired/<sha256>.json` | Archived specs from `DELETE .../retired-record`. These are not loaded as deployments. |

A legacy single-file `app-lb-state.json` is imported on first start and renamed to `.migrated`. A deployment file whose spec no longer validates is skipped with a warning and left in place. Only one app-lb process may own a state directory.

## Deployment spec

The machine-readable schema is [`app-lb/schema/deployment-spec.json`](../app-lb/schema/deployment-spec.json). Ready-to-post examples are in [`app-lb/examples/`](../app-lb/examples/README.md).

### Top-level fields

| Field | Default | Meaning |
| --- | --- | --- |
| `id` | required | Unique name. `POST /deployments` with an existing id replaces it. |
| `namespace` | `default` | Tenancy wall for tokens, secrets and the event feed. |
| `routes` | required | List of [route rules](#routes). May be empty only for a `vm` deployment. |
| `vm` | | Managed VM template. Exactly one of `vm`, `upstreams`, `site`. |
| `upstreams` | | Static backends: `host:port`, `ip:port`, or `https://host[:port]`. |
| `site` | | Serve a directory on this host. |
| `scaling` | see below | Replica policy (`vm` only). |
| `health` | `GET /`, 2 s | Readiness and liveness probe. |
| `build` | | Build `vm.image` from a Dockerfile (git or artifact store). |
| `artifact` | | Pull `vm.image` (rootfs) or a site bundle from an artifact store. Mutually exclusive with `build`. |
| `update` | | Commands to run on the host to update a static deployment or site. |
| `auth` | | Sign-in gate in front of the deployment. See [app-lb-auth](app-lb-auth.md). |
| `maintenance` | `false` | Return 503 on public routes before auth or backend selection. The pool and admin API stay up. |
| `ingress` | | `{"cloud": true, "public": true}` asks the Heyo cloud for a URL that reaches the pool through the daemon rather than this proxy (managed only). |
| `feed` | off | `{announce, issues, expose}`. Publishes lifecycle and issues to the namespace RSS feed. `expose` serves the feed at a path on this deployment's routes. |
| `discovery` | | Orchestrator-owned upstream membership. See [Discovery and regions](#discovery-and-regions). |
| `gateway` | | Regional one-hop gateway transport. See [multi-region](multi-region.md). |
| `account_id`, `user_id` | | Stamped by app-lb from a federated caller. Otherwise kept as sent. |

### Routes

A request reaches a deployment when **any** of its rules matches. Within one rule, **every** field that is set must match.

| Field | Matches |
| --- | --- |
| `host` | Exact hostname. Case-insensitive, port stripped. Falls back to HTTP/2 `:authority`. |
| `host_suffix` | The domain and all its subdomains, anchored at a label boundary (`apps.example.com` matches `a.apps.example.com` but not `notapps.example.com`). |
| `path_prefix` | Raw string prefix of the path (`/api` also matches `/apidocs`). |
| `strip_prefix` | `true` removes `path_prefix` before forwarding. Defaults to `false`. |

Across all deployments, the single most specific rule wins: an exact `host` beats any `host_suffix`, which beats any path-only rule. Within a tier, the longer suffix or prefix wins, and a host plus path outranks the same host alone. Exact ties go to the lexicographically lower deployment id. An empty rule `{}` is rejected, and a request that matches nothing gets a 404.

`"routes": []` is valid only for a managed deployment. It is still autoscaled and reachable through `exec` and `shell`, but takes no HTTP traffic. This is the normal shape for an agent sandbox. Static deployments and sites must have at least one route, and so must any deployment with `auth`.

### Hostless deployments

When a base domain is configured (`APP_LB_DEPLOY_BASE_DOMAIN`, or the first `APP_LB_ACME_WILDCARD`), a deployment with no `host` or `host_suffix` route gets a route to `<id>.<base>` at registration. Routeless VM deployments are left private.

### `vm`

| Field | Default | Meaning |
| --- | --- | --- |
| `driver` | `firecracker` | `firecracker` or `kvm` (heyvm microVMs), or `lxc` (Incus system container from an OCI image). `libvirt` and `firecracker_containerd` are rejected. |
| `image` | daemon default (`ubuntu:24.04`) | Image name in the daemon catalog. For `lxc`, a required OCI reference. |
| `port` | required | Guest port traffic is proxied to. |
| `start_command` | | Shell command run once per replica after boot. It must return, so daemonize the workload (`setsid nohup prog </dev/null >/var/log/prog.log 2>&1 &`). Its output goes to `/var/log/heyvm-start.log` inside the guest. |
| `working_directory` | guest default | Directory `start_command` runs in. |
| `size_class` | daemon default | `micro`, `mini`, `small`, `medium`, `large`, `xlarge`. This is the only CPU and memory setting. |
| `disk_size_gb` | none | Per-sandbox data disk mounted at `/workspace`. It belongs to one sandbox: a restart, rollout or `vm` edit boots a replica with a fresh disk. |
| `env_vars` | | Plain environment variables. These are readable from `GET /deployments` and the state file. |
| `env_from` | | Secrets exported as environment variables when a replica is created: `[{"secret": "db", "key": "url", "as": "DATABASE_URL"}]`. `key` defaults to `token`, and `as` defaults to the key upper-cased. |
| `open_ports` | | Extra guest ports to open alongside `port`. |
| `setup_hooks` | | Commands heyvmd runs in the guest before `start_command`. |
| `mounts` | | Up to 8 read-only (by default) directories unpacked from artifact-store tarballs. See [Mounts and workspaces](#mounts-and-workspaces). |
| `workspace` | | A writable directory owned by the deployment, captured when a replica retires and seeded into the next one. |
| `workspace_archive` | | Seed `/workspace` on every replica from a cloud-held archive (`archive_id` resolved to `s3_key` by the cloud). |
| `correlated_creates` | `false` | Use durable daemon creation receipts for autoscaler creates (needs a daemon credential and a daemon that supports it). |
| `ttl_seconds` | `3600` | Backstop TTL. It is renewed while app-lb runs, so VMs expire on their own if app-lb dies. |
| `image_download_url`, `image_size_bytes`, `image_sha256` | | Catalog download hints filled in by the cloud. Leave them unset when writing a spec by hand. |

Changing anything in `vm` is a template change and recycles the pool. `build`, `artifact`, `ingress`, `routes`, `scaling` and `health` edits do not.

`lxc` deployments refuse `correlated_creates`, `workspace_archive`, image download hints, `setup_hooks`, `open_ports`, `build`, `artifact`, `ingress` and (for now) `mounts`. Their ids must be lowercase letters, digits and dashes, short enough to fit Incus's 63-character instance names.

### `scaling`

| Field | Default | Meaning |
| --- | --- | --- |
| `min_replicas` | `0` | Replicas kept with no traffic. |
| `max_replicas` | `5` | Ceiling. Must be at most 1 with `vm.workspace`. |
| `warm_pool` | `0` | Idle ready spares on top of demand. Must be 0 with `vm.workspace`. |
| `target_concurrency` | `10` | In-flight requests per VM the autoscaler aims for. |
| `scale_to_zero_after_secs` | `300` | Idle time before a `min_replicas: 0`, `warm_pool: 0` pool is torn down. `0` tears it down on the first idle tick. |
| `cold_start_timeout_secs` | `120` | How long a request waits for a VM to boot before getting a 503. |
| `drain_timeout_secs` | `30` | How long a draining VM may keep serving in-flight requests. |
| `boot_timeout_secs` | `300` | How long a booting VM has to pass health before it is killed and replaced. `0` waits indefinitely. |
| `idle_action` | `destroy` | `destroy` kills a retired VM and its data disk. `retain` stops it, keeping its `/workspace` disk, and the next scale-up resumes it. |

Desired replicas is `ceil(demand / target_concurrency) + warm_pool`, clamped to `[min_replicas, max_replicas]`, where demand counts in-flight requests plus requests waiting on a cold start. A request that arrives at an empty pool is held while a VM boots.

`retain` preserves only the `/workspace` data disk. Writes to the rootfs and memory are lost in both modes, because the rootfs is recopied from the image on every cold boot. So `retain` is only meaningfully stateful with `disk_size_gb` set and state kept under `/workspace`. For interchangeable replicas, use `destroy`.

Consecutive failed boots back off the next create exponentially, from 30 seconds up to one hour, and reset on the first healthy boot.

### `health`

| Field | Default | Meaning |
| --- | --- | --- |
| `path` | `/` | HTTP GET path. `null` means a bare TCP connect. |
| `port` | the deployment's port | Probe a different guest port. |
| `timeout_secs` | `2` | Per-probe timeout. |
| `expected_header` | | `{"name", "value"}`. Requires a 2xx response and exactly one matching header. Without it, any status below 500 counts as healthy. |

A VM joins the pool only after the daemon reports it running, it has a guest IP, and it passes this probe. Static upstreams are re-probed every autoscaler tick, so a recovered upstream rejoins routing.

### `build`

Builds a new rootfs with `heyvm mvm build`. On success, app-lb rewrites `vm.image` to the result and the pool rolls. Set exactly one of `repo` or `store`.

| Field | Meaning |
| --- | --- |
| `repo` | Git remote: `https://`, `http://`, `ssh://`, `file://`, `user@host:path`, or an absolute path. |
| `store` | Artifact store (`http(s)://` URL or absolute path) holding a Dockerfile manifest. |
| `ref` | For git: a branch, tag or commit, defaulting to the remote's default branch. For a store: a tag or digest, which is required. |
| `dockerfile`, `context` | Git only. Relative paths within the checkout. If `dockerfile` is unset, app-lb searches for a unique `Dockerfile`. |
| `image_name` | Base image name, which defaults to the deployment id. The source version is appended. |
| `image_size_mb` | Rootfs size passed to `--size-mb`. |
| `auth` | Secret reference: a git token for HTTPS remotes (passed through `GIT_ASKPASS`, never the URL), or the store's API key. |

### `artifact`

Pulls bytes that already exist in an [artifacts](artifacts.md) store. Nothing is built.

| Field | Meaning |
| --- | --- |
| `store` | `http(s)://` URL of an `art serve` (app-lb streams and verifies the blob), or an absolute store root on this host (app-lb shells out to `APP_LB_ART_BIN`). |
| `ref` | Tag or 64-hex digest. A tag follows moves. A digest is immutable and is what a rollback names. |
| `auth` | Secret reference for a store started with `ART_API_KEY`. URL form only. |
| `grow_gb` | Managed only. Extends the materialized rootfs (sparse). |
| `image_name` | Managed only. Base name for the materialized image. |
| `strip_components` | Sites only. Leading path components to drop while unpacking (`1` for a `tar czf dist.tgz dist` bundle). |

### `site`

| Field | Default | Meaning |
| --- | --- | --- |
| `root` | required | Absolute directory to serve. Nothing outside it is served, symlinks included. |
| `index` | `index.html` | Served for a directory. `""` makes directories return 404. |
| `not_found` | plain text | 404 body, relative to `root`. |
| `spa` | `false` | Serve `index` with 200 for any unmatched path. |
| `cache_control` | `public, max-age=300` | `Cache-Control` on served files. |

Sites support `ETag`/`304`, byte ranges, `HEAD`, and a `301` from `/dir` to `/dir/`. They don't do rewrites, redirects, directory listings or compression. A site gets its files from either `update` or `artifact`, not both.

### `update`

For static deployments and sites: commands run on the app-lb host.

| Field | Default | Meaning |
| --- | --- | --- |
| `working_dir` | required | Absolute directory, which must already exist. |
| `commands` | required | Run in order through `APP_LB_UPDATE_SHELL`. The first non-zero exit stops the job. |
| `env`, `env_from` | | Extra environment variables, plain or from secrets. |
| `auth` | | Git credential through `GIT_ASKPASS`, for `git pull` over HTTPS. |
| `timeout_secs` | `APP_LB_BUILD_TIMEOUT_SECS` | Time limit per command. |
| `verify_timeout_secs` | `60` | How long to wait afterwards for every upstream to pass health. `0` skips the check. For a site, the job checks that `index` exists in `root`. |

### Mounts and workspaces

A **mount** (`vm.mounts[]`) is data the deployment is given. A **workspace** (`vm.workspace`) is data the deployment makes.

| `mounts[]` field | Default | Meaning |
| --- | --- | --- |
| `path` | required | Absolute guest path. It can't be `/proc`, `/sys`, `/dev`, `/boot`, `/run`, `/workspace`, or nested under another mount. |
| `store`, `ref`, `auth` | | Same as `artifact`. `ref` names a `tar`/`tar.gz` bundle. |
| `strip_components` | `0` | As in `tar --strip-components`. |
| `read_only` | `true` | Writable mounts are allowed on Firecracker and refused on KVM. |
| `digest` | written by the pull job | The resolved tree. |

Mount trees are fetched by a job (`POST /deployments/:id/mounts/pull`, started automatically on register or edit), not at VM create. Until the tree exists, the autoscaler refuses to create replicas.

| `workspace` field | Default | Meaning |
| --- | --- | --- |
| `path` | `/workspace` | Guest path. At `/workspace`, `disk_size_gb` sets its capacity. |
| `store` | required | `s3://bucket[/prefix]`, `http(s)://` art server, or an absolute local store root (needs `APP_LB_ART_BIN`). |
| `ref` | `workspace-<id>` | Tag for the newest snapshot (artifact stores only). |
| `auth` | | Secret reference for an artifact store. |
| `snapshot_interval_secs` | none (minimum 300) | Also snapshot periodically by recycling the replica. |

A workspace is seeded into each new replica. When a replica retires, app-lb captures its workspace (it stops the VM and extracts the image), then pushes the snapshot to the store. The replacement boots only after the capture completes. Workspaces require `driver: firecracker`, `max_replicas <= 1` and `warm_pool: 0`. Files come back owned by app-lb's uid.

`POST /deployments/:id/workspace/recoveries` explicitly promotes a stopped, retained VM's disk to be the new workspace snapshot. It needs namespace-admin credentials even when CRUD is ungated.

### Secret references

`build.auth`, `artifact.auth`, mount and workspace `auth`, `update.auth`, `discovery.source.auth` and the auth gate's secrets are all `{"secret": "<id>", "key": "token", "username": null}`. `env_from` entries add `as`. Every reference is bound to the deployment's namespace at registration, whatever the body says. See [Secrets](#secrets).

### Auth gate and `public_paths`

`auth` puts Google sign-in, app-tokens, a JWT, or a named auth provider in front of everything the deployment serves. It runs in the proxy, so the application needs no changes. `auth.public_paths` lists path prefixes the sign-in gate doesn't redirect. Each entry carries the scope app-lb requires in the gate's place:

| Entry | Requires |
| --- | --- |
| `{"path": "/healthz", "scope": "public"}` | Nothing. Use this only for paths the upstream authorizes itself, or that have nothing to protect. |
| `{"path": "/api/", "scope": "none"}` | Any credential the gate admits (for example, an app-token minted with `admin: none`). |
| `{"path": "/api/", "scope": "view"}` | A view-tier credential. |
| `"/deployments"` or `{"path": ..., "scope": "admin"}` | An admin-tier credential. **A bare string means `admin`**, the most closed scope. |

Everything else about gates, tokens, sessions and providers is in [app-lb-auth](app-lb-auth.md).

## Static and managed deployments

| | Managed (`vm`) | Static (`upstreams`) | Site (`site`) |
| --- | --- | --- | --- |
| Backends | VMs app-lb boots | Addresses someone else runs | Files on this host |
| Scaling, eviction | yes | rejected | rejected |
| `exec` / `shell` | yes | no | no |
| Content source | `build` or `artifact` | `update` | `update` or `artifact` |
| Health | gates each new VM | re-probed every tick | none |
| Routes | may be empty | required | required |

**Static upstreams.** Bare `host:port` is proxied over plain HTTP, and hostnames are re-resolved per connection. An `https://host[:port]` origin uses the hostname for SNI and certificate verification and preserves the caller's `Host`. HTTPS needs a DNS name, not an IP, with no path, credentials or query. To change targets, `PUT` the spec with a new list.

**Cordon and drain.** Operator drains are separate from health. A drained upstream stays out of rotation until you remove the drain, even if it passes every probe. The drain survives restarts and spec replays.

```sh
heyctl cordon stage us1.internal:8080 --reason 'maintenance'   # stop new traffic, return now
heyctl drain stage us1.internal:8080 --timeout 300             # ...and wait for in_flight = 0
heyctl uncordon stage us1.internal:8080
```

The raw API is `PUT`/`DELETE /deployments/:id/upstreams/<url-encoded upstream>/drain`. A first drain returns 409 unless another upstream is healthy and accepting. `{"force": true}` overrides this for an intentional outage. A drain timeout never reopens the upstream.

**Editing.** `PUT /deployments/:id` replaces the spec in place and keeps the pool unless `vm` changed. `POST /deployments` replaces the deployment and tears the pool down. `PATCH /deployments/:id/scaling` is a partial update that always keeps the pool. `DELETE /deployments/:id/vms/:sandbox_id` recycles one VM, either gracefully (202, drain) or with `?force=true` (200, kill now).

**Candidate-first rollouts.** For stateless Firecracker services, use `POST /deployments/:id/rollouts` with `{operation_id, expected_revision, spec}` (`expected_revision` is `rollout_revision` from `GET`). This avoids tearing the pool down. The target spec must pull an `artifact` by 64-hex digest and set `health.expected_header` to `x-heyo-revision: <git sha>`. Candidates boot unrouted, cut over only when healthy, and the old replicas drain and are stopped rather than destroyed. Poll `GET /deployments/:id/rollouts/:operation` until `status` is `succeeded`. The other terminal states are `failed` and `reconciliation_required`. Routes, auth, namespace and maintenance must not change in the same rollout.

## Admin API

The admin listener (`APP_LB_ADMIN_ADDR`) serves the API, the dashboards and `/healthz`. Routes fall into tiers:

- **Open:** `/healthz`, `/login`, `/logout`, UI assets.
- **View tier:** gated by the dashboard password (or a view token) unless `APP_LB_DASHBOARD_AUTH=0`.
- **CRUD tier:** gated only when `APP_LB_ADMIN_AUTH=1`. An ungated CRUD API can run code on the host (builds and updates), so gate it before you expose the listener.
- **Always authenticated:** fleet, control-plane, recovery and regional routes need credentials even when the gates are off.

A deployment- or namespace-scoped token sees a narrowed view of list and metrics routes. See [app-lb-auth](app-lb-auth.md).

### View tier

| Route | Returns |
| --- | --- |
| `GET /` | Directory: one card per routable URL, with health dots. |
| `GET /dashboard` | Live dashboard. `?view=local` forces this gateway's local view. |
| `GET /metrics` | JSON metrics. See [Metrics](#metrics). |
| `GET /security` | Security alerts, block rules and hit history. `?severity=&rule=&deployment=&limit=` |
| `GET /siem` | Security console. |
| `GET /disks` | Disk inventory and archive progress. |
| `GET /storage` | Storage console. |
| `GET /network` | Network topology console. |
| `GET /ingress` | `{"ipv4": [...], "ipv6": [...]}` from `APP_LB_PUBLIC_IPS`. |
| `GET /namespaces` | Namespaces visible to the caller. |
| `GET /auth-providers` | Declared auth providers. |
| `GET /feeds`, `GET /feeds/:namespace` | Namespace event feeds (RSS). |
| `GET /plugins`, `GET /api/plugins`, `GET /api/plugins/:id` | Plugin console and records. |

### CRUD tier

| Route | Purpose |
| --- | --- |
| `POST /deployments` | Register or replace. `If-None-Match: *` makes it create-only (412 if the id exists). |
| `GET /deployments` | List with live pool state. |
| `GET /deployments/:id` | One deployment. Carries an `ETag` of the normalized spec. |
| `PUT /deployments/:id` | Edit in place. `If-Match: "<etag>"` makes it compare-and-swap (412 on a stale tag). |
| `DELETE /deployments/:id` | Drain and reap every VM, then remove the deployment. |
| `DELETE /deployments/:id/record` | Remove a proven-empty record only (requires `If-Match`, touches no VMs). |
| `DELETE /deployments/:id/retired-record` | Archive and remove a settled, fully drained managed deployment (fleet admin, `If-Match`). |
| `PATCH /deployments/:id/scaling` | Partial scaling update. |
| `DELETE /deployments/:id/vms/:sandbox_id` | Evict one VM (`?force=true` to kill). |
| `PUT`/`DELETE /deployments/:id/upstreams/:upstream/drain` | Cordon or drain, then uncordon, a static upstream. |
| `GET /deployments/:id/discovery-status` | Discovery version and per-upstream drain and in-flight state. |
| `POST /deployments/:id/rollouts`, `GET .../rollouts/:operation` | Candidate-first rollout. |
| `POST /deployments/:id/exec` | `{command, cwd?, env?, timeout_secs?, wake?, sandbox_id?}` returns `{sandbox_id, exit_code, stdout, stderr, output}`. |
| `GET /deployments/:id/shell` | WebSocket PTY. `?cols=&rows=&cwd=&wake=&sandbox_id=` |
| `POST /deployments/:id/build` | Start a build (`{"ref": ...}` for a one-off ref). Returns 202 and a job. |
| `POST /deployments/:id/pull` | Start an artifact pull (`{"ref": ..., "force": true}`). |
| `POST /deployments/:id/mounts/pull` | Start a mount pull (`{"force": true}`). |
| `POST /deployments/:id/update` | Run `update.commands`. |
| `GET /deployments/:id/jobs`, `GET /jobs`, `GET /jobs/:job_id` | Job history, results and output tails. |
| `GET`/`POST /deployments/:id/update/rollouts`, `GET .../rollouts/:operation`, `GET .../bootstrap/:operation` | [Host executable rollouts](#host-executable-rollouts). |
| `GET /certs` | Issued certificates, expiry and renewal state. |
| `POST /secrets`, `GET /secrets`, `GET`/`PUT`/`PATCH`/`DELETE /secrets/:id` | Secret store (`?namespace=` on per-id routes). |
| `POST /security/rules`, `PATCH`/`DELETE /security/rules/:id` | Block and allow rules. |
| `PATCH /disks/:id`, `DELETE /disks/:id`, `POST /disks/:id/archive`, `POST /disks/sweep`, `POST /disks/purge-orphans` | Disk retention and reclamation. |
| `POST`/`GET /workflows`, `GET`/`PUT`/`DELETE /workflows/:id` | CI workflow objects that [ci](ci.md) polls. |
| `POST /tokens`, `GET /tokens`, `GET`/`PATCH`/`DELETE /tokens/:id` | App-tokens. |
| `POST /namespaces`, `DELETE /namespaces/:name` | Declare or remove namespaces (fleet scope). |
| `POST /auth-providers`, `GET`/`DELETE /auth-providers/:namespace/:name` | Auth providers. |
| `PUT /api/plugins/:id`, `POST /api/plugins/:id/enable`, `POST /api/plugins/:id/disable` | Plugin configuration. |

### Always-authenticated routes

| Route | Purpose |
| --- | --- |
| `GET /whoami` | What the presented credential is. |
| `GET`/`POST /deployments/:id/retirement` | Retirement status and action. |
| `POST /deployments/:id/workspace/recoveries`, `GET .../:operation_id` | Workspace recovery. |
| `POST /deployments/:id/regional-probe`, `.../regional-active-probe`, `.../route-handoff`, `.../route-handoff/commit` | Regional gateway protocol (see [multi-region](multi-region.md)). |
| `GET /fleet`, `/fleet/deployments`, `/fleet/gateways/:id/metrics`, `/fleet/network`, `/services` | Fleet observations (fleet view). |
| `GET`/`PUT /control-plane/config` | Fleet and control-plane view bindings (fleet admin). |

### Capability headers

`GET /deployments` advertises what this binary supports, so controllers can check before relying on a feature: `x-app-lb-create-only`, `x-app-lb-discovery-source`, `x-app-lb-discovery-region`, `x-app-lb-gateway`, `x-app-lb-regional-admission` (each `1`). Unknown spec fields are ignored by older binaries, which is why you should check these headers first.

The spec `ETag` is `"<hex>"`, where the hex is the lowercase SHA-256 of the compact JSON of the response's `spec` with every object's keys sorted recursively and array order preserved.

### Running commands inside a VM

`exec` and `shell` are the only way into an unrouted sandbox:

```sh
curl -XPOST localhost:9090/deployments/sb-7f3a9c/exec -H 'content-type: application/json' \
  -d '{"command": "ls -la /workspace", "cwd": "/workspace"}'
heyctl shell sb-7f3a9c
```

Without `sandbox_id`, the pool picks a VM. With it, you get that VM, a 404 (not in the deployment), or a 409 (not ready or draining). `wake` defaults to true, so a scaled-to-zero sandbox boots or resumes, bounded by `cold_start_timeout_secs`. An open command or shell counts as in-flight work, so the VM is not reaped under you. A command that fails returns 200 with a non-zero `exit_code`. app-lb failing to run the command returns 502.

## Dashboards

All pages are served by the admin listener, self-contained, and work over an SSH tunnel.

| Page | Shows |
| --- | --- |
| `/` | Directory of routable URLs. Green means healthy, amber means booting or idle at zero, red means nothing healthy. Server-rendered, no polling. |
| `/dashboard` | Host and per-VM CPU and memory, pool gauges, latency distribution and percentiles, cold starts, autoscaling activity, booting VMs, host sandboxes app-lb doesn't own, certificates, secrets (key names only) and deploy jobs with live logs. It has Scale, Edit, Drain/Kill, Shell, Build/Update and secret-rotation controls, which call the CRUD tier. |
| `/siem` | Security findings with runbooks, pre-filled block rules, and rule hit charts. |
| `/storage` | Disk inventory, with pin, archive, purge and purge-orphans actions. |
| `/network` | Topology: ingress, deployments and VMs, locally or across a configured fleet. |
| `/plugins` | Plugin cards and configuration. |

With fleet views configured, `/dashboard` defaults to the fleet overview and links to each gateway's `?view=local`.

## Security monitoring

Security monitoring is on by default (`APP_LB_SIEM=0` turns it off). app-lb analyzes every request off the request path and raises alerts with ECS field names:

| Family | Rules |
| --- | --- |
| Authentication abuse | `auth.brute-force`, `auth.spray` (4+ deployments), `auth.enumeration` (4+ identities), `auth.scope-denied`, `auth.signin-state` |
| Attack signatures | `web.rce`, `web.traversal`, `web.sqli`, `web.xss`, `web.secret-probe` |
| Traffic anomalies | `traffic.scanner` (4xx across many distinct paths), `traffic.rate-spike` |

Repeats with the same rule, source and deployment fold into one alert whose `count` climbs. Sources are keyed per /32 for IPv4 and per /64 for IPv6, on the socket peer only (`X-Forwarded-For` is never trusted). Query strings are scanned but never stored: an alert names the parameter, not the value. Credentials are never recorded. Alerts are held in memory and shipped to app-obs as `source=security`.

The `dropped` and `clients_at_capacity` counters on `/security` and `/metrics` tell you when detection is sampling. Raise the queue or client capacity if either is non-zero.

**Block rules** are enforced on the data plane and persisted to `APP_LB_GUARD_PATH`:

```sh
curl -XPOST localhost:9090/security/rules -H 'content-type: application/json' \
  -d '{"action":"block","match":{"client":"203.0.113.9"},"expires_in_secs":3600}'
curl -XPOST localhost:9090/security/rules -H 'content-type: application/json' \
  -d '{"action":"allow","match":{"client":"10.0.0.0/8"},"note":"monitoring"}'
curl -XPATCH localhost:9090/security/rules/5f295e1a86f2 -H 'content-type: application/json' \
  -d '{"expires_in_secs":null}'     # keep indefinitely; the field is required on PATCH
```

| `match` field | Matches |
| --- | --- |
| `client` | Address or CIDR (IPv4 or IPv6). |
| `host` | Hostname, exactly. |
| `deployment` | The deployment the request routed to. |
| `path_prefix`, `path_contains` | The path, literally. |
| `method` | HTTP method. |
| `user_agent_contains` | Case-insensitive `User-Agent` substring. |

All present fields must match. `allow` beats `block`. An empty match is refused. Posting the same conditions again replaces the rule. There are no regular expressions. Rules never apply to the admin API, and ACME challenges are answered before the guard runs. Use `APP_LB_GUARD_ENFORCE=0` to try a broad rule in dry-run mode first.

## Secrets

app-lb keeps its own write-only secret store. Deployments refer to secrets by name, and no endpoint ever returns a value.

```sh
curl -XPOST localhost:9090/secrets -H 'content-type: application/json' \
  -d '{"id": "db", "namespace": "team-a", "data": {"url": "postgres://..."}}'
curl 'localhost:9090/secrets?namespace=team-a'                   # ids and key names only
curl -XPATCH 'localhost:9090/secrets/db?namespace=team-a' -H 'content-type: application/json' \
  -d '{"data": {"url": "postgres://rotated..."}}'               # null removes a key
curl -XDELETE 'localhost:9090/secrets/db?namespace=team-a'       # 409 while referenced
```

- Secrets are separated by namespace, and references in a spec resolve only within the deployment's namespace.
- `env_from` is resolved each time a replica is created. Rotation reaches the next replica without re-registering, and a missing secret fails the create.
- At rest, the store is `APP_LB_SECRETS_PATH` (mode `0600`), or AES-256-GCM sealed with `APP_LB_SECRET_KEY`. Starting without the key that sealed the file is a hard failure, not an empty store.
- For HWS installations, the canonical value of a service credential lives in [heyosecret](heyosecret.md). Load it into app-lb's store under one stable id per role, and never put values in specs, fleet files or config documents.

## Metrics

`GET /metrics` returns JSON (it is not Prometheus text):

| Key | Contents |
| --- | --- |
| `host` | Whole-machine CPU and memory. |
| `fleet` | Deployments, ready, draining and pending VMs, and total in-flight requests across the visible registry. |
| `global` | Rolled-up request, latency and autoscale counters, including deregistered deployments. |
| `deployments[]` | Per deployment: `kind`, `routed`, `hosts`, `urls`, `pool`, `vms[]` (id, address, in-flight, health, draining, uptime, CPU, memory), `pending_vms[]`, and `metrics` (latency histograms and `autoscale` counters such as `vms_created`, `vms_drained`, `boot_timeouts`, `create_failures`, `last_create_error`). |
| `host_sandboxes` | Sandboxes on the host that app-lb doesn't own. These are reported, not managed. |
| `obs`, `security`, `daemon` | Log-shipping stats, SIEM summary and daemon stats. |
| `matched`, `tracked_deployments` | Filter match count, and a self-check that counters are released on deregister. |

| Query | Effect |
| --- | --- |
| `deployment=<id>` | One deployment. |
| `prefix=<s>` | Ids starting with `s`. |
| `namespace=<ns>` | One namespace. |
| `summary=true` | Drop per-VM rows and host sandboxes. |
| `limit=`, `offset=` | Page through deployments. |

Filters narrow `deployments` only. `host`, `fleet` and `global` always describe the whole visible LB. [app-obs](app-obs.md) scrapes this endpoint. `heyctl top` summarizes it.

## Log shipping

With `APP_LB_OBS_URL` set, app-lb pushes four record sources to app-obs, tagged `source`:

- `access`: one record per request, attributed to the deployment. The query string is never included.
- `app-lb`: its own events at INFO and above (scaling, slow boots, unhealthy upstreams, ACME, job outcomes).
- `job`: every line of build and update output.
- `security`: alerts.

Records that name no deployment go under `APP_LB_OBS_DEPLOYMENT`. Queues drop records rather than block, so a slow or absent collector costs you telemetry, never traffic.

## Disk management

heyvmd leaves per-sandbox disk directories behind in several cases. app-lb inventories them through the daemon (`GET /disks`, `/storage`) and reclaims them on a timer. A disk is never reclaimed while:

- its sandbox is running (not even with `?force=1`),
- a deployment expects to resume it (`idle_action: retain`),
- it is pinned (`PATCH /disks/:id {"retain": true, "note": "..."}`), or
- the daemon is unreachable (the inventory reports `complete: false` and the sweep does not run).

Unclaimed disks expire after `APP_LB_DISK_TTL_SECS` (7 days). Disks the daemon has no record of expire after `APP_LB_DISK_ORPHAN_TTL_SECS` (15 minutes). `POST /disks/purge-orphans` reclaims all orphans immediately. `POST /disks/:id/archive {"purge": true}` streams a sparse `tar.gz` to `s3://$APP_LB_DISK_ARCHIVE_BUCKET/<prefix>/<id>/<ts>.tar.gz`, then reclaims the disk only if the upload succeeded. Startup logs how much the first sweep will delete. It runs one interval later, so you have time to pin disks or set the TTL to `0`.

`heyvm prune` is complementary. It clears `/tmp` scratch and, with `--images`, can delete an image a scaled-to-zero deployment still needs. Re-run `pull` or `build` if that happens.

## Discovery and regions

A static deployment can take its upstream list from [Orchestrator](orchestrator.md):

```json
{"id": "cloud", "routes": [{"host": "cloud.example.com"}], "upstreams": [],
 "discovery": {"service_id": "cloud", "region": "eu1",
   "source": {"url": "https://orchestrator.example.com/orchestration/services/cloud/discovery",
              "auth": {"secret": "discovery-reader", "key": "token"}}}}
```

Each poll atomically replaces the upstream list with healthy, non-draining endpoints and persists the last good set. Failed or stale snapshots leave the list intact. A per-deployment `source` takes precedence over `APP_LB_DISCOVERY_URL`/`APP_LB_DISCOVERY_TOKEN`, and its token is resolved from the secret store on every poll. `region` requests region-scoped membership and rejects snapshots that don't echo it. Once a deployment has observed an authority, changing it is rejected. Withdrawn upstreams are fenced from new requests and stay counted in `discovery-status` until their in-flight requests finish.

The `gateway` block and `discovery.regional` add authenticated one-hop forwarding between regional app-lbs. That protocol, and how both regions share one discovery authority, is covered in [multi-region](multi-region.md).

**Fleet views** are read-only observations of other app-lbs. They are not placement or routing authority. Configure them with `PUT /control-plane/config` (`{"expected_revision": N, "config": {"gateways": [...], "control_plane": [...]}}`) or with `APP_LB_FLEET_FILE`/`APP_LB_CONTROL_PLANE_FILE`, which make the API read-only. Each gateway entry is:

```json
{"id": "eu1-edge", "region": "eu1", "url": "https://admin.eu1.example.com",
 "auth": {"secret": "fleet-observer", "key": "token"}}
```

Use `"use_caller_auth": true` in place of `auth` to forward the signed-in Heyo user's bearer instead. Only HTTPS origins are accepted. An observer token must be view tier and cover all deployments (`heyctl token mint fleet-observer --admin view --all-deployments`). `GET /fleet/deployments` rolls up namespace-by-deployment rows across servers. A server that can't be read appears as an error cell, never as zero capacity.

## Host executable rollouts

Replacing the app-lb binary on a host is a separate operation from VM rollouts. It is off unless `APP_LB_HOST_UPDATE_CONFIG` names an operator-owned, root-owned JSON mapping:

```json
{
  "deployment": "app-lb-host-controller",
  "namespace": "default",
  "executable": "/usr/local/bin/app-lb",
  "process": {"kind": "supervisor", "program": "app-lb"},
  "state_dir": "/var/lib/app-lb/host-updates",
  "artifact_store": "https://artifacts.example.com",
  "health_url": "https://admin.example.com/healthz",
  "config_files": ["/etc/supervisor/conf.d/app-lb.conf"]
}
```

`process` may instead be `{"kind": "systemd", "unit": "..."}`. `GET /deployments/:id/update/rollouts` reports the current `binary_sha256` and `config_sha256`. `POST` the same path with `{operation_id, expected_binary_sha256, expected_config_sha256, artifact_sha256, binary_sha256, revision}`. app-lb downloads the release bundle from the configured store, verifies `dist/app-lb`, `dist/REVISION` and `dist/SHA256SUMS`, keeps the previous binary, and has an independent systemd helper swap the binary and restart only the mapped program. Success requires a new process whose binary hash and compiled revision match, and whose public `/healthz` returns exactly that `x-heyo-revision`. Ambiguous outcomes stay fenced for operator reconciliation, with no automatic rollback. Hosts that predate the helper need the one-time `--bootstrap-host-update` path described in [`app-lb/README.md`](../app-lb/README.md#correlated-host-executable-rollout).

This restarts the regional ingress. Move traffic away from the region first. See [multi-region](multi-region.md).

## Plugins

Plugins are compiled in and switched on at runtime from `/plugins` or with `heyctl plugins`. Configs live in `app-lb-plugins.d/`, name secrets rather than holding credentials, and expose routes under `/api/plugins/<id>/` (reads on the view tier, actions on CRUD).

| Plugin | Does |
| --- | --- |
| `pgfc` | Monitors and manages [pg-fc](pg-fc.md) pools: schemas, dedicated databases, pooler settings, logs. |
| `vapi` | Monitors vapi inference gateways and exposes their admission settings and a test prompt box. |

## Troubleshooting

**A pool stays at zero ready.** Start with `GET /metrics?deployment=<id>` and look at `metrics.autoscale`:

- `vms_created` and `boot_timeouts` both rising: the daemon creates VMs but the guest never passes health. Read the start log inside the guest with `heyctl exec <id> -- cat /var/log/heyvm-start.log` (and `.err.log`). It is not in app-obs, and it lives only as long as that boot. Common causes: a `start_command` that blocks instead of daemonizing, a server bound to `127.0.0.1` instead of the guest interface, the wrong `port`, or a `health.path` behind auth or returning 5xx.
- `vms_created` flat while desired is above zero: creates fail before a VM exists (`create_failures` and `last_create_error` say why). Check for a missing image (for example, after `heyvm prune --images`), a full disk, host memory admission in heyvmd, a secret in `env_from` that doesn't exist, or a mount or workspace that isn't ready. The app-lb log names the reason (`not creating a replica yet: ...`).
- `vms_created` and `vms_drained` climbing together with no failures: scale-to-zero churn. Check `scale_to_zero_after_secs`, but first find out why the replica was retired.

Each booting VM is logged with a `waiting_on` field every 30 seconds. "the daemon has not reported it Running yet" means wait. "the guest is up but has not answered" means look at the guest.

**Health checks never pass but `ping` works.** A host firewall is rejecting forwarded TCP to the tap interface (ufw answers with `icmp-host-prohibited`, which shows up as `No route to host`). Allow traffic on the Firecracker taps, for example `sudo ufw allow in on tap-fc-+`, or scope the rule to the guest subnet.

**A workspace deployment will not boot a replica.** The log says `workspace restore pending: ...` or `workspace capture of <sb> is queued`. For a local-path `store`, restores and pushes shell out to the `art` CLI, so it must be installed on the app-lb host or pointed at with `APP_LB_ART_BIN`. With an `http(s)://` store, the art server must support `GET /tags/<name>`. Capture, restore and push run one at a time across deployments, bounded by `APP_LB_WORKSPACE_TIMEOUT_SECS`, so one stuck transfer delays the others.

**Requests hang after a VM is destroyed.** A destroyed Firecracker VM takes its tap with it, so no RST ever arrives. app-lb sets TCP keepalive (30 s idle, 10 s interval, 3 probes) and a 60-second `TCP_USER_TIMEOUT` on every upstream socket, so dead peers are dropped within about a minute. On an older build without this, list the stuck sockets with `ss -tno dst <vm-ip>` and kill them with `ss -K dst <vm-ip> dport = :<port>`.

**Deploy jobs are slow or failing on a full disk.** Builds that time out after `APP_LB_BUILD_TIMEOUT_SECS` and git failing to write lock files both point to a full disk. A pool whose guest never becomes healthy strands a data disk per failed boot. Set `min_replicas: 0` to stop allocating, then reclaim from `/storage` or with `POST /disks/purge-orphans`.

**Disks are listed but never reclaimed.** app-lb's user needs write access to the daemon's data directories (`run/`, `kvm/`). A purge that removes nothing returns 500, not success.

**`401` on everything after a restart.** The dashboard password changed and your [heyctl](heyctl.md) context still holds the old one. Log in again.

**A certificate never arrives.** Check `GET /certs` and the log for ACME backoff. HTTP-01 needs port 80 and DNS pointing at this host. `host_suffix` routes need a wildcard (`APP_LB_ACME_WILDCARD`). Test against the staging directory. Switching directories discards cached state automatically.

**A second app-lb refuses to start.** That is the instance lock working as intended. Never run a second app-lb against the same daemon (including by passing it unknown arguments on an old build). It would treat the first instance's sandboxes as orphans.
