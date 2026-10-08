# app-obs

app-obs collects logs and metrics for the deployments [app-lb](app-lb.md) manages, stores them as partitioned Parquet, and serves a query API and dashboard over them.

## What it is

app-obs is a single host process (not a microVM) that runs next to app-lb. It:

- **tails every managed VM's console and `start_command` output** from the heyvm daemon, with no shipper or code inside the guest;
- **accepts pushed logs** from applications over HTTP (JSON) and syslog (UDP and TCP);
- **polls app-lb's `GET /metrics`** for request counts, error counts, latency, pool state, and per-VM and whole-host CPU and memory;
- **stores everything** as Hive-partitioned Parquet under one data directory, compacts small files, and deletes partitions past a retention window;
- **serves a dashboard and JSON API** with a fleet view, per-deployment charts, a filterable log viewer, and a live platform status view;
- **fires webhook alerts** when a deployment's error count crosses a threshold.

It is fronted by app-lb as a static (`proxy_pass`) deployment, the same way the pg-fc and queue dashboards are.

app-obs is never part of the data plane. If it is down, app-lb keeps serving traffic, and guests that push to a dead ingest port get a connection error rather than blocking.

## How data arrives

### Native tail from the heyvm daemon

With `HEYVM_URL` set, app-obs opens a WebSocket to the daemon's `GET /sandboxes/{id}/logs/stream` for every sandbox the app-lb poll reports. Each line is stored with the deployment and sandbox it came from and a `source` of `stdout`, `stderr`, or `console`. app-lb is the authority on which sandbox serves which deployment; the daemon only knows sandbox ids. On reconnect, app-obs asks for a small backlog and drops lines it has already stored.

Sandboxes on the host that no deployment manages (made with `heyvm`, the cloud API, or the desktop app) are reported by app-lb as `host_sandboxes`. app-obs tails those too and files them under the reserved deployment id `_unmanaged`, with `backend` set to the sandbox id.

Unset `HEYVM_URL` disables native tailing.

### Push over HTTP

Every microVM sits on its own `/30`, with the host at `guest_ip - 1`. Guests send to their default gateway, which is always this host, so the ingest listener binds `0.0.0.0` by default.

```sh
# inside a guest
GW=$(ip route | awk '/^default/ {print $3}')
curl -XPOST "http://$GW:9500/ingest" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $APP_OBS_INGEST_TOKEN" \
  -d '{
    "deployment": "demo",
    "backend": "sb-abc123",
    "records": [
      {"ts": 1785260096000, "level": "info", "message": "started"},
      {"level": "error", "message": "boom", "fields": {"request_id": "r1"}}
    ]
  }'
```

Batch fields:

| Field | Meaning |
| --- | --- |
| `deployment` | Default deployment id for records that don't set their own |
| `backend` | Default instance id: a sandbox id for a VM, `host:port` for a static upstream. `sandbox_id` is accepted as an alias |
| `host` | Default host name |
| `records` | Array of records |

Record fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `message` | yes | The log line |
| `ts` | no | Epoch milliseconds, epoch seconds, or RFC 3339. Defaults to arrival time |
| `level` | no | Stored as sent. The dashboard counts `error`, `err`, `fatal`, `critical`, `crit`, `emergency`, `emerg`, `alert`, and `panic` (any case) as errors |
| `fields` | no | Any JSON value, stored as a JSON string |
| `source` | no | Defaults to `stdout` |
| `deployment`, `backend` (`sandbox_id`), `host` | no | Override the batch defaults |

The response is `202 Accepted` with `{"accepted": n, "dropped": n, "rejected": n}`. A record with no resolvable `deployment` is rejected; retrying it will not help. With `APP_OBS_INGEST_TOKEN` set, a request without the matching bearer token gets `401`.

If an application both prints to stdout and pushes the same lines, and native tailing is on, each line is stored twice under different `source` values. Pick one path per line.

### Push over syslog

```sh
logger -n "$GW" -P 9514 -t demo "hello from syslog"
```

The syslog tag becomes the deployment id when it is a valid id; otherwise records land under `syslog`. Syslog severities are normalised to `error`, `warning`, `info`, or `debug`.

### Metrics poll

Every `APP_OBS_POLL_SECS`, app-obs fetches app-lb's `GET /metrics` and writes one metric row per deployment (plus per-backend rows). Whole-host CPU and memory are stored under the reserved deployment id `_host`. Don't register deployments named `_host` or `_unmanaged`.

When app-lb has admin auth enabled, set `APP_LB_PASSWORD`; the poller then sends HTTP basic auth with `APP_LB_USER` (default `admin`).

### Back-pressure

All ingest paths feed one bounded queue (`APP_OBS_QUEUE_CAPACITY`). When it is full, records are dropped and counted, never blocked, so a slow collector cannot stall an application. `GET /stats` reports the counters.

## Storage

```text
<APP_OBS_DATA_DIR>/
  logs/deployment=<id>/date=YYYY-MM-DD/hour=HH/<ts>-<seq>.parquet
  metrics/deployment=<id>/date=YYYY-MM-DD/<ts>-<seq>.parquet
  alerts.json
```

- Logs partition hourly; metrics partition daily. `deployment`, `date`, and `hour` live in the path, not in the files, so a query filtered by deployment and time only opens matching directories.
- A partition flushes when it has `APP_OBS_FLUSH_ROWS` buffered rows or `APP_OBS_FLUSH_SECS` after its first row, whichever comes first. Until then, the newest rows are in memory and not queryable; `/stats` reports them as `buffered_rows`.
- Files are written under a temporary name and renamed into place, so readers never see a partial file.
- A background compactor merges each partition's small files into one every `APP_OBS_COMPACT_SECS`. Swaps happen with queries paused, and an interrupted merge is rolled back or cleaned up on the next pass.
- Retention deletes whole partition directories older than `APP_OBS_RETAIN_DAYS`, counting back from and including today (`7` keeps seven days). Future-dated partitions are never deleted, so a sender with a skewed clock can grow the data directory beyond what the window suggests.

### Log columns

`ts`, `backend`, `source`, `level`, `message`, `fields`, `host`, `namespace` (plus the `deployment`/`date`/`hour` partition keys).

### Metric columns

`ts`, `backend`, `cpu_percent`, `memory_bytes`, `in_flight`, `ready`, `pending`, `draining`, `requests_total`, `errors_total`, `p50_ms`, `p90_ms`, `p99_ms`, `latency_count`, `latency_sum`, `namespace`.

`namespace` is the app-lb namespace the deployment was in when the row was written, stamped by the collector (never by the sender). Platform rows (`_host`, `_lb`, `_unmanaged`, `syslog`) and rows for deployments app-lb has not reported yet carry `_`, which no namespace route can ask for. Files written before the column existed read it as null, which is treated as `default`; compaction fills the column with nulls when it merges old and new files.

Things to know when reading metrics:

- Percentiles are **p50, p90, p99** only, the ones app-lb measures. There is no p95.
- app-lb's latency histogram and request counters are **cumulative since app-lb started**. The dashboard charts mean latency per interval by differencing `latency_count` and `latency_sum`, and rates by differencing the totals. A decrease means app-lb restarted; that interval is reported as null (a gap on the chart), not zero.
- A metric that was not reported is stored as null, not zero.

## Dashboard and query API

The API listener (default `127.0.0.1:9600`) serves a single self-contained HTML dashboard at `/dashboard` (`/` redirects there). It uses no CDN, so it works on a host with no outbound route. The fleet page lists every deployment with a sparkline and error count, plus the sandboxes on the host outside any deployment. A deployment page shows charts and a log viewer filterable by level, backend, text, and an explicit time range.

| Route | Auth | Returns |
| --- | --- | --- |
| `GET /dashboard` | token | The dashboard page |
| `GET /api/fleet?window=` | token | One row per deployment, plus whole-host CPU and memory |
| `GET /api/platform-status` | token | Current app-lb topology from the latest poll: backend health, drain state, in-flight requests, pool capacity, and staleness |
| `GET /api/deployments/{id}?window=` | token | Bucketed metric series and summary figures |
| `GET /api/deployments/{id}/logs` | token | Log lines, newest first (parameters below) |
| `GET /api/alerts` | token | All alert rules |
| `POST /api/alerts` | token | Create an alert rule |
| `DELETE /api/alerts/{id}` | token | Delete an alert rule (`204` even if already gone) |
| `GET /stats` | token | Ingest counters (`accepted`, `dropped`, `gated`), `buffered_rows`, and the install gate as `collecting` |
| `GET /ns/{ns}/…` | token | One namespace's dashboard, API and alerts; see [Per-namespace plugin](#per-namespace-plugin) |
| `GET /healthz` | open | `ok`. Never waits on a query slot |
| `GET /__ui/{path}` | open | Shared stylesheet, theme script, and fonts |

"token" means the route requires `Authorization: Bearer <APP_OBS_API_TOKEN>` when that variable is set, and is open otherwise.

`/api/platform-status` reads the in-memory result of the last app-lb poll, not Parquet, so a slow historical query cannot hide it. It is marked stale once the last successful poll is older than three poll intervals (minimum 15 seconds).

### Windows

`window` accepts a preset (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`) or any relative duration such as `1d`, `45m`, or `2 weeks`. It is clamped to between one minute and 90 days. Anything unparseable falls back to `24h` instead of erroring. Bucket width is chosen from a fixed ladder (10s, 30s, 1m, 5m, 15m, 1h, 6h, 1d) based on the window; callers can't set it.

### Log query parameters

| Parameter | Meaning |
| --- | --- |
| `window` | Trailing window, as above |
| `from`, `to` | Epoch milliseconds. Pin the range instead of using a trailing window. Either alone is fine: `from` runs to now, `to` starts one window-length before it. Both ends are inclusive; a reversed pair is reordered |
| `level` | Level filter, case-insensitive exact match |
| `backend` | Sandbox id or `host:port` |
| `q` | Case-insensitive substring. `%` and `_` are literal |
| `limit` | Default 200, maximum 1000 |
| `before` | Epoch-ms page boundary, **inclusive**. De-duplicate lines at the boundary millisecond on the client |

There is no SQL passthrough. Every query is built by the server, so partition pruning and row caps always apply. Queries run in a bounded pool (`APP_OBS_QUERY_CONCURRENCY`) with a deadline (`APP_OBS_QUERY_TIMEOUT_SECS`); a query that arrives while the pool is full gets `503`, and one that runs past its deadline gets `504`.

## Per-namespace plugin

app-obs is one collector per region, shared by every tenant. Tenants reach it through app-lb's **obs plugin**, which is installed one namespace at a time:

1. The operator enables the fleet plugin on app-lb, giving it this collector's API URL and a secret reference to `APP_OBS_API_TOKEN`.
2. A namespace admin installs it in their namespace: `heyctl plugins install obs -n <ns>`.
3. Anyone who can read that namespace opens `/namespaces/<ns>/plugin-console/obs` on app-lb, which frames this dashboard, narrowed to the namespace, under app-lb's navigation. The page itself is `/namespaces/<ns>/plugins/obs/ui`. The hosted MCP server's telemetry tools use the same API.

app-lb checks the caller's namespace access and forwards to app-obs's `/ns/<ns>/…` routes with the service token. The tenant's own credential never reaches app-obs.

### What gets collected

Each poll, app-obs reads each deployment's namespace from app-lb's `/metrics`, and the installed namespaces from `GET /api/plugins/obs/installs` using the same `APP_LB_USER`/`APP_LB_PASSWORD`. Every record from every source passes the same gate: the poll, the daemon tail, `/ingest` and syslog.

- **Tenant deployments** are collected only when their namespace has installed the plugin. Records for other namespaces are dropped before they are written (counted as `gated` in `/stats`), and their sandboxes are not tailed.
- **Platform rows and deployments app-lb has not reported** are always collected, stamped `_`.
- **The gate is open** (every namespace is collected, as before namespaces existed) when `APP_OBS_REQUIRE_INSTALL=0`, when app-lb answers `404` (it predates the endpoint), or when the fleet obs plugin is disabled.
- **Until app-lb first answers**, tenant deployments are not collected. Later failures keep the last answer.
- `/stats` reports the gate as `collecting`: `"open"`, `"unknown"`, or the installed namespaces.

Uninstalling stops collection. It does not delete what was already stored; retention ages it out.

### Namespace routes

The same `APP_OBS_API_TOKEN` guards these as every other protected route. They exist for app-lb's plugin and must not be exposed to tenants directly.

| Route | Returns |
| --- | --- |
| `GET /ns/{ns}/` | The dashboard in namespace mode: no host or host-sandbox sections. `/ns/{ns}` redirects here |
| `GET /ns/{ns}/api/fleet?window=` | As `/api/fleet`, for the namespace's deployments; `host` and `host_sandboxes` are always null |
| `GET /ns/{ns}/api/deployments/{id}?window=` | As `/api/deployments/{id}`, from rows written under `ns` |
| `GET /ns/{ns}/api/deployments/{id}/logs` | As `/api/deployments/{id}/logs`, from rows written under `ns` |
| `GET /ns/{ns}/api/alerts` | Only the alert rules this namespace created |
| `POST /ns/{ns}/api/alerts` | Create a rule. The deployment must be in `ns` now, and `webhook_url` must be `https` on a public host |
| `DELETE /ns/{ns}/api/alerts/{id}` | Delete one of this namespace's rules (`204` either way) |

**Which deployments a namespace sees.** Every query filters on the stored `namespace` column, so history follows the namespace a row was written under, not the current deployment list. The following all return the same `404` as an id that never existed:

- a deployment app-lb reports in another namespace;
- a platform partition;
- a deleted deployment with no rows under the namespace in the window.

## Alerts

An alert watches one deployment's error count over the trailing minute. A checker runs every 60 seconds and, when the count is greater than the threshold, POSTs to the webhook:

```json
{"timestamp": 1785260096000, "deployment": "web", "errors": 12}
```

Create one:

```sh
curl -XPOST localhost:9600/api/alerts \
  -H 'content-type: application/json' \
  -d '{"deployment": "web", "threshold": 5, "webhook_url": "https://hooks.example.com/obs"}'
```

| Field | Required | Meaning |
| --- | --- | --- |
| `deployment` | yes | Must be a deployment app-obs already has data for, or the request is rejected. On the namespace route, it must be in that namespace |
| `threshold` | yes | Fires when errors in the last minute exceed this. `0` fires on any error |
| `webhook_url` | yes | `http` or `https` URL. On the namespace route, `https` on a public host only: no loopback, private, link-local or CGNAT addresses, no `localhost` or `.internal` names |
| `metric` | no | `errors` (the only metric today) |

Rules are stored in `APP_OBS_ALERTS_FILE` (default `<APP_OBS_DATA_DIR>/alerts.json`) and rewritten atomically on every change. A corrupt file stops app-obs from starting rather than silently dropping every rule. Webhook delivery has a 10-second timeout and is not retried; a failed query never fires an alert.

## Configuration

Configuration is environment-only; there is no config file and no CLI flags.

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_OBS_DATA_DIR` | `/var/lib/app-obs/data` | Parquet root. The process exits at startup if it can't create it |
| `APP_OBS_INGEST_ADDR` | `0.0.0.0:9500` | HTTP ingest listener. Must be reachable from every guest's gateway address |
| `APP_OBS_SYSLOG_ADDR` | `0.0.0.0:9514` | Syslog listener, UDP and TCP |
| `APP_OBS_API_ADDR` | `127.0.0.1:9600` | Dashboard and query API |
| `APP_OBS_API_TOKEN` | unset | Bearer token for the dashboard, query, alert, and stats routes. Unset leaves them open |
| `APP_OBS_INGEST_TOKEN` | unset | Bearer token for `POST /ingest`. **Unset leaves ingest open** |
| `APP_LB_URL` | `http://127.0.0.1:9090` | app-lb admin API to poll |
| `APP_LB_USER` | `admin` | Basic-auth user for app-lb; only used when `APP_LB_PASSWORD` is set |
| `APP_LB_PASSWORD` | unset | Set when app-lb requires admin auth |
| `APP_OBS_SOURCE` | `app-lb` | Collector name carried in platform-status snapshots |
| `APP_OBS_REQUIRE_INSTALL` | `1` | Collect a tenant namespace only once the obs plugin is installed in it on app-lb. `0` collects every namespace. See [What gets collected](#what-gets-collected) |
| `HEYVM_URL` | unset | heyvm daemon to tail native logs from, e.g. `http://127.0.0.1:34099`. Unset disables native tailing |
| `HEYVM_TOKEN` | unset | Bearer token for the daemon, when it runs with `JWT_SECRET` |
| `APP_OBS_POLL_SECS` | `10` | Metrics poll interval |
| `APP_OBS_RETAIN_DAYS` | `30` | Days of partitions to keep |
| `APP_OBS_FLUSH_ROWS` | `10000` | Flush a partition at this many buffered rows |
| `APP_OBS_FLUSH_SECS` | `60` | ...or this many seconds after its first row |
| `APP_OBS_COMPACT_SECS` | `600` | Compaction interval; `0` disables compaction |
| `APP_OBS_QUEUE_CAPACITY` | `65536` | Ingest queue depth before records are dropped |
| `APP_OBS_QUERY_CONCURRENCY` | `4` | Queries in flight before `503` |
| `APP_OBS_QUERY_TIMEOUT_SECS` | `30` | Per-query deadline |
| `APP_OBS_ALERTS_FILE` | `<APP_OBS_DATA_DIR>/alerts.json` | Where alert rules are persisted |
| `APP_OBS_UI_COOKIE_DOMAIN` | `HEYO_UI_COOKIE_DOMAIN` | Parent domain for the shared light/dark theme cookie |
| `APP_OBS_UI_COOKIE_NAME` | `HEYO_UI_COOKIE_NAME`, else `heyo_theme` | Theme cookie name |
| `RUST_LOG` | `info,app_obs=debug` | Log filter |

An unparseable numeric value is ignored with a warning and the default is used.

## Install and run

The crate builds two binaries: `app-obs` (the service) and `dump` (installed as `app-obs-dump`).

```sh
cargo build --release --locked --manifest-path app-obs/Cargo.toml
sudo install -m0755 app-obs/target/release/app-obs /usr/local/bin/app-obs
sudo install -m0755 app-obs/target/release/dump /usr/local/bin/app-obs-dump

sudo useradd --system --no-create-home --shell /usr/sbin/nologin app-obs
sudo install -d -o app-obs -g app-obs /var/lib/app-obs /var/log/app-obs
```

To run it under supervisord, install [`app-obs/deploy/supervisor/app-obs.conf`](../app-obs/deploy/supervisor/app-obs.conf):

```sh
sudo cp app-obs/deploy/supervisor/app-obs.conf /etc/supervisor/conf.d/
sudo supervisorctl reread && sudo supervisorctl update
```

Edit its `environment=` block first. At minimum, decide on `APP_OBS_INGEST_TOKEN`, and set `APP_LB_PASSWORD` if app-lb requires admin auth. If the file holds secrets, make it `root:root` mode `0640`.

On `SIGTERM`, app-obs drains its queue and flushes open partitions, allowing itself 30 seconds. Keep supervisord's `stopwaitsecs` above 30 (the shipped unit uses 35), or buffered rows are lost.

To try it locally:

```sh
APP_OBS_DATA_DIR=/tmp/obs APP_OBS_FLUSH_SECS=2 \
  cargo run --manifest-path app-obs/Cargo.toml --bin app-obs
# then open http://127.0.0.1:9600/dashboard
```

A short flush interval makes pushed lines queryable within seconds. Metric charts need app-lb reachable at `APP_LB_URL`; the log side works without it.

## Register with app-lb

[`app-obs/examples/app-obs.json`](../app-obs/examples/app-obs.json) is a static deployment that fronts the API port:

```json
{
  "id": "app-obs",
  "routes": [{ "host": "obs.us2.heyo.work" }],
  "upstreams": ["127.0.0.1:9600"],
  "health": { "path": "/healthz", "timeout_secs": 2 },
  "auth": {
    "client_id": "REPLACE.apps.googleusercontent.com",
    "client_secret": { "secret": "google", "key": "client_secret" },
    "allowed_domains": ["heyo.work"],
    "public_paths": ["/healthz", "/__ui/"],
    "cookie_domain": "us2.heyo.work",
    "forward_identity": true
  }
}
```

```sh
heyctl apply -f app-obs/examples/app-obs.json
```

Change the host, client id, and allowed domains first, and store the Google client secret (`heyctl create secret google --from-stdin client_secret`). See [app-lb auth](app-lb-auth.md#google) for the `auth` block.

**The `auth` block is required.** A proxied route is public unless its spec has one, and without it anyone can read every deployment's logs. Keeping `APP_OBS_API_ADDR` on loopback does not help, because app-lb proxies the whole hostname.

`APP_OBS_API_TOKEN` is for machine-to-machine access over a direct route (for example a control plane reading `/api/platform-status`). Browsers can't attach a bearer header on navigation, so keep using app-lb's sign-in for the interactive dashboard.

The ingest and syslog listeners are deliberately **not** fronted by app-lb. Guests reach them directly on the tap network.

## Common operations

```sh
curl -s localhost:9600/healthz
curl -s localhost:9600/stats                       # accepted / dropped / buffered_rows
curl -s 'localhost:9600/api/fleet?window=1h' | jq
curl -s 'localhost:9600/api/deployments/web/logs?window=15m&level=error&limit=50' | jq
```

Inspect what is on disk without the query engine:

```sh
app-obs-dump /var/lib/app-obs/data/logs/deployment=web/date=2026-09-30 | head
```

`app-obs-dump <file-or-directory>...` prints Parquet rows as JSON lines, walks directories recursively, skips in-progress temporary files, and reports the row and file count on stderr.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Dashboard shows no recent lines | Rows flush every `APP_OBS_FLUSH_SECS`; check `buffered_rows` in `/stats` |
| No VM stdout/console lines at all | `HEYVM_URL` is unset, or `HEYVM_TOKEN` is missing for a daemon with `JWT_SECRET` |
| Metrics charts empty | app-lb unreachable at `APP_LB_URL`, or `APP_LB_PASSWORD` missing; the poller logs a warning each tick |
| `dropped` climbing in `/stats` | Ingest queue full; raise `APP_OBS_QUEUE_CAPACITY` or reduce log volume |
| Dashboard returns `503` or `504` | Query pool full or query too slow; narrow the window, or raise `APP_OBS_QUERY_CONCURRENCY` / `APP_OBS_QUERY_TIMEOUT_SECS` |
| Push returns `401` | Wrong or missing `Authorization: Bearer` for `APP_OBS_INGEST_TOKEN` |
| Process running but a port is dead | Listeners bind in their own tasks; a bind failure is logged and the process keeps running. Look for three `listening` log lines, or run `ss -lntup \| grep app-obs` |
| Won't start after editing alerts | `alerts.json` is corrupt; fix or remove it |
| A chart shows a gap | app-lb restarted during that interval; counters reset and the interval is null by design |
