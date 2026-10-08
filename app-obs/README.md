# app-obs

Logs and metrics for the deployments [app-lb](../app-lb) manages. Collects logs
pushed by applications, polls app-lb for metrics, stores both as partitioned
parquet, and ages partitions out.

Runs as a **static (`proxy_pass`) deployment** registered with app-lb — it is a
host process, not a microVM, so it is fronted the same way the pg-fc dashboard
is.

> **Status: phase 2.** Collection, storage, retention-by-deletion, the query API,
> the dashboard and webhook alerts work. S3 tiering is not built yet.

## How logs arrive: native tail, or push

Two paths, complementary:

**Native tail (no guest cooperation).** The daemon now captures each sandbox's
serial console and its `start_command`'s stdout/stderr natively and serves
them over a WebSocket at `GET /sandboxes/:id/logs/stream`. With `HEYVM_URL`
set, app-obs tails that stream for every VM the app-lb poll reports, so every
line a managed VM prints is collected — attributed to its deployment and
sandbox, with `source` `stdout`, `stderr`, or `console` — without a shipper,
an ingest token, or any code inside the guest. Which sandboxes to tail, and
which deployment each belongs to, comes from the app-lb poll: app-lb is the
authority on that mapping, the daemon only knows sandbox ids.

This used to be impossible — the daemon's log store held nothing but
`execute_command` output, which is why this collector was built push-only.
That constraint is gone; the push paths remain because they carry things the
console never sees.

**Push (structured, app-authored).** An application that knows its levels and
fields ships records itself over HTTP or syslog, as below. Note an app that
both prints to stdout *and* pushes the same lines will store them twice, under
different `source` values — pick one per line.

Metrics are polled from app-lb, which already measures everything worth
keeping.

**Sandboxes outside every deployment.** app-lb also reports the sandboxes on
its host that it does not manage — made through `heyvm`, the cloud API or the
desktop — as `host_sandboxes` on `/metrics`. app-obs tails the live ones
exactly as it tails a pool's VMs, attributed to the deployment `_unmanaged`
with `backend` set to the sandbox id, and records their CPU and memory the
same way (a rollup row for the fleet view, then one row per sandbox). The
fleet page lists what is on the host right now under **Host sandboxes**, each
row linking straight to that sandbox's lines. Nothing is written under
`_unmanaged` when the list is empty, so an app-lb that predates the field
leaves no trace of it. Like `_host`, the name is app-obs's own — don't
register a deployment under it.

The latest successful poll also backs `GET /api/platform-status`. This is the
live topology view: backend probe health, administrative drain state, in-flight
requests, pool capacity, and whether the observation itself is stale. It does
not query parquet, so an expensive historical query cannot make status disappear.

## Where guests send logs

Every microVM sits on its **own /30**: the host is at `guest_ip - 1`. There is no
single address that works for every guest, so guests send to their **default
gateway**, which is always this host on their subnet. app-obs binds `0.0.0.0` so
it is reachable on all of them.

```sh
# inside a guest — the gateway is the collector
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

`deployment`, `backend`, and `host` set at the batch level apply to every
record that doesn't state its own. `backend` identifies which instance produced
the line — a sandbox id for a VM deployment, a `host:port` for a static upstream;
`sandbox_id` is accepted as an alias since a guest knows itself by that name.

`ts` accepts epoch milliseconds, epoch seconds, or RFC 3339, and defaults to arrival time — a shipper that doesn't know
the time is better than a dropped line. A record with no resolvable
`deployment` is rejected; retrying will not help.

Syslog works too, for senders that can't be taught JSON:

```sh
logger -n "$GW" -P 9514 -t demo "hello from syslog"
```

The syslog tag becomes the deployment when it is a usable id; otherwise records
land under `syslog`.

### Dropping is deliberate

Everything funnels through one bounded queue. When it is full, records are
dropped and counted — never blocked. A customer's application must not stall
because the collector fell behind. `GET /stats` on the API port reports
`accepted` and `dropped`.

## Storage

Hive-partitioned parquet, so a query filtered by deployment and day reads only
those directories:

```
data/logs/deployment=<id>/date=YYYY-MM-DD/hour=HH/<ts>-<seq>.parquet
data/metrics/deployment=<id>/date=YYYY-MM-DD/<ts>-<seq>.parquet
```

Logs partition hourly because their volume is unbounded and bursty; metrics
partition daily because they arrive at a fixed poll rate and hourly directories
would just multiply tiny files. `deployment`, `date`, and `hour` live in the
path, not inside the files. Files are written under a temporary name and renamed
into place, so a reader never sees a partial parquet.

The flush interval trades file count for freshness: rows become queryable within
a minute, at the cost of one small file per partition per flush — which, left
alone, is over a thousand files under a day-wide query, most of whose budget
would go to parquet footers rather than rows. A background compactor pays that
debt back, periodically merging each partition's files into one; the steady state
per partition is one compacted file plus whatever has been flushed since the last
pass. Swaps happen with the query pool quiesced, so a scan never sees a partition
half-swapped, and the rename protocol is crash-recoverable from file names alone
— an interrupted merge is either rolled back or its leftovers swept on the next
pass, never duplicated.

Whole-host CPU and memory land under the reserved deployment id `_host`, since
they belong to no deployment.

Metrics report **p50/p90/p99** — the percentiles app-lb's histogram actually
measures. There is no p95; interpolating one would invent a number the source
never produced. A metric that was not reported stays null rather than becoming
zero, because "not measured" and "measured as zero" mean different things on a
chart.

Those percentiles are **cumulative since app-lb started**: its histogram never
decays, so a stored p50 is a lifetime figure that barely moves and drops back
when app-lb restarts. Putting it on a time axis would be close to meaningless, so
`latency_count` and `latency_sum` are stored alongside it. Differencing those
between consecutive samples gives the mean latency *over that interval*, which is
what the dashboard charts; the percentiles appear as a figure, labelled for what
they are.

`requests_total` and `errors_total` are cumulative for the same reason and reset
the same way. Rates are differenced, and a decrease means app-lb restarted, not
negative traffic — so that interval reports null and the chart shows a gap. A
clamped zero would draw a convincing idle patch that never happened.

## Reading it back

The dashboard lives on the API port, at `/dashboard` (and `/` redirects there). It
is one self-contained HTML file compiled into the binary — no build step, no CDN,
so it loads on a host with no route out. A fleet overview lists every deployment
with a sparkline and its error count; clicking one opens per-deployment charts
and a filterable view of its logs — filterable by level, backend, message and by
an explicit time range, with every line stamped to the millisecond and copyable
on its own.

The JSON behind it:

| Endpoint | |
| --- | --- |
| `GET /api/fleet?window=` | One row per deployment, plus whole-host CPU and memory |
| `GET /api/platform-status` | Current app-lb topology, health/drain state, and staleness |
| `GET /api/deployments/<id>?window=` | Bucketed series and summary figures |
| `GET /api/deployments/<id>/logs?window=&from=&to=&level=&backend=&q=&limit=&before=` | Log lines, newest first |
| `GET/POST /api/alerts`, `DELETE /api/alerts/<id>` | Webhook alert rules |
| `GET /stats` | Ingest counters, and rows still buffered in memory |
| `GET /healthz` | Always open, never queued behind a query |

`window` is a preset (`15m`, `1h`, `6h`, `24h`, `7d`, `30d`) or any relative
duration — `1d`, `45m`, `2 weeks` — clamped to between a minute and ninety days,
with the label echoed back derived from the clamped span rather than the
spelling. Anything else falls back to `24h` rather than erroring, since these
arrive from bookmarked URLs. Bucket width is derived from the window, not
accepted from the caller. `q` is a
case-insensitive substring — `%` and `_` are literal, not wildcards. `before` is
an **inclusive** page boundary: log timestamps collide freely, and an exclusive
one would silently drop lines from a burst that straddles a page edge, so the
caller de-duplicates the boundary millisecond instead.

`from` and `to` are epoch milliseconds, and pin the log list to a fixed range
instead of a trailing window — an incident is bounded by two instants read off a
chart, and "the last six hours" means something different every time the page
refreshes. Either end alone is enough; `window` supplies the span for the other,
so `from` on its own runs up to now and `to` on its own starts a window-length
before it. Both ends are inclusive, both are optional, and neither is validated
into a `400`: a reversed pair is ordered, and an instant no timestamp can hold
falls back to the window's own edge, on the same reasoning that makes an unknown
`window` label show a day of data rather than an error. Partition pruning follows
the resolved range, not the label, so a five-minute range inside last Tuesday
opens one hour's directory.

The dashboard drives this from a `from`/`to` pair under the Logs heading, with a
button that fills both ends from the range already on screen — the usual move is
narrowing a window you are looking at, not naming an interval from memory. The
fields hold whole seconds, so pinning rounds the start down and the end up: the
pinned range covers at least what was on screen, because rounding both ends
inward would quietly drop whatever landed in the last fraction of a second.

There is no SQL passthrough. Every query is one the server built, so partition
pruning and a row cap always apply — neither is something a caller can forget.
Queries take a slot from a bounded pool and a deadline: a wide range that arrives
while the pool is full gets a `503` and the dashboard keeps its last good render,
because reading the data must never compete with collecting it.

`/stats` reports `buffered_rows` because a partition flushes on a timer — the
newest rows are legitimately not queryable yet, and the dashboard says so rather
than looking like it lost them.

## Configuration

To run it as a managed, auto-restarting service, see the supervisord unit in
[`deploy/supervisor/`](deploy/supervisor/).

Configuration is environment-only:

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_OBS_DATA_DIR` | `/var/lib/app-obs/data` | Parquet root |
| `APP_OBS_INGEST_ADDR` | `0.0.0.0:9500` | HTTP ingest; must be reachable from every tap gateway |
| `APP_OBS_SYSLOG_ADDR` | `0.0.0.0:9514` | Syslog, UDP and TCP |
| `APP_OBS_API_ADDR` | `127.0.0.1:9600` | Query API and dashboard |
| `APP_OBS_API_TOKEN` | *(unset)* | Bearer token for dashboard/query routes; `/healthz` stays open |
| `APP_OBS_INGEST_TOKEN` | *(unset)* | Bearer token for `/ingest`; **unset leaves ingest open** |
| `APP_LB_URL` | `http://127.0.0.1:9090` | app-lb admin API to poll |
| `APP_LB_USER` | `admin` | Only used when a password is set |
| `APP_LB_PASSWORD` | *(unset)* | Set when app-lb has `APP_LB_ADMIN_AUTH=1` |
| `APP_OBS_SOURCE` | `app-lb` | Stable collector/edge name carried in status snapshots |
| `APP_OBS_REQUIRE_INSTALL` | `1` | Collect a tenant namespace only once app-lb's obs plugin is installed in it; `0` collects every namespace |
| `HEYVM_URL` | *(unset)* | Sandbox daemon whose native log streams to tail (e.g. `http://127.0.0.1:34099`); **unset disables native tailing** |
| `HEYVM_TOKEN` | *(unset)* | Bearer token for the daemon, needed when it runs with `JWT_SECRET` |
| `APP_OBS_POLL_SECS` | `10` | Metrics poll interval |
| `APP_OBS_RETAIN_DAYS` | `30` | Partitions older than this are deleted |
| `APP_OBS_FLUSH_ROWS` | `10000` | Flush a partition at this many buffered rows... |
| `APP_OBS_FLUSH_SECS` | `60` | ...or this long after its first row |
| `APP_OBS_COMPACT_SECS` | `600` | Merge each partition's small parquet files into one this often; `0` disables |
| `APP_OBS_QUEUE_CAPACITY` | `65536` | Ingest queue depth before records are dropped |
| `APP_OBS_QUERY_CONCURRENCY` | `4` | Dashboard queries in flight before a `503` |
| `APP_OBS_QUERY_TIMEOUT_SECS` | `30` | Ceiling on one query |
| `APP_OBS_ALERTS_FILE` | `<APP_OBS_DATA_DIR>/alerts.json` | Where alert rules are persisted |

`APP_OBS_RETAIN_DAYS` counts back from and including today: `7` keeps seven
days, and the eighth-oldest day is removed. Future-dated partitions are never
deleted — a sender with a skewed clock shouldn't have its data destroyed before
anyone notices the skew.

## Per-namespace access

Tenants do not reach this service directly. app-lb's `obs` plugin is installed
per namespace (`heyctl plugins install obs -n <ns>`) and serves
`/namespaces/<ns>/plugins/obs/ui` by forwarding to this service's
`/ns/<ns>/…` routes with `APP_OBS_API_TOKEN`, after checking the caller may read
that namespace. Every stored row carries the namespace it was written under,
and a namespace that has not installed the plugin is not collected at all. See
[docs/app-obs.md](../docs/app-obs.md#per-namespace-plugin) for the gate and the
route table.

## Registering with app-lb

```sh
curl -XPOST localhost:9090/deployments \
  -H 'content-type: application/json' \
  -d @examples/app-obs.json
```

Edit the `host` route to a real DNS name first. With ACME configured on app-lb,
its certificate is then issued automatically like any other deployment.

Keep `APP_OBS_API_ADDR` on loopback so the only external path to it is through
app-lb, and note that the **ingest** listener is deliberately not fronted by
app-lb — guests reach it directly on the tap network.

For a direct orchestrator-managed API route, set `APP_OBS_API_TOKEN` and send it
as `Authorization: Bearer <token>`. The query API and dashboard document then
require the token while `/healthz` stays open for service readiness probes. A
normal browser navigation cannot attach that header, so keep using app-lb's auth
gate for an interactive dashboard.

### The dashboard is only as private as its `auth` block

Loopback is not the gate. app-lb proxies this whole hostname, and **a proxied
deployment route is public unless its spec carries an `auth` block** — without
one, `obs.<host>` hands every customer's logs to anyone who asks for them. So
`examples/app-obs.json` includes one, and it is not optional decoration:

```jsonc
"auth": {
  "client_id": "REPLACE.apps.googleusercontent.com",
  "client_secret": { "secret": "google", "key": "client_secret" },
  "allowed_domains": ["heyo.work"],
  "public_paths": ["/healthz"]        // app-lb's own health check
}
```

Fill in the client id, store the secret (`heyctl create secret google
--from-stdin client_secret`), and register the redirect URI Google needs —
`heyctl describe deployment app-obs` prints the exact string. See
[app-lb's Google sign-in](../app-lb/README.md#google-sign-in) for the full set of
options; `/healthz` stays public so the health probe still passes.

The app-lb gate remains the interactive authentication layer. app-obs's optional
bearer token is for direct machine-to-machine routes, such as Cloud's platform
status proxy, rather than a replacement browser login flow.

## Building

```sh
cargo build --release
cargo test
```

To try it locally — the crate has two binaries, so `--bin` is required:

```sh
APP_OBS_DATA_DIR=/tmp/obs APP_OBS_FLUSH_SECS=2 cargo run --bin app-obs
```

A short flush interval makes ingested lines queryable in seconds instead of a
minute, which is the difference between the dashboard looking broken and looking
live. Then open <http://127.0.0.1:9600/dashboard>. Metrics charts need app-lb
reachable at `APP_LB_URL` to have anything to plot; the poller logs a warning and
retries when it isn't, so the log side works on its own.

app-obs must never become a dependency of the data plane: if it is down, app-lb
keeps serving traffic, and guests shipping to a dead ingest port get a connection
error rather than blocking.
