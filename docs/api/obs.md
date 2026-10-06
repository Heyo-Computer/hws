# Observability

Once the `obs` plugin is installed in a namespace, app-obs collects metrics and logs for every deployment in it, and these endpoints read that telemetry and manage error alerts through app-lb.

Back to the [API reference](overview.md). The data model and retention are in [app-obs](../app-obs.md#namespace-routes).

Every path on this page is under `/namespaces/{ns}/plugins/obs`. app-lb checks that the caller reaches `{ns}`, then forwards `api/...` to app-obs's `/ns/{ns}/api/...` with the plugin's own service token. Your credential is never forwarded, so nothing on the client side needs to know where app-obs lives. Responses are app-obs's own and are marked `Cache-Control: no-store`.

**Crate:** `Client::obs(ns) -> ObsClient`. It makes no request until a method is called.

```rust
use hws::{LogQuery, NewAlert};

lb.install_plugin("team-a", "obs", None).await?;   // once per namespace

let obs = lb.obs("team-a");
for row in obs.fleet(Some("1h")).await?.deployments {
    println!("{}: {} log lines, {} errors", row.id, row.log_lines, row.error_logs);
}
let page = obs.logs("web", &LogQuery::new().level("error").limit(50)).await?;
for line in page.rows {
    println!("{} {}", line.ts, line.message);
}
```

## Before it works

Three things must be true, and each failure answers differently:

| Requirement | Who | Without it |
| --- | --- | --- |
| The operator has enabled `obs` on this app-lb (`PUT /api/plugins/obs` with `{"enabled": true, "config": {"url": "<app-obs API>", "api_token": {"secret": "…", "key": "…"}}}`). Check `last_error` on the result. | Operator | `409` with `"code": "plugin_disabled"`. A misconfigured `url` or token gives `502`. |
| The plugin is installed in the namespace. With `auto_install` (the default in the plugin's config), every namespace gets it when the plugin is enabled, when the namespace is declared, or when it gets its first deployment. Otherwise, [install it](namespaces.md#namespace-plugins). | Namespace admin, or automatic | `409` with `"code": "plugin_not_installed"`. Nothing is collected before the install. |
| The caller can reach this route. On a direct listener, any credential that reaches `{ns}` with View tier can. Through the managed door (`server.heyo.computer/namespaces/{ns}/lb`), these paths work only once cloud's allowlist includes them. | Heyo cloud | `404 route not exposed through the namespace proxy`, which the crate reports as `Error::Malformed`. |

`409` both ways surfaces as `hws::Error::Conflict`, with a message that says which and how to fix it.

## Namespace overview

`GET …/api/fleet[?window=]`

**Tier:** View. **Crate:** `ObsClient::fleet(window) -> ObsFleet` · `Raw::obs_fleet(ns, window)`

Every deployment in the namespace with telemetry in the window, with a coarse series and log counts for each.

| Field | Meaning |
| --- | --- |
| `generated_at_ms`, `from_ms`, `to_ms` | Epoch milliseconds. |
| `window`, `windows` | The window this answer covers, and every label the server accepts. |
| `step_secs` | Bucket width. |
| `retain_days` | How long app-obs keeps data. |
| `freshness` | `{buffered_rows, flush_secs, dropped}`. app-obs flushes on a timer, so rows newer than `flush_secs` may be missing; `dropped` counts records lost to a full buffer. |
| `deployments[]` | `{id, buckets[], log_buckets[], latest, log_lines, error_logs}`. |
| `host`, `host_sandboxes` | Operator view only; absent in a namespace's. |

A metric bucket is `{t, requests_per_sec, errors_per_sec, mean_latency_ms, p50_ms, p90_ms, p99_ms, cpu_percent, memory_bytes, in_flight, ready, pending, draining}`, where `t` is the bucket start in epoch milliseconds. Every measure may be `null`, which means nothing was sampled, not zero. The percentiles are cumulative since app-lb started, not windowed. `latest` holds the most recent non-null value of each measure. A log bucket is `{t, lines, errors}`.

## One deployment

`GET …/api/deployments/:id[?window=]`

**Tier:** View. **Crate:** `ObsClient::deployment(id, window) -> ObsDeployment` · `Raw::obs_deployment(ns, id, window)`

One deployment's series over the window: the same fields as a row of the overview plus the window fields, and `backends`, the VMs or upstreams that logged in the window. A deployment outside the namespace is the same `404` as one that does not exist.

## Logs

`GET …/api/deployments/:id/logs`

**Tier:** View. **Crate:** `ObsClient::logs(id, &LogQuery) -> ObsLogs` · `Raw::obs_logs(ns, id, &LogQuery)`

| Query | `LogQuery` | Meaning |
| --- | --- | --- |
| `window` | `.window(w)` | Trailing window: `15m`, `1h`, `6h`, `24h`, `7d`, `30d`, or any duration such as `45m`. Clamped to 1 minute–90 days. Default `24h`. |
| `from`, `to` | `.from(ms)`, `.to(ms)` | Epoch milliseconds, pinning the range instead of `window`. |
| `level` | `.level(l)` | Exact level, case-insensitive. |
| `backend` | `.backend(b)` | A sandbox id or `host:port`. |
| `q` | `.search(text)` | Case-insensitive substring of the message. |
| `limit` | `.limit(n)` | Default 200, maximum 1000. |
| `before` | `.before(ms)` | Page boundary, epoch milliseconds, **inclusive**. |

```json
{
  "id": "web",
  "from_ms": 1760000000000,
  "to_ms": 1760086400000,
  "rows": [
    {"ts": 1760086399000, "level": "INFO", "source": "app", "message": "listening on :8080",
     "backend": "applb-web-00000000002a", "host": "us5", "fields": null}
  ],
  "next_before_ms": 1760086399000,
  "limit": 200
}
```

Rows are newest first. `source` is `stdout`, `stderr`, `console`, `access`, `security`, `job` and so on. `fields` is the structured payload as a JSON string.

To page back, pass `next_before_ms` as `before` until it comes back `null`. Because the boundary is inclusive, the next page can repeat lines from that millisecond; drop the ones you already have.

## Alerts

| Method and path | Tier | Crate |
| --- | --- | --- |
| `GET …/api/alerts` | View | `ObsClient::alerts() -> Vec<ObsAlert>` · `Raw::obs_alerts(ns)` |
| `POST …/api/alerts` | CRUD | `ObsClient::create_alert(&NewAlert) -> ObsAlert` |
| `DELETE …/api/alerts/:id` | CRUD | `ObsClient::delete_alert(id) -> ()` |

An alert POSTs to `webhook_url` whenever `deployment` logs more than `threshold` errors in a minute. The create body is `{"deployment", "threshold", "webhook_url", "metric"?}`; `metric` defaults to `errors`, currently the only one. Through this route `webhook_url` must be `https` on a public host. Create answers `201` with the rule:

```json
{"id": "a1", "deployment": "web", "namespace": "team-a", "metric": "errors",
 "threshold": 5.0, "webhook_url": "https://hooks.example.com/alert"}
```

`NewAlert::errors(deployment, threshold, webhook_url)` builds the body. Delete answers `204`, and deleting an alert that does not exist also succeeds.

## Errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Invalid namespace name, or an invalid alert body. |
| `404` | `NotFound` | No such deployment in the namespace, or a path other than `ui` or `api/...`. |
| `404` | `Malformed` | Through the managed door, a path cloud does not expose. |
| `409` | `Conflict` | `plugin_disabled`, `plugin_not_installed`, or `the obs plugin is not configured`. |
| `413` | `Api` | Body over 64 KiB. |
| `502` | `Upstream` | app-obs is unreachable or rejected the plugin's token. This is not your credential's fault. |
| `504` | `Api` | A log query outran app-obs's deadline. Narrow the window. |
