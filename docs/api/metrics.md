# Metrics and host

These endpoints report what an app-lb and its host are doing: request and autoscaler metrics per deployment, issued certificates, guest disk usage, and a cross-gateway rollup.

Back to the [API reference](overview.md).

## Metrics

`GET /metrics`

**Tier:** View. Narrows itself to what the caller can see. **Crate:** `Client::metrics(&MetricsQuery) -> MetricsResponse` · `Raw::metrics(&MetricsQuery)`

A JSON snapshot. This is not Prometheus text. Unfiltered, it runs to megabytes on a large fleet, so ask for less:

| Query | `MetricsQuery` | Effect |
| --- | --- | --- |
| `deployment=<id>` | `.deployment(id)` | One deployment. |
| `prefix=<s>` | `.prefix(s)` | Ids starting with `s`. |
| `namespace=<ns>` | not in the crate | One namespace. |
| `summary=true` | `.summary(true)` | Drop per-VM rows and host sandboxes. |
| `limit=`, `offset=` | `.page(offset, limit)` | Page through `deployments`. |

Filters narrow `deployments` only. `host`, `fleet` and `global` always describe everything the caller can see.

```rust
use hws::MetricsQuery;

let m = lb.metrics(&MetricsQuery::new().prefix("api-").summary(true).page(0, 50)).await?;
println!("{} of {} deployments", m.deployments.len(), m.matched);
```

Abridged from [`metrics-response.json`](../../app-lb/testdata/wire/metrics-response.json):

```json
{"generated_at": 1722400000, "uptime_secs": 86400,
 "host": {"available": true, "cpu_count": 8, "cpu_percent": 23.5,
          "memory_total_bytes": 33554432000, "memory_used_bytes": 9663676416, "sampled_at_ms": 1722400000000},
 "fleet": {"deployments": 3, "ready": 4, "draining": 1, "pending": 1, "total_in_flight": 7},
 "global": {"requests": {"total": 7, "c2xx": 3, "c3xx": 1, "c4xx": 1, "c5xx": 1, "errors": 1},
            "latency_ms": {"count": 7, "sum": 969, "mean": 138.4, "p50": 7.5, "p90": 650.0, "p99": 965.0,
                           "buckets": [{"le": 1, "count": 0}, {"le": 2, "count": 1}, "…"]},
            "cold_start_s": {"…": "…"}, "autoscale": {"…": "…"}},
 "deployments": ["…"]}
```

Top-level fields:

| Field | Meaning |
| --- | --- |
| `generated_at`, `uptime_secs` | When the snapshot was taken, and how long app-lb has run. |
| `host` | `{available, cpu_count, cpu_percent, memory_total_bytes, memory_used_bytes, sampled_at_ms}`. `available` is false until the daemon has produced a sample. |
| `fleet` | Pool totals: `{deployments, ready, draining, pending, total_in_flight}`. |
| `global` | Metrics across every deployment, in the per-deployment shape below. |
| `daemon` | `{reachable, last_error}`. When app-lb cannot reach the VM daemon, nothing scales or boots and every other number is frozen. |
| `obs` | Log shipping: `{queued, dropped, shipped, failed, healthy}`. Absent when app-lb does not ship logs. A non-zero `dropped` is the only trace of a lost record. |
| `security` | `{open, urgent, dropped, clients_at_capacity, rules, blocked}`. Absent when security monitoring is off. The alerts themselves are on `GET /security`. |
| `deployments[]` | One entry per matched deployment, below. |
| `matched` | Deployments that matched before `limit`/`offset`. |
| `tracked_deployments` | Deployments holding counters. Climbing past the number registered means retirement is not keeping up. |
| `host_sandboxes[]` | Sandboxes on the host that no deployment owns: `{sandbox_id, name, status, image, size_class, guest_ip, uptime_secs, cpu_percent, memory_bytes, account_id, created_at}`. Emptied by `summary=true`, narrowed to the caller's accounts for a namespace caller. |

Each `deployments[]` entry (`DeploymentView`):

| Field | Meaning |
| --- | --- |
| `id`, `namespace`, `kind` | `namespace` is empty for `default`. `kind` is `vm`, `static` or `site`. |
| `routed`, `hosts`, `urls` | Whether any route points here, the exact hostnames, and the routes as URLs with the data plane's scheme and port. |
| `upstreams` | Static deployments only. |
| `site_root`, `site_spa` | Sites only. |
| `job_kind` | `build` or `update`: which deploy job the deployment accepts, if either. |
| `pool` | `{desired_replicas, ready, draining, pending, total_in_flight, target_concurrency, min_replicas, max_replicas, warm_pool, utilization, cpu_percent, memory_bytes, boot_timeout_secs, cold_start_timeout_secs}`. `utilization` is `null` when there is no capacity to divide by. |
| `vms[]` | `{sandbox_id, addr, in_flight, healthy, draining, uptime_secs, cpu_percent, memory_bytes}`. Empty with `summary=true`. |
| `pending_vms[]` | Booting VMs, oldest first: `{sandbox_id, age_secs, status}`. A pending VM older than `cold_start_timeout_secs` has already cost somebody a `503`. |
| `metrics` | `{requests, latency_ms, cold_start_s, autoscale}`, below. |

| Metrics block | Fields |
| --- | --- |
| `requests` | `total`, `c2xx`, `c3xx`, `c4xx`, `c5xx`, `errors` |
| `latency_ms`, `cold_start_s` | Histograms: `count`, `sum`, `mean`, `p50`, `p90`, `p99`, and `buckets` as `[{le, count}]` |
| `autoscale` | `vms_created`, `vms_drained`, `vms_reaped`, `scale_up_events`, `scale_down_events`, `cold_start_waits`, `cold_start_hits`, `cold_start_timeouts`, `boot_timeouts`, `create_failures`, `last_create_error` |

`create_failures` with `vms_created` and `boot_timeouts` both zero means no VM ever existed, so the daemon refused the create; `last_create_error` says why. `boot_timeouts` counts VMs that never passed their health check.

Field meanings are covered further under [Metrics](../app-lb.md#metrics).

## Certificates

`GET /certs`

**Tier:** CRUD, operator. **Crate:** `Client::certs() -> Vec<CertStatus>` · `Raw::certs()`

```json
[{"host": "sandbox.example.com", "not_after": "2026-10-29T12:00:00Z", "issuer": "R11", "needs_renewal": false}]
```

`not_after` is RFC 3339.

## Disks

`GET /disks`

**Tier:** View, operator. **Crate:** `Client::disks() -> DiskInventory` · `Raw::disks()`

The host's per-sandbox disk inventory: what each sandbox occupies, whether anything still claims it, and what the expiry sweep would reclaim. Abridged from [`disks.json`](../../app-lb/testdata/wire/disks.json):

```json
{
  "complete": true, "data_dir": "/var/lib/heyo", "tmp_dir": "/tmp",
  "ttl_secs": 604800, "orphan_ttl_secs": 900, "sweep_secs": 3600,
  "archive_enabled": false, "archive_on_expire": false,
  "free_bytes": 12884901888, "filesystem_bytes": 536870912000,
  "totals": {"disks": 3, "bytes": 3758096384, "apparent_bytes": 15032385536, "running": 1, "stopped": 1,
             "orphan": 1, "retained": 1, "expiring_now": 1, "reclaimable_bytes": 2147483648},
  "disks": [
    {"sandbox_id": "sb-1a2b3c4d", "name": "applb-web-00000000002a", "deployment": "web",
     "state": "running", "claimed": true, "retain": false,
     "bytes": 1073741824, "apparent_bytes": 8589934592, "modified_at": 1760000000,
     "held_by": "in use by a running sandbox",
     "parts": [{"kind": "data", "path": "run/sb-1a2b3c4d/data.ext4", "bytes": 1073741824,
                "apparent_bytes": 8589934592, "modified_at": 1760000000}],
     "roots": ["run/sb-1a2b3c4d"]}
  ],
  "archives": []
}
```

| Field | Meaning |
| --- | --- |
| `complete` | Both daemon listings succeeded. When `false`, nothing is classified as an orphan and the sweep declines to run, so do not read the list as residue. `incomplete_reason` says why. |
| `ttl_secs`, `orphan_ttl_secs` | How long a stopped disk and a disk with no daemon record survive. `ttl_secs: 0` disables expiry. |
| `free_bytes`, `filesystem_bytes` | The guest disk filesystem. `null` means unknown, not full. |
| `disks[].state` | `running`, `stopped`, `orphan` or `unknown`. An `unknown` disk is never reclaimed. |
| `disks[].claimed` | A live deployment intends to resume this sandbox. A claimed disk is never reclaimed. |
| `disks[].retain`, `note` | An operator pin. |
| `disks[].bytes`, `apparent_bytes` | Allocated blocks, and the nominal size. Guest disks are sparse, so `bytes` is the one that matters. |
| `disks[].expires_at`, `held_by` | When the sweep would reclaim it, or why it will not. |
| `disks[].archived` | `{uri, at, bytes}` once archived. |
| `archives[]` | Archive jobs: `{id, sandbox_id, uri, started_at, finished_at, status, bytes, expected_bytes, error, purged}`. |

Errors: `503` when disk management is off. The disk mutations (`PATCH`/`DELETE /disks/:id`, archive, sweep, purge) are in [HTTP API](../http-api.md#disks-certificates-workflows-operator); the crate does not call them.

## Fleet deployments

`GET /fleet/deployments[?namespace=]`

**Tier:** fleet view, always authenticated. A confined caller must pass one of its own namespaces. **Crate:** `Raw::fleet_deployments(namespace) -> Value`

A namespace-by-deployment rollup across the gateways this app-lb observes. Untyped in the crate. Each row has one cell per gateway; a gateway that could not be read is an explicit error, not a missing cell:

```json
{"configured": true,
 "rows": [{"id": "ci", "cells": [{"gateway": "west", "ready": 3},
                                 {"gateway": "east", "ready": null, "error": "gateway unavailable"}]}],
 "gateways": [{"id": "east", "error": "gateway unavailable"}]}
```

An app-lb with no fleet configured answers `{"configured": false}`. See [multi-region](../multi-region.md).
