# Deployments

A deployment is a routed workload on app-lb: a managed pool of microVMs (`vm`), fixed or discovered upstreams (`static`), or files served off disk (`site`). These endpoints register, read, edit, scale and remove them.

Back to the [API reference](overview.md). For what each spec field does, see the [deployment spec](../app-lb.md#deployment-spec) and its [JSON Schema](../../app-lb/schema/deployment-spec.json).

All routes on this page are CRUD tier. A confined caller may use them on deployments in its reach. An id it cannot see, including one that does not exist, answers `403 this token is not scoped to deployment "<id>"`.

## The deployment status

Every route on this page that returns a deployment returns a **deployment status** (`DeploymentStatus`). Abridged from [`deployment-status-artifact.json`](../../app-lb/testdata/wire/deployment-status-artifact.json):

```json
{
  "rollout_revision": "persisted-opaque-revision",
  "spec": {
    "id": "sandbox-pull",
    "routes": [{"host": "sandbox.example.com"}],
    "vm": {"driver": "firecracker", "image": "agent-base", "port": 8080, "size_class": "medium"},
    "scaling": {"min_replicas": 0, "max_replicas": 1, "warm_pool": 0, "target_concurrency": 1,
                "scale_to_zero_after_secs": 900, "cold_start_timeout_secs": 120,
                "drain_timeout_secs": 30, "boot_timeout_secs": 300, "idle_action": "retain"},
    "health": {"path": "/healthz", "port": 8080, "timeout_secs": 2},
    "artifact": {"store": "http://127.0.0.1:8080", "ref": "agent-base"}
  },
  "kind": "vm",
  "desired_replicas": 1,
  "ready": 1,
  "pending": 1,
  "total_in_flight": 3,
  "vms": [
    {"sandbox_id": "applb-sandbox-a1b2c3", "addr": "172.16.0.4:8080",
     "in_flight": 3, "healthy": true, "draining": false}
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `spec` | object | The stored, normalized spec (`DeploymentSpec`). `namespace` is omitted when it is `default`; read it with `DeploymentSpec::namespace()`. `vm.image` is filled in by builds and pulls, and mount `digest`s by mount pulls. `account_id`/`user_id` are stamped for federated callers. |
| `kind` | string | `vm`, `static` or `site`. |
| `desired_replicas` | integer | What the autoscaler is aiming for. |
| `ready` | integer | Backends in the pool. This includes unhealthy ones; see `vms[].healthy`. |
| `pending` | integer | VMs booting. |
| `total_in_flight` | integer | Requests in flight across the pool. |
| `vms[]` | array | `{sandbox_id, addr, in_flight, healthy, draining}` per backend. For a static deployment, `addr` is the upstream. |
| `workspace` | object | Present when `vm.workspace` is set: `{path, store, digest, captured_at, captured_from, files, bytes, pushed, pushed_at, push_pending, phase, blocked, pending[], last_error}`. `phase` is `idle`, `restoring`, `capturing`, `pushing` or `blocked`. |
| `site` | object | Present for a site: `{root, status, index_present, hint}`. `status` is `ok`, `missing`, `not_a_directory`, `unreadable` or `empty`. |
| `rollout_revision` | string | Opaque. Pass it as `expected_revision` to [start a rollout](#rollouts). |

A pool is up when `pending == 0` and the number of VMs that are `healthy && !draining` is at least `desired_replicas`. `Client::wait_for_ready(id)` polls for exactly that (see [Waiting](overview.md#waiting)).

## List deployments

`GET /deployments`

**Crate:** `Client::deployments() -> Vec<DeploymentStatus>` · `Raw::deployments()`, `Raw::deployments_in(namespace)`

Returns the deployments the caller can see, sorted by id. `?namespace=<ns>` narrows the list further. The response carries capability headers, each with the value `1`, naming what the binary supports: `x-app-lb-create-only`, `x-app-lb-discovery-source`, `x-app-lb-discovery-region`, `x-app-lb-gateway` and `x-app-lb-regional-admission`.

## Create a deployment

`POST /deployments`

**Crate:** `Client::create_deployment(&spec) -> DeploymentStatus` · `Raw::create_deployment(&spec)`

The body is a deployment spec, sent as a `serde_json::Value`. app-lb answers `201` with the deployment status, **including when the id already existed and was replaced**. A replace tears the old pool down. To refuse a replace, send `If-None-Match: *`; the crate's `create_deployment` does not set it, so use a custom `Transport` or curl when you need create-only semantics.

```rust
let spec = serde_json::json!({
    "id": "demo",
    "routes": [],
    "vm": {"driver": "firecracker", "port": 8080, "size_class": "small"},
    "artifact": {"store": "https://hub.heyo.work", "ref": "heyo/alpine:3.24"},
    "health": {"path": null, "port": 22},
    "scaling": {"min_replicas": 0, "max_replicas": 1}
});
let status = lb.create_deployment(&spec).await?;
```

Before validating, app-lb:

1. fills in `namespace` when the spec omits it and the caller reaches exactly one namespace,
2. adds a route to `<id>.<base>` when a base domain is configured and no `host`/`host_suffix` route is pinned (routeless VM deployments stay private),
3. gives a site with no `root` the managed root,
4. binds every secret reference to the spec's namespace.

If the spec declares `vm.mounts` not yet on the host, a [mount pull](jobs.md#start-a-mount-pull) starts by itself. Certificate issuance is asynchronous: a `201` does not mean a certificate exists yet.

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | The spec failed validation. `error` says why. |
| `403` | `Forbidden` | The namespace is out of reach, or the id belongs to another namespace. |
| `409` | `Conflict` | A rollout or workspace recovery reserves the id, a discovery bootstrap needs an unclaimed exact-host route, or the deployment is frozen for retirement. |
| `412` | `Api` | `If-None-Match: *` and the id exists. |
| `503` | `ColdStartTimeout` | A workspace fence could not be taken. Retry. |

## Get a deployment

`GET /deployments/:id`

**Crate:** `Client::deployment(id) -> DeploymentStatus`, `Client::deployment_exists(id) -> bool`, `Client::deployment_with_timeout(id, d)` · `Raw::deployment(id)`, `Raw::spec(id)`

Returns one deployment status and an `ETag` header: `"<64 lowercase hex>"`, the SHA-256 of `spec` as compact JSON with object keys sorted recursively.

`deployment_exists` turns a `404` into `false` and passes every other error through. `deployment_with_timeout` overrides the request deadline for one call. `Raw::spec` returns only the `spec` field, ready to edit and pass to `replace_deployment`.

Errors: `404` `NotFound` for an operator; `403` `Forbidden` for a confined caller (see above).

## Replace a deployment

`PUT /deployments/:id`

**Crate:** `Client::replace_deployment(id, &spec) -> DeploymentStatus` · `Raw::replace_deployment(id, &spec)`

Replaces the whole spec. The path id wins over the body's. The pool is rebuilt only when `vm` or `upstreams` changed; route, scaling, health, auth, build and artifact edits keep the running VMs.

Always edit the live spec. A spec rebuilt from your original file differs in fields app-lb filled in (`vm.image` after a pull, mount `digest`s), and any difference in `vm` recycles the pool.

```rust
let mut spec = lb.raw().spec("demo").await?;
spec["routes"] = serde_json::json!([{"host": "demo.us5.heyo.work"}]);
lb.replace_deployment("demo", &spec).await?;
```

For compare-and-swap, send the `ETag` from `GET` as `If-Match`; a spec that changed in between answers `412`. app-lb accepts one exact strong ETag only: no lists, no `*`, no `W/`. `PUT` returns the new `ETag`. The crate does not send `If-Match`.

Errors are those of [create](#create-a-deployment), plus `403` when a confined caller tries to move the deployment to another namespace.

## Delete a deployment

`DELETE /deployments/:id`

**Crate:** `Client::delete_deployment(id) -> ()`

Drains and reaps every VM, releases the routes, and removes the deployment. Answers `204`. Pulled images stay in the catalog until the [offload pacer](images.md) finds them idle.

## Change scaling

`PATCH /deployments/:id/scaling`

**Crate:** `Client::patch_scaling(id, &patch) -> DeploymentStatus` · `Raw::patch_scaling(id, &patch)`

The body is any subset of [`scaling`](../app-lb.md#scaling). It is merged onto the current policy, so repeating it is harmless. The pool is always kept.

```sh
curl -s -XPATCH $LB/deployments/demo/scaling -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"min_replicas": 1}'
```

| Field | Meaning |
| --- | --- |
| `min_replicas`, `max_replicas` | Pool bounds. |
| `warm_pool` | Idle VMs kept above demand. |
| `target_concurrency` | In-flight requests per VM the autoscaler aims for. |
| `scale_to_zero_after_secs` | Idle time before the pool shrinks to `min_replicas`. |
| `cold_start_timeout_secs` | How long a request waits for a VM. |
| `drain_timeout_secs` | How long a draining VM may finish its requests. |
| `boot_timeout_secs` | How long a booting VM gets to pass its health check. `0` waits forever. |
| `idle_action` | `destroy` or `retain`: what becomes of a VM the autoscaler retires. |

Errors: `400` `Api` when the merged policy is invalid (for example `min > max`) or the deployment is not a VM deployment.

## Evict a VM

`DELETE /deployments/:id/vms/:sandbox_id?force=true|false`

**Crate:** `Client::evict_vm(id, sandbox_id, force) -> EvictOutcome` · `Raw::evict_vm`

Recycles one VM. Without `force`, the VM drains and the answer is `202 {"sandbox_id": "…", "outcome": "draining"}`. With `force=true`, it is killed now and the answer is `200 {…, "outcome": "killed"}`. If the policy still wants the capacity, the autoscaler boots a replacement.

The crate always sends `force` explicitly as `true` or `false`.

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Not a VM deployment. |
| `404` | `NotFound` | No such VM in this deployment. |
| `502` | `Upstream` | The kill failed. |

## Drain a static upstream

`PUT /deployments/:id/upstreams/:upstream/drain`, `DELETE` on the same path

**Crate:** `Client::cordon_upstream(id, upstream, force, reason) -> UpstreamTrafficStatus`, `Client::uncordon_upstream(id, upstream)` · `Raw::cordon_upstream`, `Raw::uncordon_upstream`

`PUT` stops new requests to one upstream of a static deployment; requests already in flight finish. The body is `{"force": false, "reason": "…"}`, with `reason` optional and at most 512 bytes. It answers `202` while requests are in flight and `200` once the upstream is drained. `DELETE` removes the drain and returns the same shape. Health is independent: an unhealthy upstream stays out until its probe recovers.

The upstream is a path segment, so `us1.example.com:443` goes out as `us1.example.com%3A443`.

```json
{"deployment_id": "stage", "upstream": "us1.example.com:443", "state": "draining",
 "healthy": true, "in_flight": 3, "reason": "regional maintenance", "started_at": 1722400000}
```

| Field | Meaning |
| --- | --- |
| `state` | `accepting`, `draining` or `drained`. |
| `healthy` | The probe's view, independent of `state`. |
| `in_flight` | Requests still being served. Poll until `0`. |
| `reason`, `started_at` | As recorded by the drain. |

Errors: `400` for a deployment that is not static; `409` `Conflict` when draining would leave no healthy, accepting upstream, unless `force` is set.

## Rollouts

`POST /deployments/:id/rollouts`, `GET /deployments/:id/rollouts/:operation`

**Crate:** `Client::start_rollout(id, operation_id, expected_revision, &spec) -> RolloutOperation`, `Client::rollout(id, operation_id) -> RolloutOperation`

Replaces a managed deployment's spec candidate-first: a fresh pool is booted beside the old one, verified, and only then is the old pool drained. The body is:

```json
{"operation_id": "deploy-2026-10-06-1", "expected_revision": "<rollout_revision from GET>", "spec": { … }}
```

`spec.id` must equal `:id`. The spec needs a digest-pinned `artifact` and a `health.expected_header`, and must leave routes, auth, namespace and maintenance unchanged; see [candidate-first rollouts](../app-lb.md#static-and-managed-deployments).

`operation_id` is yours to choose and makes the call idempotent: repeating it with the same body returns the same operation rather than starting another, so a caller that lost the reply retries with the same id. Reusing an id with a different body is a `409`. `expected_revision` is the deployment's `rollout_revision` as you last read it; the rollout is refused with `409` if anything changed it since.

Both routes answer with the operation (`202` on start):

```json
{"operation_id": "deploy-2026-10-06-1", "deployment": "api", "source_revision": "…",
 "target_spec_sha256": "…", "status": "running", "phase": "…", "readiness_verified": false,
 "previous_stopped": false, "error": null, "preparation_stage": null}
```

| Field | Meaning |
| --- | --- |
| `status` | `running`, `succeeded`, `failed` or `reconciliation_required`. `RolloutOperation::is_finished()` is true only for `succeeded` and `failed`: `reconciliation_required` is still being settled by app-lb. |
| `phase`, `preparation_stage` | Where a running rollout is. |
| `readiness_verified` | The candidate pool passed its health check with the expected header. |
| `previous_stopped` | The old pool has been drained. |
| `error` | Why it failed. |
| `failure_settlement` | Present once a failed rollout's candidates have been reclaimed. |

Poll `rollout` until `is_finished()`.

## Discovery status

`GET /deployments/:id/discovery-status[?staged=true]`

**Crate:** `Client::discovery_status(id, staged) -> DiscoveryStatus`

For a discovery-backed static deployment, what this gateway publishes about it. Other deployments answer `400`. The body is camelCase and marked `Cache-Control: no-store`:

```json
{"serviceId": "cloud", "sourceUrl": "https://orchestrator.example.com/…", "version": 42,
 "upstreams": [{"peer": "10.0.0.5:8080", "draining": false, "inFlight": 2}]}
```

`regional` is added for regional gateways and is carried as opaque JSON. `staged=true` reads a staged route-handoff target instead of the live spec. See [multi-region](../multi-region.md).
