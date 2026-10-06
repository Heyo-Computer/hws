# app-lb HTTP API reference

This page describes app-lb's admin API at the HTTP level, for callers using curl or a language without an SDK. The [`hws`](../app-lb/heyctl) Rust crate (which `heyctl` is built on) and the [`@heyocomputer/hws`](../app-lb/sdk/typescript) TypeScript SDK wrap this API. Both are checked against the response fixtures in [`app-lb/testdata/wire/`](../app-lb/testdata/wire), which also supply the example bodies on this page.

This page sticks to the wire format. For what a deployment field does, see the [deployment spec](app-lb.md#deployment-spec). For how credentials are issued and gates are configured, see [app-lb-auth](app-lb-auth.md).

## Contents

1. [Base URLs](#base-urls)
2. [Authentication](#authentication)
3. [Conventions](#conventions)
4. [Endpoint reference](#endpoint-reference)
5. [Walkthrough: a VM with a namespace token](#walkthrough-a-vm-with-a-namespace-token)

## Base URLs

There are two ways to reach the same API.

### Direct: the admin listener

app-lb serves the admin API on `APP_LB_ADMIN_ADDR`, which defaults to `127.0.0.1:9090`. The listener speaks plain HTTP. If it is reachable from outside the host, it is behind an SSH tunnel, or behind a TLS deployment that app-lb itself serves (for example `https://admin.us5.heyo.work`).

```sh
LB=http://127.0.0.1:9090
curl -s $LB/healthz          # "ok", plus an x-heyo-revision header with the build's git SHA
```

`GET /healthz` never requires a credential. The paths on this page are relative to `$LB`.

### Managed: the Heyo cloud namespace door

On Heyo's managed fleet, customers have no access to the admin listener. They reach the same API through Heyo cloud, one namespace at a time:

```
https://server.heyo.computer/namespaces/{ns}/lb/<path>
```

Authenticate with an ordinary `heyo_api_…` key. Cloud pins each request to `{ns}`. app-lb then resolves the key into a federated grant (see [Credentials](#credentials)), so the answers are the ones a namespace-confined caller gets on the direct listener. A deployment registered through the door lands in `{ns}` even if its spec names no namespace.

```sh
LB=https://server.heyo.computer/namespaces/team-a/lb
curl -s -H "Authorization: Bearer $HEYO_API_KEY" $LB/deployments
```

The [MCP server](../mcp/README.md#managed-mode) and Heyo's cloud SDK address app-lb through this same prefix.

**Only allowlisted routes are reachable through the door.** Cloud forwards an allowlist of routes, and it maintains that list, not app-lb. Any other route answers `404 route not exposed through the namespace proxy`. The [MCP README](../mcp/README.md#managed-mode) lists what the door is known to expose:

- the deployment list, get, create, replace, scale and delete routes
- `build`, `pull`, `mounts/pull` and `update`
- the job reads
- VM eviction and `exec`
- `/metrics` and `/security`

Fleet-wide operator routes (`/disks`, `/certs` and the disk mutations) are not exposed. The obs plugin paths (`/namespaces/{ns}/plugins/obs/...` and `/namespaces/{ns}/plugins`) are reachable only once cloud's allowlist includes them. Until then they 404 at the door. If you need a route that this page documents and the door refuses, the cloud allowlist is what has to change.

## Authentication

### Credentials

The admin gate accepts the following credentials. It checks them in this order. An `Authorization` header always takes precedence over a browser session cookie.

| Credential | Header | Reach |
| --- | --- | --- |
| Operator | `Authorization: Basic base64(user:password)` from `APP_LB_DASHBOARD_USER` / `APP_LB_DASHBOARD_PASSWORD` | Everything. Unscoped. |
| App-token | `Authorization: Bearer applb_…` | The tier and scope it was minted with. See [App-tokens](#app-tokens). |
| Federated Heyo bearer | `Authorization: Bearer <JWT or heyo_api_…>` | The namespaces the Heyo auth service grants. Only when `APP_LB_AUTH_URL` is set. |
| Browser session | `__Host-heyo-admin` cookie set by `POST /login` or `POST /login/handoff` | As a federated bearer. Writes and WebSocket upgrades need a same-origin HTTPS `Origin`. |

**`?app_token=` works on one route only:** `GET /deployments/:id/shell`. A browser's `WebSocket` constructor cannot set headers, so the query string is the only place it can carry a credential. Every other route ignores the parameter. Query strings end up in logs, so mint a short-lived token for this purpose. A Basic or federated credential cannot be passed this way.

A token beginning with `applb_` is always resolved locally and never sent to the auth service. Any other bearer is resolved through `GET {APP_LB_AUTH_URL}/api/auth/scopes`, which is cached for `APP_LB_AUTH_CACHE_SECS`. If the auth service is unreachable, the request is refused.

`GET /whoami` tells you how app-lb sees the credential you presented. Call it first when a request is refused.

### Tiers

Each route belongs to a tier. Which tiers are gated depends on the environment ([table](app-lb-auth.md#which-routes-each-setting-gates)).

| Tier | Needs | Gated when |
| --- | --- | --- |
| Open | nothing | never: `/healthz`, `/login`, `/login/handoff`, `/logout`, `/__ui/*` |
| Any credential | any credential the gate recognises, at any admin scope including `none` | a password is set: `/whoami` only |
| View | admin scope `view` or `admin` | `APP_LB_DASHBOARD_PASSWORD` is set and `APP_LB_DASHBOARD_AUTH` is not `0` |
| CRUD | admin scope `admin` | `APP_LB_ADMIN_AUTH=1`. With it off, CRUD routes take no credential at all. |
| Always authenticated | admin scope `admin` (fleet view routes: `view`), and never satisfied by an ungated listener | always: retirement, workspace recovery, regional, `/fleet*`, `/services`, `/control-plane/config`, `/releases`, `/api/releases/*` |

A credential with too low a tier gets `403`. This means the credential is valid, so presenting it again will not help. A missing or unrecognised credential gets `401`.

### Admin scope and deployment scope

App-tokens carry two independent limits:

- **`admin`** (`none`, `view` or `admin`) is the tier on this API. A `none` token can pass a deployment's [app-token gate](app-lb-auth.md#app-token-gate) but can only call `/whoami` here.
- **Reach**:
  - `deployments: ["*"]` with no namespace covers the whole fleet.
  - A list of ids covers only those deployments.
  - `namespace: "<ns>"` confines the token to one namespace. Its `deployments` list then narrows within that namespace, and an empty list means every deployment there.

A federated grant maps namespaces to tiers, for example `{"team-a": "admin", "team-b": "view"}`. The tier is checked against the namespace of the deployment the route names. `fleet:admin` makes a grant unconfined.

### What a confined caller may use

A *confined* caller is a namespace token or a federated grant without `fleet:admin`. A deployment-list token (unconfined, but without `"*"`) gets the same treatment on the routes in the last row of this table. The gate classifies every route as one of the following:

| Route class | Confined caller |
| --- | --- |
| `/deployments/:id` and everything below it | Allowed when the deployment is in the caller's reach. An id the caller cannot see, **including one that does not exist**, gets the same `403 this token is not scoped to deployment "<id>"`, so you cannot probe for ids in other namespaces. |
| `POST /deployments`, `GET /deployments` | Allowed. A create must land in a namespace the caller administers. The namespace is filled in when the spec omits it and the caller reaches exactly one. Replacing an id owned by another namespace is refused. The list narrows to the caller's namespaces. |
| Routes that narrow themselves: `/`, `/metrics`, `/dashboard`, `/security`, `/siem`, `/ingress`, `/network`, `/namespaces` (GET), `/auth-providers` (GET), `/whoami`, `/onboarding` | Allowed. The answer covers only what the caller can see. |
| `/secrets`, `/secrets/:id` | Allowed for the caller's namespaces. The handler checks the namespace in `?namespace=` or the body. |
| `/auth-providers` (POST), `/auth-providers/:namespace/:name` | Allowed for the caller's namespaces. |
| `/tokens`, `/tokens/:id` | Allowed only for tokens confined to a namespace the caller administers *wholly*. See [Confinement rules for minting](#confinement-rules-for-minting). |
| `/jobs/:job_id` | Allowed. A job on a deployment the caller cannot touch answers `404`, exactly as an unknown id does. `GET /jobs` (the full list) stays fleet-only. |
| `/feeds/:namespace`, `/namespaces/:name/plugins…` | Allowed when `:namespace` / `:name` is one of the caller's. |
| `/fleet/deployments`, `/fleet/gateways/:id/metrics` | Allowed with `?namespace=` set to one of the caller's namespaces. |
| Everything else | `403 this token is scoped to specific deployments, so it cannot use a fleet-wide route`. This covers `/jobs`, `/feeds`, `/disks*`, `/images*`, `/storage`, `/plugins`, `/api/plugins*`, `/certs`, `/security/rules*`, `/workflows*`, `POST /namespaces`, `DELETE /namespaces/:name`, `/fleet`, `/fleet/network`, `/fleet/tokens`, `/services` and `/control-plane/config`. |

Deployment ids are globally unique. Because of that, a confined `POST /deployments` that is refused with `403` (the id exists in another namespace) can still be told apart from one that succeeds with `201`.

## Conventions

### Requests and responses

- Bodies are JSON. Send `Content-Type: application/json` on every request with a body. Without it, the framework answers `415`.
- Path parameters are single path segments. URL-encode them, especially static upstreams in `/deployments/:id/upstreams/:upstream/drain` (`us1.internal%3A8080`).
- Timestamps are Unix seconds unless a field name says `_ms` or `_nanos`. The obs plugin's log API uses epoch milliseconds.
- Unknown fields in a deployment spec are ignored by app-lb builds that do not know them. Check the [capability headers](#capability-headers) before relying on a newer field.
- The default request body limit is 2 MiB (the framework default). `/login`, `/login/handoff` and `/api/releases/*` take 8 KiB. Obs plugin bodies take 64 KiB.

### Errors

app-lb's own handlers answer with:

```json
{"error": "no deployment \"demo\""}
```

Some refusals add a machine-readable `code`:

```json
{"error": "the obs plugin is not installed in namespace \"team-a\"; install it with `heyctl plugins install obs -n team-a`", "code": "plugin_not_installed"}
```

Today the codes are `plugin_disabled` and `plugin_not_installed`. An image refused because it is in use also carries `references` (and `sandboxes`) naming what holds it.

Some responses are not JSON:

- `401` from the gate has a plain-text body (`authentication required`) and two `WWW-Authenticate` headers (`Basic realm="app-lb dashboard"` and `Bearer`).
- Framework rejections are plain text: `400` for malformed JSON, `415` for a missing content type, `422` for well-formed JSON of the wrong shape (a missing required field or a wrong type), and `413` for an oversized body.

Parse by status first and treat the body as optional detail.

### Status codes

| Status | Meaning here |
| --- | --- |
| `200` | Done. Also a replaced secret, namespace or auth provider, and `exec` whose command exited non-zero (check `exit_code`). |
| `201` | Created. `POST /deployments` answers `201` for a replace too. |
| `202` | Accepted and still running: build, pull, mount-pull and update jobs, rollouts, workspace recovery, retirement in progress, disk archive, an eviction that is draining, and an upstream drain with requests still in flight. |
| `204` | Deleted (deployment, record, secret, token, namespace, image, workflow, security rule) or disk policy changed. |
| `400` | The request is invalid: a spec that fails validation, a bad `If-Match`/`If-None-Match`, an invalid namespace name, scaling on a non-VM deployment, `exec` on a static deployment or site, or malformed JSON. |
| `401` | No usable credential: missing, wrong, revoked or expired. These cases are deliberately indistinguishable. |
| `403` | The credential is valid but out of tier or scope. The message names what is missing. |
| `404` | No such deployment, VM, job, secret, token, plugin or route. A job aged out of the bounded history is also `404`. Through the managed door, also a route the door does not expose. |
| `409` | State conflict. Examples: a job already running for the deployment; a candidate rollout or workspace recovery reserving the deployment; a secret still referenced; a namespace still holding deployments; an image held by a reference or pin; a plugin disabled or not installed; `exec` with `wake: false` and no running VM; a VM not ready or draining; a deployment frozen for retirement; refusing to drain the last healthy upstream. |
| `412` | A precondition failed. `If-None-Match: *` on an existing id, or an `If-Match` ETag that no longer matches. |
| `413` | The body is too large. |
| `415` | Missing `Content-Type: application/json`. |
| `422` | The JSON parsed but has the wrong shape for the route. |
| `428` | `DELETE /deployments/:id/record` or `/retired-record` was sent without `If-Match`. |
| `500` | app-lb could not persist something (token file, secret file, state). The message says what was not saved. |
| `501` | `POST /disks/:id/archive` with no archive bucket configured. |
| `502` | Something app-lb depends on failed: the heyvm daemon could not run an `exec` or open a shell, an eviction could not kill the VM, app-obs was unreachable or rejected the plugin's token, or an image offload could not be verified. |
| `503` | Not available right now: no VM became ready within `cold_start_timeout_secs`, disk management or the image inventory is off, durable state could not be written, or a fence could not be taken. Retry. |
| `504` | Passed through from app-obs when a log query outruns its deadline. |

app-lb's admin API does not rate-limit, so it never returns `429`. The security monitor records refused credentials, and block rules can refuse traffic. Neither throttles the admin API.

### Conditional requests and idempotency

- **Create-only.** `POST /deployments` with `If-None-Match: *` creates or fails with `412 deployment already exists`. Without the header, `POST` with an existing id **replaces** the deployment and tears its pool down. Any value other than `*` is a `400`.
- **Compare-and-swap edit.** `GET /deployments/:id` returns `ETag: "<64 lowercase hex>"`. This is the SHA-256 of the response's `spec` as compact JSON, with every object's keys sorted recursively. Send it back as `If-Match` on `PUT /deployments/:id` to fail with `412` if someone else changed the spec in between. `PUT` returns the new `ETag`. Only one exact, strong ETag is accepted: no lists, no `*`, no `W/`.
- **Record deletes** (`/record`, `/retired-record`) *require* `If-Match` (`428` without it).
- **Correlated operations.** Rollouts, workspace recovery, retirement, route handoffs and host rollouts take a caller-chosen `operation_id`. Re-sending the same request with the same id returns the same operation instead of starting another. A pull with `operation_id` (and a pinned digest `ref`) is idempotent in the same way. Reusing an id with a different body is a `409`.
- **Jobs are not idempotent.** A second `build`/`pull`/`update` while one is running for the same deployment is `409 a job for deployment "<id>" is already running`. Read `GET /deployments/:id/jobs` and follow the running job.
- `PATCH /deployments/:id/scaling` merges the fields you send, so repeating it is harmless.

### Capability headers

`GET /deployments` advertises what the binary supports. Each of these headers is present with the value `1`: `x-app-lb-create-only`, `x-app-lb-discovery-source`, `x-app-lb-discovery-region`, `x-app-lb-gateway`, `x-app-lb-regional-admission`.

## Endpoint reference

The **Tier** column uses the names from [Tiers](#tiers). "Operator" means you need an unconfined admin credential (Basic, or a token with `deployments: ["*"]` and no namespace, or `fleet:admin`). "Fleet admin" is the stricter check that some routes make in their handler. It refuses even an ungated listener.

### Identity

#### `GET /whoami`

Tier: any credential. This route describes the credential you presented and never echoes a secret.

```sh
curl -s -H "Authorization: Bearer $TOKEN" $LB/whoami
```

```json
{
  "caller": "app-token",
  "may": {"read_view_routes": true, "use_admin_routes": true},
  "fleet": false,
  "confined": true,
  "admin_scope": "admin",
  "token": {"id": "b2c3d4e5f6a1", "name": "team-a operator"},
  "namespace": "team-a",
  "deployments": [],
  "expires_at": 1730176000,
  "expires_in_secs": 7775000,
  "note": "A deployment's own gate checks whether this credential admits that deployment; ..."
}
```

`caller` is one of the following:

| `caller` | Additional fields |
| --- | --- |
| `ungated` | `admin_scope: "unchecked"`. The listener has no credential configured. |
| `operator` | none |
| `app-token` | `token`, `namespace`, `deployments`, `expires_at`, `expires_in_secs` |
| `federated` | `subject {user_id, email, account_id}` and `namespaces {"<ns>": "admin"\|"view"}` |

### Deployments

The request body for create and replace is a deployment spec: [field reference](app-lb.md#deployment-spec), [JSON Schema](../app-lb/schema/deployment-spec.json), [examples](../app-lb/examples/README.md).

Every deployment route returns a **deployment status**, or a list of them. Abridged from [`deployment-status-artifact.json`](../app-lb/testdata/wire/deployment-status-artifact.json):

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

| Field | Meaning |
| --- | --- |
| `spec` | The stored, normalized spec. Secret references are bound to the namespace. `vm.image` is filled in by builds and pulls. `account_id`/`user_id` are stamped for federated callers. |
| `kind` | `vm`, `static` or `site`. |
| `desired_replicas` | What the autoscaler is aiming for. |
| `ready` | Backends in the pool. This is not the same as healthy: check each entry's `vms[].healthy`. |
| `pending` | VMs booting. |
| `vms[]` | One entry per backend. For a static deployment, `addr` is the upstream. |
| `workspace` | Present when `vm.workspace` is set: which snapshot the pool runs from and what, if anything, holds it at zero. |
| `site` | Present for a site: whether its root can serve anything. |
| `rollout_revision` | Opaque. Pass it as `expected_revision` to a rollout or retirement. |

A pool is up when `pending == 0` and the count of `vms` that are `healthy && !draining` is at least `desired_replicas`.

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /deployments` | CRUD | List the deployments the caller can see, sorted by id. `?namespace=` filters further. Carries the capability headers. |
| `POST /deployments` | CRUD | Register, or replace an existing id (`201` either way). `If-None-Match: *` makes it create-only. |
| `GET /deployments/:id` | CRUD | One deployment, with an `ETag`. |
| `PUT /deployments/:id` | CRUD | Edit in place. The path id wins over the body's. `If-Match` for compare-and-swap. Returns the new `ETag`. |
| `DELETE /deployments/:id` | CRUD | Drain and reap every VM, release the routes, remove the deployment. `204`. |
| `PATCH /deployments/:id/scaling` | CRUD | Merge a partial `scaling` object. VM deployments only. Always keeps the pool. |
| `DELETE /deployments/:id/vms/:sandbox_id` | CRUD | Recycle one VM. `?force=true` kills it now. |
| `PUT /deployments/:id/upstreams/:upstream/drain` | CRUD | Cordon a static upstream. |
| `DELETE /deployments/:id/upstreams/:upstream/drain` | CRUD | Uncordon it. |
| `GET /deployments/:id/discovery-status` | CRUD | Discovery state of a discovery-backed static deployment. |
| `POST /deployments/:id/rollouts` | CRUD | Start a candidate-first rollout. |
| `GET /deployments/:id/rollouts/:operation` | CRUD | Read a rollout. |
| `DELETE /deployments/:id/record` | CRUD | Remove a proven-empty record without touching VMs. |
| `DELETE /deployments/:id/retired-record` | CRUD + fleet admin | Archive and remove a settled, drained managed record. |

#### `POST /deployments`

```sh
curl -s -XPOST $LB/deployments -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -H 'If-None-Match: *' -d @web.json
```

Before validation, app-lb does the following, in order:

1. It fills in the namespace if the spec omits it and the caller reaches exactly one namespace.
2. It adds a route to `<id>.<base>` when a base domain is configured and no `host`/`host_suffix` route is pinned. Routeless VM deployments are the exception and stay private.
3. It gives a site with no `root` the managed root.
4. It binds every secret reference to the spec's namespace.

If the spec declares `vm.mounts` that are not on the host, registering also starts a mount-pull job.

Errors:

- `400` validation, with the reason in `error`
- `403` namespace out of reach, or the id is owned by another namespace
- `409` a rollout or workspace recovery reserves the id, a discovery bootstrap needs an unclaimed exact-host route, or the deployment is frozen for retirement
- `412` create-only and the id exists
- `503` a workspace fence could not be taken

#### `PUT /deployments/:id`

This replaces the whole spec. The pool is rebuilt only when `vm` or `upstreams` changed. Route, scaling, health, auth, build and artifact edits keep the running VMs. Always start from the live spec (`GET` it, edit it, `PUT` it back). A spec rebuilt from your original file can differ in fields app-lb filled in, such as `vm.image` after a pull and mount `digest`s, and a `vm` that differs recycles the pool.

A confined caller cannot move a deployment to another namespace (`403`).

#### `PATCH /deployments/:id/scaling`

```sh
curl -s -XPATCH $LB/deployments/demo/scaling -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"min_replicas": 1}'
```

The body is any subset of [`scaling`](app-lb.md#scaling). The merged policy is validated, so `min > max` is a `400`. A non-VM deployment is a `400`. The response is the deployment status.

#### `DELETE /deployments/:id/vms/:sandbox_id`

The response is `202 {"sandbox_id": "...", "outcome": "draining"}`, or with `?force=true`, `200 {..., "outcome": "killed"}`. If the policy still wants the capacity, the autoscaler boots a replacement. Errors: `404` if there is no such VM, `400` for a non-VM deployment, `502` if the kill failed.

#### Upstream drain

`PUT /deployments/:id/upstreams/:upstream/drain` takes an optional `{"force": false, "reason": "..."}`, where `reason` is at most 512 bytes. It returns `202` while requests are in flight and `200` once the upstream is drained:

```json
{"deployment_id": "stage", "upstream": "us1.example.com:443", "state": "draining",
 "healthy": true, "in_flight": 3, "reason": "regional maintenance", "started_at": 1722400000}
```

`state` is `accepting`, `draining` or `drained`. The first drain is `409` unless another upstream is healthy and accepting, or you pass `force: true`. `DELETE` on the same path uncordons the upstream and returns the same shape. Static deployments only. Others get `400`.

#### `GET /deployments/:id/discovery-status`

This route is for discovery-backed static deployments. Others get `400`. The response is camelCase and marked `Cache-Control: no-store`:

```json
{"serviceId": "cloud", "sourceUrl": "https://orchestrator.example.com/...", "version": 42,
 "upstreams": [{"peer": "10.0.0.5:8080", "draining": false, "inFlight": 2}]}
```

`regional` is added for regional gateways. `?staged=true` reads a staged route-handoff target. See [multi-region](multi-region.md).

#### Rollouts

`POST /deployments/:id/rollouts` takes the following body:

```json
{"operation_id": "deploy-2026-10-06-1", "expected_revision": "<rollout_revision from GET>", "spec": { ... }}
```

`spec.id` must equal `:id`. Its preconditions are listed under [candidate-first rollouts](app-lb.md#static-and-managed-deployments): a digest-pinned `artifact` and `health.expected_header`, with routes, auth, namespace and maintenance unchanged. The response is `202` with the operation:

```json
{"operation_id": "deploy-2026-10-06-1", "deployment": "api", "source_revision": "...",
 "target_spec_sha256": "...", "status": "running", "phase": "...", "readiness_verified": false,
 "previous_stopped": false, "error": null, "preparation_stage": null}
```

Poll `GET /deployments/:id/rollouts/:operation` until `status` is `succeeded`, `failed` or `reconciliation_required`. A settled failure adds `failure_settlement`. Admission conflicts are `409`.

#### Record deletes

`DELETE /deployments/:id/record` removes a deployment record only when there is provably nothing behind it:

- no routes
- zero desired, live, pending or suspended VMs
- no rollout generations
- no workspace
- no build, artifact, update or mount configuration
- no discovery state
- no job history
- runtime and disk inventories confirming nothing is owned

It requires `If-Match`. Each refusal is a `409` naming the reason. `DELETE /deployments/:id/retired-record` is the fleet-admin form that archives settled rollout history. Most callers want plain `DELETE /deployments/:id`.

#### Operator-only and always-authenticated deployment routes

These routes need a credential even on an ungated listener. They are described here only briefly.

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /deployments/:id/retirement` | Always auth, namespace admin | `{deployment, revision, spec_sha256, retirement}` |
| `POST /deployments/:id/retirement` | Always auth, namespace admin | Freeze and retire. Body: `{operation_id, expected_revision, expected_spec_sha256, targets[]}`. `202` while in progress, `200` once retired. A frozen deployment refuses every other mutation with `409`. |
| `POST /deployments/:id/workspace/recoveries` | Always auth, namespace admin | Promote a stopped, retained VM's disk to be the workspace snapshot. Body: `{operation_id, source_sandbox_id, expected_snapshot, confirm_replace}`. `202`. |
| `GET /deployments/:id/workspace/recoveries/:operation_id` | Always auth, namespace admin | Read a recovery. |
| `POST /deployments/:id/regional-probe` | Always auth, namespace admin | Regional gateway candidate probe. |
| `POST /deployments/:id/regional-active-probe` | Always auth, namespace admin | Regional active-capacity probe. |
| `POST /deployments/:id/route-handoff` | Always auth, fleet admin | Prepare a route handoff (`{operationId, expectedPredecessorFingerprint, stagedSpec}`). |
| `GET /deployments/:id/route-handoff` | Always auth, fleet admin | Inspect the handoff. |
| `POST /deployments/:id/route-handoff/commit` | Always auth, fleet admin | Commit (`{operationId}`). |

The regional protocol is covered in [multi-region](multi-region.md). "Namespace admin" means `admin` tier in the deployment's namespace with the deployment in reach. An ungated listener does not qualify.

### Exec and interactive shell

Both routes are CRUD tier, on VM deployments only (others get `400`). They are the only way into a deployment with no routes.

#### `POST /deployments/:id/exec`

| Field | Default | Meaning |
| --- | --- | --- |
| `command` | required | Run through `sh -c` in the guest. Must not be empty. |
| `cwd` | guest default | Working directory. |
| `env` | none | Object of extra environment variables. |
| `timeout_secs` | `60` | Clamped to 1–3600. This bounds app-lb's call to the daemon. It does not kill the command. |
| `wake` | `true` | Boot or resume a VM if none is running, waiting up to `cold_start_timeout_secs`. `false` gets a `409` instead. |
| `sandbox_id` | pool's choice | Use this VM. If the VM is not in the deployment you get `404`; if it is not started or is draining, `409`. A named VM is never woken. |

```sh
curl -s -XPOST $LB/deployments/demo/exec -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"command": "ls /nope; ls /", "cwd": "/"}'
```

```json
{
  "sandbox_id": "applb-sandbox-a1b2c3",
  "exit_code": 1,
  "stdout": "total 0\n",
  "stderr": "ls: cannot access '/nope': No such file or directory\n",
  "output": "total 0\nls: cannot access '/nope': No such file or directory\n"
}
```

`output` interleaves stdout and stderr in the order the guest wrote them. A command that fails is still `200`, so check `exit_code`. `502` means app-lb could not run the command at all. `503` means no VM became available in time. If no VM has passed its health check yet, the command runs in one that is still booting. An open `exec` counts as in-flight work, so the VM is not reaped under it.

#### `GET /deployments/:id/shell` (WebSocket)

This opens an interactive PTY. Upgrade with a normal WebSocket handshake. Authenticate with an `Authorization` header, or `?app_token=applb_…` from a browser.

| Query | Default | Meaning |
| --- | --- | --- |
| `cols`, `rows` | `80`, `24` | Initial terminal size. |
| `cwd` | guest default | Working directory. |
| `wake` | `true` | As for `exec`. |
| `sandbox_id` | pool's choice | As for `exec`. |
| `app_token` | | App-token, for clients that cannot set headers. |

Every error (`404`, `409`, `503`, `502`, and `409` for a deployment frozen for retirement) is returned as an HTTP response *before* the upgrade. Once the socket is open, the framing is:

| Direction | Frame | Content |
| --- | --- | --- |
| server → client | text | `{"type":"ready","sandbox_id":"…"}`, sent once, first |
| client → server | binary | `0x01` followed by stdin bytes |
| client → server | text | `{"type":"resize","cols":N,"rows":N}` |
| server → client | binary | `0x02` followed by output bytes (the PTY merges stderr in) |
| server → client | text | `{"type":"exit","code":N}`, after which the server closes |
| server → client | text | `{"type":"error","message":"…"}` |

Binary frames from the client that do not start with `0x01` are dropped. An unknown exit status is reported as `code: 0`, so a VM dying under the session also looks like `0`. Treat an `error` before the `exit` as unclean. There is no resume: reconnecting opens a new shell.

### Jobs: build, pull, mount pull, update

These routes start background work and return `202` with a **job record** right away. All are CRUD tier and in reach for a namespace caller on its own deployments.

| Method and path | Body | Starts |
| --- | --- | --- |
| `POST /deployments/:id/build` | `{"ref": "<branch, tag, commit, or store tag/digest>"}`, optional | `image-build` from the spec's `build` block. `ref` overrides the spec for this build only. |
| `POST /deployments/:id/pull` | `{"ref": "<tag or 64-hex digest>", "force": false, "operation_id": "..."}`, all optional | `artifact-pull` from the spec's `artifact` block. With `operation_id`, `ref` must be a pinned digest, and the pull becomes idempotent. |
| `POST /deployments/:id/mounts/pull` | `{"force": false}`, optional | `mount-pull` for every `vm.mounts[]` entry. Starts by itself on register or edit when a tree is missing. |
| `POST /deployments/:id/update` | none | `host-update`: runs `update.commands` on the host for a static deployment or site. |
| `GET /deployments/:id/jobs` | | This deployment's job history, newest first (up to 20 per deployment). |
| `GET /jobs/:job_id` | | One job. Allowed for a confined caller on its own deployments. |
| `GET /jobs` | | Every job. Operator only. |

A successful build or pull rewrites `vm.image` (or the site's files) and rolls the pool onto it. For a pull with no `artifact.image_name`, the image is named by content, `img-<digest[..16]>`. Every deployment pulling the same bytes shares that image.

Job record (from [`job-pull.json`](../app-lb/testdata/wire/job-pull.json)):

```json
{
  "id": "job-002",
  "deployment": "sandbox",
  "kind": "artifact-pull",
  "status": "succeeded",
  "started_at": 1722400000,
  "finished_at": 1722400123,
  "rolled_out": true,
  "store": "http://127.0.0.1:8080",
  "artifact": "agent-base",
  "digest": "sha256:0f1e2d3c",
  "bytes": 2147483648,
  "reused": true,
  "error": null,
  "log": ["cloning …", "done"]
}
```

| Field | Meaning |
| --- | --- |
| `kind` | `image-build`, `artifact-pull`, `mount-pull` or `host-update`. |
| `status` | `running`, `succeeded` or `failed`. Poll until it is not `running`. |
| `error` | Why it failed, or `null`. |
| `log` | The last 400 output lines. Full output goes to app-obs as `source=job`. |
| `rolled_out` | The pool was moved onto the result. |
| kind-specific | Builds: `repo`, `ref`, `commit`, `dockerfile`, `image`. Pulls: `store`, `artifact`, `digest`, `bytes`, `reused`, `site_root`, `files`. Mount pulls: `mounts[]` with per-mount `digest`, `tree`, `bytes`, `unpacked`, `reused`, `changed`. Updates: `working_dir`, `commands_total`, `commands_run`, `verified`. |

Fields that do not apply to the kind are left out, not set to `null`. Job history is held in memory and bounded (20 per deployment, 2000 overall). An id that aged out is a `404`.

Start errors:

- `404` no deployment
- `400` the spec has no `build`/`artifact`/`update` block, or the ref is invalid for the source
- `409` a job is already running for this deployment, a rollout reserves it, or an `operation_id` was reused with a different body
- `503` the operation could not be recorded durably

**Waiting on a job.** Poll `GET /deployments/:id/jobs` and find the record by `id`. A namespace token can always read this route, including on app-lb releases that predate confined access to `GET /jobs/:job_id`. A deployment with an `artifact` block whose image is not on the host also gets a pull started automatically as soon as the autoscaler wants a VM. If your `POST .../pull` gets `409 already running`, follow the running job in the list instead.

#### Host executable rollouts (operator)

`GET /deployments/:id/update/rollouts` returns the current `binary_sha256` and `config_sha256`. `POST` on the same path starts a rollout with `{operation_id, expected_binary_sha256, expected_config_sha256, artifact_sha256, binary_sha256, revision}` and returns `202`. `GET .../update/rollouts/:operation` and `GET .../update/bootstrap/:operation` read rollout progress. These routes answer only for the deployment named in `APP_LB_HOST_UPDATE_CONFIG`, and only to an admin of its namespace. See [host executable rollouts](app-lb.md#host-executable-rollouts).

### Images

These routes manage heyvm's image catalog. They are fleet-wide, so a confined caller gets `403`. The design is in [image reuse and offload](design/image-reuse-offload.md), and the behaviour is under [image management](app-lb.md#image-management).

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /images` | View, operator | Inventory, and what holds each image. |
| `POST /images/sweep` | CRUD, operator | Run one offload pass now. |
| `POST /images/:name/offload` | CRUD, operator | Offload one image (verify the remote copy or push it, then delete it locally). Returns the image record. |
| `DELETE /images/:name` | CRUD, operator | Delete from heyvm. `204`. |
| `PATCH /images/:name` | CRUD, operator | `{"pinned": true\|false}`. Returns the image record. |

Abridged from [`images.json`](../app-lb/testdata/wire/images.json):

```json
{
  "generated_at": 1760090000, "complete": true, "delete_supported": true, "offload": true,
  "disk_used_pct": 41.3, "pressure_pct": 85, "local_bytes": 2684354560,
  "images": [
    {"name": "img-c74abee2ce8409f1", "source": "pull", "tier": "local",
     "digest": "c74abee2…0011", "store": "https://hub.heyo.work", "ref": "heyo/alpine:3.24",
     "bytes": 536870912, "last_used": 1760086400, "pinned": false, "present": true,
     "references": [{"kind": "deployment", "id": "web"}]}
  ]
}
```

`POST /images/sweep` returns `{"pressure": false, "offloaded": ["img-…"], "failed": [["img-…", "reason"]]}`.

| Error | Means |
| --- | --- |
| `400` | Not an image name. |
| `404` | No such image. |
| `409` | Referenced or pinned (the body adds `references`/`sandboxes`), or not eligible. |
| `502` | The remote copy did not verify, or the offload failed. |
| `503` | The inventory is not running, references cannot be determined, or heyvm has no delete. |

### Namespaces and namespace plugins

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /namespaces` | View, narrows itself | `[{namespace, deployments, declared, description?, created_at?}]` for namespaces the caller can see. |
| `POST /namespaces` | CRUD, operator | Declare a namespace: `{"name": "team-a", "description": "..."}`. `201` if new, `200` if it existed. |
| `DELETE /namespaces/:name` | CRUD, operator | Undeclare it. `409` while it holds deployments. `204`. |
| `GET /onboarding?namespace=` | View, narrows itself | The dashboard's "Get started" data: deployment count, `can_mint`, MCP URL, token TTL cap, and a ready-to-post fastcar spec. `namespace` defaults to the caller's only namespace. |
| `GET /namespaces/:name/plugins` | View, namespace wall | Plugins this namespace may install, and whether it has. |
| `GET /namespaces/:name/plugins/:id` | View, namespace wall | One of those. |
| `PUT /namespaces/:name/plugins/:id` | CRUD, admin of the **whole** namespace | Install. Body `{"config": {}}` is optional. |
| `DELETE /namespaces/:name/plugins/:id` | CRUD, admin of the whole namespace | Uninstall. Allowed while the plugin is disabled. |
| `GET /namespaces/:name/plugins/:id/*` | View, namespace wall | The installed plugin's pages and reads. |
| `POST`/`PUT`/`PATCH`/`DELETE /namespaces/:name/plugins/:id/*` | CRUD, namespace wall | The installed plugin's actions. |

On Heyo's managed fleet, namespaces are created in Heyo cloud (`POST /namespaces` on cloud), not on app-lb.

`GET /namespaces/team-a/plugins` ([`namespace-plugins.json`](../app-lb/testdata/wire/namespace-plugins.json)):

```json
[
  {"id": "obs", "name": "Observability",
   "description": "Logs, metrics and alerts for every app in a namespace.",
   "enabled": true, "installed": true, "installed_at": 1760000000,
   "installed_by": "token:0123456789ab", "config": {}}
]
```

Install and uninstall return the same per-plugin object. "Admin of the whole namespace" means one of the following:

- the operator
- a fleet admin token
- a namespace token with `admin` scope and no `deployments` list (or `["*"]`)
- a federated `namespace:<ns>:admin` grant

A namespace token narrowed to particular deployments is refused with `403`.

Until the plugin is installed, the plugin surface answers `409` with `"code": "plugin_not_installed"`. While the operator has the plugin switched off, it answers `409` with `"code": "plugin_disabled"`. An unknown plugin id is `404`, and an invalid namespace name is `400`.

#### The obs plugin surface

`/namespaces/{ns}/plugins/obs/...` is app-obs narrowed to one namespace. app-lb forwards `api/...` to app-obs's `/ns/{ns}/api/...` with the plugin's service token. Your credential is never forwarded. Responses are app-obs's own, marked `Cache-Control: no-store`. They are described in [app-obs](app-obs.md#namespace-routes).

| Method and path (under `/namespaces/{ns}/plugins/obs`) | Tier | app-obs route |
| --- | --- | --- |
| `GET /ui` | View | `/ns/{ns}/`, the dashboard |
| `GET /api/fleet?window=` | View | `/ns/{ns}/api/fleet` |
| `GET /api/deployments/{id}?window=` | View | `/ns/{ns}/api/deployments/{id}` |
| `GET /api/deployments/{id}/logs?…` | View | `/ns/{ns}/api/deployments/{id}/logs` |
| `GET /api/alerts` | View | `/ns/{ns}/api/alerts` |
| `POST /api/alerts` | CRUD | `/ns/{ns}/api/alerts` |
| `DELETE /api/alerts/{id}` | CRUD | `/ns/{ns}/api/alerts/{id}` |

Log query parameters:

| Parameter | Meaning |
| --- | --- |
| `window` | Trailing window: `15m`, `1h`, `6h`, `24h`, `7d`, `30d`, or any duration such as `45m`. Clamped to 1 minute–90 days. Defaults to `24h`. |
| `from`, `to` | Epoch milliseconds, pinning the range instead of `window`. |
| `level` | Exact level, case-insensitive. |
| `backend` | Sandbox id or `host:port`. |
| `q` | Case-insensitive substring. |
| `limit` | Default 200, maximum 1000. |
| `before` | Epoch-ms page boundary, **inclusive**. Pass the previous page's `next_before_ms`, and drop lines you already have at that millisecond. |

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

`next_before_ms` is `null` on the last page. An alert body is `{"deployment", "threshold", "webhook_url", "metric"?}`. On this route `webhook_url` must be `https` on a public host. A deployment outside the namespace is the same `404` as one that does not exist.

Plugin-specific errors:

- `502` app-obs is unreachable, or rejected the configured token. This is not your credential's fault.
- `409 the obs plugin is not configured`
- `413` body over 64 KiB
- `404` a path other than `ui` or `api/...`

Through the managed door, these paths work only once cloud's allowlist includes them (see [Base URLs](#managed-the-heyo-cloud-namespace-door)).

#### Fleet plugins (operator)

Plugins are compiled into app-lb and switched on per host.

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /api/plugins` | View, operator | Every plugin: `{id, name, description, config_schema, per_namespace, installed_in?, enabled, config, updated_at, last_error?, status}`. |
| `GET /api/plugins/:id` | View, operator | One plugin. |
| `GET /api/plugins/:id/installs` | View, operator | `{plugin, enabled, namespaces[], installs{ns: {installed_at, installed_by, config}}}`. app-obs polls this. |
| `PUT /api/plugins/:id` | CRUD, operator | `{"enabled": true, "config": {...}}`. Invalid config is `400`. |
| `POST /api/plugins/:id/enable`, `POST /api/plugins/:id/disable` | CRUD, operator | Switch on or off with the stored config. |
| `GET /plugins` | View, operator | The plugin console (HTML). |

Each enabled plugin also serves its own routes under `/api/plugins/<id>/`, on the same two tiers. While the plugin is disabled they answer `409`.

| Plugin | View tier | CRUD tier |
| --- | --- | --- |
| `pgfc` | `GET /nodes`, `GET /nodes/:node/{health,host,config,databases,schemas,events}`, `GET /nodes/:node/schemas/:schema`, `GET /nodes/:node/logs/:which` | `POST /nodes/:node/schemas/:schema/:action`, `POST /nodes/:node/maintenance/:op`, `PUT /nodes/:node/config`, `POST /nodes/:node/databases`, `DELETE /nodes/:node/databases/:database`, `GET /nodes/:node/logs/schema/:schema` |
| `vapi` | `GET /gateways`, `GET /gateways/:gw/stats`, `GET /gateways/:gw/models` | `POST /gateways/:gw/chat/completions`, `POST /gateways/:gw/completions`, `POST /gateways/:gw/decisions`, `PUT /gateways/:gw/settings` |

These are fleet routes, so a confined caller gets `403`. Their bodies are those of the pg-fc and vapi APIs they front. See [pg-fc](pg-fc.md).

### Secrets

Secrets are write-only: no route returns a value. They are CRUD tier and walled by namespace. Per-id routes take `?namespace=`, which defaults to `default`. A confined caller must name one of its own namespaces.

| Method and path | Does |
| --- | --- |
| `POST /secrets` | Store `{"id", "namespace"?, "description"?, "data": {"key": "value"}}`. `201` if new, `200` if replaced. |
| `GET /secrets` | Summaries the caller can reach. `?namespace=` narrows the list. |
| `GET /secrets/:id` | One summary. |
| `PUT /secrets/:id` | Replace. The path id wins over the body's, and `?namespace=` wins over the body's namespace. |
| `PATCH /secrets/:id` | `{"data": {"key": "new value", "old_key": null}, "description"?}`. `null` removes a key. |
| `DELETE /secrets/:id` | `409` while a deployment in the namespace references it, unless `?force=true`. `204`. |

```json
{"id": "github", "namespace": "default", "description": "PAT for private repos",
 "keys": ["token", "username"], "updated_at": 1722400000, "encrypted_at_rest": true}
```

A view-only federated namespace may read summaries but gets `403` on writes. Deployments reference secrets as `{"secret": "<id>", "key": "token"}`, always in their own namespace. See [secret references](app-lb.md#secret-references).

### App-tokens

App-tokens are CRUD tier. Only `sha256(secret)` is stored, and the secret appears once, in the mint response.

| Method and path | Does |
| --- | --- |
| `POST /tokens` | Mint. `201`. |
| `GET /tokens` | List the visible tokens. Expired tokens are swept first. Never shows a secret. |
| `GET /tokens/:id` | One summary. |
| `PATCH /tokens/:id` | Re-scope, rename or change expiry. The secret does not change. |
| `DELETE /tokens/:id` | Revoke. Takes effect on the next request. `204`. |

Mint body:

| Field | Default | Meaning |
| --- | --- | --- |
| `name` | required | What it is for. |
| `admin` | `none` | `none`, `view` or `admin`. |
| `deployments` | `[]` | Ids, or `["*"]` for all, present and future. |
| `namespace` | unset | Confine to one namespace. With an empty `deployments`, it reaches everything there. |
| `expires_in_secs` | never | Lifetime. |
| `fleet` | `false` | Control-plane only: a token mirrored to every gateway. `409` on an app-lb with no gateways configured. |

```sh
curl -s -XPOST $LB/tokens -H "Authorization: Bearer $NS_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"name": "ci", "admin": "admin", "namespace": "team-a", "expires_in_secs": 86400}'
```

```json
{"id": "7f3a9c2b1e4d", "name": "ci", "admin": "admin", "namespace": "team-a", "deployments": [],
 "created_at": 1722400000, "expires_at": 1722486400, "minted_by": "token:b2c3d4e5f6a1",
 "token": "applb_7f3a9c2b1e4d_…"}
```

A summary (from list, get or patch) is the same object without `token`. It may also carry `last_used_at`, `fleet`, and `mirrored_from`. A mirrored fleet token cannot be changed here: `PATCH`/`DELETE` answer `409`, naming the authority that owns it.

`PATCH` body fields are all optional: `name`, `admin`, `namespace` (`null` lifts the wall), `deployments`, and `expires_at` (absolute Unix seconds, `null` for never).

#### Confinement rules for minting

A confined caller may use the token routes only if it administers a whole namespace. That means a namespace token with `admin` scope and no `deployments` list, or a `namespace:<ns>:admin` grant. The handler then enforces the following:

- **Mint.** `namespace` is required and must be one you administer (otherwise `403`). `expires_in_secs` defaults to, and may not exceed, `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` (90 days by default; `400` past it). The new token records `minted_by`.
- **List, get and revoke** see only tokens confined to your namespaces. Any other id is `404 no token "<id>"`, the same as one that does not exist.
- **Patch** cannot move a token to another namespace (`403`), lift its wall (`namespace: null`, `403`), clear its expiry (`expires_at: null`, `403`), or push the expiry past the cap (`400`).

A deployment-scoped namespace token or a `view` caller cannot mint, because the minted token would reach past its own scope.

### Auth providers

Auth providers are named identity configurations that deployment gates inherit. The field reference and presets are in [app-lb-auth](app-lb-auth.md#auth-providers).

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /auth-providers[?namespace=]` | View, narrows itself | Providers in the caller's namespaces. |
| `POST /auth-providers` | CRUD, namespace admin | Upsert. `201` if new, `200` if replaced. |
| `GET /auth-providers/:namespace/:name` | CRUD | One provider. Secrets appear as references. |
| `DELETE /auth-providers/:namespace/:name` | CRUD | `409` while a deployment inherits it. |

### Feeds

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /feeds` | View, operator | `[{"namespace": "team-a", "events": 12}]`. |
| `GET /feeds/:namespace` (or `:namespace.xml`) | View, namespace wall | The namespace's lifecycle and issue feed as RSS. `?format=json` returns the events instead. |

A feed event:

```json
{"id": 7, "ts": 1722400000, "last_ts": 1722400120, "count": 3, "namespace": "team-a",
 "deployment": "web", "kind": "issue", "title": "web: cold start timed out",
 "detail": "a request waited 120s and no VM became available"}
```

### Metrics, security and ingress

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /metrics` | View, narrows itself | JSON metrics snapshot. This is not Prometheus text. |
| `GET /security` | View, narrows itself | Security alerts, block rules and hit history. |
| `GET /ingress` | View | `{"ipv4": [...], "ipv6": [...]}` from `APP_LB_PUBLIC_IPS`: the addresses to point DNS at. |
| `POST /security/rules` | CRUD, operator | Create a block or allow rule. `201`. |
| `PATCH /security/rules/:id` | CRUD, operator | `{"expires_in_secs": N \| null}`. `null` makes the rule permanent. |
| `DELETE /security/rules/:id` | CRUD, operator | Remove the rule. `204`. |

`GET /metrics` query parameters. Filters narrow `deployments` only. `host`, `fleet` and `global` always describe everything the caller can see.

| Query | Effect |
| --- | --- |
| `deployment=<id>` | One deployment. |
| `prefix=<s>` | Ids starting with `s`. |
| `namespace=<ns>` | One namespace. |
| `summary=true` | Drop per-VM rows and host sandboxes. |
| `limit=`, `offset=` | Page through `deployments`. |

The keys are described under [Metrics](app-lb.md#metrics). The response begins:

```json
{"generated_at": 1722400000, "uptime_secs": 86400,
 "host": {"available": true, "cpu_count": 8, "cpu_percent": 23.5, ...},
 "fleet": {"deployments": 3, "ready": 4, "draining": 1, "pending": 1, "total_in_flight": 7},
 "global": {"requests": {"total": 7, "c2xx": 3, ...}, "latency_ms": {...}},
 "deployments": [ ... ]}
```

`GET /security` takes `?severity=&rule=&deployment=&namespace=&limit=`. A rule body is as follows. At least one `match` field is required. `client` takes an address or CIDR.

```json
{"action": "block", "match": {"client": "203.0.113.0/24", "host": null, "deployment": null,
 "path_prefix": null, "path_contains": null, "method": null, "user_agent_contains": null},
 "expires_in_secs": 3600, "note": "scanner"}
```

`action` is `block` (the default) or `allow`. An allow always wins over a block.

### Disks, certificates, workflows (operator)

All of these routes are fleet-wide.

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /disks` | View | Per-sandbox disk inventory, totals and archive progress ([`disks.json`](../app-lb/testdata/wire/disks.json)). `503` when disk management is off. |
| `PATCH /disks/:id` | CRUD | `{"retain": true, "note": "..."}`. Pin or unpin a disk. `204`. |
| `DELETE /disks/:id` | CRUD | Reclaim one disk now (`?force=1` overrides retention, never a running sandbox). There is no undo. |
| `POST /disks/:id/archive` | CRUD | Stream to S3. `{"purge": true}` reclaims the disk after a successful upload. `202`. `501` without a bucket. |
| `POST /disks/sweep` | CRUD | Run one retention sweep now. |
| `POST /disks/purge-orphans` | CRUD | Reclaim every disk the daemon has no record of. |
| `GET /certs` | CRUD | Issued certificates: `[{host, not_after, issuer, needs_renewal}]`. |
| `POST /workflows`, `GET /workflows` | CRUD | CI workflow objects that [ci](ci.md) polls. `GET` returns `{"workflows": [...]}`. |
| `GET /workflows/:id`, `PUT /workflows/:id`, `DELETE /workflows/:id` | CRUD | One workflow. |

### Fleet views, control plane and releases (operator)

These routes are always authenticated and refuse an ungated listener. They observe other app-lbs. They are not placement authority.

| Method and path | Tier | Does |
| --- | --- | --- |
| `GET /fleet` | Fleet view | `{configured, gateways: [...]}`, one observation per configured gateway. |
| `GET /fleet/deployments[?namespace=]` | Fleet view | Namespace-by-deployment rollup across gateways. A confined caller must pass its own namespace. |
| `GET /fleet/gateways/:id/metrics[?namespace=&offset=]` | Fleet view | One gateway's metrics page, through this origin. |
| `GET /fleet/network` | Fleet view | Cross-gateway topology. |
| `GET /fleet/tokens` | Fleet view, operator | The fleet-token export that gateways mirror. `409` on a non-authority. |
| `GET /services[?after=]` | Fleet view, operator | Orchestrator services from the configured control plane. |
| `GET /control-plane/config`, `PUT /control-plane/config` | CRUD, fleet admin | `{"expected_revision": N, "config": {"gateways": [...], "control_plane": [...]}}`. Read-only when `APP_LB_FLEET_FILE`/`APP_LB_CONTROL_PLANE_FILE` are set. |
| `GET /releases`, `GET /api/releases/:resource`, `POST /api/releases/:resource` | CRUD, always authenticated | Release console transport to ci. `GET` accepts the resources `releases`, `release-builds` and `release-environments`. `POST` accepts `release-builds`, `release-promotions` and `release-automation`. |

See [multi-region](multi-region.md) and [discovery and regions](app-lb.md#discovery-and-regions).

### Pages and sign-in

These routes return HTML for browsers, not data. They are listed so the route inventory is complete.

| Method and path | Tier | Returns |
| --- | --- | --- |
| `GET /` | View | Directory of routable URLs. |
| `GET /dashboard` | View | Live dashboard (`?namespace=`, `?view=local`). |
| `GET /siem`, `GET /storage`, `GET /network`, `GET /plugins` | View | Consoles. |
| `GET /login`, `POST /login` | Open | Operator sign-in (federated mode). |
| `POST /login/handoff` | Open | A namespace token from the Heyo front end becomes a session cookie. |
| `POST /logout` | Open | Clears the session. |
| `GET /__ui/*path` | Open | Stylesheet, theme script and fonts. |
| `GET /healthz` | Open | `ok`, with an `x-heyo-revision` header. |

## Walkthrough: a VM with a namespace token

This walkthrough boots an Alpine microVM from the public hub image, runs commands in it, gives it a public route, reads its logs, and deletes it. Each call is plain curl with a token confined to `team-a`. The steps mirror [`app-lb/heyctl/tests/e2e_live.rs`](../app-lb/heyctl/tests/e2e_live.rs).

```sh
LB=https://admin.us5.heyo.work          # or https://server.heyo.computer/namespaces/team-a/lb
AUTH="Authorization: Bearer $TOKEN"     # applb_… namespace admin token, or heyo_api_… through the door
JSON='content-type: application/json'
```

**1. Check the credential.**

```sh
curl -s -H "$AUTH" $LB/whoami | jq '{caller, admin_scope, confined, namespace}'
```

You need `admin_scope: "admin"` and your namespace.

**2. Register the deployment, with no VMs yet.**

`heyo/alpine:3.24` on `https://hub.heyo.work` is public, so `artifact` needs no `auth`. The image runs only sshd, so readiness is a bare TCP check on port 22 (`"path": null`). `min_replicas` stays `0` until the image is pulled.

```sh
curl -s -XPOST $LB/deployments -H "$AUTH" -H "$JSON" -H 'If-None-Match: *' -d '{
  "id": "demo-alpine",
  "namespace": "team-a",
  "routes": [],
  "vm": {"driver": "firecracker", "port": 8080, "size_class": "small"},
  "artifact": {"store": "https://hub.heyo.work", "ref": "heyo/alpine:3.24"},
  "health": {"path": null, "port": 22},
  "scaling": {"min_replicas": 0, "max_replicas": 1, "warm_pool": 0,
              "boot_timeout_secs": 180, "scale_to_zero_after_secs": 900}
}' | jq '{id: .spec.id, kind, desired_replicas}'
```

The response is `201` with the deployment status. With `"routes": []` the deployment is private: it can be reached only through `exec` and `shell`.

**3. Pull the image and wait for the job.**

```sh
JOB=$(curl -s -XPOST $LB/deployments/demo-alpine/pull -H "$AUTH" -H "$JSON" -d '{}' | jq -r .id)
until curl -s -H "$AUTH" $LB/deployments/demo-alpine/jobs \
      | jq -e --arg j "$JOB" '.[] | select(.id == $j and .status != "running")' >/dev/null; do
  sleep 2
done
curl -s -H "$AUTH" $LB/deployments/demo-alpine/jobs | jq --arg j "$JOB" '.[] | select(.id == $j) | {status, error, digest}'
```

You need `status: "succeeded"`. If the `POST` answered `409 ... already running`, a pull is already in flight: take its `id` from the job list and wait on that one. The successful pull wrote `vm.image` into the spec (`img-<digest16>`).

**4. Scale to one VM and wait for it to be healthy.**

```sh
curl -s -XPATCH $LB/deployments/demo-alpine/scaling -H "$AUTH" -H "$JSON" -d '{"min_replicas": 1}' >/dev/null
until curl -s -H "$AUTH" $LB/deployments/demo-alpine | jq -e '
  .pending == 0 and ([.vms[] | select(.healthy and (.draining | not))] | length) >= .desired_replicas
  and .desired_replicas > 0' >/dev/null; do
  sleep 2
done
```

**5. Run commands.**

```sh
curl -s -XPOST $LB/deployments/demo-alpine/exec -H "$AUTH" -H "$JSON" \
  -d '{"command": "cat /etc/alpine-release && uname -s"}' | jq '{sandbox_id, exit_code, stdout}'
```

Start a tiny web server on port 8080 using busybox `nc`. The page and the handler script go in as environment variables, so nothing needs shell-escaping twice:

```sh
curl -s -XPOST $LB/deployments/demo-alpine/exec -H "$AUTH" -H "$JSON" -d @- <<'EOF' | jq .stdout
{
  "command": "mkdir -p /srv/heyo && printf '%s' \"$SERVE\" > /srv/heyo/serve.sh && chmod +x /srv/heyo/serve.sh && printf '%s' \"$HTML\" > /srv/heyo/index.html && (setsid nohup nc -lk -p 8080 -e /srv/heyo/serve.sh </dev/null >/dev/null 2>&1 &) && sleep 1 && curl -s http://127.0.0.1:8080/",
  "env": {
    "HTML": "<!doctype html><title>Heyo</title><h1>Heyo World</h1>",
    "SERVE": "#!/bin/sh\nwhile IFS= read -r line; do line=$(printf '%s' \"$line\" | tr -d '\\r'); [ -z \"$line\" ] && break; done\nbody=$(cat /srv/heyo/index.html)\nprintf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n%s' \"${#body}\" \"$body\"\n"
  },
  "timeout_secs": 20
}
EOF
```

**6. Add a route by editing the live spec.**

Do not re-send the spec from step 2. Take the live spec from `GET`, change `routes`, and `PUT` it back with the `ETag`. The pull filled in `vm.image`. A spec without that value has a different `vm` block, and any change to `vm` recycles the pool, which would kill the server you just started. A route-only edit keeps the running VM.

```sh
curl -s -D /tmp/h -H "$AUTH" $LB/deployments/demo-alpine | jq '.spec | .routes = [{"host": "demo-alpine.us5.heyo.work"}]' > /tmp/spec.json
ETAG=$(grep -i '^etag:' /tmp/h | cut -d' ' -f2 | tr -d '\r')
curl -s -XPUT $LB/deployments/demo-alpine -H "$AUTH" -H "$JSON" -H "If-Match: $ETAG" \
  -d @/tmp/spec.json | jq '{routes: .spec.routes, vms: [.vms[].sandbox_id]}'
curl -s https://demo-alpine.us5.heyo.work/     # once the certificate is issued, typically seconds
```

The `sandbox_id` should be the same one as before. A `412` means the spec changed after your `GET`. Fetch it again and retry. If the fleet has a base domain, you can instead add a path-only route (`[{"path_prefix": "/"}]`), and app-lb adds `<id>.<base>` for you.

**7. Read logs through the obs plugin.**

Install the plugin once per namespace. This needs an admin credential for the whole namespace.

```sh
curl -s -XPUT $LB/namespaces/team-a/plugins/obs -H "$AUTH" -H "$JSON" -d '{}' | jq '{installed, enabled}'
curl -s -H "$AUTH" "$LB/namespaces/team-a/plugins/obs/api/deployments/demo-alpine/logs?window=15m&limit=50" \
  | jq '.rows[] | [.ts, .level, .message] | @tsv' -r
```

Page backwards by passing `before=<next_before_ms>`. A `409` with `"code": "plugin_disabled"` means the operator has not enabled obs on this host. Nothing is collected before the install, so logs start from that point. Through the managed door, these paths 404 until cloud allowlists them.

**8. Delete.**

```sh
curl -s -o /dev/null -w '%{http_code}\n' -XDELETE $LB/deployments/demo-alpine -H "$AUTH"   # 204
```

The VM is drained and destroyed, and the route is released. The pulled image stays in the catalog until the offload pacer finds it idle.
