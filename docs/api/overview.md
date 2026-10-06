# app-lb API reference

These pages document every app-lb admin endpoint that the [`hws`](../../app-lb/heyctl) Rust crate calls, one resource per page, with the request each endpoint takes, the response it returns, the errors it answers with, and the crate method that wraps it.

[HTTP API](../http-api.md) is the companion page. It covers base URLs, the managed namespace door, credentials, tiers and confinement in depth, and lists routes the crate does not call (retirement, route handoffs, disk mutations, fleet views, security rules, releases). These pages stay with the crate's surface and go one level deeper on each endpoint.

## Pages

| Page | Endpoints |
| --- | --- |
| [Identity and health](identity.md) | `/healthz`, `/whoami`, gate probing |
| [Deployments](deployments.md) | `/deployments`, scaling, VM eviction, upstream drain, rollouts, discovery status |
| [Exec and shell](exec-shell.md) | `/deployments/:id/exec`, `/deployments/:id/shell` |
| [Jobs](jobs.md) | build, pull, mount pull, host update, `/jobs` |
| [Images](images.md) | `/images` |
| [Metrics and host](metrics.md) | `/metrics`, `/certs`, `/disks`, `/fleet/deployments` |
| [Namespaces and plugins](namespaces.md) | `/namespaces`, namespace plugins, `/api/plugins`, `/feeds` |
| [Observability](obs.md) | `/namespaces/:ns/plugins/obs/api/*` |
| [Secrets](secrets.md) | `/secrets` |
| [App-tokens](tokens.md) | `/tokens` |
| [Auth providers](auth-providers.md) | `/auth-providers` |
| [Workflows](workflows.md) | `/workflows` |

## The client

```toml
[dependencies]
hws = { version = "0.2", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The default feature set is `cli`, which links everything `heyctl` needs. A library consumer turns it off and picks what it uses:

| Feature | Adds |
| --- | --- |
| `blocking` | `hws::blocking::Client`, the same surface without `async`. |
| `config-file` | Contexts and credentials from `~/.config/heyctl`, as `heyctl` uses them. |
| `artifact` | A client for an artifact store (`art serve`). That is a different service with its own API, documented in [Artifacts](../artifacts.md), not here. |
| `test-util` | A scripted `Transport` for testing what your program does when app-lb refuses it. |

```rust
use hws::{Client, ExecRequest};

let lb = Client::builder("https://admin.us5.heyo.work")
    .token(std::env::var("APP_LB_TOKEN")?)
    .build()?;

let out = lb.exec("demo", &ExecRequest::new("uname -a")).await?;
println!("{} (exit {})", out.stdout, out.exit_code);
```

`Client::builder(server)` accepts a URL or a bare `host:port`, which becomes `http://host:port`. Trailing slashes are dropped. Through the managed door, the server is `https://server.heyo.computer/namespaces/{ns}/lb` and the token is a `heyo_api_…` key.

| Builder method | Effect |
| --- | --- |
| `.token(t)` | `Authorization: Bearer <t>`. An app-token (`applb_…`) or, through the door or a federated app-lb, a Heyo key. |
| `.basic(user, password)` | `Authorization: Basic …`, the operator credential. app-lb compares the header byte for byte, so the crate always sends standard padded base64. |
| `.timeout(d)` | Per-request deadline. Default 30 seconds. `exec` computes its own. |
| `.insecure(true)` | Skip TLS verification, for a self-signed admin listener behind a tunnel. |

`Client` is cheap to clone. `Client::with_transport` builds one over any `Transport` (a stub, a recorder, a proxy); a client built that way cannot open shells.

## Wire conventions

The crate follows these rules on every request. A client in another language should follow them too.

- **Path segments are percent-encoded.** Everything except `A–Z a–z 0–9 - _ . ~` is escaped, so an id containing `/` or `?` cannot address a different route. A static upstream such as `us1.internal:8080` goes out as `us1.internal%3A8080`.
- **Bodies are JSON with `Content-Type: application/json`.** The job routes (`build`, `pull`, `mounts/pull`, `update`) get `{}` even when there is nothing to say. app-lb reads those bodies as optional, and a body with no content type is silently treated as absent rather than rejected, so a `ref` sent without the header would be lost.
- **Query booleans are `true` or `false`.** app-lb parses them strictly: `?force=1` is a `400`, not a truthy value.
- **Reads are typed, writes are `serde_json::Value`.** `PUT /deployments/:id` replaces the whole spec. A client that parsed a spec into a struct and wrote it back would drop every field it did not know. The write methods take a `Value` and send it verbatim. To edit, read the raw spec, change it, and send it back (see [Replace a deployment](deployments.md#replace-a-deployment)).
- **Read types are lenient.** Every field defaults, and fields this build does not name land in an `extra` map instead of being discarded. The crate's tests read app-lb's own response fixtures ([`app-lb/testdata/wire/`](../../app-lb/testdata/wire)) and fail if `extra` is not empty, so a field the crate stops understanding fails a test.
- **`Client::raw()` returns responses as unparsed JSON.** Use it to print a response or to read the half of a read-modify-write. Each page lists the `Raw` method next to the typed one where there is one.

## Errors

app-lb answers a failure with `{"error": "…"}` from its handlers, or with plain text from the gate (`401`) and the framework (`400` malformed JSON, `415` missing content type, `422` wrong shape, `413` too large). The crate tries the envelope, falls back to the text, and maps the status to a variant of `hws::Error`:

| Status | `hws::Error` | Notes |
| --- | --- | --- |
| `401` | `Unauthorized { presented }` | Missing, wrong, revoked or expired. app-lb does not say which. `presented` records what was sent (`None`, `Basic`, `Token`). |
| `403` | `Forbidden { message }` | The credential is valid but out of tier or scope. The message names what is missing. |
| `404` with `no …` or no body | `NotFound { kind, name }` | A handler saying the named thing does not exist. |
| `404` with any other body | `Malformed { status, body }` | A router 404, such as `route not exposed through the namespace proxy` at the managed door. |
| `409` containing `no running VM` | `NoRunningVm { deployment }` | `exec` or `shell` with `wake: false`. Retry with `wake`. |
| `409` otherwise | `Conflict { message }` | A job already running, a secret still referenced, a plugin not installed, and the rest. |
| `502` | `Upstream { message }` | The daemon, app-obs or a remote store failed. For `exec`, includes app-lb's own call timing out while the command keeps running. |
| `503` | `ColdStartTimeout { deployment }` | Mapped this way on every route. On `exec` and `shell` it means no VM became ready within `cold_start_timeout_secs`; elsewhere it means app-lb could not do the work right now (see each page). |
| `400`, `415`, `422` without an envelope | `Malformed { status, body }` | The request was rejected before a handler saw it. |
| any other status with an envelope | `Api { status, message }` | Most `400`s, `412`, `428`, `500`. |

Errors raised without a response: `Transport` (no answer), `Decode` (a `2xx` whose body did not parse), `Shell` (the WebSocket failed), `Timeout` (a `wait_for_*` helper gave up) and `Invalid` (bad input caught before sending, such as a blank `exec` command or an unnamed token).

`Error::is_retryable()` is true for `ColdStartTimeout`, `Upstream` and `Transport` only. A `409` is not retryable: the job that is running will still be running. `Error::is_auth()` is true for `401` and `403`. `Error::status()` returns the HTTP status where there was one.

## Waiting

Builds, pulls and spec changes return before the work is done. Two helpers poll for you:

| Helper | Polls | Done when | Default timeout |
| --- | --- | --- | --- |
| `client.wait_for_job(job_id)` | `GET /jobs/:id`, or `GET /deployments/:id/jobs` with `.in_deployment(id)` | `status` is not `running`. A failed job is returned, not raised. | 30 minutes |
| `client.wait_for_ready(id)` | `GET /deployments/:id` | `pending == 0`, healthy and non-draining VMs ≥ `desired_replicas`, nothing draining. Static deployments and sites return at once. | 5 minutes |

Polling starts at 100 ms and doubles up to 3 seconds for jobs and 2 seconds for pools. `.poll_every(d)` fixes the interval, `.timeout(d)` changes the deadline, and `.on_progress(f)` gets each poll (for jobs, only the log lines that are new since the last call). Both builders can be awaited directly.

```rust
let job = lb.start_pull("demo", None, false).await?;
let done = lb.wait_for_job(&job.id)
    .in_deployment(&job.deployment)
    .on_progress(|p| for line in p.new_log { println!("{line}") })
    .await?;
if done.status != "succeeded" {
    eprintln!("pull failed: {:?}", done.error);
}
lb.wait_for_ready("demo").await?;
```

Use `.in_deployment` with a namespace token: app-lb releases before confined access to `GET /jobs/:id` refuse it that route, but always allow the deployment's job list.

## Endpoint index

| Method and path | `hws` method | Page |
| --- | --- | --- |
| `GET /healthz` | `healthz` | [Identity](identity.md#health) |
| `GET /whoami` | `whoami` | [Identity](identity.md#who-am-i) |
| `GET /deployments` | `deployments`, `raw().deployments`, `raw().deployments_in` | [Deployments](deployments.md#list-deployments) |
| `POST /deployments` | `create_deployment` | [Deployments](deployments.md#create-a-deployment) |
| `GET /deployments/:id` | `deployment`, `deployment_exists`, `deployment_with_timeout`, `raw().spec` | [Deployments](deployments.md#get-a-deployment) |
| `PUT /deployments/:id` | `replace_deployment` | [Deployments](deployments.md#replace-a-deployment) |
| `DELETE /deployments/:id` | `delete_deployment` | [Deployments](deployments.md#delete-a-deployment) |
| `PATCH /deployments/:id/scaling` | `patch_scaling` | [Deployments](deployments.md#change-scaling) |
| `DELETE /deployments/:id/vms/:sandbox_id` | `evict_vm` | [Deployments](deployments.md#evict-a-vm) |
| `PUT /deployments/:id/upstreams/:upstream/drain` | `cordon_upstream` | [Deployments](deployments.md#drain-a-static-upstream) |
| `DELETE /deployments/:id/upstreams/:upstream/drain` | `uncordon_upstream` | [Deployments](deployments.md#drain-a-static-upstream) |
| `POST /deployments/:id/rollouts` | `start_rollout` | [Deployments](deployments.md#rollouts) |
| `GET /deployments/:id/rollouts/:operation` | `rollout` | [Deployments](deployments.md#rollouts) |
| `GET /deployments/:id/discovery-status` | `discovery_status` | [Deployments](deployments.md#discovery-status) |
| `POST /deployments/:id/exec` | `exec` | [Exec and shell](exec-shell.md#exec) |
| `GET /deployments/:id/shell` | `shell` | [Exec and shell](exec-shell.md#shell) |
| `POST /deployments/:id/build` | `start_build` | [Jobs](jobs.md#start-a-build) |
| `POST /deployments/:id/pull` | `start_pull` | [Jobs](jobs.md#start-a-pull) |
| `POST /deployments/:id/mounts/pull` | `start_mount_pull` | [Jobs](jobs.md#start-a-mount-pull) |
| `POST /deployments/:id/update` | `start_update` | [Jobs](jobs.md#start-a-host-update) |
| `GET /deployments/:id/jobs` | `deployment_jobs` | [Jobs](jobs.md#read-jobs) |
| `GET /jobs`, `GET /jobs/:job_id` | `jobs`, `job` | [Jobs](jobs.md#read-jobs) |
| `GET /images` | `images` | [Images](images.md#list-images) |
| `POST /images/sweep` | `sweep_images` | [Images](images.md#run-an-offload-pass) |
| `POST /images/:name/offload` | `offload_image` | [Images](images.md#offload-an-image) |
| `PATCH /images/:name` | `pin_image` | [Images](images.md#pin-an-image) |
| `DELETE /images/:name` | `delete_image` | [Images](images.md#delete-an-image) |
| `GET /metrics` | `metrics` | [Metrics](metrics.md#metrics) |
| `GET /certs` | `certs` | [Metrics](metrics.md#certificates) |
| `GET /disks` | `disks` | [Metrics](metrics.md#disks) |
| `GET /fleet/deployments` | `raw().fleet_deployments` | [Metrics](metrics.md#fleet-deployments) |
| `GET /namespaces`, `POST /namespaces`, `DELETE /namespaces/:name` | `namespaces`, `create_namespace`, `delete_namespace` | [Namespaces](namespaces.md#namespaces) |
| `GET /namespaces/:ns/plugins` | `namespace_plugins` | [Namespaces](namespaces.md#namespace-plugins) |
| `PUT`, `DELETE /namespaces/:ns/plugins/:id` | `install_plugin`, `uninstall_plugin` | [Namespaces](namespaces.md#namespace-plugins) |
| `GET /api/plugins`, `GET`/`PUT /api/plugins/:id`, `GET /api/plugins/:id/installs` | `plugins`, `plugin`, `set_plugin`, `plugin_installs` | [Namespaces](namespaces.md#fleet-plugins) |
| `GET /feeds`, `GET /feeds/:namespace` | `feeds`, `feed_events`, `feed_rss` | [Namespaces](namespaces.md#feeds) |
| `GET /namespaces/:ns/plugins/obs/api/fleet` | `obs(ns).fleet` | [Observability](obs.md#namespace-overview) |
| `GET …/obs/api/deployments/:id` | `obs(ns).deployment` | [Observability](obs.md#one-deployment) |
| `GET …/obs/api/deployments/:id/logs` | `obs(ns).logs` | [Observability](obs.md#logs) |
| `GET`, `POST …/obs/api/alerts`, `DELETE …/obs/api/alerts/:id` | `obs(ns).alerts`, `create_alert`, `delete_alert` | [Observability](obs.md#alerts) |
| `GET /secrets`, `POST /secrets` | `secrets`, `secrets_in`, `put_secret` | [Secrets](secrets.md) |
| `GET`, `PATCH`, `DELETE /secrets/:id` | `secret_in`, `secret_exists_in`, `patch_secret_in`, `delete_secret_in` | [Secrets](secrets.md) |
| `POST /tokens`, `GET /tokens` | `mint_token`, `tokens` | [App-tokens](tokens.md) |
| `GET`, `PATCH`, `DELETE /tokens/:id` | `token`, `patch_token`, `revoke_token` | [App-tokens](tokens.md) |
| `GET /auth-providers`, `POST /auth-providers` | `auth_providers`, `create_auth_provider` | [Auth providers](auth-providers.md) |
| `GET`, `DELETE /auth-providers/:namespace/:name` | `auth_provider`, `auth_provider_exists`, `delete_auth_provider` | [Auth providers](auth-providers.md) |
| `GET /workflows`, `POST /workflows` | `workflows`, `create_workflow` | [Workflows](workflows.md) |
| `GET`, `PUT`, `DELETE /workflows/:id` | `workflow`, `replace_workflow`, `delete_workflow` | [Workflows](workflows.md) |

Tiers in these pages use the names from [HTTP API: Tiers](../http-api.md#tiers): **View**, **CRUD**, and **operator** for routes that need an unconfined credential.
