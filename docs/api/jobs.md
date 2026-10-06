# Jobs

Jobs are app-lb's background work on a deployment: building an image, pulling one from an artifact store, unpacking guest mounts, and running a static deployment's update commands on the host.

Back to the [API reference](overview.md).

Each start route answers `202` with a **job record** right away. Poll the record until `status` is no longer `running`, or use `Client::wait_for_job` (see [Waiting](overview.md#waiting)). All routes on this page are CRUD tier, and a namespace caller may use them on its own deployments, except `GET /jobs`, which is fleet-wide.

## The job record

`JobRecord`. A pull, from [`job-pull.json`](../../app-lb/testdata/wire/job-pull.json):

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

Fields every kind carries:

| Field | Meaning |
| --- | --- |
| `id` | Job id. |
| `deployment` | The deployment it runs for. |
| `kind` | `image-build`, `artifact-pull`, `mount-pull` or `host-update`. |
| `status` | `running`, `succeeded` or `failed`. |
| `started_at`, `finished_at` | Unix seconds. `finished_at` is absent while running. |
| `rolled_out` | The pool was moved onto the result. |
| `error` | Why it failed, or `null`. |
| `log` | The last 400 output lines. The full output goes to app-obs as `source=job`. |

Fields by kind. Fields that do not apply to a kind are left out, not set to `null`.

| Kind | Fields |
| --- | --- |
| `image-build` | `repo`, `ref`, `commit`, `dockerfile`, `image` |
| `artifact-pull` | `store`, `artifact` (the tag or digest asked for), `digest` (what it resolved to), `bytes` (transferred), `reused` (already on the host), and for a site bundle `site_root` and `files` |
| `mount-pull` | `mounts[]`: `{path, store, ref, digest, tree, files, bytes, unpacked, reused, changed}` per guest mount. `changed` is what recycles the pool. |
| `host-update` | `working_dir`, `commands_total`, `commands_run`, `verified` |

`bytes: 0` with `reused: true` is a skipped fetch. `bytes: 0` without `reused` is a local store hardlinking the blob instead of copying it.

Job history is held in memory and bounded: 20 per deployment and 2000 overall. A job that aged out answers `404`, the same as one that never existed.

## Start a build

`POST /deployments/:id/build`

**Crate:** `Client::start_build(id, git_ref: Option<&str>) -> JobRecord` · `Raw::start_build`

Builds the image described by the spec's `build` block and rolls the pool onto it. The body is `{"ref": "…"}`, which overrides the spec's ref for this build only: a branch, tag or commit for a git build, or a store tag or digest when the recipe comes from an artifact store. With no ref, the crate sends `{}`.

## Start a pull

`POST /deployments/:id/pull`

**Crate:** `Client::start_pull(id, artifact_ref: Option<&str>, force: bool) -> JobRecord` · `Raw::start_pull`

Pulls the image (or site bundle) named by the spec's `artifact` block, writes it into `vm.image` (or the site's root), and rolls the pool onto it. The body is:

| Field | Default | Meaning |
| --- | --- | --- |
| `ref` | the spec's | A tag or a 64-hex digest, for this pull only. |
| `force` | `false` | Fetch even when the digest is already on the host. |
| `operation_id` | none | Makes the pull idempotent. `ref` must then be a pinned digest. Not sent by the crate. |

With no `artifact.image_name`, the image is named by its content, `img-<first 16 hex of digest>`, and every deployment that pulls the same bytes shares it. A deployment whose image is missing also gets a pull started automatically the first time the autoscaler wants a VM. If your start answers `409 already running`, follow that job instead.

## Start a mount pull

`POST /deployments/:id/mounts/pull`

**Crate:** `Client::start_mount_pull(id, force) -> JobRecord` · `Raw::start_mount_pull`

Unpacks every `vm.mounts[]` entry from its artifact store and rolls the pool onto the new trees. The body is `{"force": false}`. One job covers every mount, so there is no `ref` override. A mount pull also starts by itself when a deployment is registered or edited with a mount that is not on the host. Until each mount has a `digest`, the autoscaler boots no guests.

## Start a host update

`POST /deployments/:id/update`

**Crate:** `Client::start_update(id) -> JobRecord` · `Raw::start_update`

Runs the spec's `update.commands` on the app-lb host, in `update.working_dir`, for a static deployment or site. The crate sends `{}`.

## Start errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | The spec has no `build`, `artifact`, `vm.mounts` or `update` block for this kind, or the ref is not valid for the source. |
| `404` | `NotFound` | No such deployment. |
| `409` | `Conflict` | A job is already running for this deployment (`a job for deployment "<id>" is already running`), a rollout reserves it, or an `operation_id` was reused with a different body. |
| `503` | `ColdStartTimeout` | The operation could not be recorded durably. Retry. |

Jobs are not idempotent. A second start while one is running is a `409`; read the deployment's jobs and follow the running one.

## Read jobs

| Method and path | Crate | Returns |
| --- | --- | --- |
| `GET /deployments/:id/jobs` | `Client::deployment_jobs(id)`, `Raw::deployment_jobs(id)` | This deployment's jobs, newest first. |
| `GET /jobs/:job_id` | `Client::job(job_id)`, `Raw::job(job_id)` | One job. A confined caller gets `404` for a job on a deployment it cannot reach. |
| `GET /jobs` | `Client::jobs()`, `Raw::jobs()` | Every job. Operator only. |

A namespace token can always read `GET /deployments/:id/jobs`. app-lb releases before confined access to `GET /jobs/:job_id` refuse it that route, which is why `wait_for_job(…).in_deployment(id)` exists.

```rust
let job = lb.start_build("api", Some("v2.3.1")).await?;
let done = lb.wait_for_job(&job.id).in_deployment("api").await?;
match done.status.as_str() {
    "succeeded" => println!("built {:?} at {:?}", done.image, done.commit),
    _ => eprintln!("{}\n{:?}", done.log.join("\n"), done.error),
}
```
