# ci

ci is the HWS continuous-integration service: it plans workflow files from your repository into jobs, queues them on NATS JetStream, runs each job in a fresh heyvm microVM on one of your runner hosts, and serves a dashboard and machine API over the results.

## What it is

ci is a single Rust process (`ci/`) with no agent to install on build machines. A machine becomes a runner by running `heyvmd` and joining a heyvm network; ci discovers those hosts through the heyvm control plane, opens an authenticated tunnel to each daemon, and drives builds on them.

| Piece | Role |
| --- | --- |
| **Postgres** | Authoritative state: runs, jobs, steps, logs, source descriptors, artifact records, repository registrations, VM ownership, deployment and release ledgers. |
| **NATS JetStream** | The job queue (`<prefix>_JOBS`, work-queue retention) and an event stream (`<prefix>_EVENTS`). Messages carry job IDs only. |
| **heyvmd runners** | Linux hosts in a heyvm network. Each job gets a new Firecracker or KVM microVM on one of them. |
| **Native runners** | Optional Intel macOS and Windows x86_64 hosts that poll ci over HTTPS and run jobs directly on the host. |
| **heyosecret** (optional) | Source of `${{ secrets.* }}` and `${{ vars.* }}`. See [heyosecret](heyosecret.md). |
| **artifacts store** (optional) | Destination for `ci/upload-artifact`. See [artifacts](artifacts.md). |
| **app-lb** (optional) | Fronts the dashboard with sign-in, and stores `workflow` objects. See [app-lb](app-lb.md). |

The workflow format is GitHub Actions-shaped (`jobs`, `needs`, `if`, `strategy.matrix`, `steps` with `run` or `uses`, `${{ }}` expressions), with two differences: a job's `uses:` names the heyvm network and host it runs on, and a job's `vm:` block describes the machine to boot.

You trigger runs with `git submit`, a Git subcommand that sends an exact revision to ci. There is no webhook integration with a Git host.

## Architecture

### From submit to result

1. **Submit.** `git submit` picks a commit that `origin` already has, computes a binary patch from it to the tree you want built, collects the workflow YAML from that tree, and POSTs a `git-patch` descriptor to `/api/submit`. No repository archive is uploaded.
2. **Plan.** ci selects workflow files whose `on:` includes `submit`, applies each file's branch and path filters, expands matrices, resolves each job's network, and stores the expanded job plans and the source descriptor in Postgres in one transaction. Each selected workflow file becomes one run.
3. **Queue.** Jobs whose `needs` are satisfied move from `pending` to `queued` and are published to JetStream. Postgres commits first; if the publish fails the job returns to `pending` and the scheduler retries.
4. **Claim.** A consumer for the job's subject claims the job atomically in Postgres (recording the owning ci process), which starts the job's clocks.
5. **Prepare and boot.** If the job uses `vm.build`, the runner's daemon builds or reuses the image. ci then creates a VM of the declared size on the chosen host.
6. **Checkout.** The guest fetches the pinned base revision from the repository URL, applies the patch, and refuses to continue unless the resulting Git tree matches the submitted tree exactly.
7. **Steps.** Each step runs through the daemon's exec-operation API as `sh -lc`. Output is masked for secrets and appended to shared log storage as it arrives; the dashboard streams it live.
8. **Cleanup.** After the last step ci captures the VM console, records the outcome, and hands the VM to durable cleanup, which stops and deletes it and only then forgets it.
9. **Advance.** Finishing a job re-runs the scheduler for its run, queuing dependents or skipping them.

### Queue subjects

Jobs are sharded so that several ci processes can consume without overlapping:

```text
<prefix>.job.r.<runner_id>     pinned to one host
<prefix>.job.n.<network_id>    any eligible host in that network
<prefix>.evt.<run_id>.<job_key|run>   status events (outbox publisher)
```

`<prefix>` is `CI_NATS_SUBJECT_PREFIX` (default `ci`). Two installations sharing one NATS server need different prefixes.

A running job extends its acknowledgement every 20 seconds, so `ack_wait` is 60 seconds regardless of job length and a dead dispatcher releases its job in about a minute. A job whose delivery fails *before* it is claimed is retried after 60 seconds, 5 minutes, then 15 minutes; the fourth pre-claim failure fails the job. A host's own subject is consumed one job at a time; a network subject fans out to up to four concurrent jobs across runners.

### Placement

`uses:` on a job decides where it runs:

| `uses:` | Meaning |
| --- | --- |
| absent | The repository's assigned network, any eligible host. |
| `default` | The host this ci process runs on, whatever network it is in. |
| `<network>` or `<network>/*` | Any eligible online host in that network. |
| `<network>/<host>` | That host (by daemon ID or name). `vm:` builds a VM on it. |
| `<network>/<host>/<vm>` | An existing VM on that host. `vm:` is ignored, steps exec into it, and ci never stops, deletes or extends its TTL. |

For an unpinned job, ci reads each candidate daemon's `GET /capabilities` (to skip hosts that cannot run the job's driver) and `/storage`, and picks the online host with the most free disk. A host must have room for the job's data disk, twice the declared image size, and 5 GiB of headroom; a host whose free space cannot be measured is excluded. Ties go to the lower runner ID.

The network for a job without a network in `uses:` resolves in this order, and is stamped into the stored job plan at submit time so a redelivery runs where it was scheduled:

1. the job's `uses: <network>/…`
2. the app-lb workflow object's `network`
3. the registered repository's assigned network (set on `/repos`)
4. the first entry of `CI_NETWORK`, or the account's default network when `CI_NETWORK=*`

A submit that resolves to a network this ci instance does not serve is refused with the served list in the error.

A pinned job waits for its host. If the host is offline, the job stays queued and fails after `CI_RUNNER_WAIT_SECS`. Set `fallback: any` on the job to let it run on any host in the network instead.

### VMs are disposable

Treat every job as getting a fresh VM. With `vm.reuse` false (or after guest filesystem corruption) ci destroys the VM as soon as the job ends. With the default `vm.reuse: true` it stops the VM and parks it, but the idle sweep runs with a zero-second window and destroys parked VMs on its next tick, so a later job only lands on one if it is claimed in that gap. There is no warm VM pool to plan around. What persists between jobs on a host is the **image**: a `vm.build` image is named by the hash of its Dockerfile, build context and `size_mb`, built once per host, and reused by every later job that names the same inputs. Unused built images are evicted later through heyvmd's ownership-checked eviction route, never while a runner has active work.

A job's data disk (`disk_size_gb`) is therefore new and empty in every job. Treat it as scratch space, not a cache.

### Size classes

`vm.size_class` takes the heyvm sizes:

| Class | vCPU | Memory |
| --- | --- | --- |
| `micro`, `mini`, `small` | 1 | under 4 GB |
| `medium` | 2 | 4 GB |
| `large` | 4 | 8 GB |
| `xlarge` | 8 | 16 GB |

Pick on memory. A microVM has no swap, so a build that needs more is OOM-killed rather than slowed down; `CARGO_BUILD_JOBS` in the job's `env` trades wall-clock time for memory headroom. ci reads back what the daemon actually allocated. A VM reported smaller than the declared class is resized once, and the job fails with both sizes named if it is still too small. heyvmd admits a VM only if the declared memory of its running VMs fits the host, so large classes are harder to place.

### Native runners

A job with `runs-on:` instead of `uses:`/`vm:` goes to a native runner whose advertised labels include every label listed:

```yaml
jobs:
  mac:
    runs-on: [macos, macos-intel, x86_64-apple-darwin]
    steps:
      - run: cargo build --release
```

The agent is the `native-runner-agent` binary built from `ci/`:

```bash
cargo build --locked --release --manifest-path ci/Cargo.toml --bin native-runner-agent
```

| Agent variable | Meaning |
| --- | --- |
| `CI_ENDPOINT` | ci base URL. HTTPS required except on loopback. |
| `CI_NATIVE_RUNNER_SECRET` | Must equal `CI_NATIVE_RUNNER_SECRET` on the ci server. |
| `CI_NATIVE_RUNNER_ID` | Stable runner identity. |
| `CI_NATIVE_PROFILE` | `mac-intel` or `windows-x64`. The agent refuses a profile that does not match the host OS and architecture. |
| `CI_NATIVE_RUNNER_NAME` | Display name. Default: the profile. |
| `CI_NATIVE_WORKDIR` | Working directory. Default: `<tmp>/heyo-native`. |

Profiles advertise fixed labels: `mac-intel` advertises `namespace-profile-mac-build`, `macos`, `macos-intel`, `x86_64-apple-darwin`; `windows-x64` advertises `blacksmith-2vcpu-windows-2025`, `windows`, `windows-x64`, `x86_64-pc-windows-msvc`.

Native jobs support shell steps, conditions, env, step outputs, working directories, timeouts, `continue-on-error`, cancellation, `ci/upload-artifact`, and `ci/checkout-release`. Other built-in actions fail; put them in a dependent Linux job. Logs arrive with the completion report rather than streaming. Native jobs run your code directly on the host with no sandbox. The `/api/native/` routes must be in app-lb `public_paths`; ci authenticates them itself. Protocol details are in [NATIVE_RUNNERS.md](../ci/NATIVE_RUNNERS.md).

## Running it

### Requirements

- `heyvmd` on each build host, joined to a heyvm network (`heyvm network add-host`). The daemon must require authentication (`JWT_SECRET`); ci refuses a runner that answers unauthenticated.
- Postgres. Migrations are compiled into the binary and applied at every startup under an advisory lock.
- NATS with JetStream enabled (`nats-server -js -sd /var/lib/ci-js`). Do not use the NATS system account; JetStream cannot be enabled on it.
- For image builds (`vm.build`), each runner host needs `docker`, `mke2fs`, and `fakeroot` when heyvmd does not run as root.

### Start

```bash
CI_HEYO_API_KEY=… \
CI_NETWORK=prod-runners \
CI_DATABASE_URL=postgres://ci:…@db/ci \
CI_WEBHOOK_SECRET=$(openssl rand -hex 32) \
CI_NATS_URL=nats://127.0.0.1:4222 \
ci
```

Configuration is environment-only. Every value is validated before ci binds a port or dials NATS; a bad or missing value exits non-zero with a message naming the variable (`ci: refusing to start — …`). The startup log prints one summary line of every resolved non-secret setting.

For a single machine with no heyvm cloud account, point ci at a local daemon:

```bash
CI_LOCAL_RUNNER=1 CI_ALLOW_UNAUTHENTICATED_RUNNERS=true CI_NETWORK=local \
CI_HEYO_API_KEY=unused CI_DATABASE_URL=postgres://…/ci CI_WEBHOOK_SECRET=0123456789abcdef ci
```

`CI_LOCAL_RUNNER=1` uses the SDK's default local daemon URL; any other value is taken as the daemon's base URL. The runner is named `local`.

A supervisor program template is in [`ci/deploy/supervisor/ci.conf`](../ci/deploy/supervisor/ci.conf), and an app-lb static deployment for fronting the dashboard is in [`ci/deploy/ci.json`](../ci/deploy/ci.json).

### Offline commands

| Command | What it does |
| --- | --- |
| `ci --check-workflows FILE…` | Parses and plans each workflow file (matrix, `needs`, cycles) with no configuration, database or broker. Exit 1 on any error. |
| `ci --inspect-executor` | Prints registered ci process boots from the database as JSON. |
| `ci --reconcile-service-rollout RUN_ID OPERATION_ID` | Re-checks one `ci/rollout-service` operation receipt using the configured database and heyosecret. |
| `ci --prepare-host-bootstrap …`, `--deliver-host-bootstrap …`, `--check-host-bootstrap …` | Operator tooling for the one-time native app-lb host bootstrap. See the [ci README](../ci/README.md#preparing-the-initial-native-bootstrap-manifest). |

### Configuration

Required:

| Variable | Meaning |
| --- | --- |
| `CI_HEYO_API_KEY` | Bearer for the heyvm cloud and for each runner daemon. `HEYO_API_KEY` is accepted as a fallback. |
| `CI_NETWORK` | Networks whose hosts are runners: one name or ID, a comma-separated list (the first is the default), or `*` for every network on the account. |
| `CI_DATABASE_URL` | Postgres connection string. |
| `CI_WEBHOOK_SECRET` | Shared HMAC secret for submits without a repository token. At least 16 bytes. |

Service:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CI_NAME` | `ci` | Name shown in logs and the dashboard. |
| `CI_LISTEN_ADDR` | `127.0.0.1:9500` | HTTP listen address. |
| `CI_PUBLIC_URL` | `http://<listen addr>` | External base URL, used in links and submit responses. |
| `CI_ADMIN_EMAILS` | unset | Comma-separated emails granted admin on first sight (via app-lb forwarded identity). When unset, requests with no identity are treated as admin, which is only safe for a local, ungated install. |
| `CI_REQUIRE_REPO_TOKEN` | `false` | Refuse the shared `CI_WEBHOOK_SECRET` for submits; accept only per-repository tokens. |
| `CI_WORKFLOW_PATH` | `.ci/workflows/*.yml` | Default workflow glob. A repository registration or workflow object can override it. |
| `CI_MAX_SOURCE_BYTES` | `67108864` (64 MiB) | Ceiling on a submitted source descriptor after base64 decoding. |
| `CI_DB_STATEMENT_TIMEOUT_SECS` | `30` | Per-statement Postgres timeout. |
| `CI_MIGRATIONS_DIR` | unset | Extra `*.sql` to run *after* the embedded migrations. Leave unset. |
| `CI_LOG_DIR` | `ci-logs` | Legacy local log path, imported into Postgres at startup when present. |
| `CI_WORKSPACE_DIR` | `ci-workspaces` | Local submission staging. |
| `CI_LOG_RETENTION_DAYS` | `2` | Step and VM log retention. `0` keeps logs forever. Run and step rows are kept. |
| `CI_VM_LOG_LINES` | `500` | Lines of a VM's console captured per job. |
| `CI_UI_COOKIE_DOMAIN`, `CI_UI_COOKIE_NAME` | unset | Theme cookie scope, falling back to the fleet-wide `HEYO_UI_COOKIE_*` values. |
| `RUST_LOG` | `info,ci=debug` | Log filter. |

Runners and timing:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CI_HEYO_BASE_URL` | SDK default | heyvm cloud base URL. |
| `CI_DEFAULT_NODE` | unset | Daemon ID that `uses: default` resolves to, overriding discovery. |
| `CI_DAEMON_STATE_PATH` | `$MVM_DATA_DIR/daemon.json`, else `~/.heyo/daemon.json` | heyvmd identity file used to resolve `uses: default`. |
| `CI_LOCAL_DAEMON_URL` | SDK default | Local daemon URL for the `uses: default` probe. |
| `CI_LOCAL_RUNNER` | unset | Drive one daemon directly instead of discovering hosts (see above). |
| `CI_LOCAL_RUNNER_TOKEN` | unset | Bearer for that daemon, when it requires one. |
| `CI_IROH_RELAY` | unset | iroh relay override for NAT traversal. |
| `CI_ALLOW_UNAUTHENTICATED_RUNNERS` | `false` | Accept daemons that serve their API without auth (local development only). |
| `CI_RUNNER_REFRESH_SECS` | `30` | How often the runner list is re-read. |
| `CI_RUNNER_WAIT_SECS` | `1800` | How long a job may wait for a runner that is not going to take it (offline pinned host, no consumer) before it fails. Must exceed the 21-minute redelivery ladder. |
| `CI_QUEUE_WAIT_SECS` | unset (no cap) | Optional cap on time spent queued behind a busy runner. |
| `CI_MAX_JOB_SECONDS` | `14400` | Hard ceiling on any job, measured from pickup. |
| `CI_VM_TTL_SECONDS` | `3600` | Backstop TTL on every VM ci creates; renewed while a job runs. A job's `vm.ttl_seconds` overrides it. |
| `CI_VM_LEASE_SECS` | `180` | VM lease window; renewed every third of it. |

NATS:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CI_NATS_URL` | `nats://127.0.0.1:4222` | Server URL, comma-separated for a cluster, or `wss://host/path` through a WebSocket-capable ingress. |
| `CI_NATS_SUBJECT_PREFIX` | `ci` | Namespace for streams, subjects and durable consumers. `[A-Za-z0-9_-]` only. |
| `CI_NATS_USER` + `CI_NATS_PASSWORD` | unset | User/password auth (both or neither). |
| `CI_NATS_TOKEN` | unset | Token auth. |
| `CI_NATS_CREDS` | unset | Path to a `.creds` file. |
| `CI_NATS_NKEY` | unset | nkey seed. |

Set at most one of the four NATS credential forms; naming two is a startup error. A credential embedded in the URL still works but logs a warning.

Artifacts and reports:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CI_ARTIFACT_SINK` | `disk` | `disk`, `s3`, or `artifacts` (also `art`). |
| `CI_ARTIFACT_DIR` | `ci-artifacts` | Directory for the `disk` sink. |
| `CI_ARTIFACT_URL` | required for `artifacts` | Base URL of the artifacts store (`art serve`). |
| `CI_ARTIFACT_TOKEN` | unset | Store API key. |
| `CI_ARTIFACT_GUEST_URL` | `CI_ARTIFACT_URL` | Store URL as reachable from inside a guest VM, when it differs. |
| `CI_S3_BUCKET` | required for `s3` | Bucket for the `s3` sink and for debug reports. |
| `CI_S3_PREFIX` | `ci` | Key prefix. |
| `CI_S3_REGION`, `CI_S3_ENDPOINT` | unset | S3 region and endpoint. Credentials come from the standard AWS chain. |

When `CI_S3_BUCKET` is set, ci also uploads a per-job debug report (job identity, outcome, step logs, VM console) to `<prefix>/<run>/<job>/debug-<attempt>-<sandbox>.json` before deleting the VM, regardless of the artifact sink. Use a private bucket.

Integrations:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CI_HEYOSECRET_URL` | `HEYOSECRET_URL` | heyosecret base URL. |
| `CI_HEYOSECRET_TOKEN` | `HEYOSECRET_INTERNAL_API_KEY`, then `PLATFORM_INTERNAL_API_KEY` | heyosecret bearer. Never reaches a build. |
| `CI_APP_LB_URL`, `CI_APP_LB_TOKEN` | unset | app-lb admin API for `workflow` objects and for the `ci` plugin's namespace installs (`GET /api/plugins/ci`). Without it, ci uses repository registrations and `CI_WORKFLOW_PATH` only, and no namespace can use ci. |
| `CI_PLUGIN_API_TOKEN` | unset | Bearer app-lb's `ci` plugin presents on every `/ns/{ns}/` request. The namespace routes are not mounted without it. See [Namespaces](#namespaces). |
| `CI_REQUIRE_INSTALL` | `true` | Namespace pages and submits need the namespace in app-lb's install list. `false` treats every namespace as installed while the plugin is enabled. |
| `CI_TENANT_ONLY` | `false` | Build only for namespaces: every fleet submit answers `403`, and the default network may be a tenant network. Requires `CI_PLUGIN_API_TOKEN` and `CI_APP_LB_URL`. See [A tenant-only instance](#a-tenant-only-instance). |
| `CI_NATIVE_RUNNER_SECRET` | unset | Bearer for `/api/native/*`. Native runners are disabled without it. |

Release, deployment and host-maintenance variables (`CI_RELEASE_POLICIES`, `CI_HOST_APP_LB_TARGETS`, `CI_HOST_MAINTENANCE_TARGETS`, `CI_HOST_HEYVM_BOOTSTRAP_TARGETS`, `CI_CONTROLLER_*`, `CI_APPLICATION_*`, `CI_EXPECTED_SHA`) are operator configuration for the built-in release actions. They are documented with those actions in the [ci README](../ci/README.md#operator-owned-release-policy).

### Fronting it with app-lb

app-lb's sign-in gate admits browsers only, so the machine routes must be listed in the deployment's `public_paths`; each authenticates its own requests:

```json
"public_paths": [
  { "path": "/healthz", "scope": "public" },
  { "path": "/api/submit", "scope": "public" },
  { "path": "/api/native/", "scope": "public" },
  { "path": "/api/stream/", "scope": "public" },
  { "path": "/api/runs/", "scope": "public" },
  { "path": "/__ui/", "scope": "public" }
]
```

Keep `/repos`, `/maintenance`, `/networks/*/join` and the `/vms` actions behind the gate, and never list `/ns/`: those routes are for app-lb's plugin proxy and carry their own bearer (see [Namespaces](#namespaces)). ci reads the forwarded identity headers (`x-auth-request-user`, `-email`, `-name`), which are trustworthy only on a gated deployment, and keeps its own admin list seeded from `CI_ADMIN_EMAILS`. See [app-lb auth](app-lb-auth.md).

## Submitting with git submit

### Install and configure

```bash
ci/install-git-submit.sh          # installs git-submit into ~/.local/bin
```

Register the repository on the dashboard's `/repos` page and mint a token. The page shows the token once, with the two lines to run in your clone:

```bash
git config ci.endpoint https://ci.us2.heyo.work
git config ci.token    cis_…
```

| Setting | Environment override | Meaning |
| --- | --- | --- |
| `ci.endpoint` | `CI_ENDPOINT` | ci base URL (or the full `/api/submit` URL). |
| `ci.token` | `CI_TOKEN` | Repository token, sent as a bearer. |
| `ci.secret` | `CI_WEBHOOK_SECRET` | Shared secret; the payload is HMAC-signed (`x-heyo-signature-256`) when no token is set. |
| `ci.workflowPath` | | Extra workflow globs (repeatable) when the repository uses a custom path. |

`CI_SUBMIT_TIMEOUT` (default 300 seconds) bounds the upload. The client needs `git`, `curl`, `base64`, `python3`, and `openssl` for the shared-secret path.

### Usage

```bash
git submit                     # submit HEAD
git submit --dry-run           # show what would be sent
git submit --dirty             # include uncommitted tracked changes
git submit --ref <rev>         # submit another commit
git submit pr59                # submit the exact head of GitHub PR #59
git submit --only app-lb       # run only this workflow (repeatable)
git submit --workflow <id>     # attribute the run to a named workflow object
git submit --submit-empty      # submit even when the tree equals the default branch
git submit --version
git submit --upgrade           # reinstall from the release channel
```

The client prints one run URL per started workflow, plus a submission URL when a release workflow was selected, and any warnings (for example, a pinned host that is offline).

What gets sent:

- **A pinned base and a patch.** The client asks `origin` which heads it advertises, picks the nearest published ancestor of the revision you are submitting, and sends a binary full-index patch from that base to your target tree. A pushed commit is its own base with an empty patch. Local commits and `--dirty` work as long as some ancestor is published; an unpublished root-only repository cannot be submitted. `--archive` has been removed.
- **Workflow YAML** from the target tree (not your worktree): `.ci/workflows/*.yml` and `*.yaml` by default, at most 256 KiB per file and 1 MiB total.
- **The changed-path list** for the full diff from the default branch, which drives `paths:` filters and `changed()`. If the diff cannot be computed (root commit, base unavailable, more than 5000 paths), the change set is *unknown* and every path filter matches.

The runner, not ci, does the checkout: it fetches the base from the repository URL, applies the patch, and verifies the tree. Private repositories therefore need a checkout credential in heyosecret (`CI_GIT_AUTH_TOKEN` or `GITHUB_TOKEN` in the workflow's secret scope). The submit token is not repository read access.

`pr<number>` fetches `refs/pull/<number>/head` into a temporary object store without touching your branch, index or worktree. It cannot be combined with `--ref` or `--dirty`.

`--only <selector>` runs just the named workflow files. A selector is the file path, its basename with or without extension, or the workflow's `name:`, matched case-insensitively. A named workflow runs even if its `branches`/`paths` filters would have declined, and its run is created with an unknown change set so job-level `changed()` conditions also pass. A selector that matches nothing fails the submit.

### Repository tokens

A repository token is minted per registration, stored as a SHA-256 digest, shown once, and revocable on its own. A submit whose payload names a different repository than its token is refused. Pausing a registration refuses its tokens without deleting them. `CI_WEBHOOK_SECRET` works for any repository and cannot be revoked per repository; set `CI_REQUIRE_REPO_TOKEN=true` once every repository has a token.

A registration can also set a workflow glob override and an assigned network.

### Workflow objects

With `CI_APP_LB_URL` set, ci polls app-lb for `workflow` objects, each pointing at a repository, a ref, a path glob and a network:

```bash
heyctl create workflow build \
  --repo git@github.com:me/app.git \
  --network prod-runners \
  --path '.ci/workflows/*.yml'
heyctl get workflows
```

Objects match a submit by repository URL (`git@github.com:me/app.git` and `https://github.com/me/app` are the same). Several objects may name one repository; each produces its own runs. There is no in-place edit; delete and re-create with the same ID. See [heyctl](heyctl.md).

## Namespaces

An app-lb namespace that installs the `ci` plugin gets its own repositories, submit tokens, runs and live logs on the shared fleet runners. What the fleet registers stays the fleet's, and a namespace sees only its own.

### How a namespace reaches ci

The namespace's pages and API are served at `/ns/{ns}/` and reached through app-lb's plugin proxy, which maps `/namespaces/<ns>/plugins/ci/ui/<tail>` to `/ns/<ns>/<tail>` and `/namespaces/<ns>/plugins/ci/api/<x>` to `/ns/<ns>/api/<x>`. Each proxied request carries:

| Header | Meaning |
| --- | --- |
| `Authorization: Bearer <CI_PLUGIN_API_TOKEN>` | Checked first, in constant time. Without it every `/ns/` route answers `401`. |
| `x-heyo-base` | `/namespaces/<ns>/plugins/ci`. Every link, form and stream URL on the page is built from it. Any other value is ignored and the page links its native `/ns/<ns>/` paths. |
| `x-heyo-actor`, `x-heyo-actor-email` | Who is asking. Recorded on registrations and tokens. |
| `x-heyo-actor-admin` | `true` allows writes: registering, minting and revoking tokens, pausing, removing, cancelling and re-running. Anything else is read-only (`403` on a write). |

The actor headers are trusted only behind the bearer, so the routes are not mounted at all unless `CI_PLUGIN_API_TOKEN` is set. ci polls app-lb's `GET /api/plugins/ci` (with `CI_APP_LB_URL`/`CI_APP_LB_TOKEN`) for which namespaces have installed the plugin and where they build. A namespace that is not installed gets `404` on every route, and its tokens' submits get `403`, within one poll of an uninstall. A `409` from app-lb (plugin disabled) or a `404` (an app-lb without the plugin) means no namespace is installed; a transport error keeps the last answer.

Pages: runs (`/ns/<ns>/`), a run, a job with its live log, repositories and workflows. JSON: `api/runs`, `api/runs/<id>`, `api/runs/<id>/logs`, `api/repos` and the `api/stream/<run>/<job>` log stream. A run, job, repository or token from another namespace answers `404`, the same as one that does not exist. Embedded in app-lb's console (an iframe), the page hides its own top bar.

A namespace's token submits through the ordinary `git submit` endpoint; register the repository on the namespace's repositories page and run the two `git config` lines it shows.

### A tenant-only instance

A region whose app-lb has no fleet CI of its own runs a separate ci with `CI_TENANT_ONLY=true`, its own database and NATS subject prefix, and `CI_APP_LB_URL` pointing at that region's app-lb. It refuses every fleet submit (shared-secret or a fleet registration's token) with `403`, so the only builds on it are namespaces'.

Such an instance may drive its own host's daemon directly instead of joining a heyvm network: `CI_LOCAL_RUNNER=<daemon URL>` with `CI_LOCAL_RUNNER_TOKEN` set to the daemon's bearer. Local-runner mode serves one network, `local`, which is also the default; tenant-only lifts the rule that keeps tenants off the default network, so the plugin's `tenant_network` is `local`.

### Tenant limits

A namespace submit is planned under a narrower policy than a fleet one, and a workflow that breaks it is refused at submit with the rule it broke:

- **One network.** Jobs run in the network app-lb's plugin config names for the namespace (`namespace_networks[<ns>]`, else `tenant_network`). It must be a network this instance serves and must not be the fleet default (the first entry of `CI_NETWORK`), unless the instance is [tenant-only](#a-tenant-only-instance). A job may pin a host in that network (`uses: <network>/<host>`), but not another network, `uses: default`, or an existing VM.
- **No native runners.** `runs-on` is refused.
- **No release.** `on: release` is refused, and release policies and `workflow` objects never apply to a namespace's repositories, even when they name the same URL.
- **Two actions.** Only `ci/upload-artifact` and `ci/download-artifact`; every deploy, publish, merge and host-maintenance action is refused, and refused again at execution.
- **Fresh VMs.** A namespace job's VM is never handed to the next job.

Registrations are unique per namespace and URL, so a namespace registering a fleet repository's URL gets a registration of its own and never edits the fleet's. The shared `CI_WEBHOOK_SECRET` only ever submits as the fleet.

### Secrets

A namespace run reads `${{ secrets.X }}` and `${{ vars.X }}` from heyosecret under `ci/ns/<ns>/<workflow>/<environment>/`, where `<workflow>` is the registered repository's name. The namespace segment is forced, so a repository named after a fleet workflow cannot read that workflow's secrets. heyosecret has no per-namespace authorization, so an operator writes a namespace's secrets under its prefix.

## Workflow reference

```yaml
name: build
on:
  submit:
    paths: ['api/**', 'Cargo.lock']

jobs:
  build:
    uses: prod-runners                     # any eligible host in this network
    vm:
      driver: firecracker
      build:
        dockerfile: .ci/image/Dockerfile
      size_class: large
      disk_size_gb: 20
    strategy:
      matrix:
        target: [x86_64, aarch64]
    env:
      CI_ENVIRONMENT: prod                 # selects the secret scope
    timeout-minutes: 75
    outputs:
      version: ${{ steps.stamp.outputs.version }}
    steps:
      - id: stamp
        run: echo "version=$(git describe --always)" >> "$CI_OUTPUT"
      - name: Build
        working-directory: /workspace/api
        run: cargo build --release --locked --target ${{ matrix.target }}
        timeout-minutes: 60
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
      - uses: ci/upload-artifact
        with:
          name: api-${{ matrix.target }}
          path: dist

  deploy:
    needs: [build]
    if: ${{ needs.build.result == 'success' && ci.branch == 'main' }}
    steps:
      - run: echo "deploying ${{ needs.build.outputs.version }}"
```

Every level rejects unknown keys (`stpes:`, `timeout_minutes:`) with a parse error naming the job, except inside `vm:`, where an unknown key is currently ignored. Run `ci --check-workflows` before you submit.

### Top level

| Key | Meaning |
| --- | --- |
| `name` | Display name, also usable as an `--only` selector. |
| `on` | `submit` (default when absent), a list, or a mapping with a `submit:` filter block. `release` marks the repository's single release coordinator (see [Releases](#releases-and-deployments)). Other triggers parse but never start a run. |
| `env` | Accepted, but not currently applied to steps. Put variables on the job or step. |
| `jobs` | Ordered mapping of job ID to job. IDs become queue subject tokens, so keep them to letters, digits, `-` and `_`. |

### `on: submit` filters

```yaml
on:
  submit:
    branches: [main, 'release/*']     # or branches-ignore
    paths: ['packages/api/**']        # or paths-ignore
```

| Pattern | Matches |
| --- | --- |
| `*` | Any characters within one path segment. |
| `**` | Any number of whole segments, including none. |
| `?` | One character within a segment. |

`paths` builds when any changed path matches; `paths-ignore` skips only when every changed path matches. `branches` and `branches-ignore` cannot be combined, nor can `paths` and `paths-ignore`, and a leading `!` is refused. An unknown change set matches every filter. A submit where every workflow declines is a success with no runs, and `git submit` prints each reason.

### Job keys

| Key | Meaning |
| --- | --- |
| `name` | Display name. |
| `uses` | Placement (see [Placement](#placement)). |
| `runs-on` | Native runner labels. Mutually exclusive with `uses` and `vm`. |
| `fallback` | `none` (default) or `any`: whether a pinned job may run on another host in the network. |
| `vm` | Machine to boot (below). |
| `needs` | Job IDs this job waits for. Cycles and unknown IDs are parse errors. |
| `if` | Condition. Without one, the job runs only if every dependency succeeded; failure, cancellation and skips propagate down the chain. |
| `strategy.matrix` | Axes of values, plus optional `include` and `exclude` lists. |
| `strategy.max-parallel` | Cells that may run at once. |
| `strategy.fail-fast` | Default `true`. |
| `env` | Step environment for every step in the job. Matrix expressions are substituted at plan time. `CI_ENVIRONMENT` here selects the secret scope. |
| `outputs` | Job outputs, readable as `needs.<job>.outputs.<name>`. |
| `continue-on-error` | Job failure does not fail the run. |
| `timeout-minutes` | Default 60. |
| `steps` | Required, non-empty. |

### `vm:`

| Key | Meaning |
| --- | --- |
| `driver` | Required when `vm:` is present. `firecracker` (the default when `vm:` is absent) or `kvm`. `libvirt` is refused. |
| `image` | A base image name the host already has, for example `ubuntu:24.04`. |
| `build.dockerfile` | Dockerfile path in the submitted tree. Mutually exclusive with `image`. |
| `build.context` | Build context. Default: the Dockerfile's directory. |
| `build.size_mb` | Rootfs size. Default: auto-sized from the exported tree (about 1.2x plus 64 MB). |
| `size_class` | `micro`, `mini`, `small`, `medium`, `large`, `xlarge`. |
| `disk_size_gb` | Extra data disk for the job. |
| `working_directory` | Default working directory for steps. Default `/workspace`. |
| `env_vars` | Environment passed to the VM at creation. |
| `setup_hooks` | Commands run when the VM is created. |
| `ttl_seconds` | Create-time VM TTL. Set it above the job timeout for jobs longer than `CI_VM_TTL_SECONDS`. |
| `cache_key_files` | Feeds the VM fingerprint and triggers source preparation. Parked VMs are swept almost immediately, so it rarely leads to reuse. |
| `reuse` | Default `true`: park the stopped VM instead of destroying it. The idle sweep retires parked VMs on its next tick, so reuse is incidental. |

`vm.build` runs `docker build`, `docker export`, then `mke2fs` on the runner, so Dockerfile features all work but OCI metadata does not survive: `ENV`, `CMD` and `ENTRYPOINT` are dropped. Put environment a step needs in `/etc/profile.d` with a `RUN` (steps run under `sh -lc`, a login shell). The image must have an `/init.sh` that prints `HEYVM_READY`; [`.ci/image/ci/init.sh`](../.ci/image/ci/init.sh) is a working example. The first job on a host that needs an image builds it and later jobs wait for that one build.

### Steps

| Key | Meaning |
| --- | --- |
| `name`, `id` | Label, and the ID used in `steps.<id>.outputs`. |
| `run` | Shell script. Exactly one of `run` or `uses`. |
| `uses` | A built-in action (below). Repository composite actions are not supported. |
| `with` | Action inputs. Scalars only; `true` and `3` are read as strings. |
| `if` | Step condition. |
| `env` | Step environment, overriding the job's. |
| `working-directory` | Used verbatim as `cd <value>`, so give an absolute path such as `/workspace/api`. Default: the job's working directory (`/workspace`). |
| `timeout-minutes` | Default 30. |
| `continue-on-error` | Step failure does not fail the job. |

Every step gets `CI=true`, `CI_JOB` (job ID) and `CI_JOB_KEY` (matrix-expanded key). Write `name=value` lines to `$CI_OUTPUT` to set step outputs. The checkout lands in `/workspace` and is wiped on every checkout; paths in `ci/upload-artifact` and `cache_key_files` are relative to the repository root.

### Expressions

`${{ }}` is substituted in `run`, `env`, `with`, `if` and job `outputs`. Contexts:

| Context | Contents |
| --- | --- |
| `ci` | `sha`, `before`, `ref`, `branch`, `repository`, `run_id`, `workflow`, `release_base_sha`, `changed_files` (array), `changes_known` (bool), `changes_reason` (empty when known). |
| `matrix` | The current cell's values. |
| `env` | The job's env. |
| `job` | `id`, `key`. |
| `needs` | `needs.<job>.result` (`success`, `failure`, `cancelled`, `skipped`; a matrix collapses to its worst cell) and `needs.<job>.outputs.*`. |
| `steps` | `steps.<id>.outputs.*`. |
| `secrets`, `vars` | From heyosecret (below). |

Functions: `contains`, `startsWith`, `endsWith`, `format`, `join`, `toJSON`, `fromJSON`, `success`, `failure`, `cancelled`, `always`, and `changed(pattern, …)`.

`changed()` uses the same glob matcher as `paths:` and is true when any changed file matches any argument, or when the change set is unknown. Use it to gate jobs in a monorepo:

```yaml
jobs:
  api:
    if: ${{ changed('packages/api/**', 'Cargo.lock') }}
```

An explicit `if:` replaces the default "all dependencies succeeded" rule, which is how `if: ${{ always() }}` runs a cleanup job after a failure.

### Secrets and variables

ci resolves secrets once per job from heyosecret under the prefix:

```text
ci/<workflow>/<environment>/<NAME>
```

- `<workflow>` is the app-lb workflow object's ID when one matched; otherwise the registered repository's name (by default the last segment of its URL); otherwise the submitted repository's directory name. It is exposed as `${{ ci.workflow }}`.
- `<environment>` is the job's `env.CI_ENVIRONMENT`, defaulting to `default`.
- Characters outside `[A-Za-z0-9-_.:@]` are replaced with `-`.

An entry tagged `public` in heyosecret becomes `vars.<NAME>` and is shown in plain text. Everything else becomes `secrets.<NAME>` and is masked (`***`) in logs before they are stored or streamed; values shorter than four characters are not masked. The heyosecret token itself never reaches a build. The `--secrets-prefix` field on a workflow object is stored but not currently applied.

Store the checkout credential for a private repository as `CI_GIT_AUTH_TOKEN` (or `GITHUB_TOKEN`) in the same scope.

## Artifacts

### Uploading

```yaml
- uses: ci/upload-artifact
  with:
    name: app                  # required
    path: dist                 # required, relative to the repository root
    description: App binary for x86_64-linux   # artifacts sink only
    public: true               # artifacts sink only
    alias: app-live            # artifacts sink only
```

The step packs `path` into a tar.gz in the guest. With the `artifacts` sink, the guest pushes the tarball straight to the store with `curl -T` (using `CI_ARTIFACT_GUEST_URL` or `CI_ARTIFACT_URL`); if that fails, ci reads it out through the exec channel in chunks, which is much slower on Firecracker. Both directions are checked by SHA-256.

| Sink | Where it goes | Notes |
| --- | --- | --- |
| `disk` | `CI_ARTIFACT_DIR` on the ci host | Not shared between ci instances. |
| `s3` | `CI_S3_BUCKET` / `CI_S3_PREFIX` | No public links. |
| `artifacts` | The [artifacts](artifacts.md) store at `CI_ARTIFACT_URL` | Supports `description`, `public` and `alias`. |

In the artifacts store each upload is tagged:

```text
ci-<workflow>-<run>-<job_key>-<name>
```

truncated to 64 characters. Run IDs are fixed-width hex (`%012x-%08x`, time then sequence), so sorting these tags lexicographically sorts them by time.

- `description` is stored as a label beside the digest, shown in the store and by installers' `--list`.
- `public: true` marks the blob public (`PUT /public/{digest}`), so `{store}/blobs/{digest}` downloads with no credential. The link is printed in the step log as `[ci] public link: …` and shown on the run page. Tags and listings still need the key.
- `alias` moves a second, stable tag onto this upload, so a deployment can follow the newest green build by name. Aliases cannot start with `ci-`, and a failure to set one fails the step.

Each upload writes a `ci.artifact.published.v1` event. A published artifact is not a release approval: a later step can still fail.

### Downloading in a later job

```yaml
jobs:
  package:
    needs: [build]
    steps:
      - uses: ci/download-artifact
        with:
          name: app
          path: app.tar.gz        # the uploaded tar.gz, not unpacked
          job: build              # only when several producers used this name
      - run: tar -xzf app.tar.gz
```

The producer must be in `needs` and must have succeeded. Size and SHA-256 are verified. Cross-job files must go through artifacts; each job's VM is deleted when it finishes. In a coordinated release, `with.workflow` names a validation workflow path from the same submission.

## Dashboard and HTTP API

### Pages

| Path | Shows |
| --- | --- |
| `/` | Recent runs (latest 50), fleet and namespace alike. Once a namespace has run, a Namespace column and filter appear (`?namespace=<ns>`, or `-` for the fleet's own). |
| `/runs/{run_id}` | Jobs, queued time and duration, artifacts and public links, VM logs, Release, Deployments, and an event timeline. Admin buttons: Cancel, Run again, Re-run failed jobs. |
| `/runs/{run_id}/jobs/{job_key}` | One job's steps and live log. |
| `/networks` (also `/runners`) | Every heyvm network on the account with its hosts, which ones this instance serves, each host's and network's queue depth read from JetStream, and daemons that joined no network. Admins can join this host to a network. |
| `/vms` | ci-owned VMs by host, including ones still being created (`building`), with declared vs. reported size. Admin actions: destroy, resize, clean up failed. |
| `/workflows` | app-lb workflow objects. |
| `/repos` | Admin: register the fleet's repositories, mint and revoke tokens, pause, assign a network. Namespace registrations are managed on the namespace's own page. |

A `no consumer` flag on an online host in the Queue column means jobs are routed to a subject nothing reads: the host is not in a network this instance serves, or its consumer is not bound.

Cancelling marks the run and all unfinished jobs `cancelled`. A running step cannot be aborted in the guest; ci stops waiting within seconds, records it cancelled, and cleans up the VM while the command finishes or times out. A re-run is always a new run (`rerun_of` links them). **Re-run failed jobs** carries successful jobs and their outputs over and schedules the rest.

### Machine API

These routes authenticate with the repository token (`Authorization: Bearer cis_…`) scoped to the run's repository, or with an HMAC of the request path signed by `CI_WEBHOOK_SECRET`. A run from another repository answers 404.

| Method and path | Purpose |
| --- | --- |
| `POST /api/submit` | Submit (used by `git submit`). Accepts the bearer token, or an `x-heyo-signature-256: sha256=<hex>` HMAC of the body. Returns 202 with `runs`, `url`, `warnings`, and `submission` when a release coordinator was created. |
| `GET /api/runs/{run_id}` | Run status, jobs, steps, `reruns`, `debug_reports`. |
| `GET /api/runs/{run_id}/logs?job=&tail=&failed_only=` | Step logs, tail-first. `tail` defaults to 16384 bytes per step, capped at 1 MiB. Includes the checkout (`-1`) and VM console (`-2`) pseudo-steps. |
| `GET /api/runs/{run_id}/events?limit=&before=` | Durable status events, newest first. `limit` defaults to 50, max 100. |
| `GET /api/runs/{run_id}/deployments` | Deployment operations started by the run. |
| `GET /api/runs/{run_id}/release` | Release publication state (prepared, uncertain, confirmed) and SHAs. |
| `POST /api/runs/{run_id}/rerun-failed` | Re-run failed jobs. Bearer token only; 409 while the run is active or a deployment is unresolved. Each accepted call creates a new run. |
| `POST /api/runs/{run_id}/cache/{sandbox_id}/destroy` | Destroy an idle VM last used by this run. Bearer token only. |
| `GET /api/stream/{run_id}/{job_key}` | Server-sent log stream, authorized by a short-lived token the run page mints. |
| `GET /healthz` | `ok`, with `x-ci-revision` and `x-ci-binary-sha256` headers when known. Unauthenticated. |

The `/api/native/*` routes serve native runners (bearer `CI_NATIVE_RUNNER_SECRET`), and `/api/lifecycle/*` serves managed-platform lifecycle calls (bearer `CI_APPLICATION_LIFECYCLE_TOKEN`).

```bash
curl -fsS -H "Authorization: Bearer $(git config ci.token)" \
  "https://ci.us2.heyo.work/api/runs/$RUN/logs?failed_only=true&tail=4096"
```

## Multiple instances, drain and maintenance

Several ci processes can serve the same installation, including one per region, as long as they share the same Postgres database and the same NATS server and subject prefix. Every registered process may execute work; there is no leader. A job is claimed atomically by one process, which owns its VM and cleanup until the cleanup is confirmed. If a process dies, its unclaimed queue messages are redelivered to another; work it had already claimed is not taken over automatically and needs reconciliation.

Maintenance routes are admin-only (behind the app-lb gate, never in `public_paths`), and each request applies only to the process that receives it. Send `x-ci-target-boot: <boot id>` to have any other process reject the request with 409. `ci --inspect-executor` lists boot IDs.

### Draining one ci process

```text
POST /maintenance/{operation-uuid}/pause      stop admitting new jobs on this process
GET  /maintenance                             this process's outstanding work
POST /maintenance/{operation-uuid}/quiesce    succeeds once its jobs and cleanups are done
POST /maintenance/{operation-uuid}/resume     reopen admission for the same operation
```

Unclaimed deliveries go back to NATS for the other process to take. Running jobs finish and clean up normally.

### Draining a runner host

Pausing a ci process does not stop the other process from placing jobs on a host. To empty a host, use the runner drain on either process:

```text
POST /maintenance/runners/{runner-id}/{operation-uuid}/pause
GET  /maintenance/runners/{runner-id}          running jobs, host work, cleanup, drained
POST /maintenance/runners/{runner-id}/{operation-uuid}/resume
```

Use the canonical runner ID, not its display name. The drain is stored in Postgres and survives restarts. Jobs already running finish on that host. New and queued unpinned jobs go to another healthy host in the same network; jobs pinned with `uses: <network>/<host>` (without `fallback: any`) and jobs targeting an existing VM stay pinned and wait. The host is drained when admission is closed and running jobs, outstanding host work and cleanups are all zero. Every ci process sharing the host must run a version that implements runner drain.

## Releases and deployments

A repository may define one workflow with `on: release`. On a full `git submit`, ci creates the selected validation runs and a release coordinator run together; the coordinator waits until every selected validation succeeds and then runs its jobs. `--only`, reruns and partial selections never run the coordinator. The coordinator must start with a merge job containing only `ci/merge-release`, and every deployment job must depend on it.

Built-in release and deployment actions:

| Action | Purpose |
| --- | --- |
| `ci/merge-release` | Fast-forward the default branch to the validated commit (optionally with version bumps and tags). |
| `ci/checkout-release` | Check out the confirmed release commit. |
| `ci/download-artifact` | Fetch an artifact from this run or, with `workflow`, from this submission's validation runs. |
| `ci/publish-service-archive`, `ci/promote-service-archive` | Upload a packaged tarball as an Orchestrator service archive. |
| `ci/deploy-service` | Start an Orchestrator service deployment. |
| `ci/rollout-service` | Candidate-first rollout of an app-lb deployment from a validated artifact. |
| `ci/publish-rootfs`, `ci/deploy-app-lb` | Publish a rootfs image and roll it out to an app-lb deployment. |
| `ci/rollout-host-app-lb` | Replace the app-lb executable on a host. |
| `ci/rollout-host-heyvmd`, `ci/bootstrap-host-heyvm`, `ci/host-heyvm-maintenance` | Host daemon maintenance. |
| `ci/deploy-controller` | Replace the ci controller itself; must be last. |

Sequence regional stages with `needs` so a failure in one region stops the next. Deployment actions record an operation ID before calling the remote API and reconcile that same operation after a restart or lost response rather than submitting another. Their inputs, the operator-owned target mappings they require, and recovery endpoints are specified in the [ci README](../ci/README.md#one-submission-across-validation-workflows-and-deployment). For the platform-level view of regional rollouts, see [multi-region](multi-region.md) and [orchestrator](orchestrator.md).

## This repository's release pipeline

Each installable component has one workflow file in [`.ci/workflows/`](../.ci/workflows/), with one job named `release` that builds, tests, and uploads a tarball with `ci/upload-artifact`:

| Workflow | Artifact | Contents |
| --- | --- | --- |
| `app-lb.yml` | `app-lb` | `app-lb`, `heyctl`, `app-lb.conf` |
| `app-obs.yml` | `app-obs` | `app-obs`, `app-obs-dump`, `app-obs.conf` |
| `ci.yml` | `ci` | `ci`, `ci.conf`, `migrations/` |
| `art.yml` | `art` | `art` |
| `queue.yml` | `queue` | `queue`, `queue.conf`, a deployment template |
| `heyosecret.yml` | `heyosecret` | `heyosecret`, `heyosecret.conf`, `migrations/` |
| `pg-fc.yml` | `pg-fc` | `pg-vm-pool` |
| `codegraph.yml` | `codegraph` | `codegraph` |
| `orchestrator.yml` | `orchestrator-linux` | Orchestrator release bundle |

Every artifact also carries `REVISION` or `BUILD-INFO` and a `SHA256SUMS` file. Each workflow's `paths:` filter lists its crate, its path dependencies, its own workflow file and its image directory under `.ci/image/`, so a commit only rebuilds what it touches. `regional-release.yml` is the `on: release` coordinator that merges and then rolls validated artifacts out to us3, then eu1, then replaces the ci controller.

Publishing for installation is a separate step run by someone with the store's API key:

1. The workflows upload to the artifacts store under `ci-<workflow>-<run>-release-<name>` tags.
2. [`.ci/publish-releases.sh`](../.ci/publish-releases.sh) resolves each app's newest tag to a blob digest, marks that blob public, and writes one `<app>.json` manifest per app plus `index.json`, `install-apps.sh` and `bootstrap-host.sh`.
3. `--push-tag releases-live` uploads that directory as one public bundle and moves the tag; the `releases` site deployment serves it at `get.us2.heyo.work`.

```bash
ART_API_KEY=… sh .ci/publish-releases.sh --all \
  --from-url https://get.us2.heyo.work --push-tag releases-live
heyctl pull releases
```

The installer then downloads public blobs with no credential and verifies the digest and `SHA256SUMS`. To install the binaries, see [installation](installation.md).

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `ci: refusing to start — CI_… …` | A required variable is missing or invalid. The message names it. |
| Submit returns 401 | Missing or wrong `ci.token`/`ci.secret`, or `/api/submit` is not in app-lb `public_paths` (the gate answers 401 to non-browser clients). |
| Submit refused: network not served | The job's resolved network is not in `CI_NETWORK`. Add it, use `*`, or reassign the repository's network. |
| Submit says a selector matched no workflow | `--only` value does not match a file path, basename or `name:`; or the file lacks `submit` in `on:`. |
| Submit started no runs | Every workflow's filters declined. `git submit` prints each reason; `--only` bypasses filters. |
| Every path filter matched | The change set was unknown (no published ancestor diff, root commit, more than 5000 paths). Check `${{ ci.changes_reason }}`. |
| Job stuck `queued`, host shows `no consumer` on `/networks` | The job is pinned to a host that is offline or not in a served network. It fails after `CI_RUNNER_WAIT_SECS`; set `fallback: any` or fix the host. |
| Job fails with "no runner took this job within …s", "no host in network … is online", or "… free disk bytes … this job requires …" | No eligible host: none online, none supports the job's driver, or none has enough free disk (data disk + 2x image size + 5 GiB). The error names the cause; check `/networks` and host disk. |
| Runner refused as unauthenticated | The daemon serves its API without auth. Configure `JWT_SECRET` on heyvmd, or set `CI_ALLOW_UNAUTHENTICATED_RUNNERS=true` for local use only. |
| Checkout fails on a private repository | No `CI_GIT_AUTH_TOKEN`/`GITHUB_TOKEN` in `ci/<workflow>/<environment>`. |
| Checkout fails with a tree mismatch | The base commit or patch does not reproduce the submitted tree. Resubmit after `git fetch`. |
| Image builds but every boot fails | The image lacks `/init.sh` printing `HEYVM_READY`. |
| A variable set with `ENV` in the Dockerfile is missing | OCI metadata is dropped by `docker export`. Write it to `/etc/profile.d` in a `RUN`. |
| `cd: no such file` at the start of a step | `working-directory` is used verbatim. Use an absolute path under `/workspace`. |
| Step killed at 30 minutes | Default step timeout. Set `timeout-minutes` on the step; the job default is 60. |
| Long job's VM disappears mid-build | VM TTL shorter than the job. Set `vm.ttl_seconds` above the job's timeout. |
| Build OOM-killed, or job fails "VM too small" | Raise `size_class` or lower `CARGO_BUILD_JOBS`. The daemon may also have allocated less than declared; see the size on `/vms`. |
| "host memory capacity unavailable" | heyvmd admission counts declared memory of running VMs. Free capacity or add a runner host. |
| `uses: ci/…` is not a built-in action | Only the actions listed above exist; repository composite actions are not supported. |
| `vm:` setting has no effect | Unknown keys inside `vm:` are ignored; check spelling with the table above. |
| Artifact upload is very slow | The guest could not reach the store and fell back to the serial exec channel. Set `CI_ARTIFACT_GUEST_URL` to a URL the guest can reach; the step log explains why the push failed. |
| Public link missing | `public` works only with `CI_ARTIFACT_SINK=artifacts`. |
| Logs of an old run are empty | Logs are deleted after `CI_LOG_RETENTION_DAYS` (default 2); step rows remain. |
| Log stream stops after a ci restart | Stream tokens are per process. Reload the run page. |
| NATS login succeeds, then the first stream fails | You are using the NATS system account. Use a regular account with JetStream enabled. |
| Two installations steal each other's jobs | They share a NATS server and prefix. Give each a distinct `CI_NATS_SUBJECT_PREFIX`. |

For offline validation of every workflow file:

```bash
ci --check-workflows .ci/workflows/*.yml
```

This checks parsing and planning only, not that the build commands work.
