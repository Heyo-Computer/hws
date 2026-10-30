# heyo-mcp

[heyo.computer](https://heyo.computer)

An MCP server over heyo: **sandboxes** — boot a microVM, run commands in it
(short ones, or long ones detached), get files in and out — and the services
that answer operational questions about a fleet, [app-lb](../app-lb)
(deployments and VM pools, and your namespace's artifacts — the bytes a
deployment runs from), [app-obs](../app-obs) (logs and metrics) and [ci](../ci)
(builds). Sandboxes are app-lb deployments, so app-lb serves both halves; the
server never calls the Heyo cloud API.

The sandbox half is the API an agent runs work on. The operational half exists
because its questions span three services: "why is nothing running" is app-lb's
topology *and* app-obs's logs *and* ci's queue, and a tool per endpoint leaves
that join to be redone by hand every time. The diagnostic tools below do the
join and carry what it cost to learn which endpoint answers what.

## An app-lb URL and a token

```bash
APPLB_URL=https://admin.us5.heyo.work   # app-lb's admin API
APPLB_TOKEN=applb_…                     # an app-lb token, from its dashboard
```

That is a complete configuration: every sandbox and deployment tool works with
it. A namespace token's namespace comes from app-lb's own `/whoami`, so it is
never asked for. Everything below is for the cases that need more: app-obs, ci,
the git remote, or a self-hosted app-lb with Basic auth.

## Configuration

| Variable | Purpose |
|---|---|
| `APPLB_URL` | app-lb's admin API — required for every app-lb and sandbox tool |
| `APPLB_NAMESPACE` | the namespace tools name when the caller does not; without it, a namespace token's own (from `/whoami`) |
| `APPLB_TOKEN` | an app-lb token (`applb_…`), or… |
| `APPLB_BASIC` | `user:pass`, or a complete `Basic …` header |
| `APP_OBS_URL` | app-obs base URL |
| `APP_OBS_API_TOKEN` | bearer for its query routes (`/healthz` stays open) |
| `CI_URL` | ci's **own** listener for the pages — see below; the read API works either way |
| `CI_TOKEN` | a repository submit token (`git config ci.token`) — what `ci_run_status` and `ci_run_logs` present |
| `REMOTE_URL` | the Heyo git remote (`remote/`) — the `repo_*` tools |
| `REMOTE_TOKEN` | its credential; defaults to `APPLB_TOKEN` (the remote resolves `applb_…` tokens through app-lb). Over HTTP the caller's own bearer is always used |
| `REMOTE_NAMESPACE` | the namespace repo tools default to; falls back to `APPLB_NAMESPACE`, then the token's own |
| `HEYO_MCP_TIMEOUT_MS` | per-request bound, default 30000 |

Each service is independent: configure one and its tools work while the others
report themselves unconfigured. `heyo_status` says which is which. `HEYO_API_KEY`
and `HEYO_BASE_URL` are no longer read: a configuration still carrying them is
reported as a fault at start and by `heyo_status`, with what to set instead.

A `Basic` value is passed through byte for byte, because app-lb compares it that
way — a re-encoded-but-equivalent header is rejected.

## From generated files to a running site

An agent with files and no repo:

1. `repo_create {name}` — a repo on the Heyo git remote, plus a write token and
   the exact `git push` command.
2. `repo_write_files {repo, message, files | directory}` — or push with git.
3. `repo_deploy {repo, host, context: "dist"}` — stores a read token as an
   app-lb secret, registers a `site` (or `kind: "vm"` for a Dockerfile) whose
   `build` points at the repo, and runs the build. app-lb picks the site's root
   on its own host; never name a path on your machine as `site.root`.

## Artifacts: your namespace's, on app-lb

app-lb fronts one artifact store for the fleet and serves each namespace's
corner of it on its admin API at `/namespaces/{ns}/artifacts/…`. Every `art_*`
tool goes there with **the caller's own app-lb credential** — the same base the
`applb_*` tools use — and
app-lb is the single enforcement point: reads need the view tier in the
namespace, writes need the admin tier over the whole namespace (not a token
narrowed to particular deployments), and tags must start with `<namespace>/`.
This server holds no store key and has no gateway of its own; the namespace
is `APPLB_NAMESPACE`, or the one app-lb's `GET /whoami` confines the token to.

| Route (under `/namespaces/{ns}/artifacts`) | Tool |
|---|---|
| `GET` | `heyo_status` probe: `{namespace, available, prefix}` |
| `GET /tags`, `GET\|PUT\|DELETE /tags/{tag}` | `art_list_tags`, `art_get_tag`, `art_delete_tag` |
| `GET /manifests/{ref}`, `PUT /manifests` | `art_get_manifest`, `art_publish*` |
| `HEAD\|GET\|PUT /blobs/{digest}` | `art_fetch`, `art_publish*` |
| `PUT /repos/{repo}` `{public}` | `art_set_public` |

`art_publish_files` bundles files (or a local directory) into the `.tar.gz` a
site pull unpacks; `art_fetch` downloads a tag, manifest entry or blob with its
digest verified. A blob too large to pass inline is one `curl` against app-lb
itself — `GET <app-lb>/namespaces/<ns>/artifacts/blobs/<digest>` with your own
bearer — and the same route takes a `PUT` of raw bytes with no size cap.

app-lb answers `503` when it has no artifact store configured, `502` when the
store is unreachable, and `403` outside the namespace or below the needed tier;
the tools add a sentence saying which.

## Publishing a build

`art_publish` is the tool for "update deployment X with this build". It is the
step `applb_pull` cannot do: app-lb rolls a deployment onto bytes that must
already be published, so without this the workflow dead-ends halfway.

A publish is **three** requests and the order and the digests matter:

```
PUT …/blobs/{sha256}    the bytes, at their own hash
PUT …/manifests         {schema:1, kind:"generic", entries:[{name,digest,size}]}
                        → answers {digest} — the MANIFEST's digest
PUT …/tags/{tag}        that manifest digest, as text/plain
```

**A tag names a manifest, never a blob.** Nothing checks this: tagging a blob
digest succeeds and then resolves for no reader — a tag that looks right in a
listing and works for nobody. That is why publishing is one composite tool
rather than three primitives with a warning: a composite that always uses the
manifest digest cannot make the mistake.

To deploy it, the spec names only the ref — `"artifact": {"ref":
"<ns>/site:v3"}`, no `store`, no `auth`. app-lb pulls from its own store and
authenticates the pull itself for a ref under the deployment's namespace (or a
digest). A hand-written store URL with no `auth` is pulled anonymously and
401s for anything not public; `applb_deploy` warns about exactly that. Then
`applb_pull` to roll the deployment onto it, and `applb_job` to watch the job
it returns.

**Not `applb_host_update`.** That runs a *static* deployment's own
`update.commands` on the app-lb host and refuses a managed (`vm`) deployment
outright — app-lb's `HostUpdate` job applies to `upstreams` and `site` backends
only. Until 2026-09-10 both this page and `art_publish`'s own result named it as
the next step, which was wrong for the main case; `applb_pull` is what rolls a
managed deployment onto new bytes, and `applb_build` is what rebuilds an image
from a Dockerfile.

## ci: the pages need a direct URL, the read API does not

`ci` deployed behind an app-lb `AuthGate` **admits browsers and almost nothing
else.** The gate splits on `Accept: text/html`, and ci's `public_paths` are only:

```json
["/healthz", "/api/submit", "/api/runs/", "/api/stream/", "/__ui/"]
```

The pages — runs, jobs, `/networks`, `/runners`, `/vms`, `/repos` — are outside
that list, so a machine client is refused there whatever credential it presents.
This is deliberate in ci: minting a submit token is minting the right to run code
on a runner, so those routes are for browsers with an admin role.

So `CI_URL` wants **ci's own listener** for `diagnose_ci_job` and the rest — from
the host it runs on, or through an SSH tunnel:

```bash
ssh -N -L 8081:127.0.0.1:8081 us2.heyo.work   # then CI_URL=http://127.0.0.1:8081
```

`/api/runs/` is the exception, and it is the one that matters most often.
`ci_run_status` and `ci_run_logs` are machine routes with their own credential —
a repository submit token in `CI_TOKEN`, the same value `git submit` uses — so
they work against the public hostname too. Without them a client that submitted a
build was blind to its outcome, and silence reads as failure: a run that is
merely slow is indistinguishable from one that died. Read `run.finished`, not the
status string; builds here routinely take tens of minutes.

Pointed at the gated host, the page-backed tools fail with that explanation
rather than a bare 401, because a token hunt is the wrong response to it.

app-lb and app-obs are ordinary bearer APIs and need no such arrangement.

## Which credential am I?

`heyo_whoami` answers it: admin scope, namespace, deployment scope, expiry.

Run it first on any 401 or 403 from an `applb_*` tool. Scope problems and
authentication problems look identical from outside — a token minted without
admin scope, or scoped to the wrong namespace, produces a refusal that reads as
a broken connection — and this is what tells them apart. It used to take a
second, wider credential on another machine to answer, because listing tokens is
itself an `admin` route.

Two scopes decide everything, and they are checked in **different places**:

- the **admin tier** (`none` / `view` / `admin`) is what app-lb's admin API
  requires;
- the **deployment scope** is what a deployment's own gate requires — that gate
  checks reach and never the tier.

So a token can pass a gate and be refused by the admin API, and the reverse.
Read both fields.

## Sandboxes

A sandbox is an app-lb deployment with no route: one Firecracker VM from a hub
image (`heyo/debian:latest` unless you name another), a data disk at
`/workspace`, and `idle_action: retain`, so stopping it keeps that disk. It is
reached only through these tools, with the same app-lb token as everything
else.

```
sandbox_create → id                 waits until the VM is ready
sandbox_exec                        a short command (under ~30s)
sandbox_exec_start → operation      a long one, detached; several at once
sandbox_exec_status {offset}        its state and a page of output
sandbox_read_file / write_file      small files (≤1 MiB), over the console
sandbox_upload / download → URL     archives: curl the one-time URL
sandbox_stop / start                pause between steps; /workspace is kept
sandbox_kill                        delete it and its disk
```

**Long work goes through operations.** `sandbox_exec` holds the VM's only
console until the command ends, and the call is bounded by this server's own
timeout (`HEYO_MCP_TIMEOUT_MS`, 30s). `sandbox_exec_start` returns at once; the
command runs in its own session with its output in `/workspace/.heyo/ops/<id>`,
and while it runs the sandbox is not stopped for idleness.

**Big files never cross the console.** `sandbox_upload` returns a single-use
URL: `curl -T repo.tar.gz '<url>'` from wherever the file is, and the guest
fetches it, checks its sha256, and unpacks it at `path`. `sandbox_download`
does the reverse — a file, or a directory as a tar.gz. The URL is the
credential: keep it out of logs.

**Only `/workspace` survives a stop.** The rest of the filesystem is the image
again on start.

## Running it

```bash
npm install && npm run build
```

Register with Claude Code:

```bash
claude mcp add heyo -- node /path/to/hws/mcp/dist/index.js
```

Credentials come from the environment the host launches it in, so nothing is
deployed and no secret lives in this directory.

## Running it as a deployment, behind heyo's JWT gate

`deploy/heyo-mcp.json` registers this with app-lb as a static (`proxy_pass`)
deployment — a host process, like app-obs — gated on JWTs issued by the Heyo
auth API:

```jsonc
"auth": {
  "provider": "jwt",
  "jwt": {
    "secret":        {"secret": "heyo-auth", "key": "jwt_secret"},
    "algorithms":    ["HS256"],
    "issuer":        "auth-service",
    "audience":      "heyo-app",
    "subject_claim": "userId",
    "require":       {"role": ["user", "admin"]}
  },
  "public_paths": ["/healthz"],
  "forward_identity": true
}
```

Four things in that block are load-bearing:

- **`secret` is a reference, never a literal.** The same HMAC value that
  verifies a token also *mints* one, so a spec carrying it would hand anyone who
  can read a deployment the ability to issue identities.
- **`algorithms` has no default, by design.** The algorithm is named in the
  token's own header, which is attacker-controlled: a verifier that dispatches
  on it accepts both `alg: none` and a public key used as an HMAC secret.
- **`require`, not `allowed_domains`/`allowed_emails`.** Those two describe a
  *Google* identity and mean nothing against your own issuer — app-lb refuses a
  jwt-only gate that sets them rather than appearing to restrict something it
  does not. `{"role": ["user", "admin"]}` is the equivalent, and an empty
  `require` means "any signed-in user of this product".
- **`public_paths` is only `/healthz`.** Everything else, `/mcp` included, is
  behind the gate.

Install `deploy/supervisor/heyo-mcp.conf`, fill in the two upstream tokens, and
register the deployment. `HEYO_MCP_HTTP_PORT` is what switches the process from
stdio to HTTP.

### How the server treats the identity

It does **not** re-verify the JWT. app-lb checked the signature, issuer,
audience and `require` claims before forwarding anything, and it strips
`x-auth-request-*` unconditionally before setting them, so they cannot be
spoofed. Re-verifying would need the minting secret in a second process — a
larger risk than the one it removes. The signed token is still in the
`Authorization` header if the app ever wants more than the identity.

What the server *does* check is that a forwarded identity is present at all. The
listener binds loopback and app-lb is the only thing expected to reach it, so a
request without one did not come through the gate — a missing `auth` block, a
path wrongly in `public_paths`, or something on the box talking to the port
directly. All three fail with `401` and an explanation, because every tool
behind this can change production.

The check keys on **`x-auth-request-user`**, falling back to email. That
ordering matters: under a JWT gate `user` carries `subject_claim`, which app-lb
refuses a token for missing, while `email` carries `email_claim` and is filled
with `unwrap_or_default()` — so a valid token from an issuer that sends no email
arrives with that header empty. Keying on email would reject those callers while
telling them they had bypassed the gate.

Every call is logged to stderr with the caller's identity, so "who asked for
that" stays answerable after a destructive tool runs.

`HEYO_MCP_REQUIRE_IDENTITY=0` disables the check.

**An app-token gate is the one shape that needs it off.** app-lb admits
`Authorization: Bearer applb_…` with no `Identity` at all — deliberately: "a
token is not a person, and forwarding `x-auth-request-email` for one would put a
name upstream that belongs to nobody" — so nothing is forwarded and the check
above refuses every request that gate admits. A machine client (an agent, a
daemon, anything holding a static bearer) therefore wants either

- `provider: ["app-token"]` on the deployment **and**
  `HEYO_MCP_REQUIRE_IDENTITY=0` here — safe because the gate in front is doing
  exactly the work this check stands in for, and the port is still loopback; or
- `provider: ["jwt"]`, where the caller's own token carries a subject and the
  check keeps working as written.

Pick deliberately. Turning the check off *without* a gate in front leaves an
unauthenticated hole into a process that can delete a deployment.

## Deploying: one tool, and reference material behind it

`applb_deploy` is the entry point. It carries the deployment spec's schema —
generated from app-lb's own Rust types, not transcribed — checks the cross-field
rules a schema cannot express, registers *or* edits as appropriate, starts the
job that matches the backend, and reports what TLS will do.

Three of those steps exist because each was easy to get wrong by hand:

- **Register or edit.** `POST /deployments` replaces a deployment and recycles
  its VM pool; `PUT` preserves the pool whenever the `vm` block is unchanged.
  Only the first was exposed, so every scaling or route edit cost a full roll.
- **Which job.** app-lb's job kinds each apply to a subset of backends. `build`
  is for a `vm` with a Dockerfile, `pull` rolls a `vm` or `site` onto published
  artifact bytes, and `host_update` runs a *static* deployment's own commands on the
  app-lb host and refuses a managed one. Picking wrong is refused, not ignored.
- **TLS.** An exact `host` route is issued automatically within seconds. A
  `host_suffix` route never gets its own certificate and needs a fleet wildcard;
  one no wildcard covers is served a fallback that will not validate.

The primitives are still there — `applb_create_deployment`,
`applb_update_deployment`, `applb_build`, `applb_pull`, `applb_pull_mounts`,
`applb_host_update`, `applb_job` — for when you want exactly one request.

### What a host's approval dialog sees

Every tool carries MCP annotations, derived rather than declared: `destructiveHint`
comes from the `DESTRUCTIVE.` sentence at the front of a description, so the two
cannot drift apart. The prose is what the model reads — the SDK is explicit that
clients should never make tool use decisions from annotations — and the
annotation is what an approval UI reads.

Only what the MCP defaults do not already say is emitted, which matters for
correctness and not just size: `destructiveHint` defaults to **true**, so a tool
that is neither read-only nor destructive has to say `destructiveHint: false` out
loud or a host is told it destroys things.

`readOnlyHint` is the one hint that cannot be derived, and the one where being
wrong is a safety problem — a host may auto-approve what it believes is a read.
The list of read-only tools is checked by running each of them against a stubbed
transport and failing if any issues anything but a `GET`.

### Resources and prompts

The server serves reference material as MCP **resources**, which are pulled when
wanted rather than pushed on every connect:

| URI | What |
|---|---|
| `heyo://applb/deployment-spec` | the full generated schema, plus every cross-field rule |
| `heyo://applb/deploy-guide` | the sequence end to end |
| `heyo://applb/tls` | why an exact host gets HTTPS and a suffix does not |
| `heyo://applb/examples/{name}` | each of app-lb's shipped example specs, with its notes |

That split is what makes it honest for the advertised schema to summarise the
auth gate and the mount blocks: `applb_spec_schema` and these resources have
them in full, one call away, costing nothing until asked for.

There is one **prompt**, `deploy_a_service(kind, id, host?)`, which returns the
ordered plan for that backend kind. A host that surfaces prompts as slash
commands turns "how do I deploy" into a visible affordance rather than something
to infer from sixty tool names.

## Tools

<!-- BEGIN GENERATED CATALOGUE -->

### Start here

Step-by-step plans for common tasks and failures, and what this server can reach.

| Tool | | Does |
| --- | --- | --- |
| `heyo_guide` | read-only | START HERE for a task you have not done on Heyo, or with an error you do not understand. |

### Diagnostics

Cross-service, shaped like the question rather than the endpoint.

| Tool | | Does |
| --- | --- | --- |
| `heyo_status` | read-only | Which of app-lb, app-obs and ci this server can reach, whether your namespace's artifacts on app-lb are available, and what each says about itself. |
| `heyo_whoami` | read-only | What this server's credential is and what it may do: admin scope, namespace, deployment scope and expiry. |
| `diagnose_deployment` | read-only | Everything about one deployment at once: app-lb's record and its VM pool, app-obs's bucketed series, and the most recent error-level logs. |
| `deployment_logs` | read-only | Log lines for one deployment, newest first, with the filters app-obs supports: time window or explicit from/to, level, backend, a substring query, and a cursor for paging. |
| `namespace_telemetry` | read-only | One namespace's telemetry: each deployment's requests, errors, latency, CPU and memory over a window, plus one deployment's series and recent errors when `deployment` is given. fleet_overview for a namespace-confined credential — call it first for 'how are my apps doing'. |
| `diagnose_vm_boot` |  | Why a VM deployment boots but never passes its health check (ready 0, boot timeouts). |
| `fleet_overview` | read-only | The whole managed fleet in one call: app-obs's per-deployment rows with host CPU and memory, app-lb's current topology with health and drain state, and app-obs's ingest counters. |
| `diagnose_empty_pool` | read-only | Why a deployment's VM pool is empty or will not fill. |
| `diagnose_ci_job` | read-only | Why a ci job is not running. |

### Deploying

`applb_deploy` is the entry point and does the whole sequence; the rest are the primitives underneath it. Which job tool applies depends on the backend, and picking wrong is refused rather than ignored — `applb_build` for a Dockerfile, `applb_pull` for bytes from a store, `applb_host_update` for a static deployment's own commands.

| Tool | | Does |
| --- | --- | --- |
| `applb_deploy` |  | Just files, no spec? repo_deploy fits better; see heyo_guide. |
| `applb_spec_schema` | read-only | The deployment spec in full: every field of a named block with its complete documentation, plus the cross-field rules that apply to it. |
| `applb_create_deployment` |  | Register a deployment from a full spec, REPLACING any deployment with the same id and recycling its VM pool. |
| `applb_update_deployment` |  | Edit an existing deployment in place, replacing its whole spec. |
| `applb_delete_deployment` | **destructive** | Deregisters a deployment from app-lb and tears down its backends. |
| `applb_scale` |  | Change a deployment's scaling parameters. |
| `applb_build` |  | Build a managed (`vm`) deployment's image from its `build` block and roll the pool onto it. |
| `applb_pull` |  | Materialize a `vm` or `site` deployment's bytes from your namespace's artifacts and roll it onto them. |
| `applb_pull_mounts` |  | Re-unpack the guest mounts a `vm` deployment declares, from their artifact stores. |
| `applb_host_update` |  | Run a STATIC (`upstreams`) or `site` deployment's own `update.commands` on the app-lb host, then re-probe its upstreams. |
| `applb_job` | read-only | One job by its id — what applb_build, applb_pull, applb_pull_mounts and applb_host_update each return. |
| `applb_deployment_jobs` | read-only | Recent build/pull/update jobs for a deployment, with their outcomes. |

### Fleet and pools

Reads over app-lb's topology, plus the operations that move VMs and disks.

| Tool | | Does |
| --- | --- | --- |
| `applb_list_deployments` | read-only | Every deployment app-lb manages, with its backends and current state. |
| `applb_get_deployment` | read-only | One deployment in full: its spec, desired and ready replica counts, and every VM with its health. |
| `applb_metrics` | read-only | app-lb's live metrics: per-deployment pool counters, request stats, and create/boot outcomes. |
| `applb_disks` | read-only | Disk inventory and usage. |
| `applb_certs` | read-only | TLS certificates app-lb holds, with their hostname, issuer and expiry. |
| `applb_security_events` | read-only | app-lb's SIEM findings: authentication abuse, attack signatures and traffic anomalies, newest first, plus any block rules in force and the guard's counters. |
| `applb_drain_upstream` | **destructive** | Take one upstream of a STATIC (`upstreams`) deployment out of rotation. |
| `applb_uncordon_upstream` |  | Put a drained upstream back into rotation. |
| `applb_evict_vm` | **destructive** | Removes one VM from a deployment's pool and destroys it. |
| `applb_purge_disk` | **destructive** | Permanently deletes one disk and everything on it. |
| `applb_purge_orphan_disks` | **destructive** | Deletes every disk app-lb considers orphaned, in one call. |
| `applb_sweep_disks` | **destructive** | Runs the disk expiry sweep now instead of waiting for the next tick, deleting every disk past its TTL. |
| `applb_exec` | **destructive** | Runs a command inside a deployment's guest and returns its output. |

### The event feed

app-lb's per-namespace RSS, as data.

| Tool | | Does |
| --- | --- | --- |
| `applb_feeds` | read-only | Which namespaces have deployment events, and how many. |
| `applb_feed` | read-only | Deployment events for one namespace, newest first: deployed, updated, removed, and operational issues. |

### Sandboxes

VMs to run code in, on app-lb: create, exec (or start detached and poll), files, one-time upload/download URLs, stop/start, kill.

| Tool | | Does |
| --- | --- | --- |
| `sandbox_create` |  | Create a sandbox: a Firecracker VM from a hub image (default heyo/debian:latest) with a /workspace disk that survives sandbox_stop. |
| `sandbox_exec` | **destructive** | Run a short command (under ~30s) in the sandbox and return its output. |
| `sandbox_exec_start` | **destructive** | Start a command detached in the sandbox and return at once with an operation id. |
| `sandbox_exec_status` | read-only | An operation's state (running, succeeded, failed, cancelled, timed_out, lost), exit code, and a page of its output from offset (next_offset continues it; tail for the end). |
| `sandbox_read_file` | read-only | Read up to 256 KiB of a file in the sandbox from offset; next_offset continues it. |
| `sandbox_write_file` | **destructive** | Write up to 1 MiB to a file in the sandbox (replace, or append); parent directories are created. |
| `sandbox_upload` |  | Get a one-time URL to upload a file or archive into the sandbox: curl -T it there (no credential needed) and the guest places it at path, unpacking tar/tar.gz into it. |
| `sandbox_download` |  | Get a one-time URL to download a file, or a directory as a tar.gz, from the sandbox. |
| `sandbox_stop` |  | Pause the sandbox: its VM stops and /workspace is kept for sandbox_start. |
| `sandbox_start` |  | Resume a stopped sandbox with its /workspace, and wait for it. |
| `sandbox_kill` | **destructive** | Delete the sandbox, its VM and its /workspace disk. |
| `sandbox_list` | read-only | Your sandboxes (deployments with no route), with their pool state. |
| `sandbox_info` | read-only | One sandbox: its spec, VMs and state. |
| `sandbox_exec_cancel` |  | Cancel an operation: SIGTERM to its process group, SIGKILL 10s later. |
| `sandbox_transfer_status` | read-only | One upload or download: its state, size, sha256 and any error. |
| `sandbox_restart` |  | Restart the sandbox keeping /workspace, or with fresh: true boot a new VM with an empty disk. force: true as for sandbox_stop. |
| `heyo_capacity` | read-only | What the host has left (CPU, memory, disk) and your sandboxes' VMs. |

### Git repos

Repos on the Heyo git remote: somewhere a generated project can live, and what app-lb builds from.

| Tool | | Does |
| --- | --- | --- |
| `repo_create` |  | Create a git repo on the Heyo remote, the place an agent's project lives so app-lb can build it. |
| `repo_write_files` |  | Commit files to a repo with no git on your side. |
| `repo_deploy` |  | Deploy a repo from the Heyo remote through app-lb, in one call: mints a read token, stores it as an app-lb secret, registers (or edits) the deployment with `build` pointing at the repo, and starts the build. |
| `repo_list` | read-only | The repos in a namespace on the Heyo remote, with their clone URLs. |
| `repo_get` | read-only | One repo: its clone URL, HEAD, every ref and its commit, and whether it is still empty. |
| `repo_token` |  | Mint a repo token: `read` to clone or let app-lb build, `write` to push. |

### Artifacts

Your namespace's artifacts, held by app-lb (`/namespaces/{ns}/artifacts` on its admin API, with your own app-lb credential): where a deployment's bytes come from.

| Tool | | Does |
| --- | --- | --- |
| `art_publish_files` |  | Bundle files into a .tar.gz and publish it into your namespace's artifacts on app-lb under a tag (must start with "<namespace>/"), the format a `site` deployment's `artifact` pull unpacks into its root. |
| `art_publish` |  | Publish a bundle into your namespace's artifacts on app-lb and point a tag at it. |
| `art_fetch` |  | Download one of your namespace's artifacts from app-lb: a tag or manifest digest (its single entry, or `entry`), or a blob digest. |
| `art_list_tags` | read-only | Every tag in your namespace's artifacts on app-lb (all under "<namespace>/") and the manifest digest each points at. |
| `art_delete_tag` | **destructive** | Remove one of your namespace's artifact tags on app-lb. |
| `art_set_public` |  | Make one of your namespace's artifact repos anonymously pullable (`public: true`) or private again. |
| `art_get_tag` | read-only | What one of your namespace's tags points at: JSON `{tag, digest}`, the digest being its manifest's. |
| `art_get_manifest` | read-only | One manifest from your namespace's artifacts, by digest or by tag: its kind, its entries and their digests and sizes. |

### ci

Build status and VM pool control.

| Tool | | Does |
| --- | --- | --- |
| `ci_run_status` | read-only | Whether a ci run has finished and whether it worked, with every job and step. |
| `ci_run_logs` | read-only | What a run printed, per job and step. |
| `ci_cancel_run` | **destructive** | Cancels a ci run and every unfinished job in it. |
| `ci_destroy_vm` | **destructive** | Destroys one pooled ci VM. |
| `ci_cleanup_failed_vms` | **destructive** | Destroys every idle ci VM whose last run failed. |

### Raw escape hatches

Everything without a dedicated tool. Prefer a named tool when one exists — a raw call's intent cannot be read without reading its arguments.

| Tool | | Does |
| --- | --- | --- |
| `applb_request` |  | Raw HTTP against app-lb, for endpoints without a dedicated tool above. |
| `obs_request` |  | Raw HTTP against app-obs, for endpoints without a dedicated tool above. |
| `ci_request` |  | Raw HTTP against ci, for endpoints without a dedicated tool above. |

_76 tools. Generated from the server's own listing by `scripts/gen-catalogue.mjs`; run `npm run catalogue` after adding one._

<!-- END GENERATED CATALOGUE -->

### Destructive tools are named, not hidden

Each has its own tool and a description that opens with `DESTRUCTIVE` — marked
in the tables above, so the set is generated rather than listed here. It used to
be listed here, and named eight when there were eleven.

Folding them into a generic request tool would hide a `DELETE` inside a
parameter, where it is invisible in a transcript and in an approval prompt. The
same reasoning names `sandbox_kill` rather than leaving it to `applb_request`.

The prose is the part that matters: the SDK is explicit that clients should
never make tool-use decisions from annotations, so the sentence the model reads
carries the warning and `destructiveHint` is derived from it.

The raw `applb_request` / `obs_request` / `ci_request`
tools reach the rest of each API, including destructive methods. Prefer a named tool when one exists —
the raw one's intent cannot be read without reading its arguments.

`applb_purge_orphan_disks` deserves particular care: *orphaned* is app-lb's
inference, and a disk belonging to something app-lb has lost track of looks
exactly like one belonging to nothing.

## Two things the tools cannot see

**A guest's `start_command` failure.** It writes to the guest's own
`/var/log/heyvm-start.log`, which never reaches app-obs. An empty log section
beside a pool that will not fill is a signal, not the absence of one — read the
file with `applb_exec`.

**ci's pages, when ci is behind its gate.** Runs, jobs, runners, vms and repos
need ci's own listener. `ci_run_status` and `ci_run_logs` are the exception and
work either way — see above.
