# heyo-mcp

An MCP server over heyo: **heyo cloud** for sandboxes — boot a microVM, run a
command in it, get files in and out — and the three services that answer
operational questions about a fleet, [app-lb](../app-lb) (deployments and VM
pools), [app-obs](../app-obs) (logs and metrics), [ci](../ci) (builds) and the
[artifact store](../artifacts) (the bytes a deployment runs from).

The sandbox half is the API an agent runs work on. The operational half exists
because its questions span three services: "why is nothing running" is app-lb's
topology *and* app-obs's logs *and* ci's queue, and a tool per endpoint leaves
that join to be redone by hand every time. The diagnostic tools below do the
join and carry what it cost to learn which endpoint answers what.

## Two API keys and nothing else

```bash
HEYO_API_KEY=heyo_api_…      # heyo cloud: sandboxes
APPLB_TOKEN=heyo_api_…       # the managed app-lb, through cloud's namespace door
```

That is a complete configuration. Cloud's base defaults to
`https://server.heyo.computer`; app-lb defaults to the same base and discovers
its namespace from the key on first use — one namespace is the answer, several
is ambiguous and names them, none says how to create one. Through that door the
app-lb credential *is* a heyo API key, so a lone `HEYO_API_KEY` configures both;
the second variable exists for a deployment that wants them separate, and for a
self-hosted app-lb where they genuinely differ.

Everything below is for the cases that need more: a self-hosted app-lb, app-obs,
ci, or a cloud that is not the public one.

## Configuration

| Variable | Purpose |
|---|---|
| `HEYO_API_KEY` | heyo cloud API key — the sandbox tools, and app-lb's default credential. Unset, the sandbox tools are not listed at all |
| `HEYO_BASE_URL` | cloud base URL; defaults to `https://server.heyo.computer` |
| `APPLB_URL` | app-lb base URL — its own admin listener, or heyo cloud (see managed mode). Unset means the managed door at cloud's base |
| `APPLB_NAMESPACE` | managed mode: the namespace to reach app-lb in, through heyo cloud |
| `APPLB_TOKEN` | bearer token (a `heyo_api_*` key in managed mode), or… |
| `APPLB_BASIC` | `user:pass`, or a complete `Basic …` header |
| `APP_OBS_URL` | app-obs base URL |
| `APP_OBS_API_TOKEN` | bearer for its query routes (`/healthz` stays open) |
| `CI_URL` | ci's **own** listener for the pages — see below; the read API works either way |
| `CI_TOKEN` | a repository submit token (`git config ci.token`) — what `ci_run_status` and `ci_run_logs` present |
| `ART_URL` | artifact store base URL |
| `ART_API_KEY` | the store's own key, sent as `x-api-key` |
| `ART_GATE_TOKEN` | app-token for the gate in front of the store; defaults to `APPLB_TOKEN` |
| `REMOTE_URL` | the Heyo git remote (`remote/`) — the `repo_*` tools |
| `REMOTE_TOKEN` | its credential; defaults to `APPLB_TOKEN` (the remote resolves `applb_…` tokens through app-lb), then `HEYO_API_KEY`. Over HTTP the caller's own bearer is always used |
| `REMOTE_NAMESPACE` | the namespace repo tools default to; falls back to `APPLB_NAMESPACE`, then app-lb's discovered namespace |
| `HEYO_MCP_PUBLIC_URL` | HTTP mode: this server's public base, so tools can point at the `/art` gateway for blobs too large to pass inline |
| `HEYO_MCP_TIMEOUT_MS` | per-request bound, default 30000 |

Each service is independent: configure one and its tools work while the others
report themselves unconfigured. `heyo_status` says which is which — and its
app-lb probe is also what resolves the managed namespace, so an ambiguous one
surfaces there rather than inside some later call.

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

## The artifact-store gateway

Beyond `art_publish`: `art_publish_files` bundles files (or a local directory)
into the `.tar.gz` a site pull unpacks; `art_fetch` downloads a tag, manifest
entry or blob with its digest verified; `art_list_manifests`, `art_delete_tag`
and `art_set_public` cover the rest. Over HTTP, `/art/{blobs,manifests,tags,
labels,public,usage}…` is forwarded to the store with this server's store key
and the caller's own bearer, so `curl -T bundle.tgz` works for anything too
large for a tool call.

## Publishing a build

`art_publish` is the tool for "update deployment X with this build". It is the
step `applb_pull` cannot do: app-lb rolls a deployment onto bytes that must
already be in the store, so without this the workflow dead-ends halfway.

A publish is **three** requests and the order and the digests matter:

```
PUT /blobs/{sha256}     the bytes, at their own hash
PUT /manifests          {schema:1, kind:"generic", entries:[{name,digest,size}]}
                        → answers {digest} — the MANIFEST's digest
PUT /tags/{tag}         that manifest digest, as text/plain
```

**A tag names a manifest, never a blob.** The store does not check this: it
writes whatever digest it is handed, so tagging a blob digest succeeds and then
resolves for no reader — a tag that looks right in a listing and works for
nobody. That is why publishing is one composite tool rather than three
primitives with a warning: a composite that always uses the manifest digest
cannot make the mistake. The primitives are still there (`art_request`) for
everything else.

Then `applb_pull` to roll the deployment onto it, and `applb_job` to watch the
job it returns.

**Not `applb_host_update`.** That runs a *static* deployment's own
`update.commands` on the app-lb host and refuses a managed (`vm`) deployment
outright — app-lb's `HostUpdate` job applies to `upstreams` and `site` backends
only. Until 2026-09-10 both this page and `art_publish`'s own result named it as
the next step, which was wrong for the main case; `applb_pull` is what rolls a
managed deployment onto new bytes, and `applb_build` is what rebuilds an image
from a Dockerfile.

### Two credentials, one request

The store is the only service here with **two authenticators stacked in front of
it**, and until both were used it could not be written to from outside the
network at all:

| Layer | Credential | Header |
|---|---|---|
| app-lb's gate | app-token with `admin` scope over the `artifacts` deployment | `Authorization: Bearer applb_…` |
| the store itself | `ART_API_KEY` | `x-api-key` |

Both are ordinarily presented as `Authorization`, which is why this reads as
unsatisfiable: whichever one you send, the other layer refuses it. The way
through is that the store also accepts `x-api-key`, so one request passes both
doors. ci never hits this because ci runs inside the network, where there is no
gate.

Reached on its own listener there is no gate, and `ART_API_KEY` alone is enough.

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

`sandbox_create` boots a microVM and returns its id; every other sandbox tool
names that id. There is **one endpoint for every sandbox** — no per-sandbox
connection, nothing to re-establish after a restart, and `sandbox_list` recovers
an id that was lost. A sandbox outlives the call that made it: it is a VM with a
TTL, not a request scope.

```
sandbox_create → id
sandbox_exec / sandbox_read_file / sandbox_write_file
sandbox_set_ttl        keep it alive across a conversation
sandbox_stop / start   park it: disk kept, TTL clock stopped
sandbox_kill           destroy it and its disk
```

### The 1 MB body, and the way around it

Cloud's JSON API caps a request body at 1 MB, and file writes cross it base64,
so ~768 KB of payload is already `413 Request Entity Too Large` — 512 KB
succeeds, measured against the live API. MCP inherits that limit because it is
the same API underneath; a photograph from a phone routinely exceeds it.

The archive route is not subject to it, because the bytes never enter a JSON
body:

```
sandbox_upload_url        → { archive_id, upload_url }
PUT the tar.gz to upload_url   ← Content-Type: application/gzip, NO Authorization
sandbox_finalize_upload   → the archive is now usable
sandbox_create { archive_id }  or  sandbox_attach_archive { id, archive_id }
```

The presigned URL belongs to the object store, so its ceiling is the store's,
not the API's — hundreds of megabytes, which is the case it exists for. The
signature is the credential; sending a bearer alongside it is what makes some
stores refuse. `sandbox_attach_archive` is what makes this usable
mid-conversation: it mounts an archive onto a sandbox that is already running,
so a large file reaches an existing sandbox without booting a new one to carry
it.

`sandbox_write_file` refuses more than 512 KiB rather than spending a round trip
to be told 413, and the refusal names this route.

### 503 is capacity, not a fault

`ApiError(503): No available backend in region US supports libvirt` means no
host in that region runs that driver with room to spare. Retrying immediately
fails identically; retrying with backoff does not. So `sandbox_create` retries
exactly that status — three attempts by default, doubling from 2s, `retries: 0`
to disable — and retries nothing else, because a rejected spec only gets
rejected again. Naming a driver the region actually runs (`firecracker`) or the
other region often succeeds where the default did not.

`heyo_capacity` is the pre-flight, and is honest about its reach: it lists the
daemons *this key* has registered, online or not, plus every sandbox already
running. Cloud publishes no per-region or per-driver free capacity, so for
heyo-hosted regions a 503 on create remains the first signal.

## Managed mode

Heyo runs one app-lb as a platform service. Customers do not reach its admin
listener; they reach it through heyo cloud, per namespace, at
`/namespaces/{ns}/lb/…`, with their ordinary `heyo_api_*` key. Cloud pins every
request to that namespace and app-lb resolves the key into a grant, so the
same admin API answers, walled to what the key may see.

This server needs no code for that — only a different base:

```bash
APPLB_URL=https://server.heyo.computer \
APPLB_NAMESPACE=team-a \
APPLB_TOKEN=heyo_api_… \
node dist/index.js
```

`APPLB_NAMESPACE` turns the base into `${APPLB_URL}/namespaces/team-a/lb`;
every tool then appends its path as before. (Spelling the full
`…/namespaces/team-a/lb` URL out in `APPLB_URL` works too and is not rewritten
again.) A namespace is created once, with `POST /namespaces` on cloud or the
SDK's `Namespaces.create`, and deployments registered through this door land
in it whether or not the spec says so.

What the door exposes: `applb_list_deployments`, `applb_get_deployment`,
`applb_deploy`, `applb_create_deployment`, `applb_update_deployment`,
`applb_scale`, `applb_build`, `applb_pull`, `applb_pull_mounts`,
`applb_host_update`, `applb_job`, `applb_deployment_jobs`,
`applb_delete_deployment`, `applb_spec_schema`,
`applb_evict_vm`, `applb_exec`, `applb_metrics` and `applb_security_events`. The fleet-wide operator
tools — `applb_disks`, `applb_certs`, `applb_purge_disk`,
`applb_purge_orphan_disks`, `applb_sweep_disks` — answer `404 route not exposed
through the namespace proxy`, and `applb_request` is bounded by the same list.
VMs a managed deployment boots are billed to the namespace's account like any
other sandbox.

A hosted instance can serve many tenants from one process: leave `APPLB_TOKEN`
and `APPLB_BASIC` unset and, in HTTP mode, each request's own `Authorization`
header goes upstream instead, so every caller acts under their own key and
therefore their own namespaces. A configured token otherwise wins over a
caller's header — an instance deployed to act as itself must not be talked into
acting as someone else.

**Behind an app-token gate, the instance's own MCP path has to be public.** A
gate checks a token against the deployment *it* belongs to before anything
behind it runs, and a hosted instance usually lives in `default` — so a token
confined to any other namespace is refused at the door with a 403, however well
it is scoped for everything else. Give the path
`{"path": "/mcp", "scope": "public"}` and set `HEYO_MCP_REQUIRE_IDENTITY=0`.
That is safe only because the instance holds no credential: an anonymous
request reaches a server with nothing to act with, and every call it makes
carries the caller's own token to be judged where it lands. Over HTTP,
`art_publish` takes `content_base64` only. `deploy/vm.md` has the reasoning.

**One credential overrides that, and must: a token app-lb minted itself.** A
caller presenting `Authorization: Bearer applb_…` reaches app-lb with *that*
token, whether or not this process has one of its own. An app-token carries a
scope — an `admin` level and a `deployments` list — which app-lb enforces per
route, so substituting the operator's fleet-wide `APPLB_TOKEN` for it would
hand a token scoped to one deployment the reach of a credential scoped to all
of them. The gate in front authenticated a narrow principal; acting for it with
broad authority is a confused deputy, and this is the shape that closes it.

The rule keys on the `applb_` prefix, so nothing else changes: a `heyo_api_*`
key or a JWT means nothing to app-lb's admin API and still falls to the
configured credential, leaving managed mode and JWT-gated deployments exactly
as they were. Nor is preferring the caller's token an escalation the other way
— it is a credential they already hold, and app-lb re-checks its scope whoever
relayed it.

**app-obs and ci follow the same rule when app-lb is what gates them.** Reached
directly on loopback they authenticate themselves: `APP_OBS_API_TOKEN` and
`CI_TOKEN` are their *own* service tokens, an `applb_…` bearer means nothing to
either, and forwarding one would 401 every obs and ci tool on a deployment that
was working. Reached at a hostname behind an app-lb gate the credential *is* an
app-lb token, and then the caller's must win — a caller whose scope omits
`app-obs` must not read app-obs on this process's ticket.

What separates the two is the shape of what is configured, so there is no new
switch: nothing at all, or another `applb_…`, both mean the gate authenticates
and the caller's token is used; a service's own token means it does not, and is
left alone. Configure neither and the process holds no credential for any of
the four services — every call runs as whoever asked. That is the shape
`deploy/vm.md` deploys.

Cloud is outside this, and outside the borrow-when-empty rule too. An
`applb_…` token is not a cloud credential — cloud has never heard of it — so it
is never substituted for one. That leaves two honest configurations and no
third:

- **`HEYO_API_KEY` set.** The sandbox tools work, and every caller an app-token
  gate admits shares that one cloud account. There is no per-user cloud
  counterpart to switch to, so **treat sandbox reach as shared** and mint tokens
  with the `deployments` scope the caller should actually have.
- **`HEYO_API_KEY` unset.** Cloud stays unconfigured and `buildTools` lists no
  sandbox tools at all. This is the fleet-operations shape — app-lb, app-obs, ci
  and the feed, and nothing that needs a credential the gate cannot supply. See
  `deploy/vm.md`.

The gate is on the credential rather than a switch, so a hosted instance
carrying no key of its own still hands the sandbox tools to a caller who
presents a `heyo_api_*` key, per request. That is what keeps managed mode
multi-tenant.

And know what `admin` buys, because it is coarser than it sounds. `none` passes
the gate and reaches no admin route; `view` covers `/metrics`, `/disks`,
`/feeds`, `/security`, `/ingress` and `/storage` — which is `applb_metrics`,
`applb_security_events`, `applb_disks` and the feed tools, and nothing else;
`admin` is everything.
There is **no read-only tier for deployment routes**: `GET /deployments` and
`GET /deployments/:id` are CRUD-tier, because a spec's env vars can hold
secrets, so `applb_list_deployments`, `applb_get_deployment` and
`applb_deployment_jobs` all require `admin` — the same scope that deletes a
deployment and execs in its VMs. A token that can read one can delete it. For a
caller who needs deployment reads, the `deployments` list and `namespace` are
the only narrowing that exists.

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
  is for a `vm` with a Dockerfile, `pull` rolls a `vm` or `site` onto bytes from
  a store, and `host_update` runs a *static* deployment's own commands on the
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
| `heyo_status` | read-only | Which of heyo cloud, app-lb, app-obs, ci and the artifact store this server can reach, and what each says about itself. |
| `heyo_whoami` | read-only | What this server's credential is and what it may do: admin scope, namespace, deployment scope and expiry. |
| `diagnose_deployment` | read-only | Everything about one deployment at once: app-lb's record and its VM pool, app-obs's bucketed series, and the most recent error-level logs. |
| `deployment_logs` | read-only | Log lines for one deployment, newest first, with the filters app-obs supports: time window or explicit from/to, level, backend, a substring query, and a cursor for paging. |
| `fleet_overview` | read-only | The whole managed fleet in one call: app-obs's per-deployment rows with host CPU and memory, app-lb's current topology with health and drain state, and app-obs's ingest counters. |
| `diagnose_empty_pool` | read-only | Why a deployment's VM pool is empty or will not fill. |
| `diagnose_ci_job` | read-only | Why a ci job is not running. |

### Deploying

`applb_deploy` is the entry point and does the whole sequence; the rest are the primitives underneath it. Which job tool applies depends on the backend, and picking wrong is refused rather than ignored — `applb_build` for a Dockerfile, `applb_pull` for bytes from a store, `applb_host_update` for a static deployment's own commands.

| Tool | | Does |
| --- | --- | --- |
| `applb_deploy` |  | No spec yet, just files? repo_deploy or art_publish_files fit better; see heyo_guide. |
| `applb_spec_schema` | read-only | The deployment spec in full: every field of a named block with its complete documentation, plus the cross-field rules that apply to it. |
| `applb_create_deployment` |  | Register a deployment from a full spec, REPLACING any deployment with the same id and recycling its VM pool. |
| `applb_update_deployment` |  | Edit an existing deployment in place, replacing its whole spec. |
| `applb_delete_deployment` | **destructive** | Deregisters a deployment from app-lb and tears down its backends. |
| `applb_scale` |  | Change a deployment's scaling parameters. |
| `applb_build` |  | Build a managed (`vm`) deployment's image from its `build` block and roll the pool onto it. |
| `applb_pull` |  | Materialize a `vm` or `site` deployment's bytes from an artifact store and roll it onto them. |
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

heyo cloud. Listed only when a usable cloud API key is configured.

| Tool | | Does |
| --- | --- | --- |
| `sandbox_create` |  | Boot a sandbox (a microVM) and return it once it is running. |
| `sandbox_list` |  | Every sandbox this key can see, with status, image, uptime and bound URLs. |
| `sandbox_info` |  | One sandbox by id: status, region, size, TTL and bound URLs. |
| `sandbox_exec` |  | Run a command in the sandbox with `sh -c` and return stdout, stderr and exit_code. |
| `sandbox_read_file` |  | Read a file from the sandbox. |
| `sandbox_write_file` |  | Write a file into the sandbox. |
| `sandbox_upload_url` |  | Reserve an archive and return a presigned URL to PUT its bytes to. |
| `sandbox_finalize_upload` |  | Close out an upload started by sandbox_upload_url: the archive is only usable once finalized. |
| `sandbox_attach_archive` |  | Mount a finalized archive onto a sandbox that is already running, replacing what is at `sandbox_path`. |
| `sandbox_set_ttl` |  | Reset how long the sandbox may run unattended, from now. |
| `sandbox_stop` |  | Stop the sandbox without destroying it. |
| `sandbox_start` |  | Start a stopped sandbox again, with its disk as it was left. |
| `sandbox_restart` |  | Reboot the sandbox. |
| `sandbox_kill` | **destructive** | Permanently deletes the sandbox and its disk. |
| `heyo_capacity` | read-only | What can be told about capacity *before* booting something. |

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

### The artifact store

Where a deployment's bytes come from.

| Tool | | Does |
| --- | --- | --- |
| `art_publish_files` |  | Bundle files into a .tar.gz and publish it under a tag, the format a `site` deployment's `artifact` pull unpacks into its root. |
| `art_publish` |  | Publish a bundle to the artifact store and point a tag at it. |
| `art_fetch` |  | Download from the store: a tag or manifest digest (its single entry, or `entry`), or a blob digest. |
| `art_list_tags` | read-only | Every tag in the store and the digest it points at. |
| `art_list_manifests` | read-only | Every manifest in the store: digest, kind and entries. |
| `art_delete_tag` | **destructive** | Remove a tag. |
| `art_set_public` |  | Make a blob anonymously downloadable (`public: true`) or private again. |
| `art_get_tag` | read-only | What one tag points at. |
| `art_get_manifest` | read-only | One manifest by digest or by tag: its kind, its entries and their digests and sizes. |
| `art_list_blobs` | read-only | Every blob with its size, its label and the tags pointing at it. |
| `art_usage` | read-only | The store's disk usage. |

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
| `heyo_request` |  | Raw HTTP against heyo cloud, for endpoints without a dedicated tool above. |
| `applb_request` |  | Raw HTTP against app-lb, for endpoints without a dedicated tool above. |
| `obs_request` |  | Raw HTTP against app-obs, for endpoints without a dedicated tool above. |
| `ci_request` |  | Raw HTTP against ci, for endpoints without a dedicated tool above. |
| `art_request` |  | Raw HTTP against the artifact store, for endpoints without a dedicated tool above. |

_77 tools. Generated from the server's own listing by `scripts/gen-catalogue.mjs`; run `npm run catalogue` after adding one._

<!-- END GENERATED CATALOGUE -->

### Destructive tools are named, not hidden

Each has its own tool and a description that opens with `DESTRUCTIVE` — marked
in the tables above, so the set is generated rather than listed here. It used to
be listed here, and named eight when there were eleven.

Folding them into a generic request tool would hide a `DELETE` inside a
parameter, where it is invisible in a transcript and in an approval prompt. The
same reasoning names `sandbox_kill` rather than leaving it to `heyo_request`.

The prose is the part that matters: the SDK is explicit that clients should
never make tool-use decisions from annotations, so the sentence the model reads
carries the warning and `destructiveHint` is derived from it.

The raw `heyo_request` / `applb_request` / `obs_request` / `ci_request` /
`art_request` tools reach the rest of each API, including destructive methods. Prefer a named tool when one exists —
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
